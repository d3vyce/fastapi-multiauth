"""MultiAuth: combine multiple authentication sources into a single callable."""

import copy
import inspect
import logging
from collections.abc import Callable, Iterable, Sequence
from typing import Annotated, Any, Self, cast

from fastapi import Depends
from fastapi.requests import HTTPConnection
from fastapi.security import SecurityScopes

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import (
    AuthSource,
    _anonymous_scopes_error,
    _carry_scheme,
    _step_up_optional_error,
    _step_up_optional_guard,
    _unenforceable_scopes_error,
)
from ..utils import challenge_headers, log_decision

logger = logging.getLogger(__name__)


class MultiAuth:
    """Combine multiple authentication sources into a single callable.

    Sources are tried in declaration order through the same ``extract()``/
    ``authenticate()`` pair used by direct ``Security(source)`` access.

    Args:
        *sources: Auth source instances to try in order.

    Raises:
        TypeError: If a source is not an :class:`AuthSource` instance.
    """

    _optional: bool = False

    def __init__(self, *sources: AuthSource) -> None:
        for source in sources:
            if not isinstance(source, AuthSource):
                hint = (
                    " (MultiAuth cannot be nested)"
                    if isinstance(source, MultiAuth)
                    else ""
                )
                raise TypeError(
                    "MultiAuth sources must be AuthSource instances, "
                    f"got {type(source).__name__}{hint}"
                )
        self._sources = sources

        merged: list[inspect.Parameter] = [
            inspect.Parameter(
                "request",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=HTTPConnection,
            ),
            inspect.Parameter(
                "security_scopes",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=SecurityScopes,
            ),
        ]
        carried = sources[0].scheme if sources else None
        if carried is not None:
            _carry_scheme(self, carried)
        for i, source in enumerate(sources):
            if source.scheme is None or (i == 0 and carried is not None):
                continue
            merged.append(
                inspect.Parameter(
                    f"_s{i}_credentials",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Annotated[Any, Depends(cast(Any, source.scheme))],
                    default=None,
                )
            )
        self.__signature__ = inspect.Signature(merged, return_annotation=Any)

        # The combined challenge is fixed once the sources are known; build it
        # once here instead of rebuilding it on every unauthenticated request.
        challenges: list[str] = []
        for source in sources:
            challenge = source.www_authenticate()
            if challenge and challenge not in challenges:
                challenges.append(challenge)
        self._www_authenticate = ", ".join(challenges) or None

        self._unenforceable = tuple(
            type(source).__name__ for source in sources if not source._enforces_scopes()
        )
        self._catalogued = tuple(
            source for source in sources if source._scope_catalogue
        )

    def www_authenticate(self) -> str | None:
        """Combined challenge of all sources (RFC 9110 §11.6.1), or ``None``."""
        return self._www_authenticate

    def optional(self) -> Self:
        """Return a copy that yields ``None`` when no source has a credential.

        Raises:
            ValueError: On a :meth:`fresh` or :meth:`stepped_up` copy:
                anonymous has proven no factor.
        """
        for source in self._sources:
            guard = _step_up_optional_guard(source)
            if guard is not None:
                raise _step_up_optional_error(self, guard)
        clone = copy.copy(self)
        clone._optional = True
        return clone

    def fresh(
        self,
        max_age: float,
        *,
        authenticated_at: Callable[..., Any] | None = None,
        leeway: float = 0.0,
    ) -> "MultiAuth":
        """Return a copy whose sources all require a recently proven credential.

        Applies :meth:`AuthSource.fresh` to every source, so one that cannot be
        dated refuses here instead of becoming the way around the window.

        Raises:
            ValueError: As :meth:`AuthSource.fresh`, naming the source that
                cannot be dated or already has a window of its own.
        """
        if self._optional:
            raise _step_up_optional_error(self, "fresh()")
        return self._with_sources(
            source.fresh(max_age, authenticated_at=authenticated_at, leeway=leeway)
            for source in self._sources
        )

    def stepped_up(
        self,
        acr_values: Sequence[str],
        *,
        acr: Callable[..., Any],
    ) -> "MultiAuth":
        """Return a copy whose sources all require one of *acr_values*.

        Applies :meth:`AuthSource.stepped_up` to every source, so no source
        becomes the way around the requirement.

        Raises:
            TypeError: As :meth:`AuthSource.stepped_up`.
            ValueError: As :meth:`AuthSource.stepped_up`, naming the source
                that already has levels of its own.
        """
        if self._optional:
            raise _step_up_optional_error(self, "stepped_up()")
        return self._with_sources(
            source.stepped_up(acr_values, acr=acr) for source in self._sources
        )

    def _with_sources(self, sources: Iterable[AuthSource]) -> "MultiAuth":
        """A new :class:`MultiAuth` over *sources*, carrying this one's flags."""
        clone = MultiAuth(*sources)
        clone._optional = self._optional
        return clone

    async def dispatch(self, request: HTTPConnection, scopes: list[str]) -> Any:
        """Authenticate with the first source whose credential is present."""
        if scopes:
            if self._optional:
                raise _anonymous_scopes_error(self, scopes)
            for source in self._catalogued:
                source._reject_undeclared_scopes(scopes)
            if self._unenforceable:
                raise _unenforceable_scopes_error(
                    self,
                    scopes,
                    f"{', '.join(self._unenforceable)} cannot check them, so "
                    "enforcement would depend on which credential the client "
                    "presents",
                )
        for source in self._sources:
            credential = await source.extract(request)
            if credential is not None:
                return await source._authenticate_with_challenge(
                    credential, scopes, request=request
                )
        if self._optional:
            log_decision(
                logger, logging.DEBUG, "anonymous", source="MultiAuth", scheme=None
            )
            return None
        log_decision(
            logger,
            logging.INFO,
            "missing_credential",
            source="MultiAuth",
            scheme=None,
            status=401,
        )
        raise UnauthorizedError(headers=challenge_headers(self.www_authenticate()))

    async def __call__(self, **kwargs: Any) -> Any:
        return await self.dispatch(kwargs["request"], kwargs["security_scopes"].scopes)

    def require(self, **kwargs: Any) -> "MultiAuth":
        """Return a new :class:`MultiAuth` with kwargs forwarded to each source."""
        return self._with_sources(
            cast(Any, source).require(**kwargs)
            if hasattr(source, "require")
            else source
            for source in self._sources
        )
