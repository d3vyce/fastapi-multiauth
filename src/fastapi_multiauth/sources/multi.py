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
    """Combine several sources on one route.

    Sources are tried in order, and the first one that finds a credential
    decides: an invalid credential is refused, not passed to the next
    source. All sources appear in OpenAPI.

    Args:
        *sources: The sources to try, in order.

    Raises:
        TypeError: If a source is not an `AuthSource`, or is a `MultiAuth`.
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
        """Return the challenges of all sources, joined, or `None` when none has one."""
        return self._www_authenticate

    def optional(self) -> Self:
        """Return a copy that yields `None` when no source finds a credential.

        Raises:
            ValueError: On a copy made by `fresh()` or `stepped_up()`.
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
        """Return a copy whose sources all refuse a credential older than `max_age`.

        Applies `AuthSource.fresh()` to every source, with the same arguments.

        Raises:
            ValueError: As `AuthSource.fresh()`, naming the source at fault.
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
        acr: Callable[..., Any] | None = None,
    ) -> "MultiAuth":
        """Return a copy whose sources all require one of `acr_values`.

        Applies `AuthSource.stepped_up()` to every source, with the same arguments.

        Raises:
            TypeError: As `AuthSource.stepped_up()`.
            ValueError: As `AuthSource.stepped_up()`, naming the source at fault.
        """
        if self._optional:
            raise _step_up_optional_error(self, "stepped_up()")
        return self._with_sources(
            source.stepped_up(acr_values, acr=acr) for source in self._sources
        )

    def _with_sources(self, sources: Iterable[AuthSource]) -> "MultiAuth":
        """A new `MultiAuth` over `sources`, carrying this one's flags."""
        clone = MultiAuth(*sources)
        clone._optional = self._optional
        return clone

    async def dispatch(self, request: HTTPConnection, scopes: list[str]) -> Any:
        """Authenticate with the first source that finds a credential."""
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
        """Run as a FastAPI dependency."""
        return await self.dispatch(kwargs["request"], kwargs["security_scopes"].scopes)

    def require(self, **kwargs: Any) -> "MultiAuth":
        """Return a copy passing extra keyword arguments to every validator."""
        return self._with_sources(
            cast(Any, source).require(**kwargs)
            if hasattr(source, "require")
            else source
            for source in self._sources
        )
