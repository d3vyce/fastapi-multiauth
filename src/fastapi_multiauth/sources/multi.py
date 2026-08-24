"""MultiAuth: combine multiple authentication sources into a single callable."""

import inspect
from typing import Annotated, Any, cast

from fastapi import Depends, Request
from fastapi.security import SecurityScopes

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import AuthSource, _anonymous_scopes_error, _carry_scheme
from ..utils import challenge_headers


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
                annotation=Request,
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

    def www_authenticate(self) -> str | None:
        """Combined challenge of all sources (RFC 9110 §11.6.1), or ``None``."""
        return self._www_authenticate

    def optional(self) -> "MultiAuth":
        """Return a copy that yields ``None`` when no source has a credential."""
        clone = MultiAuth(*self._sources)
        clone._optional = True
        return clone

    async def dispatch(self, request: Request, scopes: list[str]) -> Any:
        """Authenticate with the first source whose credential is present."""
        if self._optional and scopes:
            raise _anonymous_scopes_error(self, scopes)
        if scopes:
            for source in self._sources:
                source._reject_undeclared_scopes(scopes)
        if scopes and self._unenforceable:
            raise RuntimeError(
                f"MultiAuth cannot enforce the security scopes {scopes!r} "
                f"declared on this route: {', '.join(self._unenforceable)} "
                "cannot check them, so enforcement would depend on which "
                "credential the client presents. Add a 'scopes' parameter to "
                "that source's validator (or override authenticate_scoped()), "
                "or remove scopes=... from Security()."
            )
        for source in self._sources:
            credential = await source.extract(request)
            if credential is not None:
                return await source._authenticate_with_challenge(credential, scopes)
        if self._optional:
            return None
        raise UnauthorizedError(headers=challenge_headers(self.www_authenticate()))

    async def __call__(self, **kwargs: Any) -> Any:
        return await self.dispatch(kwargs["request"], kwargs["security_scopes"].scopes)

    def require(self, **kwargs: Any) -> "MultiAuth":
        """Return a new :class:`MultiAuth` with kwargs forwarded to each source."""
        new_sources = tuple(
            cast(Any, source).require(**kwargs)
            if hasattr(source, "require")
            else source
            for source in self._sources
        )
        clone = MultiAuth(*new_sources)
        clone._optional = self._optional
        return clone
