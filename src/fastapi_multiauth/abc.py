"""Abstract base classes for authentication sources."""

import copy
import inspect
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, Request
from fastapi.security import SecurityScopes
from fastapi.security.base import SecurityBase

from fastapi_multiauth.exceptions import UnauthorizedError
from fastapi_multiauth.utils import add_challenge, challenge_headers, ensure_async

if TYPE_CHECKING:
    from typing_extensions import Self


_RESERVED_KWARGS = {
    "scopes": "injected from the route by Security(..., scopes=[...])",
    "session_id": "injected by APIKeyCookieAuth(session_id=True)",
}


def _reject_reserved_kwargs(kwargs: dict[str, Any]) -> None:
    """Reject validator kwargs the library injects itself."""
    for name, injected in _RESERVED_KWARGS.items():
        if name in kwargs:
            raise ValueError(
                f"'{name}' is a reserved validator kwarg ({injected}): "
                "the library sets it. Use a different keyword name."
            )


def _accepts_kwarg(fn: Callable[..., Any], name: str) -> bool:
    """Return whether *fn* declares a *name* parameter."""
    try:
        parameters = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    param = parameters.get(name)
    return param is not None and param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


def _unenforceable_scopes_error(owner: object, scopes: list[str]) -> RuntimeError:
    """Error for scopes declared on a route that this source cannot check."""
    return RuntimeError(
        f"{type(owner).__name__} cannot enforce the security scopes "
        f"{scopes!r} declared on this route: its validator does not "
        "declare a 'scopes' parameter. Add one to the validator (or "
        "override authenticate_scoped()), or remove scopes=... from "
        "Security()."
    )


class _DocOnlyScheme(SecurityBase):
    """Inert stand-in for a ``fastapi.security`` scheme.

    Carries the scheme's OpenAPI metadata but never executes its parsing, so
    there is no second authentication path diverging from ``extract()``.
    """

    def __init__(self, scheme: Any) -> None:
        self.model = scheme.model
        self.scheme_name = scheme.scheme_name

    async def __call__(self, request: Request) -> None:
        return None


_SCHEME_CLASSES: dict[type, type] = {}


def _carry_scheme(dependency: Any, scheme: SecurityBase) -> None:
    """Make *dependency* itself the security scheme FastAPI puts in OpenAPI."""
    cls = type(dependency)
    promoted = _SCHEME_CLASSES.get(cls)
    if promoted is None:
        promoted = _SCHEME_CLASSES[cls] = type(
            cls.__name__,
            (cls, SecurityBase),
            {"__module__": cls.__module__, "__doc__": cls.__doc__},
        )
    dependency.__class__ = promoted
    dependency.model = scheme.model
    dependency.scheme_name = scheme.scheme_name


class AuthSource(ABC):
    """Abstract base class for authentication sources.

    Subclasses implement :meth:`extract` and :meth:`authenticate`; both
    ``Security(source)`` and ``MultiAuth`` route through that pair via
    :meth:`dispatch`.
    """

    scheme: SecurityBase | None

    def __init__(self, scheme: Any = None) -> None:
        """Set up the FastAPI dependency signature.

        Args:
            scheme: Optional ``fastapi.security`` scheme; only its OpenAPI
                metadata is used, extraction always goes through :meth:`extract`.
        """
        self.scheme = _DocOnlyScheme(scheme) if scheme is not None else None
        if self.scheme is not None:
            _carry_scheme(self, self.scheme)

        parameters = [
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
        self.__signature__ = inspect.Signature(parameters, return_annotation=Any)

    @abstractmethod
    async def extract(self, request: Request) -> str | None:
        """Extract the raw credential from the request without validating.

        Must return ``None`` — never an empty string — when the credential is
        absent, empty, or does not belong to this source.
        """

    @abstractmethod
    async def authenticate(self, credential: str) -> Any:
        """Validate a credential and return the authenticated identity."""

    def www_authenticate(self) -> str | None:
        """Challenge value for the ``WWW-Authenticate`` header on 401 responses.

        Returns ``None`` when the source has no HTTP auth scheme (cookies, API keys).
        """
        return None

    async def authenticate_scoped(self, credential: str, scopes: list[str]) -> Any:
        """Validate a credential, enforcing the scopes declared on the route."""
        if scopes:  # fail closed: plain authenticate() cannot check scopes
            raise _unenforceable_scopes_error(self, scopes)
        return await self.authenticate(credential)

    async def _authenticate_with_challenge(
        self, credential: str, scopes: list[str]
    ) -> Any:
        """Authenticate, attaching this source's challenge to any 401 raised."""
        try:
            return await self.authenticate_scoped(credential, scopes)
        except HTTPException as exc:
            add_challenge(exc, self.www_authenticate())
            raise

    async def dispatch(self, request: Request, scopes: list[str]) -> Any:
        """Extract the credential, then authenticate it with the route scopes.

        Raises:
            UnauthorizedError: When no credential is present. This source's
                ``WWW-Authenticate`` challenge is attached to any 401 raised.
        """
        credential = await self.extract(request)
        if credential is None:
            raise UnauthorizedError(headers=challenge_headers(self.www_authenticate()))
        return await self._authenticate_with_challenge(credential, scopes)

    async def __call__(self, **kwargs: Any) -> Any:
        """FastAPI dependency dispatch."""
        return await self.dispatch(kwargs["request"], kwargs["security_scopes"].scopes)


class ValidatedAuthSource(AuthSource):
    """Base for sources whose credential is checked by a user-supplied validator.

    Owns the shared validator plumbing (sync/async normalization, scope and
    kwargs forwarding, :meth:`require`). Subclasses implement :meth:`extract`.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        scheme: Any = None,
        /,
        **kwargs: Any,
    ) -> None:
        """Bind the validator and its forwarded kwargs.

        Args:
            validator: Sync or async callable returning the identity.
            scheme: Optional ``fastapi.security`` scheme for OpenAPI.
            **kwargs: Extra keyword arguments forwarded to the validator on
                every call. Names the library injects itself are reserved:
                ``scopes`` and ``session_id``.
        """
        _reject_reserved_kwargs(kwargs)
        self._validator = ensure_async(validator)
        self._accepts_scopes = _accepts_kwarg(validator, "scopes")
        self._kwargs = kwargs
        super().__init__(scheme)

    async def _call_validator(
        self, *args: Any, scopes: list[str], **injected: Any
    ) -> Any:
        """Invoke the validator with scope and configured kwargs forwarding."""
        if self._accepts_scopes:
            injected["scopes"] = scopes
        elif scopes:  # fail closed: the validator cannot check them
            raise _unenforceable_scopes_error(self, scopes)
        return await self._validator(*args, **self._kwargs, **injected)

    async def authenticate(self, credential: str) -> Any:
        """Validate a credential and return the identity (no route scopes)."""
        return await self.authenticate_scoped(credential, [])

    async def authenticate_scoped(self, credential: str, scopes: list[str]) -> Any:
        """Validate a credential, forwarding route-declared scopes to the validator."""
        return await self._call_validator(credential, scopes=scopes)

    def require(self, **kwargs: Any) -> "Self":
        """Return a copy of this source with additional (or overriding) validator kwargs.

        Reserved names (``scopes``, ``session_id``) are rejected here too.
        """
        _reject_reserved_kwargs(kwargs)
        clone = copy.copy(self)
        clone._kwargs = {**self._kwargs, **kwargs}
        return clone
