"""Abstract base classes for authentication sources."""

import copy
import inspect
from abc import ABC, abstractmethod
from typing import Annotated, Any, Callable, TypeVar

from fastapi import Depends, HTTPException, Request
from fastapi.security import SecurityScopes
from fastapi.security.base import SecurityBase

from fastapi_multiauth.exceptions import UnauthorizedError
from fastapi_multiauth.utils import add_challenge, challenge_headers, ensure_async

_V = TypeVar("_V", bound="ValidatedAuthSource")


def _reject_scopes_kwarg(kwargs: dict[str, Any]) -> None:
    """Reject ``scopes`` as a validator kwarg."""
    if "scopes" in kwargs:
        raise ValueError(
            "'scopes' is a reserved validator kwarg: security scopes declared "
            "on the route via Security(..., scopes=[...]) are injected "
            "automatically. Use a different keyword name."
        )


def _accepts_scopes(fn: Callable[..., Any]) -> bool:
    """Return whether *fn* declares a ``scopes`` parameter."""
    try:
        parameters = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    param = parameters.get("scopes")
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


def _scope_kwargs(
    owner: object, accepts_scopes: bool, scopes: list[str]
) -> dict[str, Any]:
    """Return the ``scopes`` kwarg for a validator, failing closed when unsupported."""
    if accepts_scopes:
        return {"scopes": scopes}
    if scopes:
        raise _unenforceable_scopes_error(owner, scopes)
    return {}


class _DocOnlyScheme(SecurityBase):
    """Inert stand-in for a ``fastapi.security`` scheme.

    Carries the scheme's OpenAPI metadata but never executes its parsing, so
    there is no second authentication path diverging from ``extract()``.
    """

    def __init__(self, scheme: Any) -> None:
        self.model = scheme.model
        self.scheme_name = scheme.scheme_name

    async def __call__(self, request: Request) -> None:  # noqa: ARG002
        return None


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
        if self.scheme is not None:
            # Declared only so the scheme is registered in OpenAPI; the
            # extracted value is ignored in favor of extract().
            parameters.append(
                inspect.Parameter(
                    "credentials",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Annotated[Any, Depends(self.scheme)],
                    default=None,
                )
            )
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
                every call. ``scopes`` is reserved (injected from the route).
        """
        _reject_scopes_kwarg(kwargs)
        self._validator = ensure_async(validator)
        self._accepts_scopes = _accepts_scopes(validator)
        self._kwargs = kwargs
        super().__init__(scheme)

    async def _call_validator(self, *args: Any, scopes: list[str]) -> Any:
        """Invoke the validator with scope and configured kwargs forwarding."""
        extra = _scope_kwargs(self, self._accepts_scopes, scopes)
        return await self._validator(*args, **extra, **self._kwargs)

    async def authenticate(self, credential: str) -> Any:
        """Validate a credential and return the identity (no route scopes)."""
        return await self.authenticate_scoped(credential, [])

    async def authenticate_scoped(self, credential: str, scopes: list[str]) -> Any:
        """Validate a credential, forwarding route-declared scopes to the validator."""
        return await self._call_validator(credential, scopes=scopes)

    def require(self: _V, **kwargs: Any) -> _V:
        """Return a copy of this source with additional (or overriding) validator kwargs."""
        _reject_scopes_kwarg(kwargs)
        clone = copy.copy(self)
        clone._kwargs = {**self._kwargs, **kwargs}
        return clone
