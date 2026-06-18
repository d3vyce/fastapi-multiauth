"""Bearer token authentication source."""

import secrets
from typing import Any, Callable

from fastapi import Request
from fastapi.security import HTTPBearer

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource
from ..utils import authorization_credential


class HTTPBearerAuth(ValidatedAuthSource):
    """Bearer token authentication source (wraps ``HTTPBearer`` for OpenAPI).

    The validator is called as ``await validator(credential, **kwargs)``.

    Args:
        validator: Sync or async callable returning the identity; raises
            :class:`~fastapi_multiauth.exceptions.UnauthorizedError` on failure.
        prefix: Optional token prefix (e.g. ``"user_"``); only tokens with this
            prefix are matched, and the prefix is kept in the validated value.
        scheme_name: OpenAPI security scheme name (default ``HTTPBearer``); give
            each source a distinct name when several appear in the same app.
        **kwargs: Extra keyword arguments forwarded to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        prefix: str | None = None,
        scheme_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._prefix = prefix
        super().__init__(
            validator,
            HTTPBearer(auto_error=False, scheme_name=scheme_name),
            **kwargs,
        )

    def www_authenticate(self) -> str:
        """``Bearer`` challenge per RFC 6750 §3."""
        return "Bearer"

    async def extract(self, request: Request) -> str | None:
        """Return the bearer token, or ``None`` when absent, empty, or mismatched.

        The ``Bearer`` scheme is matched case-insensitively; the prefix, when
        configured, is kept in the returned value.
        """
        token = authorization_credential(request, "bearer")
        if token is None:
            return None
        if self._prefix is not None and not token.startswith(self._prefix):
            return None
        return token

    async def authenticate_scoped(self, credential: str, scopes: list[str]) -> Any:
        """Validate the credential, re-checking the prefix and forwarding scopes."""
        if self._prefix is not None and not credential.startswith(self._prefix):
            raise UnauthorizedError()
        return await self._call_validator(credential, scopes=scopes)

    def generate_token(self, nbytes: int = 32) -> str:
        """Generate a secure URL-safe random token, prefixed when configured.

        Args:
            nbytes: Number of random bytes before base64 encoding (default 32).

        Returns:
            A ready-to-use token string (e.g. ``"user_Xk3..."``).
        """
        token = secrets.token_urlsafe(nbytes)
        if self._prefix is not None:
            return f"{self._prefix}{token}"
        return token
