"""Exceptions raised by authentication sources and OAuth helpers."""

from fastapi import HTTPException, status


class UnauthorizedError(HTTPException):
    """HTTP 401 — authentication credentials were missing or invalid.

    Raise from a validator (or any ``HTTPException``) to reject a credential.
    """

    def __init__(
        self,
        detail: str = "Unauthorized",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            detail: Human-readable message returned in the response body.
            headers: Extra response headers (e.g. ``WWW-Authenticate``).
        """
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers=headers
        )


class ForbiddenError(HTTPException):
    """HTTP 403 — the identity is authenticated but lacks permission.

    Keep 401 (:class:`UnauthorizedError`) for absent or invalid credentials.
    """

    def __init__(
        self,
        detail: str = "Forbidden",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            detail: Human-readable message returned in the response body.
            headers: Extra response headers.
        """
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN, detail=detail, headers=headers
        )


class OAuthError(Exception):
    """Base class for OAuth flow errors.

    Not an ``HTTPException``: the route decides the HTTP outcome of a failed flow.
    """


class OAuthDiscoveryError(OAuthError):
    """Raised when the OIDC discovery document cannot be fetched or is invalid."""


class OAuthExchangeError(OAuthError):
    """Raised when the OAuth authorization code exchange fails."""


class OAuthUserinfoError(OAuthError):
    """Raised when the userinfo endpoint cannot be reached or returns garbage."""
