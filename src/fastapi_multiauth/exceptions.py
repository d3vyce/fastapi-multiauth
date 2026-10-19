"""Exceptions raised by authentication sources and OAuth helpers."""

from typing import ClassVar

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


class InsufficientAuthenticationError(UnauthorizedError):
    """HTTP 401: the credential is valid but its authentication falls short.

    Raised by a route guarded with :meth:`~fastapi_multiauth.AuthSource.stepped_up`
    when the credential was not proven at a requested level, and the base of
    :class:`StaleCredentialError`. ``detail`` is the stable string
    ``"Insufficient user authentication"``, and sources with an HTTP auth
    scheme carry the `RFC 9470 <https://datatracker.ietf.org/doc/html/rfc9470>`_
    step-up challenge listing every requirement of the route. A handler
    rendering its own body reads :attr:`max_age` and :attr:`acr_values`.
    """

    error_description: ClassVar[str] = "A different authentication level is required"
    """The challenge's ``error_description`` for this refusal."""

    max_age: float | None
    """The route's freshness window in seconds, ``None`` without :meth:`fresh`."""

    acr_values: tuple[str, ...] | None
    """The levels the route accepts, ``None`` without :meth:`stepped_up`."""

    def __init__(
        self,
        detail: str = "Insufficient user authentication",
        headers: dict[str, str] | None = None,
        *,
        max_age: float | None = None,
        acr_values: tuple[str, ...] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            detail: Human-readable message returned in the response body.
            headers: Extra response headers (e.g. the step-up challenge).
            max_age: The route's freshness window, in seconds.
            acr_values: The authentication context classes the route accepts.
        """
        self.max_age = max_age
        self.acr_values = acr_values
        super().__init__(detail=detail, headers=headers)


class StaleCredentialError(InsufficientAuthenticationError):
    """HTTP 401 — the credential is valid but was proven too long ago.

    Raised by a route guarded with :meth:`~fastapi_multiauth.AuthSource.fresh`.
    Everything else is as :class:`InsufficientAuthenticationError`.
    """

    error_description: ClassVar[str] = "More recent authentication is required"


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


class OAuthStateError(OAuthError):
    """Raised when the OAuth ``state`` parameter fails its CSRF check.

    The callback did not originate from a redirect this session started: the
    route must not exchange the code.
    """


class OAuthExchangeError(OAuthError):
    """Raised when the OAuth authorization code exchange fails."""


class OAuthUserinfoError(OAuthError):
    """Raised when the userinfo endpoint cannot be reached or returns garbage."""


class OAuthIDTokenError(OAuthError):
    """Raised when an OpenID Connect ID token fails validation.

    Its signature, issuer, audience, lifetime, ``nonce`` or ``at_hash`` did not
    check out, or the provider's signing keys could not be fetched: do not
    trust any of its claims.
    """
