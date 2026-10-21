"""Exceptions raised by authentication sources and OAuth helpers."""

from typing import ClassVar

from fastapi import HTTPException, status


class UnauthorizedError(HTTPException):
    """HTTP 401: the credential is missing or invalid.

    Raise it from a validator to refuse a credential. The source adds its
    `WWW-Authenticate` challenge to the response.

    Args:
        detail: Message returned in the response body.
        headers: Extra response headers.
    """

    def __init__(
        self,
        detail: str = "Unauthorized",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers=headers
        )


class InsufficientAuthenticationError(UnauthorizedError):
    """HTTP 401: the credential is valid, but not proven strongly enough.

    Raised by a route guarded with `AuthSource.stepped_up()`, and the base
    class of `StaleCredentialError`. `detail` is always
    `"Insufficient user authentication"`. Sources with an HTTP auth scheme
    send the [RFC 9470](https://datatracker.ietf.org/doc/html/rfc9470)
    challenge listing every requirement of the route.

    Args:
        detail: Message returned in the response body.
        headers: Extra response headers, such as the step-up challenge.
        max_age: The route's freshness window in seconds, if any.
        acr_values: The authentication levels the route accepts, if any.
    """

    error_description: ClassVar[str] = "A different authentication level is required"
    """The challenge's `error_description` for this refusal."""

    max_age: float | None
    """The route's freshness window in seconds, `None` without `fresh()`."""

    acr_values: tuple[str, ...] | None
    """The levels the route accepts, `None` without `stepped_up()`."""

    def __init__(
        self,
        detail: str = "Insufficient user authentication",
        headers: dict[str, str] | None = None,
        *,
        max_age: float | None = None,
        acr_values: tuple[str, ...] | None = None,
    ) -> None:
        self.max_age = max_age
        self.acr_values = acr_values
        super().__init__(detail=detail, headers=headers)


class StaleCredentialError(InsufficientAuthenticationError):
    """HTTP 401: the credential is valid, but was proven too long ago.

    Raised by a route guarded with `AuthSource.fresh()`. Otherwise
    identical to `InsufficientAuthenticationError`.
    """

    error_description: ClassVar[str] = "More recent authentication is required"


class ForbiddenError(HTTPException):
    """HTTP 403: the identity is authenticated, but not allowed here.

    Use `UnauthorizedError` instead when the credential itself is the problem.

    Args:
        detail: Message returned in the response body.
        headers: Extra response headers.
    """

    def __init__(
        self,
        detail: str = "Forbidden",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN, detail=detail, headers=headers
        )


class OAuthError(Exception):
    """Base class of every OAuth login flow error.

    Not an `HTTPException`: your route decides what a failed login returns.
    """


class OAuthDiscoveryError(OAuthError):
    """The provider's discovery document cannot be fetched or is invalid."""


class OAuthStateError(OAuthError):
    """The `state` parameter failed its CSRF check.

    The callback does not come from a login this browser started: do not
    exchange the code.
    """


class OAuthExchangeError(OAuthError):
    """The authorization code exchange failed."""


class OAuthUserinfoError(OAuthError):
    """The userinfo endpoint failed or returned something other than JSON."""


class OAuthIDTokenError(OAuthError):
    """The OpenID Connect ID token failed validation.

    Its signature, issuer, audience, lifetime, `nonce` or `at_hash` did not
    check out, or the provider's keys could not be fetched. Do not trust
    any of its claims.
    """
