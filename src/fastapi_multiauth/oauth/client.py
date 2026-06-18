"""OAuth 2.0 / OIDC network operations: discovery, code exchange, userinfo."""

import functools
from typing import Any, Literal, NamedTuple

import httpx
from async_lru import alru_cache

from .._http import DEFAULT_TIMEOUT, _get_json, _require_https
from .._imports import require_extra
from ..exceptions import OAuthDiscoveryError, OAuthExchangeError, OAuthUserinfoError

__all__ = [
    "OIDCEndpoints",
    "oauth_exchange_code",
    "oauth_fetch_userinfo",
    "oauth_resolve_provider_urls",
]

_DISCOVERY_SUFFIX = "/.well-known/openid-configuration"
_DISCOVERY_CACHE_TTL = 3600

TokenEndpointAuthMethod = Literal["client_secret_post", "client_secret_basic"]


class OIDCEndpoints(NamedTuple):
    """Validated endpoint URLs from an OIDC discovery document.

    All URLs are HTTPS-checked (loopback hosts excepted). Optional fields are
    ``None`` when the provider does not advertise them.
    """

    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str | None
    jwks_uri: str | None
    end_session_endpoint: str | None
    issuer: str | None


def _validate_issuer(discovery_url: str, issuer: Any) -> None:
    """Check the discovery document claims the issuer it was fetched from."""
    if not discovery_url.endswith(_DISCOVERY_SUFFIX):
        return
    expected = discovery_url.removesuffix(_DISCOVERY_SUFFIX).rstrip("/")
    if not isinstance(issuer, str) or issuer.rstrip("/") != expected:
        raise OAuthDiscoveryError(
            f"discovery document issuer {issuer!r} does not match the "
            f"expected issuer {expected!r} derived from the discovery URL"
        )


@functools.lru_cache(maxsize=1)
def _import_httpx_oauth() -> Any:
    """Import ``httpx_oauth.oauth2`` lazily (the optional ``oauth`` extra)."""
    try:
        from httpx_oauth import oauth2
    except ImportError:  # pragma: no cover
        require_extra("httpx-oauth", "oauth")
    return oauth2


@functools.lru_cache(maxsize=1)
def _oauth2_client_class() -> type:
    """Return an httpx-oauth ``OAuth2`` subclass with an explicit timeout."""

    class _TimeoutOAuth2(_import_httpx_oauth().OAuth2):
        """OAuth2 client whose HTTP calls run under an explicit timeout."""

        def __init__(
            self,
            client_id: str,
            client_secret: str,
            access_token_endpoint: str,
            timeout: float,
            token_endpoint_auth_method: TokenEndpointAuthMethod,
        ) -> None:
            super().__init__(
                client_id,
                client_secret,
                # Only the token endpoint is used; the authorization redirect
                # is built by oauth_build_authorization_redirect().
                authorize_endpoint="",
                access_token_endpoint=access_token_endpoint,
                token_endpoint_auth_method=token_endpoint_auth_method,
            )
            self._timeout = timeout

        def get_httpx_client(self) -> httpx.AsyncClient:
            return httpx.AsyncClient(timeout=self._timeout)

    return _TimeoutOAuth2


@alru_cache(maxsize=32, ttl=_DISCOVERY_CACHE_TTL)
async def oauth_resolve_provider_urls(
    discovery_url: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> OIDCEndpoints:
    """Fetch the OIDC discovery document and return its validated endpoints.

    Cached for one hour. The discovery URL must come from configuration, never
    from request input (SSRF / cache-poisoning).

    Args:
        discovery_url: Provider's openid-configuration URL.
        timeout: Discovery request timeout in seconds.

    Returns:
        Validated :class:`OIDCEndpoints`; optional fields are ``None`` when absent.

    Raises:
        ValueError: If *discovery_url* is not HTTPS.
        OAuthDiscoveryError: If the document is unreachable, malformed, or
            advertises non-HTTPS endpoints or a mismatched issuer.
    """
    _require_https(discovery_url, "OIDC discovery URL")
    cfg = await _get_json(
        discovery_url,
        timeout=timeout,
        error_cls=OAuthDiscoveryError,
        description="OIDC discovery document",
    )
    if not isinstance(cfg, dict):
        raise OAuthDiscoveryError("OIDC discovery document is not a JSON object")
    _validate_issuer(discovery_url, cfg.get("issuer"))

    def _optional(key: str) -> str | None:
        url = cfg.get(key)
        return None if url is None else _require_https(url, f"OIDC {key}")

    try:
        return OIDCEndpoints(
            authorization_endpoint=_require_https(
                cfg["authorization_endpoint"], "OIDC authorization_endpoint"
            ),
            token_endpoint=_require_https(cfg["token_endpoint"], "OIDC token_endpoint"),
            userinfo_endpoint=_optional("userinfo_endpoint"),
            jwks_uri=_optional("jwks_uri"),
            end_session_endpoint=_optional("end_session_endpoint"),
            issuer=cfg.get("issuer"),
        )
    except KeyError as exc:
        raise OAuthDiscoveryError(
            f"OIDC discovery document is missing the {exc.args[0]!r} endpoint"
        ) from exc
    except ValueError as exc:
        raise OAuthDiscoveryError(str(exc)) from exc


async def oauth_exchange_code(
    *,
    token_url: str,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    required_scopes: str | None = None,
    code_verifier: str | None = None,
    token_endpoint_auth_method: TokenEndpointAuthMethod = "client_secret_post",  # noqa: S107 — method name, not a secret
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Exchange an authorization code for tokens and return the token response.

    Delegates the exchange (including PKCE) to httpx-oauth (the ``oauth`` extra).

    Args:
        token_url: Provider's token endpoint.
        code: Authorization code from the provider's callback.
        client_id: OAuth application client ID.
        client_secret: OAuth application client secret.
        redirect_uri: Redirect URI used in the authorization request.
        required_scopes: Space-separated scopes that must be present in the
            token response (RFC 6749 §3.3).
        code_verifier: PKCE code verifier matching the challenge sent earlier
            (from :func:`~fastapi_multiauth.oauth.oauth_generate_pkce_pair`).
        token_endpoint_auth_method: How credentials are sent — in the POST body
            (``client_secret_post``, default) or as a Basic header.
        timeout: Timeout in seconds for the token request.

    Returns:
        The full token response as a ``dict`` (``access_token`` plus whatever
        else the provider returned).

    Raises:
        ValueError: If *token_url* is not HTTPS.
        OAuthExchangeError: If the exchange is rejected or fails, grants a
            non-bearer token, or omits a required scope.
    """
    _require_https(token_url, "OAuth token_url")

    oauth_client = _oauth2_client_class()(
        client_id, client_secret, token_url, timeout, token_endpoint_auth_method
    )
    try:
        token_data = await oauth_client.get_access_token(
            code, redirect_uri, code_verifier=code_verifier
        )
    except _import_httpx_oauth().GetAccessTokenError as exc:
        raise OAuthExchangeError(str(exc)) from exc

    token_type = token_data.get("token_type", "bearer")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise OAuthExchangeError(f"unsupported token_type: {token_type!r}")

    if required_scopes is not None:
        scope = token_data.get("scope", "")
        # Fail closed on a malformed (non-string) scope field.
        granted = set(scope.split()) if isinstance(scope, str) else set()
        missing = set(required_scopes.split()) - granted
        if missing:
            raise OAuthExchangeError(
                f"provider did not grant required scopes: {missing}"
            )

    return dict(token_data)


async def oauth_fetch_userinfo(
    *,
    userinfo_url: str,
    access_token: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Fetch the userinfo payload with a bearer access token.

    Args:
        userinfo_url: Provider's userinfo endpoint.
        access_token: Access token from :func:`oauth_exchange_code`.
        timeout: Timeout in seconds for the userinfo request.

    Returns:
        The JSON payload returned by the userinfo endpoint as a plain ``dict``.

    Raises:
        ValueError: If *userinfo_url* is not HTTPS.
        OAuthUserinfoError: If the endpoint fails or does not return JSON.
    """
    _require_https(userinfo_url, "OAuth userinfo_url")
    return await _get_json(
        userinfo_url,
        timeout=timeout,
        error_cls=OAuthUserinfoError,
        description="userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
