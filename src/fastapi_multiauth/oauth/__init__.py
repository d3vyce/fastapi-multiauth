"""OAuth 2.0 / OIDC login-flow helpers (the ``oauth`` extra).

These obtain a credential through the browser authorization-code flow — a
distinct concern from the request-time auth sources in the top-level package.
``client`` holds the network operations (discovery, code exchange, userinfo);
``utils`` holds the pure helpers (state, PKCE, the authorization redirect).
"""

from ..exceptions import (
    OAuthDiscoveryError,
    OAuthError,
    OAuthExchangeError,
    OAuthUserinfoError,
)
from .client import (
    OIDCEndpoints,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_resolve_provider_urls,
)
from .utils import (
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_encode_state,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
)

__all__ = [
    "OAuthDiscoveryError",
    "OAuthError",
    "OAuthExchangeError",
    "OAuthUserinfoError",
    "OIDCEndpoints",
    "oauth_build_authorization_redirect",
    "oauth_decode_state",
    "oauth_encode_state",
    "oauth_exchange_code",
    "oauth_fetch_userinfo",
    "oauth_generate_pkce_pair",
    "oauth_generate_state_token",
    "oauth_resolve_provider_urls",
]
