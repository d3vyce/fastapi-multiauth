"""OAuth 2.0 / OIDC login-flow helpers (the ``oauth`` extra).

These obtain a credential through the browser authorization-code flow — a
distinct concern from the request-time auth sources in the top-level package.
``client`` holds the network operations (discovery, code exchange, userinfo);
``id_token`` validates OpenID Connect ID tokens (needs the ``jwt`` extra too);
``utils`` holds the pure helpers (state, nonce, PKCE, the authorization redirect).
"""

from ..exceptions import (
    OAuthDiscoveryError,
    OAuthError,
    OAuthExchangeError,
    OAuthIDTokenError,
    OAuthStateError,
    OAuthUserinfoError,
)
from .client import (
    OIDCEndpoints,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_resolve_provider_urls,
)
from .id_token import oauth_validate_id_token
from .utils import (
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_encode_state,
    oauth_generate_nonce,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
)

__all__ = [
    "OAuthDiscoveryError",
    "OAuthError",
    "OAuthExchangeError",
    "OAuthIDTokenError",
    "OAuthStateError",
    "OAuthUserinfoError",
    "OIDCEndpoints",
    "oauth_build_authorization_redirect",
    "oauth_decode_state",
    "oauth_encode_state",
    "oauth_exchange_code",
    "oauth_fetch_userinfo",
    "oauth_generate_nonce",
    "oauth_generate_pkce_pair",
    "oauth_generate_state_token",
    "oauth_resolve_provider_urls",
    "oauth_validate_id_token",
]
