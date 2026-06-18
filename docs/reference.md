# API Reference

The auth sources, validators, token helpers, and core exceptions import directly from `fastapi_multiauth`:

```python
from fastapi_multiauth import (
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    AuthSource,
    HTTPBasicAuth,
    HTTPBearerAuth,
    APIKeyCookieAuth,
    ForbiddenError,
    JWTValidator,
    MultiAuth,
    UnauthorizedError,
    hash_token,
    verify_token_hash,
)
```

The OAuth 2.0 / OIDC login-flow helpers are a separate concern: they obtain credentials via the browser redirect flow rather than validating credentials on an incoming request, and they require the `oauth` extra. They live in the `fastapi_multiauth.oauth` namespace:

```python
from fastapi_multiauth.oauth import (
    OAuthDiscoveryError,
    OAuthError,
    OAuthExchangeError,
    OAuthUserinfoError,
    OIDCEndpoints,
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_encode_state,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
    oauth_resolve_provider_urls,
)
```

## Sources

## ::: fastapi_multiauth.AuthSource

## ::: fastapi_multiauth.HTTPBearerAuth

## ::: fastapi_multiauth.APIKeyCookieAuth

## ::: fastapi_multiauth.APIKeyHeaderAuth

## ::: fastapi_multiauth.APIKeyQueryAuth

## ::: fastapi_multiauth.HTTPBasicAuth

## ::: fastapi_multiauth.MultiAuth

## Validators

## ::: fastapi_multiauth.JWTValidator

## Token helpers

## ::: fastapi_multiauth.hash_token

## ::: fastapi_multiauth.verify_token_hash

## Exceptions

## ::: fastapi_multiauth.UnauthorizedError

## ::: fastapi_multiauth.ForbiddenError

## OAuth helpers

The OAuth login-flow helpers live in the `fastapi_multiauth.oauth` namespace and require the `oauth` extra (`pip install fastapi-multiauth[oauth]`). See [OAuth 2.0 / OIDC login](oauth.md) for the walkthrough.

## ::: fastapi_multiauth.oauth.OAuthError

## ::: fastapi_multiauth.oauth.OAuthDiscoveryError

## ::: fastapi_multiauth.oauth.OAuthExchangeError

## ::: fastapi_multiauth.oauth.OAuthUserinfoError

## ::: fastapi_multiauth.oauth.OIDCEndpoints

## ::: fastapi_multiauth.oauth.oauth_resolve_provider_urls

## ::: fastapi_multiauth.oauth.oauth_exchange_code

## ::: fastapi_multiauth.oauth.oauth_fetch_userinfo

## ::: fastapi_multiauth.oauth.oauth_generate_state_token

## ::: fastapi_multiauth.oauth.oauth_generate_pkce_pair

## ::: fastapi_multiauth.oauth.oauth_build_authorization_redirect

## ::: fastapi_multiauth.oauth.oauth_encode_state

## ::: fastapi_multiauth.oauth.oauth_decode_state
