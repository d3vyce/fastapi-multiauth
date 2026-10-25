---
icon: lucide/file-search
---

# API reference

Everything below `fastapi_multiauth` is importable from the package root:

```python
from fastapi_multiauth import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    AuthSource,
    AuthenticationMethodReference,
    ForbiddenError,
    HMACSignatureAuth,
    HTTPBasicAuth,
    HTTPBearerAuth,
    HTTPDPoPAuth,  # needs the jwt extra at construction
    InsufficientAuthenticationError,
    IntrospectionValidator,
    JWTValidator,  # needs the jwt extra at construction
    MultiAuth,
    OAuth2AuthorizationCodeBearerAuth,
    OAuth2PasswordBearerAuth,
    OpenIdConnectAuth,
    RouteAuth,
    SchemeRequirement,
    StaleCredentialError,
    UnauthorizedError,
    auth_surface,
    checksum_token_generator,
    hash_token,
    totp_generate_secret,
    totp_provisioning_uri,
    totp_verify,
    verify_token_checksum,
    verify_token_hash,
)
```

The OAuth login helpers live in `fastapi_multiauth.oauth` and need the `oauth` extra:

```python
from fastapi_multiauth.oauth import (
    OAuthDiscoveryError,
    OAuthError,
    OAuthExchangeError,
    OAuthIDTokenError,
    OAuthStateError,
    OAuthUserinfoError,
    OIDCEndpoints,
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_encode_state,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_generate_nonce,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
    oauth_resolve_provider_urls,
    oauth_validate_id_token,
)
```

## Sources

Request-time authentication dependencies. Guide: [the sources](guide/index.md#the-sources).

## ::: fastapi_multiauth.AuthSource

## ::: fastapi_multiauth.HTTPBearerAuth

## ::: fastapi_multiauth.HTTPDPoPAuth

## ::: fastapi_multiauth.APIKeyCookieAuth

## ::: fastapi_multiauth.APIKeyHeaderAuth

## ::: fastapi_multiauth.APIKeyQueryAuth

## ::: fastapi_multiauth.HTTPBasicAuth

## ::: fastapi_multiauth.HMACSignatureAuth

## ::: fastapi_multiauth.OAuth2AuthorizationCodeBearerAuth

## ::: fastapi_multiauth.OAuth2PasswordBearerAuth

## ::: fastapi_multiauth.OpenIdConnectAuth

## ::: fastapi_multiauth.MultiAuth

## Validators

Ready-made validators to pass to a source. Guide: [JWT and OAuth 2.0 tokens](guide/jwt-and-oauth2.md).

## ::: fastapi_multiauth.JWTValidator

## ::: fastapi_multiauth.IntrospectionValidator

## Claims

Guide: [step-up authentication](guide/step-up.md#strong-login-stepped_up).

## ::: fastapi_multiauth.AuthenticationMethodReference

## Introspection

Guide: [auditing the auth surface](guide/auditing.md).

## ::: fastapi_multiauth.auth_surface

## ::: fastapi_multiauth.RouteAuth

## ::: fastapi_multiauth.SchemeRequirement

## Token helpers

Guide: [issuing and storing tokens](guide/bearer-tokens.md#issuing-and-storing-tokens).

## ::: fastapi_multiauth.hash_token

## ::: fastapi_multiauth.verify_token_hash

## ::: fastapi_multiauth.checksum_token_generator

## ::: fastapi_multiauth.verify_token_checksum

## Second factor

Recipe: [two-factor login](recipes/two-factor.md).

## ::: fastapi_multiauth.totp_generate_secret

## ::: fastapi_multiauth.totp_provisioning_uri

## ::: fastapi_multiauth.totp_verify

## Exceptions

Guide: [status codes](security-model.md#status-codes).

## ::: fastapi_multiauth.UnauthorizedError

## ::: fastapi_multiauth.ForbiddenError

## ::: fastapi_multiauth.InsufficientAuthenticationError

## ::: fastapi_multiauth.StaleCredentialError

## OAuth helpers

The login-flow helpers in `fastapi_multiauth.oauth`. Guide: [OAuth login flow](guide/oauth-login.md).

## ::: fastapi_multiauth.oauth.oauth_resolve_provider_urls

## ::: fastapi_multiauth.oauth.OIDCEndpoints

## ::: fastapi_multiauth.oauth.oauth_generate_state_token

## ::: fastapi_multiauth.oauth.oauth_generate_nonce

## ::: fastapi_multiauth.oauth.oauth_generate_pkce_pair

## ::: fastapi_multiauth.oauth.oauth_build_authorization_redirect

## ::: fastapi_multiauth.oauth.oauth_encode_state

## ::: fastapi_multiauth.oauth.oauth_decode_state

## ::: fastapi_multiauth.oauth.oauth_exchange_code

## ::: fastapi_multiauth.oauth.oauth_fetch_userinfo

## ::: fastapi_multiauth.oauth.oauth_validate_id_token

## ::: fastapi_multiauth.oauth.OAuthError

## ::: fastapi_multiauth.oauth.OAuthStateError

## ::: fastapi_multiauth.oauth.OAuthDiscoveryError

## ::: fastapi_multiauth.oauth.OAuthExchangeError

## ::: fastapi_multiauth.oauth.OAuthUserinfoError

## ::: fastapi_multiauth.oauth.OAuthIDTokenError
