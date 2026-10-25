"""Composable authentication sources for FastAPI.

The OAuth 2.0 / OpenID Connect login helpers live in the separate
`fastapi_multiauth.oauth` namespace and need the `oauth` extra:

```python
from fastapi_multiauth.oauth import oauth_build_authorization_redirect
```
"""

import logging

from . import oauth
from .abc import AuthSource
from .amr import AuthenticationMethodReference
from .exceptions import (
    ForbiddenError,
    InsufficientAuthenticationError,
    StaleCredentialError,
    UnauthorizedError,
)
from .introspection import IntrospectionValidator
from .jwt import JWTValidator
from .sources import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    HMACSignatureAuth,
    HTTPBasicAuth,
    HTTPBearerAuth,
    HTTPDPoPAuth,
    MultiAuth,
    OAuth2AuthorizationCodeBearerAuth,
    OAuth2PasswordBearerAuth,
    OpenIdConnectAuth,
)
from .surface import RouteAuth, SchemeRequirement, auth_surface
from .totp import totp_generate_secret, totp_provisioning_uri, totp_verify
from .utils import (
    checksum_token_generator,
    hash_token,
    verify_token_checksum,
    verify_token_hash,
)

__version__ = "0.8.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "APIKeyCookieAuth",
    "APIKeyHeaderAuth",
    "APIKeyQueryAuth",
    "AuthSource",
    "AuthenticationMethodReference",
    "ForbiddenError",
    "HMACSignatureAuth",
    "HTTPBasicAuth",
    "HTTPBearerAuth",
    "HTTPDPoPAuth",
    "InsufficientAuthenticationError",
    "IntrospectionValidator",
    "JWTValidator",
    "MultiAuth",
    "OAuth2AuthorizationCodeBearerAuth",
    "OAuth2PasswordBearerAuth",
    "OpenIdConnectAuth",
    "RouteAuth",
    "SchemeRequirement",
    "StaleCredentialError",
    "UnauthorizedError",
    "auth_surface",
    "checksum_token_generator",
    "hash_token",
    "oauth",
    "totp_generate_secret",
    "totp_provisioning_uri",
    "totp_verify",
    "verify_token_checksum",
    "verify_token_hash",
]
