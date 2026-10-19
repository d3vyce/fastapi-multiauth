"""Composable authentication sources for FastAPI using Security().

The OAuth 2.0 / OIDC login-flow helpers live in the :mod:`fastapi_multiauth.oauth`
namespace — they are a distinct concern from the request-time auth sources
exported here, and require the ``oauth`` extra. Import them explicitly::

    from fastapi_multiauth import oauth

    redirect = oauth.oauth_build_authorization_redirect(...)
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
from .jwt import JWTValidator
from .sources import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    HTTPBasicAuth,
    HTTPBearerAuth,
    MultiAuth,
    OAuth2AuthorizationCodeBearerAuth,
    OAuth2PasswordBearerAuth,
    OpenIdConnectAuth,
)
from .surface import RouteAuth, SchemeRequirement, auth_surface
from .utils import (
    checksum_token_generator,
    hash_token,
    verify_token_checksum,
    verify_token_hash,
)

__version__ = "0.7.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "APIKeyCookieAuth",
    "APIKeyHeaderAuth",
    "APIKeyQueryAuth",
    "AuthSource",
    "AuthenticationMethodReference",
    "ForbiddenError",
    "HTTPBasicAuth",
    "HTTPBearerAuth",
    "InsufficientAuthenticationError",
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
    "verify_token_checksum",
    "verify_token_hash",
]
