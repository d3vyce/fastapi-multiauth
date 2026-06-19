"""Composable authentication sources for FastAPI using Security().

The OAuth 2.0 / OIDC login-flow helpers live in the :mod:`fastapi_multiauth.oauth`
namespace — they are a distinct concern from the request-time auth sources
exported here, and require the ``oauth`` extra. Import them explicitly::

    from fastapi_multiauth import oauth

    redirect = oauth.oauth_build_authorization_redirect(...)
"""

from . import oauth
from .abc import AuthSource
from .exceptions import ForbiddenError, UnauthorizedError
from .jwt import JWTValidator
from .sources import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    HTTPBasicAuth,
    HTTPBearerAuth,
    MultiAuth,
)
from .utils import hash_token, verify_token_hash

__version__ = "0.1.0"

__all__ = [
    "APIKeyCookieAuth",
    "APIKeyHeaderAuth",
    "APIKeyQueryAuth",
    "AuthSource",
    "ForbiddenError",
    "HTTPBasicAuth",
    "HTTPBearerAuth",
    "JWTValidator",
    "MultiAuth",
    "UnauthorizedError",
    "hash_token",
    "oauth",
    "verify_token_hash",
]
