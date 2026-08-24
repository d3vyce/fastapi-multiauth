"""Built-in authentication source implementations."""

from .basic import HTTPBasicAuth
from .bearer import HTTPBearerAuth
from .cookie import APIKeyCookieAuth
from .header import APIKeyHeaderAuth
from .multi import MultiAuth
from .oauth2 import (
    OAuth2AuthorizationCodeBearerAuth,
    OAuth2PasswordBearerAuth,
    OpenIdConnectAuth,
)
from .query import APIKeyQueryAuth

__all__ = [
    "APIKeyCookieAuth",
    "APIKeyHeaderAuth",
    "APIKeyQueryAuth",
    "HTTPBasicAuth",
    "HTTPBearerAuth",
    "MultiAuth",
    "OAuth2AuthorizationCodeBearerAuth",
    "OAuth2PasswordBearerAuth",
    "OpenIdConnectAuth",
]
