"""Built-in authentication source implementations."""

from .basic import HTTPBasicAuth
from .bearer import HTTPBearerAuth
from .cookie import APIKeyCookieAuth
from .header import APIKeyHeaderAuth
from .multi import MultiAuth
from .query import APIKeyQueryAuth

__all__ = [
    "APIKeyCookieAuth",
    "APIKeyHeaderAuth",
    "APIKeyQueryAuth",
    "HTTPBasicAuth",
    "HTTPBearerAuth",
    "MultiAuth",
]
