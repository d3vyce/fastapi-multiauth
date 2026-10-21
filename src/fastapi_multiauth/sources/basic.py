"""HTTP Basic authentication source."""

import base64
from collections.abc import Callable
from typing import Any

from fastapi.requests import HTTPConnection
from fastapi.security import HTTPBasic

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource
from ..utils import authorization_credential, refusal


def _basic_challenge(realm: str | None) -> str:
    """Build the `WWW-Authenticate` challenge, escaping `realm` (RFC 7230 §3.2.6)."""
    if realm is None:
        return "Basic"
    if not (realm.isascii() and realm.isprintable()):
        raise ValueError(
            f"realm must be printable US-ASCII (RFC 7617 §2.1), got {realm!r}: "
            "control characters have no escaped form in a quoted-string, and "
            "non-ASCII cannot be carried in a header value"
        )
    escaped = realm.replace("\\", "\\\\").replace('"', '\\"')
    return f'Basic realm="{escaped}"'


class HTTPBasicAuth(ValidatedAuthSource):
    """Authentication source for HTTP Basic credentials.

    Decodes the header as [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617)
    defines it and calls the validator with `username, password`. Compare secrets with
    `secrets.compare_digest`, never `==`.

    Args:
        validator: Sync or async callable taking `username, password` and
            returning the identity, or raising to refuse.
        realm: Realm sent in the `WWW-Authenticate` challenge.
        scheme_name: Name of the security scheme in OpenAPI, `HTTPBasic` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        realm: str | None = None,
        scheme_name: str | None = None,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._challenge = _basic_challenge(realm)
        super().__init__(
            validator,
            HTTPBasic(
                auto_error=False,
                scheme_name=scheme_name,
                description=description,
            ),
            **kwargs,
        )

    def www_authenticate(self) -> str:
        """Return the `Basic` challenge, with the realm when configured."""
        return self._challenge

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the encoded credentials, or `None` when absent or empty.

        Decoding happens in `authenticate_scoped()`, so a malformed value is a
        401 rather than a missing credential.
        """
        return authorization_credential(request, "basic")

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Decode the credentials, then pass them on to the validator."""
        try:
            decoded = base64.b64decode(credential, validate=True).decode("utf-8")
        except ValueError:  # covers binascii.Error and UnicodeDecodeError
            raise refusal(UnauthorizedError(), "malformed") from None
        username, sep, password = decoded.partition(":")
        if not sep:
            raise refusal(UnauthorizedError(), "malformed")
        return await self._call_validator(
            username, password, scopes=scopes, request=request
        )
