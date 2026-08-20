"""HTTP Basic authentication source."""

import base64
from collections.abc import Callable
from typing import Any

from fastapi import Request
from fastapi.security import HTTPBasic

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource
from ..utils import authorization_credential


def _basic_challenge(realm: str | None) -> str:
    """Build the ``WWW-Authenticate`` challenge, escaping *realm* (RFC 7230 §3.2.6)."""
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
    """HTTP Basic authentication source (wraps ``HTTPBasic`` for OpenAPI, RFC 7617).

    The validator is called as ``await validator(username, password, **kwargs)``;
    compare the password in constant time (``secrets.compare_digest``).

    Args:
        validator: Sync or async callable receiving ``(username, password)`` and
            returning the identity; raises
            :class:`~fastapi_multiauth.exceptions.UnauthorizedError` on failure.
        realm: Optional protection-space name for the ``WWW-Authenticate``.
        scheme_name: OpenAPI security scheme name (default ``HTTPBasic``).
        **kwargs: Extra keyword arguments forwarded to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        realm: str | None = None,
        scheme_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._challenge = _basic_challenge(realm)
        super().__init__(
            validator,
            HTTPBasic(auto_error=False, scheme_name=scheme_name),
            **kwargs,
        )

    def www_authenticate(self) -> str:
        """``Basic`` challenge, with the realm when configured (RFC 7617 §2)."""
        return self._challenge

    async def extract(self, request: Request) -> str | None:
        """Return the base64 credentials blob, or ``None`` when absent or empty.

        The ``Basic`` scheme is matched case-insensitively; decoding and the
        split happen in :meth:`authenticate`, so a malformed blob is a 401.
        """
        return authorization_credential(request, "basic")

    async def authenticate_scoped(self, credential: str, scopes: list[str]) -> Any:
        """Decode the blob, forwarding route-declared scopes to the validator."""
        try:
            decoded = base64.b64decode(credential, validate=True).decode("utf-8")
        except ValueError:  # covers binascii.Error and UnicodeDecodeError
            raise UnauthorizedError() from None
        username, sep, password = decoded.partition(":")
        if not sep:
            raise UnauthorizedError()
        return await self._call_validator(username, password, scopes=scopes)
