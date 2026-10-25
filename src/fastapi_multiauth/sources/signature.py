"""HMAC request signature authentication source, for incoming webhooks."""

import hashlib
import hmac
import string
import time
from collections.abc import Sequence
from typing import Any

from fastapi import Request
from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyHeader

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import AuthSource, _unenforceable_scopes_error
from ..utils import normalize_secret_keys, refusal, require_positive_seconds

_MIN_SECRET_KEY_BYTES = 16
_MAX_TIMESTAMP_DIGITS = 12
_HEX_DIGITS = frozenset(string.hexdigits)
_BODY = "{body}"
_TIMESTAMP = "{timestamp}"


def _malformed() -> UnauthorizedError:
    """The 401 for a signature header that does not parse."""
    return refusal(UnauthorizedError(), "malformed")


def _split_template(signed_message: str, *, timestamped: bool) -> tuple[bytes, bytes]:
    """Split `signed_message` into the text before and after `{timestamp}`.

    Raises:
        ValueError: If the template does not end with its only `{body}`, has
            other placeholders, or names `{timestamp}` without a timestamp
            configured, or the other way around.
    """
    head = signed_message.removesuffix(_BODY)
    if head == signed_message or _BODY in head:
        raise ValueError(
            f"signed_message must end with {_BODY} and name it once "
            f"(got {signed_message!r})"
        )
    if head.count(_TIMESTAMP) != (1 if timestamped else 0):
        raise ValueError(
            f"signed_message must name {_TIMESTAMP} exactly when a timestamp is "
            "configured: an unsigned timestamp could be changed to replay the "
            f"request (got {signed_message!r})"
        )
    before, _, after = head.partition(_TIMESTAMP)
    if any(brace in before + after for brace in "{}"):
        raise ValueError(
            f"signed_message only knows {_TIMESTAMP} and {_BODY} "
            f"(got {signed_message!r})"
        )
    return before.encode(), after.encode()


class HMACSignatureAuth(AuthSource):
    """Authentication source for requests signed with an HMAC-SHA256 of their body.

    Verifies incoming webhooks: the sender signs the raw body, and a
    timestamp when it sends one, with a secret you share, and puts the hex
    signature in a header. The route receives the verified body as `bytes`,
    and can still declare a JSON body parameter, which FastAPI parses from
    the same bytes.

    The signature header carries either one signature after a `prefix`
    (`sha256=<signature>`), or a comma-separated list of `key=value` items
    read with `signature_key` and `timestamp_key` (`t=<time>,v1=<signature>`).

    Args:
        secret_key: Shared secret of at least 16 bytes, or a list to rotate
            secrets (any of them verifies).
        header: Header carrying the signature.
        prefix: Text before the signature in the header, e.g. `"sha256="`.
        signature_key: Key of the signatures in a `key=value` list header,
            e.g. `"v1"`. Several items with this key are all tried.
        timestamp_key: Key of the timestamp in a `key=value` list header,
            e.g. `"t"`. Needs `signature_key`.
        timestamp_header: Header carrying the timestamp, when it travels on
            its own.
        signed_message: What the sender signs: a template ending with
            `{body}`, naming `{timestamp}` when a timestamp is configured,
            e.g. `"v0:{timestamp}:{body}"`. Defaults to `{timestamp}.{body}`
            with a timestamp, `{body}` without.
        tolerance: How far the timestamp may be from now, in seconds.
        scheme_name: Name of the security scheme in OpenAPI, `APIKeyHeader_{header}` by default.
        description: Description of the security scheme in OpenAPI.

    Raises:
        ValueError: On an invalid configuration, such as a short secret, a
            `tolerance` that is not positive, two timestamp sources, or a
            `signed_message` that leaves the timestamp unsigned.
    """

    def __init__(
        self,
        secret_key: str | Sequence[str],
        *,
        header: str,
        prefix: str = "",
        signature_key: str | None = None,
        timestamp_key: str | None = None,
        timestamp_header: str | None = None,
        signed_message: str | None = None,
        tolerance: float = 300.0,
        scheme_name: str | None = None,
        description: str | None = None,
    ) -> None:
        require_positive_seconds(tolerance, "tolerance")
        if signature_key is not None and prefix:
            raise ValueError(
                "prefix and signature_key describe two header layouts: pass one"
            )
        if timestamp_key is not None and signature_key is None:
            raise ValueError("timestamp_key requires signature_key")
        if timestamp_key is not None and timestamp_header is not None:
            raise ValueError("pass one of timestamp_key or timestamp_header")
        timestamped = timestamp_key is not None or timestamp_header is not None
        if signed_message is None:
            signed_message = f"{_TIMESTAMP}.{_BODY}" if timestamped else _BODY
        self._before, self._after = _split_template(
            signed_message, timestamped=timestamped
        )
        self._keys = [
            key.encode()
            for key in normalize_secret_keys(
                secret_key, min_bytes=_MIN_SECRET_KEY_BYTES
            )
        ]
        self._header = header
        self._prefix = prefix
        self._signature_key = signature_key
        self._timestamp_key = timestamp_key
        self._timestamp_header = timestamp_header
        self._timestamped = timestamped
        self._tolerance = tolerance
        super().__init__(
            APIKeyHeader(
                name=header,
                auto_error=False,
                scheme_name=scheme_name or f"APIKeyHeader_{header}",
                description=description,
            )
        )

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the signature header, or `None` when absent or empty."""
        return request.headers.get(self._header) or None

    async def authenticate(self, credential: str) -> Any:
        """Refuse: a signature cannot be checked without the request body.

        Raises:
            RuntimeError: Always. Let FastAPI call the source as a dependency.
        """
        raise RuntimeError(
            f"{type(self).__name__} signs the request body: it can only "
            "authenticate a request, as a FastAPI dependency"
        )

    def _parse(
        self, value: str, request: HTTPConnection
    ) -> tuple[str | None, list[str]]:
        """The timestamp and the signatures a request carries."""
        timestamps: list[str] = []
        if self._signature_key is None:
            if not value.startswith(self._prefix):
                raise _malformed()
            signatures = [value[len(self._prefix) :]]
        else:
            signatures = []
            for item in value.split(","):
                key, sep, item_value = item.strip().partition("=")
                if not sep:
                    raise _malformed()
                if key == self._signature_key:
                    signatures.append(item_value)
                elif key == self._timestamp_key:
                    timestamps.append(item_value)
            if not signatures:
                raise _malformed()
        if self._timestamp_header is not None:
            timestamps = request.headers.getlist(self._timestamp_header)
        if not self._timestamped:
            return None, signatures
        if len(timestamps) != 1:
            raise _malformed()
        return timestamps[0], signatures

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> bytes:
        """Verify the timestamp and signature, and return the request body.

        Raises:
            UnauthorizedError: If the header does not parse (`malformed`),
                the timestamp is outside `tolerance` (`expired`), or no
                signature matches (`invalid_signature`).
            RuntimeError: If the route declares scopes, is a WebSocket, or
                already consumed the body.
        """
        if scopes:
            raise _unenforceable_scopes_error(
                self, scopes, "a signed request carries no scopes"
            )
        if not isinstance(request, Request):
            return await self.authenticate(credential)
        timestamp, signatures = self._parse(credential, request)
        signed_prefix = self._before
        if timestamp is not None:
            if not (
                timestamp.isascii()
                and timestamp.isdigit()
                and len(timestamp) <= _MAX_TIMESTAMP_DIGITS
            ):
                raise _malformed()
            if abs(time.time() - int(timestamp)) > self._tolerance:
                raise refusal(UnauthorizedError(), "expired")
            signed_prefix += timestamp.encode() + self._after
        try:
            body = await request.body()
        except RuntimeError as exc:
            raise RuntimeError(
                f"{type(self).__name__} needs the raw body, but the route "
                "already consumed it, as Form() and File() parameters do: take "
                "the verified bytes from the source and parse them yourself"
            ) from exc
        candidates = [
            signature.lower()
            for signature in signatures
            if signature and _HEX_DIGITS.issuperset(signature)
        ]
        for key in self._keys:
            mac = hmac.new(key, signed_prefix, hashlib.sha256)
            mac.update(body)
            digest = mac.hexdigest()
            if any(hmac.compare_digest(digest, c) for c in candidates):
                return body
        raise refusal(UnauthorizedError(), "invalid_signature")

    def _enforces_scopes(self) -> bool:
        """A signature proves who sent the request, never what it may do."""
        return False
