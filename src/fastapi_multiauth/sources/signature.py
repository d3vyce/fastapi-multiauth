"""HMAC request signature authentication source, for incoming webhooks."""

import hashlib
import hmac
import string
import time
from collections.abc import Callable, Sequence
from typing import Any

from fastapi import HTTPException, Request
from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyHeader

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import AuthSource, _unenforceable_scopes_error
from ..utils import (
    ensure_async,
    first_use,
    normalize_secret_keys,
    refusal,
    require_positive_seconds,
)

_MIN_SECRET_KEY_BYTES = 16
_MAX_TIMESTAMP_DIGITS = 12
_HEX_DIGITS = frozenset(string.hexdigits)
_HEX_SHA256_LENGTH = 64
_BODY = "{body}"
_TIMESTAMP = "{timestamp}"


def _malformed() -> UnauthorizedError:
    """The 401 for a signature header that does not parse."""
    return refusal(UnauthorizedError(), "malformed")


def _too_large() -> HTTPException:
    """The 413 for a body over `max_body_size`."""
    return refusal(
        HTTPException(
            status_code=413,
            detail="Request body too large",
        ),
        "body_too_large",
    )


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
        replay_check: Sync or async callable recording a verified request
            until the epoch time it receives, returning `False` if it was
            already recorded. It receives a SHA-256 digest of `scheme_name`
            and the signed message, the same whichever key signed it. Needs
            a timestamp.
        max_body_size: Largest body accepted, in bytes; a larger one gets a
            413. The body has to be read before its signature can be
            checked, so without a limit anyone can make the app buffer a
            body of any size. Set it to what the sender documents, unless
            your proxy already limits bodies. On a route that declares a
            body parameter FastAPI has read the body first: the limit then
            only refuses it.
        scheme_name: Name of the security scheme in OpenAPI, `APIKeyHeader_{header}` by default.
        description: Description of the security scheme in OpenAPI.

    Raises:
        ValueError: On an invalid configuration, such as a short secret, a
            `tolerance` that is not positive, two timestamp sources, a
            `signed_message` that leaves the timestamp unsigned, a
            `replay_check` without a timestamp, or a `max_body_size` that
            is not a positive integer.
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
        replay_check: Callable[[str, float], Any] | None = None,
        max_body_size: int | None = None,
        scheme_name: str | None = None,
        description: str | None = None,
    ) -> None:
        require_positive_seconds(tolerance, "tolerance")
        if max_body_size is not None and (
            isinstance(max_body_size, bool)
            or not isinstance(max_body_size, int)
            or max_body_size < 1
        ):
            raise ValueError("max_body_size must be a positive number of bytes")
        self._max_body_size = max_body_size
        if signature_key is not None and prefix:
            raise ValueError(
                "prefix and signature_key describe two header layouts: pass one"
            )
        if timestamp_key is not None and signature_key is None:
            raise ValueError("timestamp_key requires signature_key")
        if timestamp_key is not None and timestamp_header is not None:
            raise ValueError("pass one of timestamp_key or timestamp_header")
        timestamped = timestamp_key is not None or timestamp_header is not None
        if replay_check is not None and not timestamped:
            raise ValueError(
                "replay_check needs a timestamp: without one, every signature "
                "would have to be kept forever. Deduplicate on the sender's "
                "event id instead"
            )
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
        if header.lower() == "authorization":
            self.authorization_scheme = "*"
        self._prefix = prefix
        self._signature_key = signature_key
        self._timestamp_key = timestamp_key
        self._timestamp_header = timestamp_header
        self._timestamped = timestamped
        self._tolerance = tolerance
        self._replay_check = ensure_async(replay_check) if replay_check else None
        scheme_name = scheme_name or f"APIKeyHeader_{header}"
        name = scheme_name.encode()
        self._replay_namespace = b"%d:%s:" % (len(name), name)
        super().__init__(
            APIKeyHeader(
                name=header,
                auto_error=False,
                scheme_name=scheme_name,
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
                the timestamp is outside `tolerance` (`expired`), no
                signature matches (`invalid_signature`), or `replay_check`
                already saw it (`replay`).
            HTTPException: 413 if the body is larger than `max_body_size`
                (`body_too_large`).
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
        expires_at = None
        if timestamp is not None:
            if not (
                timestamp.isascii()
                and timestamp.isdigit()
                and len(timestamp) <= _MAX_TIMESTAMP_DIGITS
            ):
                raise _malformed()
            issued_at = int(timestamp)
            if abs(time.time() - issued_at) > self._tolerance:
                raise refusal(UnauthorizedError(), "expired")
            signed_prefix += timestamp.encode() + self._after
            expires_at = issued_at + self._tolerance
        candidates = [
            signature.lower()
            for signature in signatures
            if len(signature) == _HEX_SHA256_LENGTH
            and _HEX_DIGITS.issuperset(signature)
        ]
        if not candidates:  # refused before the body is read
            raise refusal(UnauthorizedError(), "invalid_signature")
        try:
            body = await self._read_body(request)
        except RuntimeError as exc:
            raise RuntimeError(
                f"{type(self).__name__} needs the raw body, but the route "
                "already consumed it, as Form() and File() parameters do: take "
                "the verified bytes from the source and parse them yourself"
            ) from exc
        for key in self._keys:
            mac = hmac.new(key, signed_prefix, hashlib.sha256)
            mac.update(body)
            digest = mac.hexdigest()
            if any(hmac.compare_digest(digest, c) for c in candidates):
                if self._replay_check is not None and expires_at is not None:
                    # One key per request, not per signature: with several keys
                    # in rotation, each signature would let one more copy through.
                    message = hashlib.sha256(self._replay_namespace)
                    message.update(signed_prefix)
                    message.update(body)
                    if not await first_use(
                        self._replay_check, message.hexdigest(), expires_at, request
                    ):
                        raise refusal(UnauthorizedError(), "replay")
                return body
        raise refusal(UnauthorizedError(), "invalid_signature")

    async def _read_body(self, request: Request) -> bytes:
        """The raw body, refused with a 413 once it passes `max_body_size`.

        A declared `Content-Length` over the limit is refused unread, and a
        body without one stops being read at the limit.

        Raises:
            RuntimeError: If the body stream was already consumed.
        """
        limit = self._max_body_size
        if limit is None:
            return await request.body()
        declared = request.headers.get("content-length", "")
        if declared.isascii() and declared.isdigit() and int(declared) > limit:
            raise _too_large()
        if hasattr(request, "_body"):  # FastAPI read it for a body parameter
            body = await request.body()
            if len(body) > limit:
                raise _too_large()
            return body
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise _too_large()
            chunks.append(chunk)
        # What Request.body() caches, so the route can still read the body.
        body = request._body = b"".join(chunks)
        return body

    def _enforces_scopes(self) -> bool:
        """A signature proves who sent the request, never what it may do."""
        return False
