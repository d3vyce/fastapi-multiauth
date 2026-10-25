"""Standalone helpers: public token utilities plus internal source helpers."""

import base64
import functools
import hashlib
import hmac
import inspect
import logging
import math
import secrets
import string
import time
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar
from urllib.parse import urlsplit

import anyio.to_thread
from fastapi import HTTPException
from fastapi.requests import HTTPConnection


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url, as JOSE, PKCE and the cookie payload carry bytes."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url.

    Raises:
        ValueError: If `text` is not base64url.
    """
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def normalize_origin(origin: str, label: str) -> str:
    """Validate a configured origin, `scheme://host[:port]`, and normalize it.

    Returns:
        The origin lowercased, without its scheme's default port.

    Raises:
        ValueError: If `origin` is not an http(s) origin, or has a path,
            a trailing slash or credentials. `label` names it in the message.
    """
    lowered = origin.lower()
    parts = urlsplit(lowered)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or "@" in parts.netloc
        or lowered != f"{parts.scheme}://{parts.netloc}"
    ):
        raise ValueError(
            f"{label} must be an origin such as 'https://app.example.com', "
            f"without path or trailing slash (got {origin!r})"
        )
    default_port = ":443" if parts.scheme == "https" else ":80"
    return f"{parts.scheme}://{parts.netloc.removesuffix(default_port)}"


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token, to store instead of the token.

    Right for random tokens, which cannot be guessed. Never use it for
    passwords.

    Args:
        token: The token, prefix included.

    Returns:
        A 64-character lowercase hex digest.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token: str, stored_hash: str) -> bool:
    """Check a token against a stored hash, in constant time.

    Args:
        token: The token presented by the client.
        stored_hash: The digest stored with `hash_token()`.

    Returns:
        `True` if the token matches.
    """
    return hmac.compare_digest(hash_token(token), stored_hash)


_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
_CHECKSUM_LENGTH = 6


def _base62(value: int, width: int) -> str:
    """`value` in base62, zero-padded to `width` characters."""
    digits = []
    for _ in range(width):
        value, digit = divmod(value, 62)
        digits.append(_BASE62[digit])
    return "".join(reversed(digits))


def _checksum(body: str) -> str:
    """The CRC32 of `body` in base62, six characters."""
    return _base62(zlib.crc32(body.encode()), _CHECKSUM_LENGTH)


def checksum_token_generator(nbytes: int = 32) -> str:
    """Generate a token body ending in a CRC32 checksum, GitHub-style.

    Pass it as `HTTPBearerAuth(..., token_generator=checksum_token_generator)`
    and check tokens with `verify_token_checksum()`. The checksum filters
    typos; it is not a security mechanism.

    Args:
        nbytes: Bytes of random entropy in the body.

    Returns:
        A base62 body followed by a six-character checksum: 49 characters
        at the default `nbytes`.

    Raises:
        ValueError: If `nbytes` is not positive.
    """
    if nbytes < 1:
        raise ValueError("nbytes must be a positive number of bytes")
    length = math.ceil(nbytes * 8 / math.log2(len(_BASE62)))
    body = _base62(int.from_bytes(secrets.token_bytes(nbytes)), length)
    return body + _checksum(body)


def verify_token_checksum(token: str, *, prefix: str | None = None) -> bool:
    """Check the checksum of a token made by `checksum_token_generator()`.

    Call it first in the validator to refuse a typo before the lookup.
    Anyone can compute a checksum, so passing proves nothing else.

    Args:
        token: The token as presented, prefix included.
        prefix: The source's prefix, stripped before the check.

    Returns:
        `True` if the token has the prefix, an alphanumeric body, and the
        right checksum.
    """
    if prefix is not None:
        if not token.startswith(prefix):
            return False
        token = token[len(prefix) :]
    body, checksum = token[:-_CHECKSUM_LENGTH], token[-_CHECKSUM_LENGTH:]
    if not body or not (token.isascii() and token.isalnum()):
        return False
    return _checksum(body) == checksum


_HTTPError = TypeVar("_HTTPError", bound=HTTPException)

_REFUSAL_REASON = "_fastapi_multiauth_reason"


def refusal(exc: _HTTPError, reason: str) -> _HTTPError:
    """Tag `exc` with the reason code logged when it refuses a request."""
    setattr(exc, _REFUSAL_REASON, reason)
    return exc


def refusal_reason(exc: HTTPException) -> str:
    """The reason code of a refusal, derived from its status when untagged."""
    reason = getattr(exc, _REFUSAL_REASON, None)
    if reason is not None:
        return reason
    if exc.status_code == 401:
        return "rejected"
    if exc.status_code == 403:
        return "forbidden"
    return "error"


def log_decision(
    logger: logging.Logger,
    level: int,
    reason: str,
    *,
    source: str,
    scheme: str | None,
    status: int | None = None,
) -> None:
    """Log one authentication decision, never the credential or the identity.

    Args:
        logger: The deciding module's logger.
        level: `WARNING` for a refusal, `DEBUG` for a success.
        reason: The decision's reason code (`"authenticated"` on success).
        source: Class name of the deciding source.
        scheme: Its OpenAPI security scheme name, `None` when it has none.
        status: The refusal's HTTP status, `None` when nothing was refused.
    """
    logger.log(
        level,
        "%s: %s",
        source,
        reason,
        extra={
            "auth_source": source,
            "auth_scheme": scheme,
            "auth_reason": reason,
            "auth_status": status,
        },
    )


def ensure_async(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap `fn` so it can always be awaited, regardless of sync or async."""
    if inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(
        getattr(fn, "__call__", None)  # noqa: B004 (detecting async __call__, not callability)
    ):
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
        if inspect.isawaitable(result):
            return await result
        return result

    return wrapper


def challenge_headers(challenge: str | None) -> dict[str, str] | None:
    """Build the `WWW-Authenticate` header dict for a 401 (RFC 7235 §4.1)."""
    if not challenge:
        return None
    return {"WWW-Authenticate": challenge}


def add_challenge(exc: HTTPException, challenge: str | None) -> None:
    """Attach a `WWW-Authenticate` challenge to a 401 that lacks one."""
    if exc.status_code != 401 or not challenge:
        return
    headers = dict(exc.headers or {})
    if "WWW-Authenticate" not in headers:
        headers["WWW-Authenticate"] = challenge
        exc.headers = headers


def credential_age(instant: Any) -> float | None:
    """Seconds since `instant`, or `None` when it is not a point in time.

    Epoch seconds or a `datetime` (naive read as UTC). Anything else,
    a missing or non-finite instant included, fails closed.
    """
    if isinstance(instant, datetime):
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=UTC)
        instant = instant.timestamp()
    elif isinstance(instant, bool) or not isinstance(instant, (int, float)):
        return None
    try:
        age = time.time() - instant
    except OverflowError:
        return None
    return age if math.isfinite(age) else None


def step_up_challenge(
    challenge: str | None,
    description: str,
    *,
    max_age: float | None = None,
    acr_values: tuple[str, ...] | None = None,
) -> dict[str, str] | None:
    """The RFC 9470 step-up `WWW-Authenticate` header, `None` without a challenge."""
    if not challenge:
        return None
    params = [
        'error="insufficient_user_authentication"',
        f'error_description="{description}"',
    ]
    if acr_values:
        params.append(f'acr_values="{" ".join(acr_values)}"')
    if max_age is not None:
        params.append(f'max_age="{max(1, int(max_age))}"')
    separator = ", " if " " in challenge else " "
    return challenge_headers(f"{challenge}{separator}{', '.join(params)}")


def authorization_credential(request: HTTPConnection, scheme: str) -> str | None:
    """Extract the value of an `Authorization: <scheme> <value>` header.

    The scheme is matched case-insensitively (RFC 7235 §2.1). Returns `None`
    when the header is absent, carries a different scheme, or has an empty value.
    """
    authorization = request.headers.get("Authorization")
    if authorization is None:
        return None
    header_scheme, sep, value = authorization.partition(" ")
    if not sep or header_scheme.lower() != scheme:
        return None
    return value.strip() or None
