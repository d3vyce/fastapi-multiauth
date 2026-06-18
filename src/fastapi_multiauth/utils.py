"""Standalone helpers: public token utilities plus internal source helpers."""

import functools
import hashlib
import hmac
import inspect
from typing import Any, Callable

from fastapi import HTTPException, Request


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of an opaque token.

    Args:
        token: The opaque token, including any prefix.

    Returns:
        A 64-character lowercase hex digest.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token: str, stored_hash: str) -> bool:
    """Compare a presented token against a stored hash in constant time.

    Args:
        token: The opaque token presented by the client.
        stored_hash: The hex digest previously stored via :func:`hash_token`.

    Returns:
        ``True`` if the token matches the stored hash.
    """
    return hmac.compare_digest(hash_token(token), stored_hash)


def ensure_async(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap *fn* so it can always be awaited, regardless of sync or async."""
    if inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(
        getattr(fn, "__call__", None)  # noqa: B004 — detecting async __call__, not callability
    ):
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = fn(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result

    return wrapper


def challenge_headers(challenge: str | None) -> dict[str, str] | None:
    """Build the ``WWW-Authenticate`` header dict for a 401 (RFC 7235 §4.1)."""
    if not challenge:
        return None
    return {"WWW-Authenticate": challenge}


def add_challenge(exc: HTTPException, challenge: str | None) -> None:
    """Attach a ``WWW-Authenticate`` challenge to a 401 that lacks one."""
    if exc.status_code != 401 or not challenge:
        return
    headers = dict(exc.headers or {})
    if "WWW-Authenticate" not in headers:
        headers["WWW-Authenticate"] = challenge
        exc.headers = headers


def authorization_credential(request: Request, scheme: str) -> str | None:
    """Extract the value of an ``Authorization: <scheme> <value>`` header.

    The scheme is matched case-insensitively (RFC 7235 §2.1). Returns ``None``
    when the header is absent, carries a different scheme, or has an empty value.
    """
    authorization = request.headers.get("Authorization")
    if authorization is None:
        return None
    header_scheme, sep, value = authorization.partition(" ")
    if not sep or header_scheme.lower() != scheme:
        return None
    return value.strip() or None
