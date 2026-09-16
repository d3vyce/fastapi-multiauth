"""Standalone helpers: public token utilities plus internal source helpers."""

import functools
import hashlib
import hmac
import inspect
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import anyio.to_thread
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
        result = await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
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


def credential_age(instant: Any) -> float | None:
    """Seconds since *instant*, or ``None`` when it is not a point in time.

    Epoch seconds or a ``datetime`` (naive read as UTC). Anything else,
    a missing instant included, fails closed.
    """
    if isinstance(instant, datetime):
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        instant = instant.timestamp()
    elif isinstance(instant, bool) or not isinstance(instant, (int, float)):
        return None
    return time.time() - instant


def step_up_challenge(challenge: str | None, max_age: float) -> dict[str, str] | None:
    """Build the stale-credential ``WWW-Authenticate`` header (RFC 9470 §3).

    The window is advertised in whole seconds, never ``0``. A challenge already
    holding a parameter (``Basic realm="api"``) continues with a comma, a bare
    scheme with a space (RFC 7235). ``None`` when the source has no HTTP auth
    scheme to challenge with, leaving the body to carry the signal.
    """
    if not challenge:
        return None
    separator = ", " if " " in challenge else " "
    return challenge_headers(
        f'{challenge}{separator}error="insufficient_user_authentication", '
        'error_description="More recent authentication is required", '
        f'max_age="{max(1, int(max_age))}"'
    )


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
