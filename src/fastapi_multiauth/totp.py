"""TOTP second factor (RFC 6238): enrolment and verification helpers."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

_DIGITS = 6
_PERIOD = 30
_SECRET_BYTES = 20
_MIN_SECRET_BYTES = 10


def _compact_secret(secret: str) -> str:
    """A base32 secret without spaces or padding, uppercased."""
    return "".join(secret.split()).upper().rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """The key of a base32 secret, spaces and case ignored, padding optional."""
    compact = _compact_secret(secret)
    try:
        key = base64.b32decode(compact + "=" * (-len(compact) % 8))
    except ValueError:
        key = b""
    if len(key) < _MIN_SECRET_BYTES:
        raise ValueError(
            f"secret must be a base32 string of at least {_MIN_SECRET_BYTES * 8} "
            "bits, 16 characters"
        )
    return key


def _hotp(key: bytes, counter: int) -> str:
    """The six-digit HOTP value of `counter` (RFC 4226 §5.3)."""
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**_DIGITS).zfill(_DIGITS)


def totp_generate_secret() -> str:
    """Generate a TOTP secret for a user enrolling in a second factor.

    Store it encrypted at rest: anyone holding it can compute every code.

    Returns:
        160 random bits in base32, 32 characters.
    """
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii")


def totp_provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """Build the `otpauth://` URI an authenticator app enrols from.

    Follows the Key Uri Format with its defaults (SHA-1, 6 digits, 30
    seconds), the only settings every app supports. Render it as a QR code
    for the user to scan.

    Args:
        secret: The base32 secret from `totp_generate_secret()`.
        account: The user's account name, such as their email address.
        issuer: Your service's name, shown in the app.

    Returns:
        The provisioning URI.

    Raises:
        ValueError: If `secret` is not base32 or shorter than 80 bits, or
            `account` or `issuer` is empty or contains a colon, the label's
            separator.
    """
    _decode_secret(secret)
    for label, value in (("account", account), ("issuer", issuer)):
        if not value or ":" in value:
            raise ValueError(f"{label} must be non-empty and contain no colon")
    query = urlencode(
        {"secret": _compact_secret(secret), "issuer": issuer}, quote_via=quote
    )
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    return f"otpauth://totp/{label}?{query}"


def totp_verify(
    secret: str, code: str, *, last_step: int | None = None, window: int = 1
) -> int | None:
    """Check a TOTP code, refusing one already used.

    Store the returned step with the user and pass it back as `last_step`
    next time: a code from that step or an earlier one is refused, so a
    code cannot be replayed within its window. Save it atomically, only if
    the stored step is still older, e.g. `UPDATE ... SET last_step = :step
    WHERE last_step IS NULL OR last_step < :step`, and refuse the login
    when nothing was updated: two requests carrying the same code would
    otherwise both read the old step and both pass.

    Each guess has three chances in a million at the default `window`, and
    nothing here counts them: cap failed attempts per account.

    Args:
        secret: The user's base32 secret.
        code: The six digits the user typed, spaces ignored.
        last_step: The step returned by the user's last successful check,
            `None` before the first.
        window: Steps accepted on each side of the current one, for clock
            drift. `1` accepts the previous and next 30 seconds.

    Returns:
        The time step the code matched, or `None` when it does not match,
        is malformed, or is not later than `last_step`.

    Raises:
        ValueError: If `secret` is not base32 or shorter than 80 bits, or
            `window` is negative.
    """
    if isinstance(window, bool) or not isinstance(window, int) or window < 0:
        raise ValueError("window must be a non-negative integer")
    key = _decode_secret(secret)
    code = "".join(code.split())
    if len(code) != _DIGITS or not (code.isascii() and code.isdigit()):
        return None
    current = int(time.time() // _PERIOD)
    first = current - window
    if last_step is not None:
        first = max(first, last_step + 1)
    matched = None
    for step in range(first, current + window + 1):
        if hmac.compare_digest(_hotp(key, step), code):
            matched = step
    return matched
