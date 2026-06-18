"""Pure OAuth helpers: state, PKCE, and the authorization redirect (no I/O)."""

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Sequence
from urllib.parse import urlencode, urlsplit

from fastapi import status
from fastapi.responses import RedirectResponse

__all__ = [
    "oauth_build_authorization_redirect",
    "oauth_decode_state",
    "oauth_encode_state",
    "oauth_generate_pkce_pair",
    "oauth_generate_state_token",
]


def oauth_generate_state_token() -> str:
    """Generate a cryptographically random CSRF token for the OAuth ``state`` parameter."""
    return secrets.token_urlsafe(32)


def oauth_generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE ``(code_verifier, code_challenge)`` pair (RFC 7636, S256).

    Store the verifier server-side and pass it back to
    :func:`~fastapi_multiauth.oauth.oauth_exchange_code` on the callback.

    Returns:
        A ``(code_verifier, code_challenge)`` tuple; the challenge is the
        base64url SHA-256 of the verifier.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def oauth_build_authorization_redirect(
    authorization_url: str,
    *,
    client_id: str,
    scopes: str,
    redirect_uri: str,
    destination: str,
    state_token: str,
    code_challenge: str | None = None,
) -> RedirectResponse:
    """Return an OAuth 2.0 authorization ``RedirectResponse`` (303 See Other).

    Args:
        authorization_url: Provider's authorization endpoint.
        client_id: OAuth application client ID.
        scopes: Space-separated list of requested scopes.
        redirect_uri: URI the provider should redirect back to.
        destination: Post-login URL (embedded in ``state``).
        state_token: CSRF token from :func:`oauth_generate_state_token`; verify
            it with :func:`oauth_decode_state` on the callback.
        code_challenge: PKCE challenge from :func:`oauth_generate_pkce_pair`;
            when set, ``code_challenge_method=S256`` is sent along.

    Returns:
        A :class:`~fastapi.responses.RedirectResponse` to the provider's
        authorization page, retaining any query string already present.
    """
    params = {
        "client_id": client_id,
        "response_type": "code",
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "state": oauth_encode_state(destination, state_token),
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    sep = "&" if urlsplit(authorization_url).query else "?"
    return RedirectResponse(
        f"{authorization_url}{sep}{urlencode(params)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def oauth_encode_state(url: str, state_token: str) -> str:
    """Encode a destination URL and CSRF token into an OAuth ``state`` parameter.

    Args:
        url: Post-login destination URL.
        state_token: CSRF token from :func:`oauth_generate_state_token`.
    """
    payload = json.dumps({"n": state_token, "d": url}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _destination_allowed(destination: str, allowed_hosts: Sequence[str]) -> bool:
    """Check a decoded destination against the open-redirect allowlist."""
    # Browsers normalize backslashes to slashes, turning "/\evil.com" into a
    # scheme-relative redirect — reject them outright.
    if "\\" in destination:
        return False
    parsed = urlsplit(destination)
    if not parsed.scheme and not parsed.netloc:
        return destination.startswith("/") and not destination.startswith("//")
    if parsed.scheme not in ("http", "https"):
        return False
    return parsed.hostname in allowed_hosts


def oauth_decode_state(
    state: str | None,
    *,
    expected_state_token: str,
    fallback: str,
    allowed_hosts: Sequence[str] | None = (),
) -> str:
    """Decode and CSRF-verify an OAuth ``state`` parameter (constant-time).

    The stored token is single-use: delete it from the session after this call,
    matched or not, so a captured callback cannot be replayed.

    Args:
        state: Raw ``state`` query parameter from the callback.
        expected_state_token: Token stored before the authorization redirect;
            a mismatch returns ``fallback``.
        fallback: URL returned when ``state`` is absent, malformed, or fails
            verification.
        allowed_hosts: Open-redirect guard — the decoded destination must be a
            relative path or an absolute http(s) URL whose host is listed. The
            default (``()``) allows relative paths only; ``None`` disables the check.

    Returns:
        The destination URL embedded in ``state``, or ``fallback``.
    """
    if not state or state == "null":  # "null" guards against JS JSON.stringify(null)
        return fallback
    try:
        padded = state + "=" * (-len(state) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if not isinstance(payload, dict):
            return fallback
        token = payload.get("n", "")
        if not isinstance(token, str) or not hmac.compare_digest(
            token.encode(), expected_state_token.encode()
        ):
            return fallback
        destination = payload["d"]
        if not isinstance(destination, str):
            return fallback
        if allowed_hosts is not None and not _destination_allowed(
            destination, allowed_hosts
        ):
            return fallback
        return destination
    except (UnicodeDecodeError, ValueError, KeyError):
        return fallback
