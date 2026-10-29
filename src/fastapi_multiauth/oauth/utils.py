"""Pure OAuth helpers: state, PKCE, and the authorization redirect (no I/O)."""

import hashlib
import hmac
import json
import secrets
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import status
from fastapi.responses import RedirectResponse

from .._http import _require_https
from ..exceptions import OAuthStateError
from ..utils import b64url_decode, b64url_encode

__all__ = [
    "oauth_build_authorization_redirect",
    "oauth_decode_state",
    "oauth_encode_state",
    "oauth_generate_nonce",
    "oauth_generate_pkce_pair",
    "oauth_generate_state_token",
]


def oauth_generate_state_token() -> str:
    """Generate a random CSRF token for the OAuth `state` parameter."""
    return secrets.token_urlsafe(32)


def oauth_generate_nonce() -> str:
    """Generate a random OpenID Connect `nonce`.

    Store it next to the state token, send it with
    `oauth_build_authorization_redirect()`, and pass it to
    `oauth_validate_id_token()` on the callback.
    """
    return oauth_generate_state_token()


def oauth_generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE verifier and its S256 challenge.

    See [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636). Send the
    challenge with the redirect, keep the verifier server-side, and pass it
    to `oauth_exchange_code()` on the callback.

    Returns:
        A `(code_verifier, code_challenge)` tuple.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return code_verifier, b64url_encode(digest)


def oauth_build_authorization_redirect(
    authorization_url: str,
    *,
    client_id: str,
    scopes: str,
    redirect_uri: str,
    destination: str,
    state_token: str,
    code_challenge: str | None = None,
    nonce: str | None = None,
) -> RedirectResponse:
    """Return the redirect that sends the user to the provider's login page.

    Args:
        authorization_url: HTTPS URL of the provider's authorization endpoint.
        client_id: Your application's client id.
        scopes: Space-separated scopes to request.
        redirect_uri: Where the provider sends the user back.
        destination: Where to send the user after login, carried in `state`.
        state_token: CSRF token from `oauth_generate_state_token()`.
        code_challenge: PKCE challenge from `oauth_generate_pkce_pair()`, sent
            with `code_challenge_method=S256`.
        nonce: OpenID Connect nonce from `oauth_generate_nonce()`.

    Returns:
        A 303 redirect to the provider, keeping any query string already
        in `authorization_url`.

    Raises:
        ValueError: If `authorization_url` is not HTTPS.
    """
    _require_https(authorization_url, "OAuth authorization_url")
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
    if nonce is not None:
        params["nonce"] = nonce
    sep = "&" if urlsplit(authorization_url).query else "?"
    return RedirectResponse(
        f"{authorization_url}{sep}{urlencode(params)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def oauth_encode_state(url: str, state_token: str) -> str:
    """Encode a destination and a CSRF token into an OAuth `state` value.

    `oauth_build_authorization_redirect()` calls it for you.

    Args:
        url: Where to send the user after login.
        state_token: CSRF token from `oauth_generate_state_token()`.
    """
    payload = json.dumps({"n": state_token, "d": url}, separators=(",", ":"))
    return b64url_encode(payload.encode())


def _destination_allowed(destination: str, allowed_hosts: Sequence[str]) -> bool:
    """Check a decoded destination against the open-redirect allowlist."""
    # Browsers normalize backslashes to slashes ("/\evil.com" becomes a
    # scheme-relative redirect) and strip tabs/newlines before parsing
    # ("/\t/evil.com" becomes "//evil.com"), so reject control chars outright.
    if "\\" in destination or any(ch <= " " for ch in destination):
        return False
    try:
        parsed = urlsplit(destination)
    except ValueError:
        return False
    if not parsed.scheme and not parsed.netloc:
        return destination.startswith("/") and not destination.startswith("//")
    if parsed.scheme not in ("http", "https"):
        return False
    return parsed.hostname in allowed_hosts


def _verified_payload(
    state: str | None, expected_state_token: str
) -> dict[str, Any] | None:
    """Decode `state` and return its payload when its token matches, else `None`."""
    if not state:
        return None
    try:
        payload = json.loads(b64url_decode(state).decode("utf-8"))
        token = payload.get("n") if isinstance(payload, dict) else None
        matches = isinstance(token, str) and hmac.compare_digest(
            token.encode(), expected_state_token.encode()
        )
    except (ValueError, RecursionError):
        return None
    return payload if matches else None


def oauth_decode_state(
    state: str | None,
    *,
    expected_state_token: str,
    fallback: str,
    allowed_hosts: Sequence[str] | None = (),
) -> str:
    """Verify the `state` of a callback and return the destination it carries.

    Pop the stored token from the session before calling this, so a
    callback cannot be replayed. The comparison is constant-time.

    Args:
        state: The `state` query parameter of the callback.
        expected_state_token: The token stored before the redirect. An
            empty token never matches.
        fallback: Returned when the destination is missing or refused.
        allowed_hosts: Hosts allowed in an absolute destination. The
            default allows relative paths only; `None` disables the check.

    Returns:
        The destination, or `fallback`.

    Raises:
        OAuthStateError: If no token was stored, or `state` is missing,
            malformed or carries another token. Do not exchange the code.
    """
    if not expected_state_token:
        raise OAuthStateError("no state token was stored for this session")
    payload = _verified_payload(state, expected_state_token)
    if payload is None:
        raise OAuthStateError("state failed verification")
    destination = payload.get("d")
    if not isinstance(destination, str):
        return fallback
    if allowed_hosts is None or _destination_allowed(destination, allowed_hosts):
        return destination
    return fallback
