"""OpenID Connect ID token validation (OIDC Core §3.1.3.7), needs the `jwt` extra."""

import functools
import hmac
from collections.abc import Sequence
from typing import Any

from .._http import DEFAULT_TIMEOUT, _require_https
from ..exceptions import OAuthIDTokenError
from ..jwt import (
    _import_pyjwt,
    _JWKSKeySet,
    _JWKSUnavailable,
    _MalformedToken,
    _reject_symmetric,
    _UnknownKey,
)
from .utils import _b64url

__all__ = ["oauth_validate_id_token"]

_REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat")


@functools.lru_cache(maxsize=32)
def _key_set(jwks_uri: str, algorithms: tuple[str, ...], timeout: float) -> _JWKSKeySet:
    """The cached JWKS of one provider, shared by every callback."""
    return _JWKSKeySet(_import_pyjwt(), jwks_uri, algorithms, timeout=timeout)


def _check_at_hash(pyjwt: Any, alg: str, claim: Any, access_token: str) -> None:
    """Refuse an ID token whose `at_hash` does not bind `access_token`."""
    if not isinstance(claim, str):
        raise OAuthIDTokenError("ID token has no at_hash to bind the access token")
    try:
        digest = pyjwt.get_algorithm_by_name(alg).compute_hash_digest(
            access_token.encode("ascii")
        )
    except NotImplementedError:
        raise OAuthIDTokenError(f"at_hash cannot be checked for alg {alg!r}") from None
    except UnicodeEncodeError:
        raise OAuthIDTokenError("ID token at_hash does not match") from None
    expected = _b64url(digest[: len(digest) // 2])
    if not hmac.compare_digest(claim.encode(), expected.encode()):
        raise OAuthIDTokenError("ID token at_hash does not match")


async def oauth_validate_id_token(
    id_token: str,
    *,
    issuer: str,
    jwks_uri: str,
    client_id: str,
    nonce: str | None = None,
    access_token: str | None = None,
    algorithms: Sequence[str] = ("RS256", "ES256"),
    leeway: float = 0.0,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Validate an OpenID Connect ID token and return its claims.

    Needs the `jwt` extra too. Checks the signature against the provider's
    keys (cached as `JWTValidator` does), `iss`, `aud`, `azp`, `exp`,
    `iat` and `sub` ([OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)).

    Args:
        id_token: The `id_token` of the token response.
        issuer: Expected `iss`, compared exactly (`OIDCEndpoints.issuer`).
        jwks_uri: HTTPS URL of the provider's keys (`OIDCEndpoints.jwks_uri`).
        client_id: Your client id: it must be in `aud`, and equal `azp`
            when the token has one.
        nonce: The nonce sent with the login, compared in constant time.
            An empty string never matches; `None` skips the check.
        access_token: The access token issued alongside, checked against
            the token's `at_hash`. Omit it if the provider sends no `at_hash`.
        algorithms: Accepted algorithms; `HS*` is refused.
        leeway: Clock-skew tolerance in seconds for `exp` and `iat`.
        timeout: Timeout of the key fetch, in seconds.

    Returns:
        The verified claims.

    Raises:
        ValueError: If `jwks_uri` is not HTTPS, `issuer` or `client_id` is
            empty, or `algorithms` is empty or includes `HS*`.
        OAuthIDTokenError: If any check fails, or the keys cannot be
            fetched and none are cached.
    """
    pyjwt = _import_pyjwt()
    _require_https(jwks_uri, "OIDC jwks_uri")
    if not issuer:
        raise ValueError("issuer must be a non-empty string")
    if not client_id:
        raise ValueError("client_id must be a non-empty string")
    accepted = tuple(algorithms)
    if not accepted:
        raise ValueError("algorithms must list at least one algorithm")
    _reject_symmetric(accepted, "jwks_uri")
    try:
        key = await _key_set(jwks_uri, accepted, timeout).key_for_token(id_token)
    except _MalformedToken:
        raise OAuthIDTokenError("ID token is malformed") from None
    except _UnknownKey:
        raise OAuthIDTokenError("ID token is signed with an unknown key") from None
    except _JWKSUnavailable as exc:
        raise OAuthIDTokenError(
            "the provider's signing keys cannot be fetched"
        ) from exc
    try:
        decoded = pyjwt.decode_complete(
            id_token,
            key=key,
            algorithms=list(accepted),
            audience=client_id,
            issuer=issuer,
            leeway=leeway,
            options={"require": list(_REQUIRED_CLAIMS)},
        )
    except (pyjwt.PyJWTError, TypeError, ValueError) as exc:
        raise OAuthIDTokenError(f"ID token failed validation: {exc}") from exc
    claims = decoded["payload"]
    azp = claims.get("azp")
    if azp is not None and azp != client_id:
        raise OAuthIDTokenError("ID token was issued to another client (azp)")
    if nonce is not None:
        presented = claims.get("nonce")
        if (
            not nonce
            or not isinstance(presented, str)
            or not hmac.compare_digest(presented.encode(), nonce.encode())
        ):
            raise OAuthIDTokenError("ID token nonce does not match")
    if access_token is not None:
        _check_at_hash(
            pyjwt, decoded["header"]["alg"], claims.get("at_hash"), access_token
        )
    return claims
