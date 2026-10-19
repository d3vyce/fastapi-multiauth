"""JWT validation built on PyJWT, for use as a ``HTTPBearerAuth`` validator."""

import enum
import logging
import time
from collections.abc import Callable, Sequence
from typing import Any, ClassVar

import anyio
from fastapi import HTTPException, status

from ._http import DEFAULT_TIMEOUT, _get_json, _require_https
from ._imports import require_extra
from .exceptions import ForbiddenError, UnauthorizedError
from .utils import ensure_async

logger = logging.getLogger("fastapi_multiauth.jwt")

_MIN_SECRET_BYTES = 32


class AnyAudience(enum.Enum):
    """Type of :attr:`JWTValidator.ANY_AUDIENCE`, the explicit ``aud`` opt-out."""

    ANY = "any"

    def __repr__(self) -> str:
        return "JWTValidator.ANY_AUDIENCE"


# Inferred "alg" for JWKS entries that omit it (e.g. some Entra/ADFS setups).
_KTY_DEFAULT_ALG = {"RSA": "RS256"}
_CRV_DEFAULT_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


class _JWKSFetchError(Exception):
    """JWKS endpoint unreachable or returned an unusable document."""


class _JWKSUnavailable(Exception):
    """No signing key is cached and the JWKS cannot be fetched."""


class _MalformedToken(Exception):
    """The token header does not parse."""


class _UnknownKey(Exception):
    """The JWKS does not hold the key that signed the token."""


def _reject_symmetric(algorithms: Sequence[str], url_param: str) -> None:
    """Refuse ``HS*`` algorithms against a public JWKS (key confusion)."""
    if any(alg.upper().startswith("HS") for alg in algorithms):
        raise ValueError(
            f"symmetric (HS*) algorithms cannot be used with {url_param}: "
            "a public JWKS key must never double as an HMAC secret "
            "(key-confusion attack)"
        )


def _import_pyjwt() -> Any:
    try:
        import jwt as pyjwt
    except ImportError:  # pragma: no cover
        require_extra("pyjwt", "jwt")
    return pyjwt


def _default_alg(entry: dict[str, Any]) -> str | None:
    """Best-effort default algorithm for a JWKS entry without ``alg``."""
    kty = entry.get("kty")
    if kty == "EC":
        return _CRV_DEFAULT_ALG.get(entry.get("crv", ""))
    return _KTY_DEFAULT_ALG.get(kty or "")


class _JWKSKeySet:
    """The signing keys of one JWKS document, cached and refreshed on rotation.

    Args:
        pyjwt: The imported ``jwt`` module.
        url: HTTPS URL of the JWKS document.
        algorithms: Accepted signature algorithms; entries for any other
            algorithm are never loaded.
        cache_ttl: Cache lifetime in seconds.
        refresh_cooldown: Minimum interval in seconds between fetch attempts.
        timeout: Timeout in seconds for the JWKS request.
    """

    def __init__(
        self,
        pyjwt: Any,
        url: str,
        algorithms: Sequence[str],
        *,
        cache_ttl: float = 3600.0,
        refresh_cooldown: float = 30.0,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._jwt = pyjwt
        self._url = url
        self._algorithms = list(algorithms)
        self._cache_ttl = cache_ttl
        self._refresh_cooldown = refresh_cooldown
        self._timeout = timeout
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._attempted_at = float("-inf")
        self._refresh_lock = anyio.Lock()

    async def key_for_token(self, token: str) -> Any:
        """The key that signed *token*, found by its header ``kid``.

        Raises:
            _MalformedToken: The token header does not parse.
            _UnknownKey: The JWKS does not hold the key, even after a refresh.
            _JWKSUnavailable: Nothing is cached and the JWKS cannot be fetched.
        """
        try:
            kid = self._jwt.get_unverified_header(token).get("kid")
        except self._jwt.InvalidTokenError:
            raise _MalformedToken() from None
        if self._cache_stale():
            await self._refresh()
        key = self._lookup_key(kid)
        if key is None:
            # Unknown kid: the provider may have rotated keys. The refresh is
            # rate-limited so unauthenticated junk can't force fetch storms.
            await self._refresh(force=True)
            key = self._lookup_key(kid)
        if key is None:
            raise _UnknownKey()
        return key

    def _lookup_key(self, kid: str | None) -> Any | None:
        if kid is not None:
            return self._keys.get(kid)
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    def _cache_stale(self) -> bool:
        return not self._keys or time.monotonic() - self._fetched_at > self._cache_ttl

    async def _refresh(self, force: bool = False) -> None:
        """Refetch the JWKS, coalescing concurrent and repeated refreshes.

        At most one attempt per ``refresh_cooldown``; a failed fetch falls
        back on cached keys, or raises when the cache is empty.
        """
        async with self._refresh_lock:
            # Re-check after acquiring: another request may just have tried.
            if time.monotonic() - self._attempted_at < self._refresh_cooldown:
                if not self._keys:
                    raise _JWKSUnavailable()
                return
            if not force and not self._cache_stale():
                return
            self._attempted_at = time.monotonic()
            try:
                await self._fetch()
            except _JWKSFetchError as exc:
                logger.warning("JWKS refresh failed: %s", exc)
                if not self._keys:
                    raise _JWKSUnavailable() from exc
                # Stale fallback: keep validating with the cached keys.

    async def _fetch(self) -> None:
        document = await _get_json(
            self._url,
            timeout=self._timeout,
            error_cls=_JWKSFetchError,
            description="JWKS document",
        )
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise _JWKSFetchError("JWKS document has no 'keys' list")
        keys: dict[str, Any] = {}
        for entry in document["keys"]:
            if not isinstance(entry, dict):
                continue
            if entry.get("use") not in (None, "sig"):
                continue
            if "alg" not in entry:
                alg = _default_alg(entry)
                if alg is None:
                    continue
                entry = {**entry, "alg": alg}
            if entry["alg"] not in self._algorithms:
                continue
            try:
                key = self._jwt.PyJWK(entry)
            except Exception as exc:  # noqa: BLE001
                # Unsupported or malformed entry: one broken key in the
                # provider's JWKS must not take down every login.
                logger.warning(
                    "skipping unloadable JWKS entry %r: %s",
                    entry.get("kid"),
                    type(exc).__name__,
                )
                continue
            keys[entry.get("kid") or ""] = key
        if not keys:
            raise _JWKSFetchError(
                f"JWKS document has no usable signing key "
                f"({len(document['keys'])} entries)"
            )
        self._keys = keys
        self._fetched_at = time.monotonic()


class JWTValidator:
    """Validate JWTs — plug directly into :class:`~fastapi_multiauth.HTTPBearerAuth`.

    Requires the ``jwt`` extra. Configure exactly one of ``secret`` (symmetric
    ``HS*``) or ``jwks_url`` (asymmetric, against the provider's JWKS).

    Args:
        secret: Symmetric key for ``HS*`` validation (at least 32 bytes).
        jwks_url: HTTPS URL of the provider's JWKS document.
        algorithms: Accepted signature algorithms. Defaults to ``["HS256"]``
            in secret mode and ``["RS256", "ES256"]`` in JWKS mode. Symmetric
            algorithms are rejected in JWKS mode (key-confusion risk).
        audience: Expected ``aud`` claim value(s). Required in JWKS mode,
            where the provider's keys also sign tokens for its other clients
            and tenants; pass :attr:`ANY_AUDIENCE` to skip the check on
            purpose. Unset in secret mode → ``aud`` not checked.
        issuer: Expected ``iss`` claim value. Unset → ``iss`` not checked.
        leeway: Clock-skew tolerance in seconds for time-based claims.
        required_claims: Claims that must be present (default ``("exp",)``).
        scopes_claim: Claim holding granted scopes — a space-separated string
            (``scope``) or a list (``scp``, ``roles``). A valid token missing
            a route-declared scope raises a 403.
        claims_to_identity: Optional sync or async hook mapping verified claims
            to a domain object. Defaults to returning the claims.
        jwks_cache_ttl: JWKS cache lifetime in seconds (default 1 h).
        jwks_refresh_cooldown: Minimum interval in seconds between JWKS fetch
            attempts (default 30 s).
        timeout: Timeout in seconds for the JWKS request.

    Raises:
        ValueError: On an invalid configuration, including a JWKS mode
            validator without ``audience``.
    """

    ANY_AUDIENCE: ClassVar[AnyAudience] = AnyAudience.ANY
    """Explicit ``audience`` opt-out: accept a token whatever its ``aud``."""

    def __init__(
        self,
        *,
        secret: str | None = None,
        jwks_url: str | None = None,
        algorithms: Sequence[str] | None = None,
        audience: str | Sequence[str] | AnyAudience | None = None,
        issuer: str | None = None,
        leeway: float = 0.0,
        required_claims: Sequence[str] = ("exp",),
        scopes_claim: str = "scope",
        claims_to_identity: Callable[[dict[str, Any]], Any] | None = None,
        jwks_cache_ttl: float = 3600.0,
        jwks_refresh_cooldown: float = 30.0,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._jwt = _import_pyjwt()
        if (secret is None) == (jwks_url is None):
            raise ValueError("provide exactly one of 'secret' or 'jwks_url'")
        if secret is not None:
            if len(secret.encode()) < _MIN_SECRET_BYTES:
                raise ValueError(
                    f"secret must be at least {_MIN_SECRET_BYTES} bytes of "
                    "high-entropy material (e.g. secrets.token_urlsafe(32))"
                )
            self._algorithms = list(algorithms or ["HS256"])
        else:
            _require_https(jwks_url or "", "jwks_url")
            self._algorithms = list(algorithms or ["RS256", "ES256"])
            _reject_symmetric(self._algorithms, "jwks_url")
            if not audience:
                raise ValueError(
                    "audience is required with jwks_url: the provider's keys "
                    "also sign tokens for its other clients and tenants. Pass "
                    "audience=JWTValidator.ANY_AUDIENCE to skip the check"
                )
        if audience is AnyAudience.ANY:
            audience = None
        self._secret = secret
        self._audience = audience
        self._issuer = issuer
        self._leeway = leeway
        self._decode_options = {
            "require": list(required_claims),
            "verify_aud": audience is not None,
            "verify_iss": issuer is not None,
        }
        self._scopes_claim = scopes_claim
        self._claims_to_identity = (
            ensure_async(claims_to_identity) if claims_to_identity else None
        )
        self._key_set = (
            _JWKSKeySet(
                self._jwt,
                jwks_url,
                self._algorithms,
                cache_ttl=jwks_cache_ttl,
                refresh_cooldown=jwks_refresh_cooldown,
                timeout=timeout,
            )
            if jwks_url is not None
            else None
        )

    async def __call__(self, token: str, scopes: list[str] | None = None) -> Any:
        """Verify *token* and return the identity.

        Raises:
            UnauthorizedError: Invalid/expired signature or claims (401).
            ForbiddenError: Valid token missing route-required scopes (403).
            HTTPException: 503 when the JWKS cannot be fetched and no keys
                are cached — the token cannot be checked either way.
        """
        if self._key_set is None:
            key: Any = self._secret
        else:
            key = await self._resolve_jwks_key(self._key_set, token)
        try:
            claims = self._jwt.decode(
                token,
                key=key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options=self._decode_options,
            )
        except (self._jwt.exceptions.PyJWTError, TypeError, ValueError):
            raise UnauthorizedError() from None
        if scopes:
            missing = set(scopes) - self._granted_scopes(claims)
            if missing:
                raise ForbiddenError("Insufficient scope")
        if self._claims_to_identity is not None:
            return await self._claims_to_identity(claims)
        return claims

    def _granted_scopes(self, claims: dict[str, Any]) -> set[str]:
        """Read the configured scopes claim: space-separated string or list."""
        value = claims.get(self._scopes_claim)
        if isinstance(value, str):
            return set(value.split())
        if isinstance(value, (list, tuple)):
            return {str(item) for item in value}
        return set()

    @staticmethod
    async def _resolve_jwks_key(key_set: _JWKSKeySet, token: str) -> Any:
        """Resolve the verification key for *token* from the cached JWKS."""
        try:
            return await key_set.key_for_token(token)
        except (_MalformedToken, _UnknownKey):
            raise UnauthorizedError() from None
        except _JWKSUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication temporarily unavailable",
            ) from exc
