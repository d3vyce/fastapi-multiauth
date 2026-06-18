"""JWT validation built on PyJWT, for use as a ``HTTPBearerAuth`` validator."""

import logging
import time
from collections.abc import Sequence
from typing import Any, Callable

import anyio
from fastapi import HTTPException, status

from ._http import DEFAULT_TIMEOUT, _get_json, _require_https
from ._imports import require_extra
from .exceptions import ForbiddenError, UnauthorizedError
from .utils import ensure_async

logger = logging.getLogger("fastapi_multiauth.jwt")

_MIN_SECRET_BYTES = 32

# Inferred "alg" for JWKS entries that omit it (e.g. some Entra/ADFS setups).
_KTY_DEFAULT_ALG = {"RSA": "RS256"}
_CRV_DEFAULT_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


class _JWKSFetchError(Exception):
    """JWKS endpoint unreachable or returned an unusable document."""


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
        audience: Expected ``aud`` claim value(s). Unset → ``aud`` not checked.
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
    """

    def __init__(
        self,
        *,
        secret: str | None = None,
        jwks_url: str | None = None,
        algorithms: Sequence[str] | None = None,
        audience: str | Sequence[str] | None = None,
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
            if any(alg.upper().startswith("HS") for alg in self._algorithms):
                raise ValueError(
                    "symmetric (HS*) algorithms cannot be used with jwks_url: "
                    "a public JWKS key must never double as an HMAC secret "
                    "(key-confusion attack)"
                )
        self._secret = secret
        self._jwks_url = jwks_url
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
        self._jwks_cache_ttl = jwks_cache_ttl
        self._jwks_refresh_cooldown = jwks_refresh_cooldown
        self._timeout = timeout
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._attempted_at = float("-inf")
        self._refresh_lock = anyio.Lock()

    async def __call__(self, token: str, scopes: list[str] | None = None) -> Any:
        """Verify *token* and return the identity.

        Raises:
            UnauthorizedError: Invalid/expired signature or claims (401).
            ForbiddenError: Valid token missing route-required scopes (403).
            HTTPException: 503 when the JWKS cannot be fetched and no keys
                are cached — the token cannot be checked either way.
        """
        if self._secret is not None:
            key: Any = self._secret
        else:
            key = (await self._resolve_jwks_key(token)).key
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
        except self._jwt.InvalidTokenError:
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

    def _lookup_key(self, kid: str | None) -> Any | None:
        if kid is not None:
            return self._keys.get(kid)
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    def _cache_stale(self) -> bool:
        return (
            not self._keys or time.monotonic() - self._fetched_at > self._jwks_cache_ttl
        )

    async def _resolve_jwks_key(self, token: str) -> Any:
        """Resolve the verification key for *token* from the cached JWKS."""
        try:
            header = self._jwt.get_unverified_header(token)
        except self._jwt.InvalidTokenError:
            raise UnauthorizedError() from None
        kid = header.get("kid")
        if self._cache_stale():
            await self._refresh_jwks()
        key = self._lookup_key(kid)
        if key is None:
            # Unknown kid: the provider may have rotated keys. The refresh is
            # rate-limited so unauthenticated junk can't force fetch storms.
            await self._refresh_jwks(force=True)
            key = self._lookup_key(kid)
        if key is None:
            raise UnauthorizedError()
        return key

    @staticmethod
    def _unavailable() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication temporarily unavailable",
        )

    async def _refresh_jwks(self, force: bool = False) -> None:
        """Refetch the JWKS, coalescing concurrent and repeated refreshes.

        At most one attempt per ``jwks_refresh_cooldown``; a failed fetch falls
        back on cached keys, or surfaces as a 503 when the cache is empty.
        """
        async with self._refresh_lock:
            # Re-check after acquiring: another request may just have tried.
            if time.monotonic() - self._attempted_at < self._jwks_refresh_cooldown:
                if not self._keys:
                    raise self._unavailable()
                return
            if not force and not self._cache_stale():
                return
            self._attempted_at = time.monotonic()
            try:
                await self._fetch_jwks()
            except _JWKSFetchError as exc:
                logger.warning("JWKS refresh failed: %s", exc)
                if not self._keys:
                    raise self._unavailable() from exc
                # Stale fallback: keep validating with the cached keys.

    async def _fetch_jwks(self) -> None:
        document = await _get_json(
            self._jwks_url or "",
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
            try:
                key = self._jwt.PyJWK(entry)
            except (self._jwt.exceptions.PyJWTError, KeyError):
                # Unsupported or malformed entry: one broken key in the
                # provider's JWKS must not take down every login.
                continue
            keys[entry.get("kid") or ""] = key
        self._keys = keys
        self._fetched_at = time.monotonic()
