"""Token introspection (RFC 7662), for use as a `HTTPBearerAuth` validator."""

import base64
import copy
import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any, ClassVar
from urllib.parse import quote_plus

import httpx

from ._http import DEFAULT_TIMEOUT, _request_json, _require_https
from .exceptions import UnauthorizedError
from .jwt import AnyAudience
from .utils import (
    ensure_async,
    finite_number,
    hash_token,
    refusal,
    require_nonnegative_seconds,
    require_scopes,
    service_unavailable,
)

logger = logging.getLogger(__name__)


class _IntrospectionUnavailable(Exception):
    """The introspection endpoint is unreachable or answered unusably."""


class _Answer:
    """A checked introspection answer, handed to each request as its own copy."""

    __slots__ = ("claims", "nested")

    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims
        self.nested = tuple(
            name for name, value in claims.items() if isinstance(value, (dict, list))
        )

    def copy(self) -> dict[str, Any]:
        """The claims, copied deeply only where they hold a container."""
        copied = dict(self.claims)
        for name in self.nested:
            copied[name] = copy.deepcopy(self.claims[name])
        return copied


def _basic_authorization(client_id: str, client_secret: str) -> str:
    """`client_secret_basic`: both halves form-encoded before base64 (RFC 6749 §2.3.1)."""
    pair = f"{quote_plus(client_id, safe='')}:{quote_plus(client_secret, safe='')}"
    return f"Basic {base64.b64encode(pair.encode()).decode()}"


class IntrospectionValidator:
    """Validator asking the provider whether an opaque token is active.

    For providers that issue opaque access tokens instead of JWTs. Each new
    token costs one request to the introspection endpoint; active answers
    are cached, so a revoked token keeps working for up to `cache_ttl`.
    If the endpoint is down, the request is answered with a 503.

    Args:
        url: HTTPS URL of the provider's introspection endpoint.
        client_id: Your client id at the provider.
        client_secret: Your client secret, sent with HTTP Basic.
        audience: Expected `aud`. Required, since the provider answers for
            every application's tokens; a response without `aud` is refused.
            Pass `ANY_AUDIENCE` to skip the check on purpose.
        issuer: Expected `iss`; not checked when unset.
        leeway: Clock-skew tolerance in seconds for `exp` and `nbf`.
        scopes_claim: Field holding granted scopes: a space-separated string
            (`scope`) or a list. A missing route scope is a 403.
        claims_to_identity: Sync or async callable turning the introspection
            response into your identity; the response is returned otherwise.
        cache_ttl: How long an active answer is cached, in seconds, never
            past the token's `exp`. `0` asks the provider on every request.
        cache_size: How many answers are cached at most.
        timeout: Timeout of the introspection request, in seconds, when no
            `client` is given.
        client: An `httpx.AsyncClient` to send the requests with, reusing
            its connections and its own timeout. Without it, each request
            opens a new client: pass one when tokens change often.

    Raises:
        ValueError: On an invalid configuration, such as a plain-HTTP `url`,
            a missing `audience`, or a negative `leeway` or `cache_ttl`.
    """

    ANY_AUDIENCE: ClassVar[AnyAudience] = AnyAudience.ANY
    """Explicit `audience` opt-out: accept a token whatever its `aud`."""

    def __init__(
        self,
        *,
        url: str,
        client_id: str,
        client_secret: str,
        audience: str | Sequence[str] | AnyAudience | None = None,
        issuer: str | None = None,
        leeway: float = 0.0,
        scopes_claim: str = "scope",
        claims_to_identity: Callable[[dict[str, Any]], Any] | None = None,
        cache_ttl: float = 60.0,
        cache_size: int = 10_000,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        _require_https(url, "url")
        if not audience:
            raise ValueError(
                "audience is required: the provider introspects the tokens of "
                "its other clients too. Pass "
                "audience=IntrospectionValidator.ANY_AUDIENCE to skip the check"
            )
        require_nonnegative_seconds(leeway, "leeway")
        require_nonnegative_seconds(cache_ttl, "cache_ttl")
        if cache_size < 1:
            raise ValueError("cache_size must be at least 1")
        self._url = url
        self._headers = {
            "Authorization": _basic_authorization(client_id, client_secret),
            "Accept": "application/json",
        }
        if audience is AnyAudience.ANY:
            self._audiences: frozenset[str] | None = None
        elif isinstance(audience, str):
            self._audiences = frozenset({audience})
        else:
            self._audiences = frozenset(audience)
        self._issuer = issuer
        self._leeway = leeway
        self._scopes_claim = scopes_claim
        self._claims_to_identity = (
            ensure_async(claims_to_identity) if claims_to_identity else None
        )
        self._cache_ttl = cache_ttl
        self._cache_size = cache_size
        self._cache: OrderedDict[str, tuple[float, _Answer]] = OrderedDict()
        self._timeout = timeout
        self._client = client

    async def __call__(self, token: str, scopes: list[str] | None = None) -> Any:
        """Introspect a token and return the identity.

        Raises:
            UnauthorizedError: If the token is inactive, or a claim is invalid (401).
            ForbiddenError: If the token lacks a scope the route requires (403).
            HTTPException: 503 if the introspection endpoint cannot be used.
        """
        key = hash_token(token)
        answer = self._cached(key)
        if answer is None:
            claims = await self._introspect(token)
            self._check_claims(claims)
            answer = _Answer(claims)
            self._store(key, answer)
        claims = answer.copy()
        if scopes:
            require_scopes(claims, self._scopes_claim, scopes)
        if self._claims_to_identity is not None:
            return await self._claims_to_identity(claims)
        return claims

    async def _introspect(self, token: str) -> dict[str, Any]:
        """The provider's answer for an active token; refuse an inactive one."""
        try:
            response = await _request_json(
                "POST",
                self._url,
                timeout=self._timeout,
                error_cls=_IntrospectionUnavailable,
                description="introspection response",
                headers=self._headers,
                data={"token": token, "token_type_hint": "access_token"},
                client=self._client,
            )
            if not isinstance(response, dict):
                raise _IntrospectionUnavailable("response is not a JSON object")
        except _IntrospectionUnavailable as exc:
            cause = exc.__cause__
            code = (
                cause.response.status_code
                if isinstance(cause, httpx.HTTPStatusError)
                else None
            )
            if code in (401, 403):
                logger.error(
                    "the introspection endpoint refused the client credentials "
                    "(HTTP %s): check client_id and client_secret",
                    code,
                )
            logger.warning("token introspection failed: %s", exc)
            raise service_unavailable("introspection_unavailable") from exc
        if response.get("active") is not True:
            raise refusal(UnauthorizedError(), "inactive")
        return response

    def _check_claims(self, claims: dict[str, Any]) -> None:
        """Check `exp`, `nbf`, `aud` and `iss` locally, as for a JWT."""
        now = time.time()
        if "exp" in claims:
            exp = finite_number(claims["exp"])
            if exp is None:
                raise refusal(UnauthorizedError(), "invalid_token")
            if exp <= now - self._leeway:
                raise refusal(UnauthorizedError(), "expired")
        if "nbf" in claims:
            nbf = finite_number(claims["nbf"])
            if nbf is None:
                raise refusal(UnauthorizedError(), "invalid_token")
            if nbf > now + self._leeway:
                raise refusal(UnauthorizedError(), "not_yet_valid")
        if self._audiences is not None:
            aud = claims.get("aud")
            granted = [aud] if isinstance(aud, str) else aud
            if not isinstance(granted, list) or self._audiences.isdisjoint(
                item for item in granted if isinstance(item, str)
            ):
                raise refusal(UnauthorizedError(), "invalid_audience")
        if self._issuer is not None and claims.get("iss") != self._issuer:
            raise refusal(UnauthorizedError(), "invalid_issuer")

    def _cached(self, key: str) -> _Answer | None:
        """A cached answer still within its lifetime, `None` otherwise."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires_at, answer = entry
        if time.monotonic() >= expires_at:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return answer

    def _store(self, key: str, answer: _Answer) -> None:
        """Cache an active answer for `cache_ttl`, never past the token's `exp`."""
        ttl = self._cache_ttl
        exp = finite_number(answer.claims.get("exp"))
        if exp is not None:
            ttl = min(ttl, exp - time.time())
        if ttl <= 0:
            return
        self._cache[key] = (time.monotonic() + ttl, answer)
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
