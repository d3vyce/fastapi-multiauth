"""DPoP authentication source: access tokens bound to a key the client holds (RFC 9449)."""

import enum
import hashlib
import hmac
import json
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from typing import Any, ClassVar
from urllib.parse import urlsplit

from fastapi.requests import HTTPConnection
from fastapi.security.http import HTTPBase

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource
from ..jwt import _import_pyjwt
from ..utils import (
    authorization_credential,
    b64url_encode,
    ensure_async,
    finite_number,
    normalize_origin,
    refusal,
    require_nonnegative_seconds,
    require_positive_seconds,
)

_DEFAULT_ALGORITHMS = ("ES256", "RS256", "PS256", "EdDSA")
_THUMBPRINT_MEMBERS = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_PROOF_CLAIMS = ["iat", "jti", "htm", "htu", "ath"]
_KEY_CACHE_SIZE = 1024


class NoReplayCheck(enum.Enum):
    """Type of `HTTPDPoPAuth.NO_REPLAY_CHECK`."""

    NONE = "none"

    def __repr__(self) -> str:
        return "HTTPDPoPAuth.NO_REPLAY_CHECK"


def _jwk_thumbprint(jwk: Mapping[str, Any]) -> str | None:
    """The RFC 7638 SHA-256 thumbprint of a public JWK, `None` if it lacks a member."""
    kty = jwk.get("kty")
    members = _THUMBPRINT_MEMBERS.get(kty) if isinstance(kty, str) else None
    if members is None or not all(isinstance(jwk.get(m), str) for m in members):
        return None
    canonical = json.dumps(
        {member: jwk[member] for member in members},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url_encode(hashlib.sha256(canonical.encode()).digest())


def _normalize_url(url: str) -> str | None:
    """`url` without query and fragment, scheme and host lowercased, default port dropped."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme, host = parts.scheme.lower(), parts.hostname
    if not scheme or not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}{parts.path or '/'}"


def _claims_jkt(identity: Any) -> Any:
    """The `cnf.jkt` of an identity that is the token's claims."""
    cnf = identity.get("cnf") if isinstance(identity, Mapping) else None
    return cnf.get("jkt") if isinstance(cnf, Mapping) else None


class HTTPDPoPAuth(ValidatedAuthSource):
    """Authentication source for DPoP-bound access tokens (RFC 9449).

    A stolen bearer token works for anyone; a DPoP-bound one only works
    with the private key it is bound to. The client sends
    `Authorization: DPoP <token>` and a `DPoP` header: a short JWT, signed
    with its key, naming the method and URL of this request. The source
    checks that proof, passes the token to the validator, then checks the
    token's `cnf.jkt` claim names the proof's key. Needs the `jwt` extra.

    Args:
        validator: Sync or async callable returning the identity, or raising
            to refuse, e.g. a `JWTValidator`.
        replay_check: Sync or async callable taking a proof's `jti` and the
            epoch time after which it can be forgotten, recording it, and
            returning `False` if it was already recorded. Make it atomic,
            e.g. Redis `SET NX EXAT`. Pass `NO_REPLAY_CHECK` to accept a
            proof replayed within `proof_max_age`.
        algorithms: Accepted proof algorithms; asymmetric only.
        proof_max_age: How old a proof may be, in seconds.
        leeway: Clock-skew tolerance in seconds for the proof's `iat`.
        public_origin: The scheme and host clients call, e.g.
            `"https://api.example.com"`, when a proxy changes them; the
            URL the request arrived on otherwise.
        jkt: Sync or async callable taking the identity and returning the
            thumbprint the token is bound to. Defaults to reading
            `identity["cnf"]["jkt"]`, right when the identity is the claims.
            A `None` result refuses the request.
        scheme_name: Name of the security scheme in OpenAPI, `DPoP` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.

    Raises:
        ValueError: On an invalid configuration, such as no `replay_check`,
            a symmetric or unknown algorithm, or a `public_origin` with a path.
    """

    NO_REPLAY_CHECK: ClassVar[NoReplayCheck] = NoReplayCheck.NONE
    """Explicit `replay_check` opt-out."""

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        replay_check: Callable[[str, float], Any] | NoReplayCheck | None = None,
        algorithms: Sequence[str] = _DEFAULT_ALGORITHMS,
        proof_max_age: float = 60.0,
        leeway: float = 5.0,
        public_origin: str | None = None,
        jkt: Callable[..., Any] | None = None,
        scheme_name: str | None = None,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._jwt = _import_pyjwt()
        if replay_check is None:
            raise ValueError(
                "replay_check is required: without it, a proof captured in "
                "transit can be replayed until it is proof_max_age old. Pass "
                "replay_check=HTTPDPoPAuth.NO_REPLAY_CHECK to accept that"
            )
        if isinstance(algorithms, str):
            raise TypeError("algorithms must be a sequence of strings, not a string")
        supported = self._jwt.algorithms.get_default_algorithms()
        self._algorithms = tuple(algorithms)
        if not self._algorithms:
            raise ValueError("algorithms must list at least one algorithm")
        for alg in self._algorithms:
            if alg not in supported or alg.upper().startswith("HS") or alg == "none":
                raise ValueError(
                    f"{alg!r} cannot sign a DPoP proof: use asymmetric "
                    "algorithms PyJWT supports, such as ES256"
                )
        require_positive_seconds(proof_max_age, "proof_max_age")
        require_nonnegative_seconds(leeway, "leeway")
        self._replay_check = (
            None if replay_check is NoReplayCheck.NONE else ensure_async(replay_check)
        )
        self._proof_max_age = proof_max_age
        self._leeway = leeway
        self._algs = " ".join(self._algorithms)
        self._origin = (
            normalize_origin(public_origin, "public_origin") if public_origin else None
        )
        self._jkt = ensure_async(jkt) if jkt else None
        self._keys: OrderedDict[tuple[str, str], Any] = OrderedDict()
        super().__init__(
            validator,
            HTTPBase(
                scheme="DPoP",
                scheme_name=scheme_name or "DPoP",
                description=description,
                auto_error=False,
            ),
            **kwargs,
        )

    def www_authenticate(self) -> str:
        """Return the `DPoP` challenge listing the accepted algorithms."""
        return f'DPoP algs="{self._algs}"'

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the token of an `Authorization: DPoP` header, `None` when absent."""
        return authorization_credential(request, "dpop")

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Check the proof, validate the token, then check the token is bound to the proof's key.

        A proof's `jti` is recorded last, so a refused request never uses it up.

        Raises:
            UnauthorizedError: With `error="invalid_dpop_proof"` when the
                proof is missing or invalid, names another key than the
                token, or was already used.
        """
        thumbprint, jti, iat = self._verify_proof(credential, request)
        identity = await self._call_validator(
            credential, scopes=scopes, request=request
        )
        bound = await self._jkt(identity) if self._jkt else _claims_jkt(identity)
        if not isinstance(bound, str) or not hmac.compare_digest(
            bound.encode(), thumbprint.encode()
        ):
            raise self._proof_error("dpop_key_mismatch")
        if self._replay_check is not None and not await self._replay_check(
            jti, iat + self._proof_max_age + self._leeway
        ):
            raise self._proof_error("dpop_replay")
        return identity

    def _proof_error(self, reason: str) -> UnauthorizedError:
        """The 401 for a refused proof, with the `invalid_dpop_proof` challenge."""
        challenge = f'DPoP error="invalid_dpop_proof", algs="{self._algs}"'
        return refusal(
            UnauthorizedError(headers={"WWW-Authenticate": challenge}), reason
        )

    def _request_url(self, request: HTTPConnection) -> str | None:
        """The URL the client called, as `htu` must name it."""
        if self._origin is not None:
            return self._origin + (request.url.path or "/")
        return _normalize_url(str(request.url))

    def _proof_key(self, jwk: dict[str, Any], alg: str, thumbprint: str) -> Any:
        """The parsed public key of a proof, cached by its thumbprint."""
        cache_key = (thumbprint, alg)
        key = self._keys.get(cache_key)
        if key is None:
            key = self._jwt.PyJWK(jwk, algorithm=alg)
            self._keys[cache_key] = key
            if len(self._keys) > _KEY_CACHE_SIZE:
                self._keys.popitem(last=False)
        else:
            self._keys.move_to_end(cache_key)
        return key

    def _verify_proof(
        self, token: str, request: HTTPConnection | None
    ) -> tuple[str, str, float]:
        """Check the request's proof (RFC 9449 §4.3) for `token`.

        Returns:
            The proof key's thumbprint, the proof's `jti` and its `iat`.
        """
        if request is None:
            raise self._proof_error("invalid_dpop_proof")
        proofs = request.headers.getlist("dpop")
        if len(proofs) != 1:
            raise self._proof_error("invalid_dpop_proof")
        try:
            header = self._jwt.get_unverified_header(proofs[0])
        except self._jwt.InvalidTokenError:
            raise self._proof_error("invalid_dpop_proof") from None
        jwk, alg, typ = header.get("jwk"), header.get("alg"), header.get("typ")
        if (
            not isinstance(typ, str)
            or typ.lower() != "dpop+jwt"
            or alg not in self._algorithms
            or not isinstance(jwk, dict)
            or "d" in jwk
        ):
            raise self._proof_error("invalid_dpop_proof")
        thumbprint = _jwk_thumbprint(jwk)
        if thumbprint is None:
            raise self._proof_error("invalid_dpop_proof")
        try:
            claims = self._jwt.decode(
                proofs[0],
                key=self._proof_key(jwk, alg, thumbprint),
                algorithms=[alg],
                leeway=self._leeway,
                options={
                    "require": _PROOF_CLAIMS,
                    "verify_aud": False,
                    "verify_iat": False,
                },
            )
        except (self._jwt.exceptions.PyJWTError, TypeError, ValueError):
            raise self._proof_error("invalid_dpop_proof") from None
        now = time.time()
        iat = finite_number(claims["iat"])
        if iat is None or not (
            now - self._proof_max_age - self._leeway <= iat <= now + self._leeway
        ):
            raise self._proof_error("invalid_dpop_proof")
        jti = claims["jti"]
        if not isinstance(jti, str) or not jti:
            raise self._proof_error("invalid_dpop_proof")
        htu, expected_url = claims["htu"], self._request_url(request)
        if (
            claims["htm"] != request.scope.get("method", "GET")
            or not isinstance(htu, str)
            or expected_url is None
            or _normalize_url(htu) != expected_url
        ):
            raise self._proof_error("invalid_dpop_proof")
        ath = claims["ath"]
        expected_ath = b64url_encode(hashlib.sha256(token.encode()).digest())
        if not isinstance(ath, str) or not hmac.compare_digest(
            ath.encode(), expected_ath.encode()
        ):
            raise self._proof_error("invalid_dpop_proof")
        return thumbprint, jti, iat
