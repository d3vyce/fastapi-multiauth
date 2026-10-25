"""Performance benchmarks, run under CodSpeed instrumentation."""

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Coroutine, MutableMapping
from http.cookies import SimpleCookie
from typing import Any

import anyio
import httpx
import jwt as pyjwt
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request, Response, Security
from jwt.algorithms import ECAlgorithm

from fastapi_multiauth import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    HMACSignatureAuth,
    HTTPBearerAuth,
    HTTPDPoPAuth,
    IntrospectionValidator,
    JWTValidator,
    MultiAuth,
    OAuth2PasswordBearerAuth,
)

COOKIE_SECRET = "benchmark-cookie-secret-32-bytes-min!"
JWT_SECRET = "benchmark-jwt-secret-32-bytes-minimum"
TOKEN = "benchmark-token"
COOKIE_VALUE = "user-42"
WEBHOOK_SECRET = "benchmark-webhook-secret"
WEBHOOK_BODY = json.dumps(
    {"type": "invoice.paid", "data": {"items": [{"id": i} for i in range(64)]}}
).encode()
JWKS_URL = "https://idp.example.com/jwks"
INTROSPECTION_URL = "https://idp.example.com/introspect"


def drive(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run *coro* to completion without an event loop."""
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    coro.close()
    raise RuntimeError("coroutine suspended: benchmark it on a real event loop")


async def validate(credential: str) -> dict:
    """Validator doing nothing measurable: the library glue is what we time."""
    return {"user": credential}


def _app(auth: Any) -> FastAPI:
    app = FastAPI()

    @app.get("/me")
    async def me(user=Security(auth)):
        return user

    return app


def _scope(*headers: tuple[bytes, bytes], method: str = "GET") -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/me",
        "raw_path": b"/me",
        "query_string": b"",
        "root_path": "",
        "headers": list(headers),
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }


async def _receive() -> dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


async def _receive_webhook() -> dict[str, Any]:
    return {"type": "http.request", "body": WEBHOOK_BODY, "more_body": False}


class _Sink:
    """Records the response status so a benchmark cannot silently time a 401."""

    status = 0

    async def __call__(self, message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]


def _signed_cookie(auth: APIKeyCookieAuth, value: str, **kwargs: Any) -> str:
    """Mint a signed cookie through the public API and read it back."""
    response = Response()
    auth.set_cookie(response, value, **kwargs)
    return SimpleCookie(response.headers["set-cookie"])[auth.name].value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _ec_jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of an EC public JWK."""
    members = {member: jwk[member] for member in ("crv", "kty", "x", "y")}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def test_asgi_request_single_source(benchmark):
    """Full ASGI request through Security(source): FastAPI's dependency solving."""
    app = _app(HTTPBearerAuth(validate))
    scope = _scope((b"authorization", f"Bearer {TOKEN}".encode()))
    sink = _Sink()

    benchmark(lambda: drive(app(scope, _receive, sink)))

    assert sink.status == 200


def test_asgi_request_multiauth_three_sources(benchmark):
    """Same request with MultiAuth(3): how the per-source cost scales.

    The credential sits on the last source, so all three are tried.
    """
    cookie_auth = APIKeyCookieAuth("session", validate, secret_key=COOKIE_SECRET)
    app = _app(
        MultiAuth(
            HTTPBearerAuth(validate),
            APIKeyHeaderAuth("X-API-Key", validate),
            cookie_auth,
        )
    )
    scope = _scope(
        (b"cookie", f"session={_signed_cookie(cookie_auth, TOKEN)}".encode())
    )
    sink = _Sink()

    benchmark(lambda: drive(app(scope, _receive, sink)))

    assert sink.status == 200


def test_asgi_request_missing_credential(benchmark):
    """Full ASGI request with no credential: the 401 a logged-out client gets."""
    app = _app(HTTPBearerAuth(validate))
    scope = _scope()
    sink = _Sink()

    benchmark(lambda: drive(app(scope, _receive, sink)))

    assert sink.status == 401


def test_cookie_signed_verify(benchmark):
    """Signature and timestamp check on a signed cookie: itsdangerous."""
    auth = APIKeyCookieAuth("session", validate, secret_key=COOKIE_SECRET)
    cookie = _signed_cookie(auth, COOKIE_VALUE)

    identity = benchmark(lambda: drive(auth.authenticate(cookie)))

    assert identity == {"user": COOKIE_VALUE}


def test_cookie_dispatch_fresh_stepped_up(benchmark):
    """A signed cookie behind fresh() and stepped_up(): both guards read the cookie."""
    auth = APIKeyCookieAuth("session", validate, secret_key=COOKIE_SECRET)
    guarded = auth.fresh(300).stepped_up(["mfa"])
    cookie = _signed_cookie(auth, COOKIE_VALUE, acr="mfa")
    request = Request(_scope((b"cookie", f"session={cookie}".encode())))

    identity = benchmark(lambda: drive(guarded.dispatch(request, [])))

    assert identity == {"user": COOKIE_VALUE}


def test_jwt_hs256_validate(benchmark):
    """Symmetric JWT validation: PyJWT decode plus our claim checks."""
    validator = JWTValidator(secret=JWT_SECRET)
    token = pyjwt.encode(
        {"sub": "alice", "exp": int(time.time()) + 3600},
        JWT_SECRET,
        algorithm="HS256",
    )

    claims = benchmark(lambda: drive(validator(token)))

    assert claims["sub"] == "alice"


def test_jwt_es256_jwks_validate(benchmark):
    """Asymmetric JWT against a warm JWKS cache: the kid lookup plus PyJWT."""
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = {**ECAlgorithm.to_jwk(key.public_key(), as_dict=True), "kid": "k1"}
    token = pyjwt.encode(
        {"sub": "alice", "aud": "api", "exp": int(time.time()) + 3600},
        key,
        algorithm="ES256",
        headers={"kid": "k1"},
    )
    validator = JWTValidator(jwks_url=JWKS_URL, audience="api")
    with respx.mock:
        respx.get(JWKS_URL).respond(json={"keys": [{**jwk, "alg": "ES256"}]})
        anyio.run(validator, token)

    claims = benchmark(lambda: drive(validator(token)))

    assert claims["sub"] == "alice"


def test_introspection_cache_hit(benchmark):
    """Opaque token already introspected: the hash and LRU lookup every request pays."""

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "active": True,
                "sub": "alice",
                "aud": "api",
                "exp": int(time.time()) + 3600,
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(provider))
    validator = IntrospectionValidator(
        url=INTROSPECTION_URL,
        client_id="benchmark",
        client_secret="benchmark-secret",
        audience="api",
        cache_ttl=3600,
        client=client,
    )
    anyio.run(validator, TOKEN)
    anyio.run(client.aclose)

    claims = benchmark(lambda: drive(validator(TOKEN)))

    assert claims["sub"] == "alice"


def test_bearer_dispatch(benchmark):
    """Our own glue with no ASGI or dependency solving around it."""
    auth = HTTPBearerAuth(validate)
    request = Request(_scope((b"authorization", f"Bearer {TOKEN}".encode())))

    identity = benchmark(lambda: drive(auth.dispatch(request, [])))

    assert identity == {"user": TOKEN}


async def validate_with_request(
    credential: str, request: Request | None = None
) -> dict:
    """Request-aware twin of validate(): times the injection branch."""
    return {"user": credential}


def test_bearer_dispatch_with_request(benchmark):
    """The opt-in path: the validator declares 'request', so it is injected."""
    auth = HTTPBearerAuth(validate_with_request)
    request = Request(_scope((b"authorization", f"Bearer {TOKEN}".encode())))

    identity = benchmark(lambda: drive(auth.dispatch(request, [])))

    assert identity == {"user": TOKEN}


async def validate_scoped(credential: str, scopes: list[str]) -> dict:
    """Scope-aware twin of validate(): the guards only run on a scoped route."""
    return {"user": credential, "scopes": scopes}


def test_multiauth_dispatch_scoped(benchmark):
    """The scoped path: every route-scope guard, plus a published catalogue."""
    auth = MultiAuth(
        HTTPBearerAuth(validate_scoped, prefix="user_"),
        APIKeyHeaderAuth("X-API-Key", validate_scoped),
        OAuth2PasswordBearerAuth(
            validate_scoped, token_url="/token", scopes={"admin": "Everything"}
        ),
    )
    request = Request(_scope((b"authorization", f"Bearer {TOKEN}".encode())))

    identity = benchmark(lambda: drive(auth.dispatch(request, ["admin"])))

    assert identity == {"user": TOKEN, "scopes": ["admin"]}


def test_hmac_signature_dispatch(benchmark):
    """Signed webhook: header parsing, body read, and the HMAC over a 1 KB body.

    The request is rebuilt each round, since it caches the body it read.
    """
    auth = HMACSignatureAuth(
        WEBHOOK_SECRET, header="X-Signature", signature_key="v1", timestamp_key="t"
    )
    timestamp = str(int(time.time()))
    signature = hmac.new(
        WEBHOOK_SECRET.encode(), f"{timestamp}.".encode() + WEBHOOK_BODY, "sha256"
    ).hexdigest()
    scope = _scope(
        (b"x-signature", f"t={timestamp},v1={signature}".encode()), method="POST"
    )

    body = benchmark(lambda: drive(auth.dispatch(Request(scope, _receive_webhook), [])))

    assert body == WEBHOOK_BODY


def test_dpop_dispatch(benchmark):
    """DPoP-bound token: the ES256 proof, its URL and token hash, then the binding."""
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    access_token = pyjwt.encode(
        {
            "sub": "alice",
            "exp": int(time.time()) + 3600,
            "cnf": {"jkt": _ec_jwk_thumbprint(jwk)},
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    proof = pyjwt.encode(
        {
            "jti": "proof-1",
            "iat": int(time.time()),
            "htm": "GET",
            "htu": "http://testserver/me",
            "ath": _b64url(hashlib.sha256(access_token.encode()).digest()),
        },
        key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    auth = HTTPDPoPAuth(
        JWTValidator(secret=JWT_SECRET), replay_check=HTTPDPoPAuth.NO_REPLAY_CHECK
    )
    request = Request(
        _scope(
            (b"authorization", f"DPoP {access_token}".encode()),
            (b"dpop", proof.encode()),
        )
    )

    claims = benchmark(lambda: drive(auth.dispatch(request, [])))

    assert claims["sub"] == "alice"
