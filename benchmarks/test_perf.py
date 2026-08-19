"""Performance benchmarks, run under CodSpeed instrumentation."""

import time
from collections.abc import Coroutine, MutableMapping
from http.cookies import SimpleCookie
from typing import Any

import jwt as pyjwt
from fastapi import FastAPI, Request, Response, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    HTTPBearerAuth,
    JWTValidator,
    MultiAuth,
)

COOKIE_SECRET = "benchmark-cookie-secret-32-bytes-min!"
JWT_SECRET = "benchmark-jwt-secret-32-bytes-minimum"
TOKEN = "benchmark-token"
COOKIE_VALUE = "user-42"


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


def _scope(*headers: tuple[bytes, bytes]) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
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


class _Sink:
    """Records the response status so a benchmark cannot silently time a 401."""

    status = 0

    async def __call__(self, message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]


def _signed_cookie(auth: APIKeyCookieAuth, value: str) -> str:
    """Mint a signed cookie through the public API and read it back."""
    response = Response()
    auth.set_cookie(response, value)
    return SimpleCookie(response.headers["set-cookie"])[auth.name].value


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


def test_cookie_signed_verify(benchmark):
    """Signature and timestamp check on a signed cookie: itsdangerous."""
    auth = APIKeyCookieAuth("session", validate, secret_key=COOKIE_SECRET)
    cookie = _signed_cookie(auth, COOKIE_VALUE)

    identity = benchmark(lambda: drive(auth.authenticate(cookie)))

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


def test_bearer_dispatch(benchmark):
    """Our own glue with no ASGI or dependency solving around it."""
    auth = HTTPBearerAuth(validate)
    request = Request(_scope((b"authorization", f"Bearer {TOKEN}".encode())))

    identity = benchmark(lambda: drive(auth.dispatch(request, [])))

    assert identity == {"user": TOKEN}
