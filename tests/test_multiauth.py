"""Tests for fastapi_multiauth."""

import base64
import hashlib
import hmac
import json
import logging
import math
import secrets
import string
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
import pyotp
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    Security,
    WebSocket,
    routing,
)
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from fastapi.security.base import SecurityBase
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
from pydantic import BaseModel
from starlette.testclient import WebSocketDenialResponse

from fastapi_multiauth import (
    APIKeyCookieAuth,
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    AuthenticationMethodReference,
    AuthSource,
    ForbiddenError,
    HMACSignatureAuth,
    HTTPBasicAuth,
    HTTPBearerAuth,
    HTTPDPoPAuth,
    InsufficientAuthenticationError,
    IntrospectionValidator,
    JWTValidator,
    MultiAuth,
    OAuth2AuthorizationCodeBearerAuth,
    OAuth2PasswordBearerAuth,
    OpenIdConnectAuth,
    SchemeRequirement,
    StaleCredentialError,
    auth_surface,
    checksum_token_generator,
    hash_token,
    totp_generate_secret,
    totp_provisioning_uri,
    totp_verify,
    verify_token_checksum,
    verify_token_hash,
)
from fastapi_multiauth._http import DEFAULT_TIMEOUT
from fastapi_multiauth.abc import _DocOnlyScheme, _override_accepts_request
from fastapi_multiauth.exceptions import UnauthorizedError
from fastapi_multiauth.oauth import (
    OAuthDiscoveryError,
    OAuthError,
    OAuthExchangeError,
    OAuthIDTokenError,
    OAuthStateError,
    OAuthUserinfoError,
    OIDCEndpoints,
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_encode_state,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_generate_nonce,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
    oauth_resolve_provider_urls,
    oauth_validate_id_token,
)
from fastapi_multiauth.oauth.id_token import _key_set as _id_key_set
from fastapi_multiauth.sources.dpop import _jwk_thumbprint
from fastapi_multiauth.utils import step_up_challenge


def _app(*routes_setup_fns):
    """Build a minimal FastAPI test app."""
    app = FastAPI()
    for fn in routes_setup_fns:
        fn(app)
    return app


VALID_TOKEN = "secret"
VALID_COOKIE = "session123"
COOKIE_SECRET = "unit-test-secret-key-32-bytes-minimum!"


def _signed_cookie_auth(**kwargs) -> APIKeyCookieAuth:
    """A signed "session" cookie source over plain HTTP, validated by cookie_validator."""
    return APIKeyCookieAuth(
        "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False, **kwargs
    )


def _cookie_value(response: Response) -> str:
    """The value of the cookie *response* sets."""
    return response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]


def _stock_signer(*keys: str, salt: str = "session") -> TimestampSigner:
    """A stock itsdangerous signer, salted like the cookie named *salt*."""
    return TimestampSigner(
        list(keys),
        salt=f"fastapi-multiauth.cookie.{salt}",
        digest_method=hashlib.sha256,
    )


def _client(auth) -> TestClient:
    """App exposing a single /me route guarded by *auth*."""

    def setup(app: FastAPI):
        @app.get("/me")
        async def me(user=Security(auth)):
            return user

    return TestClient(_app(setup))


def _request(*, query_string: bytes = b"", **headers: str) -> Request:
    """Bare HTTP request; header names are given in snake_case."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": query_string,
            "headers": [
                (k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()
            ],
        }
    )


async def simple_validator(credential: str) -> dict:
    if credential != VALID_TOKEN:
        raise UnauthorizedError()
    return {"user": "alice"}


async def role_validator(credential: str, *, role: str) -> dict:
    if credential != VALID_TOKEN:
        raise UnauthorizedError()
    return {"user": "alice", "role": role}


async def cookie_validator(value: str) -> dict:
    if value != VALID_COOKIE:
        raise UnauthorizedError()
    return {"session": value}


class TestBearerTokenAuth:
    def test_authenticates_the_bearer_token(self):
        client = _client(HTTPBearerAuth(simple_validator))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}
        assert client.get("/me").status_code == 401
        assert (
            client.get("/me", headers={"Authorization": "Bearer wrong"}).status_code
            == 401
        )

        client = _client(HTTPBearerAuth(role_validator, role="admin"))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_prefix_matching_passes_full_token(self):
        """Token with matching prefix: full token (with prefix) is passed to validator."""
        received: list[str] = []

        async def capturing_validator(credential: str) -> dict:
            received.append(credential)
            return {"user": "alice"}

        client = _client(HTTPBearerAuth(capturing_validator, prefix="user_"))
        response = client.get("/me", headers={"Authorization": "Bearer user_abc123"})
        assert response.status_code == 200
        # Prefix is kept — validator receives the full token as stored in DB
        assert received == ["user_abc123"]

        response = client.get("/me", headers={"Authorization": "Bearer org_abc123"})
        assert response.status_code == 401
        assert received == ["user_abc123"]

    @pytest.mark.anyio
    async def test_extract(self):
        bearer = HTTPBearerAuth(simple_validator)
        assert await bearer.extract(_request()) is None
        assert await bearer.extract(_request(authorization="Bearer ")) is None
        assert (
            await bearer.extract(_request(authorization="Bearer mytoken")) == "mytoken"
        )

        prefixed = HTTPBearerAuth(simple_validator, prefix="user_")
        assert (
            await prefixed.extract(_request(authorization="Bearer user_abc"))
            == "user_abc"
        )
        assert await prefixed.extract(_request(authorization="Bearer org_abc")) is None

    def test_generate_token(self):
        """A generated token (with prefix) is accepted by the same auth source."""
        token = HTTPBearerAuth(simple_validator).generate_token()
        assert isinstance(token, str)
        assert len(token) > 0

        stored: list[str] = []

        async def storing_validator(credential: str) -> dict:
            stored.append(credential)
            return {"token": credential}

        bearer = HTTPBearerAuth(storing_validator, prefix="user_")
        token = bearer.generate_token()
        assert token.startswith("user_")
        assert bearer.generate_token() != token

        response = _client(bearer).get(
            "/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert stored == [token]

    def test_custom_generator(self):
        seen: list[int] = []

        def generator(nbytes: int) -> str:
            seen.append(nbytes)
            return secrets.token_hex(nbytes)

        bearer = HTTPBearerAuth(simple_validator, token_generator=generator)
        bearer.generate_token()
        bearer.generate_token(8)
        assert seen == [32, 8]

        bearer = HTTPBearerAuth(
            simple_validator, prefix="user_", token_generator=lambda _n: "fixed-body"
        )
        assert bearer.generate_token() == "user_fixed-body"
        assert bearer.optional().generate_token() == "user_fixed-body"
        assert bearer.require(tenant="acme").generate_token() == "user_fixed-body"

    def test_custom_generator_whitespace(self):
        """Only the edges matter: `partition(" ")` keeps everything after the scheme."""
        for returned, match in [
            ("", "must return a non-empty string"),
            (" leading", "leading or trailing whitespace"),
            ("trailing ", "leading or trailing whitespace"),
        ]:
            bearer = HTTPBearerAuth(
                simple_validator, token_generator=lambda _n, returned=returned: returned
            )
            with pytest.raises(ValueError, match=match):
                bearer.generate_token()

        bearer = HTTPBearerAuth(
            simple_validator, prefix="user_", token_generator=lambda _n: " leading"
        )
        assert bearer.generate_token() == "user_ leading"

        stored: list[str] = []

        async def storing_validator(credential: str) -> dict:
            stored.append(credential)
            return {"token": credential}

        bearer = HTTPBearerAuth(
            storing_validator, token_generator=lambda _n: "has space"
        )
        token = bearer.generate_token()
        assert token == "has space"

        response = _client(bearer).get(
            "/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert stored == [token]


class TestCookieAuth:
    def test_authenticates_the_cookie(self):
        client = _client(APIKeyCookieAuth("session", cookie_validator))
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE}
        assert client.get("/me").status_code == 401
        assert client.get("/me", cookies={"session": "wrong"}).status_code == 401

        async def session_validator(value: str, *, scope: str) -> dict:
            if value != VALID_COOKIE:
                raise UnauthorizedError()
            return {"session": value, "scope": scope}

        client = _client(APIKeyCookieAuth("session", session_validator, scope="read"))
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.json() == {"session": VALID_COOKIE, "scope": "read"}

    @pytest.mark.anyio
    async def test_extract(self):
        auth = APIKeyCookieAuth("session", cookie_validator)
        assert await auth.extract(_request()) is None
        assert await auth.extract(_request(cookie="session=abc")) == "abc"


class TestAPIKeyHeaderAuth:
    def test_authenticates_the_header(self):
        client = _client(APIKeyHeaderAuth("X-API-Key", simple_validator))
        response = client.get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}
        assert client.get("/me").status_code == 401
        assert client.get("/me", headers={"X-API-Key": "wrong"}).status_code == 401

        client = _client(APIKeyHeaderAuth("X-API-Key", role_validator, role="admin"))
        response = client.get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_require(self):
        auth = APIKeyHeaderAuth("X-API-Key", role_validator, role="user")
        derived = auth.require(role="admin")
        assert derived._name == "X-API-Key"
        assert auth._kwargs == {"role": "user"}

        response = _client(derived).get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_in_multi_auth(self):
        """APIKeyHeaderAuth.authenticate() is exercised inside MultiAuth."""
        api_key = APIKeyHeaderAuth("X-API-Key", simple_validator)
        assert isinstance(api_key, AuthSource)
        client = _client(MultiAuth(HTTPBearerAuth(simple_validator), api_key))
        # No bearer → falls through to API key header
        response = client.get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    @pytest.mark.anyio
    async def test_extract(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        assert await auth.extract(_request()) is None
        assert await auth.extract(_request(x_api_key="")) is None
        assert await auth.extract(_request(x_api_key="mykey")) == "mykey"


class TestAPIKeyQueryAuth:
    def test_authenticates_the_query_param(self):
        client = _client(APIKeyQueryAuth("api_key", simple_validator))
        response = client.get("/me", params={"api_key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}
        assert client.get("/me").status_code == 401
        assert client.get("/me", params={"api_key": "wrong"}).status_code == 401

        client = _client(APIKeyQueryAuth("api_key", role_validator, role="admin"))
        response = client.get("/me", params={"api_key": VALID_TOKEN})
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_in_multi_auth(self):
        """APIKeyQueryAuth.authenticate() is exercised inside MultiAuth."""
        query = APIKeyQueryAuth("api_key", simple_validator)
        assert isinstance(query, AuthSource)
        client = _client(MultiAuth(HTTPBearerAuth(simple_validator), query))
        # No bearer → falls through to API key query param
        response = client.get("/me", params={"api_key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    @pytest.mark.anyio
    async def test_extract(self):
        auth = APIKeyQueryAuth("api_key", simple_validator)
        assert await auth.extract(_request()) is None
        assert await auth.extract(_request(query_string=b"api_key=")) is None
        assert await auth.extract(_request(query_string=b"api_key=mykey")) == "mykey"


class TestMultiAuth:
    def test_first_present_source_wins(self):
        client = _client(
            MultiAuth(
                HTTPBearerAuth(simple_validator),
                APIKeyCookieAuth("session", cookie_validator),
            )
        )
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

        # No Authorization header — falls through to cookie
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE}

        assert client.get("/me").status_code == 401

    def test_invalid_credential_does_not_fallthrough(self):
        """If a credential is found but invalid, the next source is NOT tried."""
        second_called: list[bool] = []

        async def tracking_validator(credential: str) -> dict:
            second_called.append(True)
            return {"from": "second"}

        bearer = HTTPBearerAuth(simple_validator)  # raises on wrong token
        cookie = APIKeyCookieAuth("session", tracking_validator)
        client = _client(MultiAuth(bearer, cookie))
        # Bearer credential present but wrong — should NOT try cookie
        response = client.get(
            "/me",
            headers={"Authorization": "Bearer wrong"},
            cookies={"session": VALID_COOKIE},
        )
        assert response.status_code == 401
        assert second_called == []  # cookie validator was never called

    def test_prefix_routes_to_correct_source(self):
        """Prefix-based dispatch: only the matching source's validator is called."""
        user_calls: list[str] = []
        org_calls: list[str] = []

        async def user_validator(credential: str) -> dict:
            user_calls.append(credential)
            return {"type": "user", "id": credential}

        async def org_validator(credential: str) -> dict:
            org_calls.append(credential)
            return {"type": "org", "id": credential}

        user_bearer = HTTPBearerAuth(user_validator, prefix="user_")
        org_bearer = HTTPBearerAuth(org_validator, prefix="org_")
        client = _client(MultiAuth(user_bearer, org_bearer))

        response = client.get("/me", headers={"Authorization": "Bearer user_alice"})
        assert response.status_code == 200
        assert response.json() == {"type": "user", "id": "user_alice"}
        assert user_calls == ["user_alice"]
        assert org_calls == []

        user_calls.clear()

        response = client.get("/me", headers={"Authorization": "Bearer org_acme"})
        assert response.status_code == 200
        assert response.json() == {"type": "org", "id": "org_acme"}
        assert user_calls == []
        assert org_calls == ["org_acme"]

    def test_rejects_invalid_sources_at_construction(self):
        with pytest.raises(TypeError, match="AuthSource"):
            MultiAuth(HTTPBearerAuth(role_validator), object())  # ty: ignore[invalid-argument-type]

        inner = MultiAuth(HTTPBearerAuth(role_validator))
        with pytest.raises(TypeError, match="nested"):
            MultiAuth(inner)  # ty: ignore[invalid-argument-type]

    def test_require_forwards_kwargs_to_sources(self):
        """multi.require() propagates to all sources that support it."""
        multi = MultiAuth(HTTPBearerAuth(role_validator))
        response = _client(multi.require(role="admin")).get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_require_derives_new_sources(self):
        """require() applies to sources with require(), skips those without."""
        from fastapi_multiauth.sources import MultiAuth as MultiAuthClass

        bearer = HTTPBearerAuth(role_validator, role="user")
        header_auth = _HeaderAuth(secret="s3cr3t")
        multi = MultiAuth(bearer, header_auth)
        derived = multi.require(role="admin")
        assert isinstance(derived, MultiAuthClass)
        assert derived is not multi
        # bearer got require() applied, header_auth passed through
        assert cast(HTTPBearerAuth, derived._sources[0])._kwargs == {"role": "admin"}
        assert derived._sources[1] is header_auth
        assert bearer._kwargs == {"role": "user"}
        assert MultiAuth(header_auth).require(role="admin")._sources[0] is header_auth


class TestRequire:
    def test_bearer_require_forwards_kwargs(self):
        """require() kwargs are forwarded, and override kwargs set at instantiation."""
        for bearer in [
            HTTPBearerAuth(role_validator),
            HTTPBearerAuth(role_validator, role="user"),
        ]:
            response = _client(bearer.require(role="admin")).get(
                "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
            )
            assert response.status_code == 200
            assert response.json() == {"user": "alice", "role": "admin"}

    def test_require_keeps_the_original_settings(self):
        """require() returns a new instance — original kwargs are unchanged."""
        bearer = HTTPBearerAuth(role_validator, prefix="user_", role="user")
        assert bearer.require(role="admin")._prefix == "user_"
        assert bearer._kwargs == {"role": "user"}

        cookie = APIKeyCookieAuth("session", cookie_validator)
        assert cookie.require(scope="admin")._name == "session"

    def test_cookie_require_forwards_kwargs(self):
        async def scoped_validator(value: str, *, scope: str) -> dict:
            if value != VALID_COOKIE:
                raise UnauthorizedError()
            return {"session": value, "scope": scope}

        cookie = APIKeyCookieAuth("session", scoped_validator)
        response = _client(cookie.require(scope="admin")).get(
            "/me", cookies={"session": VALID_COOKIE}
        )
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE, "scope": "admin"}

    def test_bearer_require_in_multi_auth(self):
        """require() instances work seamlessly inside MultiAuth."""
        PREFIXED_TOKEN = f"user_{VALID_TOKEN}"

        async def prefixed_role_validator(credential: str, *, role: str) -> dict:
            if credential != PREFIXED_TOKEN:
                raise UnauthorizedError()
            return {"user": "alice", "role": role}

        bearer = HTTPBearerAuth(prefixed_role_validator, prefix="user_")
        response = _client(MultiAuth(bearer.require(role="admin"))).get(
            "/me", headers={"Authorization": f"Bearer {PREFIXED_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}


class TestSyncValidators:
    """Sync (non-async) validators — covers the sync path in _call_validator."""

    def test_sync_validator(self):
        """Both the direct dependency and authenticate() (MultiAuth path)."""

        def sync_validator(credential: str) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            return {"user": "alice"}

        bearer = HTTPBearerAuth(sync_validator)
        for auth in [bearer, MultiAuth(bearer)]:
            response = _client(auth).get(
                "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
            )
            assert response.status_code == 200
            assert response.json() == {"user": "alice"}


class TestCookieAuthSigned:
    """APIKeyCookieAuth with signed cookies (secret_key path, itsdangerous format)."""

    def test_valid_signed_cookie_via_set_cookie(self):
        """set_cookie signs the value; the signed cookie is verified on read."""
        # secure=False for test client which runs over plain HTTP
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )

        def setup(app: FastAPI):
            @app.get("/login")
            async def login(response: Response):
                auth.set_cookie(response, VALID_COOKIE)
                return {"ok": True}

            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        with TestClient(_app(setup)) as client:
            client.get("/login")
            response = client.get("/me")
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE}

    def test_set_cookie_attributes(self):
        """Review invariant: cookie defaults are Secure + HttpOnly + SameSite=lax."""

        def header(**kwargs) -> str:
            response = Response()
            APIKeyCookieAuth("session", cookie_validator, **kwargs).set_cookie(
                response, "value"
            )
            return response.headers["set-cookie"].lower()

        default = header(secret_key=COOKIE_SECRET)
        assert "secure" in default
        assert "httponly" in default
        assert "samesite=lax" in default
        assert "secure" not in header(secret_key=COOKIE_SECRET, secure=False)

        custom = header(
            secret_key=COOKIE_SECRET,
            samesite="strict",
            domain="example.com",
            path="/app",
        )
        assert "samesite=strict" in custom
        assert "domain=example.com" in custom
        assert "path=/app" in custom

    def test_without_secret_key_the_value_is_raw(self):
        auth = APIKeyCookieAuth("session", cookie_validator)
        response = Response()
        auth.set_cookie(response, "rawvalue")
        assert "session=rawvalue" in response.headers["set-cookie"]
        with pytest.raises(RuntimeError, match="secret_key"):
            auth._sign("data")

    def test_delete_cookie_keeps_cookie_attributes(self):
        """delete_cookie clears the cookie on the same domain/path it was set."""
        response = Response()
        APIKeyCookieAuth("session", cookie_validator).delete_cookie(response)
        assert "session" in response.headers["set-cookie"]

        auth = APIKeyCookieAuth(
            "session",
            cookie_validator,
            secret_key=COOKIE_SECRET,
            domain="example.com",
            path="/app",
        )
        response = Response()
        auth.delete_cookie(response)
        header = response.headers["set-cookie"].lower()
        assert "session" in header
        assert "domain=example.com" in header
        assert "path=/app" in header

    def test_forged_cookies_return_401(self):
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )
        other_key = APIKeyCookieAuth(
            "session",
            cookie_validator,
            secret_key="another-secret-key-32-bytes-or-more!!",
        )
        # Same secret_key, different cookie name → signature must not transfer.
        other_name = APIKeyCookieAuth(
            "admin_session", cookie_validator, secret_key=COOKIE_SECRET
        )
        signed = auth._sign(VALID_COOKIE)
        payload, _, rest = signed.partition(".")
        client = _client(auth)
        for forged in [
            f"forged{payload[6:]}.{rest}",
            signed[:-5],
            other_key._sign(VALID_COOKIE),
            other_name._sign(VALID_COOKIE),
            VALID_COOKIE,
        ]:
            response = client.get("/me", cookies={"session": forged})
            assert response.status_code == 401, forged

        # A present-but-empty cookie is treated as absent, not validated.
        assert client.get("/me", headers={"Cookie": "session="}).status_code == 401
        assert client.get("/me", cookies={"session": signed}).status_code == 200

    def test_expired_signed_cookie_returns_401(self):
        """A signed cookie older than ttl is rejected; a fresh one accepted."""
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, ttl=60, secure=False
        )
        client = _client(auth)
        signed = auth._sign(VALID_COOKIE)

        response = client.get("/me", cookies={"session": signed})
        assert response.status_code == 200

        with patch("time.time", return_value=time.time() + 61):
            response = client.get("/me", cookies={"session": signed})
        assert response.status_code == 401


async def sid_validator(value: str, *, session_id: str) -> dict:
    return {"session": value, "sid": session_id}


def _sid_client(auth, value=VALID_COOKIE) -> TestClient:
    """App exposing the whole session-id surface of *auth*, one cookie jar."""

    def setup(app: FastAPI):
        @app.get("/login")
        async def login(response: Response):
            return {"sid": auth.set_cookie(response, value)}

        @app.get("/logout")
        async def logout(request: Request, response: Response):
            return {"sid": auth.delete_cookie(response, request)}

        @app.get("/whoami")
        async def whoami(request: Request):
            return {"sid": auth.session_id_of(request)}

        @app.get("/me")
        async def me(user=Security(auth)):
            return user

    return TestClient(_app(setup))


class TestCookieSessionId:
    """Per-session identity: minted by set_cookie, read back by session_id_of."""

    def _auth(self, **kwargs):
        return APIKeyCookieAuth(
            "session",
            sid_validator,
            secret_key=COOKIE_SECRET,
            session_id=True,
            secure=False,
            **kwargs,
        )

    def test_sid_round_trip(self):
        with _sid_client(self._auth()) as client:
            minted = client.get("/login").json()["sid"]
            response = client.get("/me")
            assert response.status_code == 200
            assert response.json() == {"session": VALID_COOKIE, "sid": minted}
            assert client.get("/whoami").json()["sid"] == minted
            # the whole point: readable again, so it was not a one-shot
            assert client.get("/whoami").json()["sid"] == minted
            assert client.cookies.get("session")
            assert client.get("/logout").json()["sid"] == minted

    def test_value_containing_delimiter_survives_roundtrip(self):
        """The app's payload may contain dots: only the first one splits."""
        with _sid_client(self._auth(), "user.42:v3") as client:
            minted = client.get("/login").json()["sid"]
            assert client.get("/me").json() == {"session": "user.42:v3", "sid": minted}

    def test_rotating_the_cookie_swaps_the_sid_and_keeps_the_session(self):
        """Session-fixation defence: the newest cookie wins on the next request."""
        auth = self._auth()
        assert auth.set_cookie(Response(), VALID_COOKIE) != auth.set_cookie(
            Response(), VALID_COOKIE
        )
        with _sid_client(auth) as client:
            first = client.get("/login").json()["sid"]
            second = client.get("/login").json()["sid"]
            assert second != first
            assert client.get("/me").json() == {"session": VALID_COOKIE, "sid": second}

    def test_unusable_cookie_reads_as_none(self):
        client = _sid_client(self._auth())
        for cookies in [{}, {"session": "forged"}, {"session": ""}]:
            assert client.get("/whoami", cookies=cookies).json()["sid"] is None
            assert client.get("/logout", cookies=cookies).json()["sid"] is None
        assert self._auth().delete_cookie(Response()) is None

        # The salt differs, so pre-upgrade cookies fail closed instead of parsing.
        legacy = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )
        response = client.get("/me", cookies={"session": legacy._sign(VALID_COOKIE)})
        assert response.status_code == 401

        with _sid_client(self._auth(ttl=60)) as client:
            client.get("/login")
            with patch("time.time", return_value=time.time() + 61):
                assert client.get("/whoami").json()["sid"] is None

    def test_reads_none_when_session_id_disabled(self):
        """Nothing to read, and the unsigned path must never try to verify."""
        signed = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )
        assert signed.set_cookie(Response(), VALID_COOKIE) is None
        unsigned = APIKeyCookieAuth("session", cookie_validator, secure=False)
        for auth in [signed, unsigned]:
            with _sid_client(auth) as client:
                client.get("/login")
                assert client.get("/whoami").json()["sid"] is None
                assert client.get("/logout").json()["sid"] is None

    def test_misconfiguration_rejected(self):
        with pytest.raises(ValueError, match="session_id requires secret_key"):
            APIKeyCookieAuth("session", sid_validator, session_id=True)
        with pytest.raises(ValueError, match="declaring a 'session_id' parameter"):
            APIKeyCookieAuth(
                "session", cookie_validator, secret_key=COOKIE_SECRET, session_id=True
            )
        # 'session_id' is injected, so require() cannot override it.
        with pytest.raises(ValueError, match="reserved"):
            self._auth().require(session_id="forged")


class TestCookieConfig:
    """Cookie settings: accessors, SR-M5 weak secrets, and name prefix rules."""

    def test_name_and_ttl_are_readable(self):
        """name and ttl are readable so callers stop duplicating them."""
        auth = APIKeyCookieAuth("sess", cookie_validator, ttl=1234)
        assert (auth.name, auth.ttl) == ("sess", 1234)
        assert APIKeyCookieAuth("sess", cookie_validator).ttl == 86400

    def test_weak_secret_key_rejected(self):
        """SR-M5: weak secret_key configurations must fail at startup."""
        for secret_key, match in [
            ("", "secret_key"),
            ("short", "at least 32"),
            ([], "at least one key"),
            ([COOKIE_SECRET, "short"], "at least 32"),
        ]:
            with pytest.raises(ValueError, match=match):
                APIKeyCookieAuth("session", cookie_validator, secret_key=secret_key)
        for ttl in [0, -1]:
            with pytest.raises(ValueError, match="ttl"):
                APIKeyCookieAuth(
                    "session", cookie_validator, secret_key="x" * 32, ttl=ttl
                )

        APIKeyCookieAuth("session", cookie_validator, secret_key="x" * 32)
        APIKeyCookieAuth("session", cookie_validator)

    def test_name_prefix_rules(self):
        for name in ["__Host-session", "__Secure-session"]:
            APIKeyCookieAuth(name, cookie_validator, secret_key=COOKIE_SECRET)
        APIKeyCookieAuth(
            "__Secure-session", cookie_validator, domain="example.com", path="/app"
        )
        APIKeyCookieAuth(
            "session", cookie_validator, secure=False, domain="example.com", path="/x"
        )

        for name in ["__Host-session", "__secure-session"]:
            with pytest.raises(ValueError, match="secure=True"):
                APIKeyCookieAuth(name, cookie_validator, secure=False)
        host_violations: list[dict[str, Any]] = [
            {"domain": "example.com"},
            {"path": "/app"},
        ]
        for kwargs in host_violations:
            with pytest.raises(ValueError, match="__Host-"):
                APIKeyCookieAuth("__HOST-session", cookie_validator, **kwargs)


class TestCookieKeyRotation:
    """secret_key rotation: first key signs, every key verifies."""

    OLD = "old-rotation-secret-key-32-bytes-min!"
    NEW = "new-rotation-secret-key-32-bytes-min!"

    def test_rotation(self):
        old_auth = APIKeyCookieAuth("session", cookie_validator, secret_key=self.OLD)
        rotated = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=[self.NEW, self.OLD], secure=False
        )
        new_only = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=[self.NEW], secure=False
        )
        old_cookie = {"session": old_auth._sign(VALID_COOKIE)}
        assert _client(rotated).get("/me", cookies=old_cookie).status_code == 200
        assert _client(new_only).get("/me", cookies=old_cookie).status_code == 401
        response = _client(new_only).get(
            "/me", cookies={"session": rotated._sign(VALID_COOKIE)}
        )
        assert response.status_code == 200

    def test_wire_format_matches_a_stock_signer(self):
        """Cookies stay byte-compatible with a stock signer despite precomputed keys."""
        auth = APIKeyCookieAuth("session", cookie_validator, secret_key=self.NEW)
        signed = auth._sign(VALID_COOKIE).encode()
        stock = _stock_signer(self.NEW, salt="session.v2")
        assert stock.unsign(signed, max_age=86400) == f".{VALID_COOKIE}".encode()

        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=[self.NEW, self.OLD]
        )
        stock = _stock_signer(self.OLD, salt="session.v2")
        signed = stock.sign(f".{VALID_COOKIE}".encode()).decode()
        assert auth._verify(signed) == VALID_COOKIE

    def test_session_id_salt_still_separates_the_two_layouts(self):
        auth = APIKeyCookieAuth(
            "session",
            sid_validator,
            secret_key=self.NEW,
            session_id=True,
        )
        stock = _stock_signer(self.NEW, salt="session.v2")
        signed = stock.sign(f".{VALID_COOKIE}".encode()).decode()
        with pytest.raises(UnauthorizedError):
            auth._verify(signed)


class TestSecurityScopes:
    """Scopes declared via Security(..., scopes=[...]) are enforced, not ignored."""

    def test_scopes_reach_the_validator(self):
        received: list[tuple[str, list[str]]] = []

        def recorder(name: str):
            async def scoped_validator(credential: str, scopes: list[str]) -> dict:
                received.append((name, scopes))
                return {"user": "alice"}

            return scoped_validator

        def sync_scoped_validator(credential: str, scopes: list[str]) -> dict:
            received.append(("sync", scopes))
            return {"user": "alice"}

        async def kw_scoped_validator(credential: str, *, scopes: list[str]) -> dict:
            received.append(("kw", scopes))
            return {"user": "alice"}

        bearer = HTTPBearerAuth(recorder("bearer"))
        cookie = APIKeyCookieAuth("session", recorder("cookie"))
        api_key = APIKeyHeaderAuth("X-API-Key", recorder("api-key"))
        multi = MultiAuth(
            HTTPBearerAuth(recorder("multi")),
            APIKeyCookieAuth("session", recorder("x")),
        )
        sync = HTTPBearerAuth(sync_scoped_validator)
        unscoped = HTTPBearerAuth(kw_scoped_validator)

        def setup(app: FastAPI):
            @app.get("/bearer")
            async def r1(user=Security(bearer, scopes=["admin", "billing"])):
                return user

            @app.get("/cookie")
            async def r2(user=Security(cookie, scopes=["admin"])):
                return user

            @app.get("/api-key")
            async def r3(user=Security(api_key, scopes=["admin"])):
                return user

            @app.get("/multi")
            async def r4(user=Security(multi, scopes=["admin"])):
                return user

            @app.get("/sync")
            async def r5(user=Security(sync, scopes=["admin"])):
                return user

            @app.get("/unscoped")
            async def r6(user=Security(unscoped)):
                return user

        client = TestClient(_app(setup))
        bearer_header = {"Authorization": f"Bearer {VALID_TOKEN}"}
        for path in ["/bearer", "/multi", "/sync", "/unscoped"]:
            assert client.get(path, headers=bearer_header).status_code == 200
        assert (
            client.get("/cookie", cookies={"session": VALID_COOKIE}).status_code == 200
        )
        assert (
            client.get("/api-key", headers={"X-API-Key": VALID_TOKEN}).status_code
            == 200
        )
        assert received == [
            ("bearer", ["admin", "billing"]),
            ("multi", ["admin"]),
            ("sync", ["admin"]),
            ("kw", []),
            ("cookie", ["admin"]),
            ("api-key", ["admin"]),
        ]

    def test_scoped_validator_can_reject(self):
        """A validator enforcing scopes turns missing scopes into a 401."""

        async def scoped_validator(credential: str, scopes: list[str]) -> dict:
            if credential != VALID_TOKEN or "admin" in scopes:
                raise UnauthorizedError()
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 401

    def test_scopes_declared_without_scopes_param_raises(self):
        """Fail closed: validator can't receive scopes → RuntimeError, not silent authz skip."""
        for auth, kwargs in [
            (
                HTTPBearerAuth(simple_validator),
                {"headers": {"Authorization": f"Bearer {VALID_TOKEN}"}},
            ),
            (
                APIKeyCookieAuth("session", cookie_validator),
                {"cookies": {"session": VALID_COOKIE}},
            ),
            (
                APIKeyHeaderAuth("X-API-Key", simple_validator),
                {"headers": {"X-API-Key": VALID_TOKEN}},
            ),
            (
                MultiAuth(HTTPBearerAuth(simple_validator)),
                {"headers": {"Authorization": f"Bearer {VALID_TOKEN}"}},
            ),
            # AuthSource.authenticate_scoped default raises when scopes are declared.
            (_HeaderAuth(secret="s3cr3t"), {"headers": {"X-Token": "s3cr3t"}}),
        ]:

            def setup(app: FastAPI, auth=auth):
                @app.get("/admin")
                async def admin(user=Security(auth, scopes=["admin"])):
                    return user

            client = TestClient(_app(setup))
            with pytest.raises(RuntimeError, match="security scopes"):
                client.get("/admin", **kwargs)

    def test_scopes_kwarg_rejected(self):
        """'scopes' is reserved for route-declared scopes — fail at startup."""
        for factory in [
            lambda: HTTPBearerAuth(simple_validator, scopes=["admin"]),
            lambda: APIKeyCookieAuth("session", cookie_validator, scopes=["admin"]),
            lambda: APIKeyHeaderAuth("X-API-Key", simple_validator, scopes=["admin"]),
            # require() goes through __init__, so the same guard applies.
            lambda: HTTPBearerAuth(simple_validator).require(scopes=["admin"]),
        ]:
            with pytest.raises(ValueError, match="reserved"):
                factory()

    def test_accepts_scopes_non_introspectable_callable(self):
        """Callables without an inspectable signature are treated as scope-less."""
        from fastapi_multiauth.abc import _accepts_kwarg

        not_introspectable = cast(Callable[..., Any], object())
        assert _accepts_kwarg(not_introspectable, "scopes") is False

    @pytest.mark.anyio
    async def test_authenticate_passes_no_scopes(self):
        """authenticate() remains the scope-less entry point."""
        bearer = HTTPBearerAuth(simple_validator)
        assert await bearer.authenticate(VALID_TOKEN) == {"user": "alice"}
        auth = APIKeyCookieAuth("session", cookie_validator)
        assert await auth.authenticate(VALID_COOKIE) == {"session": VALID_COOKIE}
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        assert await auth.authenticate(VALID_TOKEN) == {"user": "alice"}


# Minimal concrete subclass used only in tests below.
class _HeaderAuth(AuthSource):
    """Reads a custom X-Token header — no FastAPI security scheme."""

    def __init__(self, secret: str) -> None:
        super().__init__()
        self._secret = secret

    async def extract(self, request) -> str | None:
        return request.headers.get("X-Token") or None

    async def authenticate(self, credential: str) -> dict:
        if credential != self._secret:
            raise UnauthorizedError()
        return {"token": credential}


class TestRequestForwarding:
    """Validators declaring a 'request' parameter are handed the live Request."""

    def test_request_reaches_the_validator_and_state_survives_to_the_route(self):
        async def validator(credential: str, request: Request | None = None) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            assert request is not None
            request.state.token_scopes = ["challenges:write"]
            return {"user": "alice"}

        bearer = HTTPBearerAuth(validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(request: Request, user=Security(bearer)):
                return {"user": user, "scopes": request.state.token_scopes}

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {
            "user": {"user": "alice"},
            "scopes": ["challenges:write"],
        }

    @pytest.mark.anyio
    async def test_sequential_requests_in_one_task_see_their_own_state(self):
        """Two requests in one context: the shape a task-scoped ContextVar gets wrong."""

        async def validator(credential: str, request: Request | None = None) -> dict:
            assert request is not None
            request.state.token = credential
            return {"user": credential}

        bearer = HTTPBearerAuth(validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(request: Request, user=Security(bearer)):
                return {"token": request.state.token}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_app(setup)),
            base_url="http://test",
        ) as client:
            first = await client.get("/me", headers={"Authorization": "Bearer first"})
            second = await client.get("/me", headers={"Authorization": "Bearer second"})
        assert first.json() == {"token": "first"}
        assert second.json() == {"token": "second"}

    def test_validator_without_the_parameter_is_called_unchanged(self):
        """Opt-in by signature: nothing is injected into a validator that never asked."""
        # JWTValidator declares no 'request', so JWT-backed bearers are untouched.
        assert HTTPBearerAuth(JWTValidator(secret="s" * 32))._accepts_request is False
        bearer = HTTPBearerAuth(simple_validator)
        assert bearer._accepts_request is False
        response = _client(bearer).get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_every_source_forwards_the_request(self):
        async def basic_validator(
            username: str, password: str, request: Request | None = None
        ) -> dict:
            assert request is not None
            request.state.who = username
            return {"u": username, "p": password}

        async def bearer_validator(
            credential: str, request: Request | None = None
        ) -> dict:
            assert request is not None
            request.state.who = "bearer"
            return {"user": "alice"}

        def sync_validator(credential: str, request: Request | None = None) -> dict:
            assert request is not None
            request.state.who = "sync"
            return {"user": "alice"}

        async def cookie_validator_(value: str, request: Request | None = None) -> dict:
            assert request is not None
            request.state.who = "cookie"
            return {"session": value}

        basic = HTTPBasicAuth(basic_validator)
        multi = MultiAuth(
            HTTPBearerAuth(bearer_validator),
            APIKeyCookieAuth("session", cookie_validator, secure=False),
        )
        sync = HTTPBearerAuth(sync_validator)
        cookie = APIKeyCookieAuth("session", cookie_validator_, secure=False)

        def setup(app: FastAPI):
            @app.get("/basic")
            async def r1(request: Request, user=Security(basic)):
                return {"user": user, "who": request.state.who}

            @app.get("/multi")
            async def r2(request: Request, user=Security(multi)):
                return {"user": user, "who": request.state.who}

            @app.get("/sync")
            async def r3(request: Request, user=Security(sync)):
                return {"user": user, "who": request.state.who}

            @app.get("/cookie")
            async def r4(request: Request, user=Security(cookie)):
                return {"user": user, "who": request.state.who}

        client = TestClient(_app(setup))
        blob = base64.b64encode(b"alice:pw").decode()
        response = client.get("/basic", headers={"Authorization": f"Basic {blob}"})
        assert response.json() == {"user": {"u": "alice", "p": "pw"}, "who": "alice"}
        bearer_header = {"Authorization": f"Bearer {VALID_TOKEN}"}
        response = client.get("/multi", headers=bearer_header)
        assert response.json() == {"user": {"user": "alice"}, "who": "bearer"}
        response = client.get("/sync", headers=bearer_header)
        assert response.json() == {"user": {"user": "alice"}, "who": "sync"}
        response = client.get("/cookie", cookies={"session": VALID_COOKIE})
        assert response.json() == {"user": {"session": VALID_COOKIE}, "who": "cookie"}

    def test_request_and_scopes_are_injected_together(self):
        received: list[tuple[list[str], bool]] = []

        async def validator(
            credential: str, scopes: list[str], request: Request | None = None
        ) -> dict:
            received.append((scopes, request is not None))
            return {"user": "alice"}

        bearer = HTTPBearerAuth(validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert received == [(["admin"], True)]

    def test_cookie_forwards_the_request_alongside_the_session_id(self):
        received: list[tuple[str, str, bool]] = []

        async def validator(
            value: str, *, session_id: str, request: Request | None = None
        ) -> dict:
            received.append((value, session_id, request is not None))
            return {"session": value, "sid": session_id}

        auth = APIKeyCookieAuth(
            "session",
            validator,
            secret_key=COOKIE_SECRET,
            session_id=True,
            secure=False,
        )

        with _sid_client(auth) as client:
            minted = client.get("/login").json()["sid"]
            assert client.get("/me").json() == {"session": VALID_COOKIE, "sid": minted}
        assert received == [(VALID_COOKIE, minted, True)]

    def test_override_signatures_seen_by_dispatch(self):
        """A custom source written before this feature keeps its original call shape."""
        # A callable with no inspectable signature is assumed current, not stale.
        assert _override_accepts_request(cast(Callable[..., Any], object())) is True

        class _StaleAuth(_HeaderAuth):
            async def authenticate_scoped(  # ty: ignore[invalid-method-override]
                self, credential: str, scopes: list[str]
            ) -> dict:
                return await self.authenticate(credential)

        auth = _StaleAuth("s3cr3t")
        assert auth._scoped_takes_request is False
        response = _client(auth).get("/me", headers={"X-Token": "s3cr3t"})
        assert response.status_code == 200
        assert response.json() == {"token": "s3cr3t"}

        # **kwargs is a current signature: the injected request lands in it.
        received: list[Any] = []

        class _KwargsAuth(_HeaderAuth):
            async def authenticate_scoped(
                self, credential: str, scopes: list[str], **kwargs
            ) -> dict:
                received.append(kwargs.get("request"))
                return await self.authenticate(credential)

        auth = _KwargsAuth("s3cr3t")
        assert auth._scoped_takes_request is True
        response = _client(auth).get("/me", headers={"X-Token": "s3cr3t"})
        assert response.status_code == 200
        assert response.json() == {"token": "s3cr3t"}
        assert isinstance(received[0], Request)

    @pytest.mark.anyio
    async def test_direct_authenticate(self):
        """authenticate() is reachable off a request path, so the Request is optional."""
        seen: list[Request | None] = []

        async def validator(credential: str, request: Request | None = None) -> dict:
            seen.append(request)
            return {"user": "alice"}

        bearer = HTTPBearerAuth(validator)
        assert await bearer.authenticate(VALID_TOKEN) == {"user": "alice"}
        assert await bearer.authenticate_scoped(VALID_TOKEN, []) == {"user": "alice"}
        assert seen == [None, None]

        # authenticate() honours the same old call shape dispatch() does.
        class _StaleBearer(HTTPBearerAuth):
            async def authenticate_scoped(  # ty: ignore[invalid-method-override]
                self, credential: str, scopes: list[str]
            ) -> dict:
                return {"user": credential}

        auth = _StaleBearer(simple_validator)
        assert auth._scoped_takes_request is False
        assert await auth.authenticate(VALID_TOKEN) == {"user": VALID_TOKEN}

    def test_request_kwarg_rejected(self):
        """'request' is reserved for the injected Request — fail at startup."""
        for factory in [
            lambda: HTTPBearerAuth(simple_validator, request="nope"),
            lambda: APIKeyCookieAuth("session", cookie_validator, request="nope"),
            lambda: APIKeyHeaderAuth("X-API-Key", simple_validator, request="nope"),
            lambda: HTTPBearerAuth(simple_validator).require(request="nope"),
        ]:
            with pytest.raises(ValueError, match="reserved"):
                factory()


class TestAuthSource:
    def test_abstract_base(self):
        with pytest.raises(TypeError):
            AuthSource()  # ty: ignore[call-non-callable]
        for auth in [
            HTTPBearerAuth(simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
        ]:
            assert isinstance(auth, AuthSource)

    def test_custom_source(self):
        """Default __call__ wires extract + authenticate via Request injection."""
        auth = _HeaderAuth(secret="s3cr3t")
        client = _client(auth)
        response = client.get("/me", headers={"X-Token": "s3cr3t"})
        assert response.status_code == 200
        assert response.json() == {"token": "s3cr3t"}
        assert client.get("/me").status_code == 401
        assert client.get("/me", headers={"X-Token": "wrong"}).status_code == 401

        # Custom AuthSource works transparently inside MultiAuth.
        client = _client(MultiAuth(HTTPBearerAuth(simple_validator), auth))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}
        # No bearer → falls through to custom header source
        response = client.get("/me", headers={"X-Token": "s3cr3t"})
        assert response.status_code == 200
        assert response.json() == {"token": "s3cr3t"}


class TestEncodeDecodeOAuthState:
    def test_round_trip(self):
        state_token = "test-state-token"
        result = oauth_encode_state("https://example.com/dashboard", state_token)
        assert isinstance(result, str)
        assert "+" not in result
        assert "/" not in result

        for url in ["/after-login?next=/home", "/dashboard/x"]:
            encoded = oauth_encode_state(url, state_token)
            for state in [encoded, encoded.rstrip("=")]:
                assert (
                    oauth_decode_state(
                        state, expected_state_token=state_token, fallback="/"
                    )
                    == url
                )
        assert oauth_generate_state_token() != oauth_generate_state_token()

    def test_decode_bad_state_raises(self):
        for state, expected in [
            (None, "any"),
            ("", "any"),
            ("null", "any"),
            ("!!!notbase64!!!", "any"),
            (base64.urlsafe_b64encode(b"[" * 100_000).decode(), "any"),
            (_raw_state({"n": "\ud800", "d": "/x"}), "any"),
            (oauth_encode_state("/dashboard", "correct-token"), "wrong-token"),
            # An empty stored token (session miss) must never match an empty "n".
            (oauth_encode_state("/dashboard", ""), ""),
        ]:
            with pytest.raises(OAuthStateError):
                oauth_decode_state(
                    state, expected_state_token=expected, fallback="/home"
                )

    def test_error_message_does_not_echo_state(self):
        assert issubclass(OAuthStateError, OAuthError)
        encoded = oauth_encode_state("/dashboard", "attacker-token")
        with pytest.raises(OAuthStateError) as exc_info:
            oauth_decode_state(encoded, expected_state_token="expected", fallback="/")
        assert encoded not in str(exc_info.value)
        assert "attacker-token" not in str(exc_info.value)


class TestBuildAuthorizationRedirect:
    def test_redirect_location_contains_all_params(self):
        """303 forces a GET even when the login route was a POST form."""
        from fastapi.responses import RedirectResponse

        state_token = "test-state-token"
        response = oauth_build_authorization_redirect(
            "https://auth.example.com/authorize",
            client_id="my-client",
            scopes="openid email",
            redirect_uri="https://app.example.com/callback",
            destination="https://app.example.com/dashboard",
            state_token=state_token,
        )
        assert isinstance(response, RedirectResponse)
        assert response.status_code == 303
        location = response.headers["location"]
        parsed = urlparse(location)
        assert (
            parsed.scheme + "://" + parsed.netloc + parsed.path
            == "https://auth.example.com/authorize"
        )
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["my-client"]
        assert params["response_type"] == ["code"]
        assert params["scope"] == ["openid email"]
        assert params["redirect_uri"] == ["https://app.example.com/callback"]
        assert (
            oauth_decode_state(
                params["state"][0],
                expected_state_token=state_token,
                fallback="",
                allowed_hosts=("app.example.com",),
            )
            == "https://app.example.com/dashboard"
        )

    def test_preserves_existing_query_string(self):
        """RFC 6749 §3.1: a query component on the endpoint must be retained."""
        response = oauth_build_authorization_redirect(
            "https://auth.example.com/authorize?tenant=acme",
            client_id="my-client",
            scopes="openid",
            redirect_uri="https://app.example.com/callback",
            destination="/",
            state_token="test-state-token",
        )
        location = response.headers["location"]
        assert location.count("?") == 1
        params = parse_qs(urlparse(location).query)
        assert params["tenant"] == ["acme"]
        assert params["client_id"] == ["my-client"]


_WELL_KNOWN = "/.well-known/openid-configuration"
DISCOVERY_URL = f"https://auth.example.com{_WELL_KNOWN}"


def _discovery_doc(*, userinfo=True, **overrides):
    doc = {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
    }
    if userinfo:
        doc["userinfo_endpoint"] = "https://auth.example.com/userinfo"
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


class TestResolveProviderUrls:
    @pytest.mark.anyio
    @respx.mock
    async def test_returns_endpoints(self):
        route = respx.get(DISCOVERY_URL)

        route.respond(json=_discovery_doc())
        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)
        assert isinstance(endpoints, OIDCEndpoints)
        assert endpoints.authorization_endpoint == "https://auth.example.com/authorize"
        assert endpoints.token_endpoint == "https://auth.example.com/token"
        assert endpoints.userinfo_endpoint == "https://auth.example.com/userinfo"
        assert endpoints.issuer == "https://auth.example.com"
        assert endpoints.jwks_uri is None
        assert endpoints.end_session_endpoint is None

        route.respond(
            json=_discovery_doc(
                userinfo=False,
                jwks_uri="https://auth.example.com/jwks",
                end_session_endpoint="https://auth.example.com/logout",
            )
        )
        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)
        assert endpoints.jwks_uri == "https://auth.example.com/jwks"
        assert endpoints.end_session_endpoint == "https://auth.example.com/logout"
        assert endpoints.userinfo_endpoint is None

    @pytest.mark.anyio
    @respx.mock
    async def test_caches_discovery_document(self):
        route = respx.get(DISCOVERY_URL).respond(json=_discovery_doc())

        oauth_resolve_provider_urls.cache_clear()
        await oauth_resolve_provider_urls(DISCOVERY_URL)
        await oauth_resolve_provider_urls(DISCOVERY_URL)

        assert route.call_count == 1

    @pytest.mark.anyio
    @respx.mock
    async def test_unusable_document_raises_discovery_error(self):
        no_token_endpoint = _discovery_doc()
        del no_token_endpoint["token_endpoint"]
        route = respx.get(DISCOVERY_URL)
        for response, match in [
            (httpx.Response(500), "failed to fetch"),
            (httpx.ConnectTimeout("connection timed out"), "failed to fetch"),
            (httpx.Response(200, content=b"<html>not json</html>"), "not valid JSON"),
            (httpx.Response(200, content=b'{"issuer": "\xff"}'), "not valid JSON"),
            (httpx.Response(200, json=["not", "an", "object"]), "not a JSON object"),
            (
                httpx.Response(200, json=no_token_endpoint),
                "missing the 'token_endpoint'",
            ),
            (
                httpx.Response(200, json=_discovery_doc(token_endpoint=123)),
                "must be a string URL",
            ),
        ]:
            route.mock(side_effect=[response])
            oauth_resolve_provider_urls.cache_clear()
            with pytest.raises(OAuthDiscoveryError, match=match):
                await oauth_resolve_provider_urls(DISCOVERY_URL)


def _authorization_redirect(url="https://auth.example.com/authorize", **kwargs):
    kwargs = {
        "client_id": "my-client",
        "scopes": "openid",
        "redirect_uri": "https://app.example.com/callback",
        "destination": "/dashboard",
        "state_token": "test-state-token",
        **kwargs,
    }
    return oauth_build_authorization_redirect(url, **kwargs)


class TestOAuthHttpsEnforcement:
    """client_secret / codes / tokens must never travel over plaintext HTTP."""

    def test_http_authorization_url_rejected(self):
        with pytest.raises(ValueError, match="authorization_url must use https"):
            _authorization_redirect("http://idp.example/authorize")
        for host in ["localhost", "127.0.0.1"]:
            response = _authorization_redirect(f"http://{host}:8080/authorize")
            assert response.headers["location"].startswith(
                f"http://{host}:8080/authorize?"
            )

    @pytest.mark.anyio
    @respx.mock
    async def test_http_discovery_url_rejected_before_fetch(self):
        # No respx routes are registered: any HTTP request would error out.
        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(ValueError, match="discovery URL must use https"):
            await oauth_resolve_provider_urls(
                "http://auth.example.com/.well-known/openid-configuration"
            )

        assert len(respx.calls) == 0

    @pytest.mark.anyio
    @respx.mock
    async def test_http_endpoint_in_discovery_document_rejected(self):
        route = respx.get(DISCOVERY_URL)
        for endpoint in [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "end_session_endpoint",
        ]:
            route.respond(
                json=_discovery_doc(
                    **{endpoint: "http://attacker.example.com/endpoint"}
                )
            )
            oauth_resolve_provider_urls.cache_clear()
            with pytest.raises(OAuthDiscoveryError, match=f"{endpoint} must use https"):
                await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_http_loopback_discovery_allowed(self):
        """Local development IdPs over plain HTTP keep working."""
        for host in ["localhost", "127.0.0.1"]:
            respx.get(f"http://{host}:8080/.well-known/openid-configuration").respond(
                json={
                    "issuer": f"http://{host}:8080",
                    "authorization_endpoint": f"http://{host}:8080/authorize",
                    "token_endpoint": f"http://{host}:8080/token",
                    "userinfo_endpoint": f"http://{host}:8080/userinfo",
                }
            )

            oauth_resolve_provider_urls.cache_clear()
            endpoints = await oauth_resolve_provider_urls(
                f"http://{host}:8080/.well-known/openid-configuration"
            )

            assert endpoints.authorization_endpoint == f"http://{host}:8080/authorize"
            assert endpoints.token_endpoint == f"http://{host}:8080/token"
            assert endpoints.userinfo_endpoint == f"http://{host}:8080/userinfo"

    @pytest.mark.anyio
    async def test_foreign_or_missing_issuer_rejected(self):
        """OIDC Discovery §4.3: the document must claim the expected issuer."""
        no_issuer = _discovery_doc()
        del no_issuer["issuer"]
        attacker = _discovery_doc(issuer="https://attacker.example.com")
        for url, doc in [
            (DISCOVERY_URL, attacker),
            (DISCOVERY_URL, no_issuer),
            # Query strings and trailing slashes must not skip the issuer check.
            (f"{DISCOVERY_URL}?p=B2C_1_signin", attacker),  # Azure AD B2C policy
            (f"{DISCOVERY_URL}/", attacker),
            # The expectation comes from the whole URL, not a substring of it.
            (
                f"https://attacker.example.com/https://auth.example.com{_WELL_KNOWN}",
                _discovery_doc(),
            ),
        ]:
            with respx.mock:
                respx.get(url).respond(json=doc)
                oauth_resolve_provider_urls.cache_clear()
                with pytest.raises(OAuthDiscoveryError, match="issuer"):
                    await oauth_resolve_provider_urls(url)

    @pytest.mark.anyio
    async def test_issuer_variants_accepted(self):
        """Auth0-style trailing slash, Keycloak/Microsoft-style path, Azure query."""
        issuer = "https://auth.example.com/realms/myrealm"
        for url, doc in [
            (DISCOVERY_URL, _discovery_doc(issuer="https://auth.example.com/")),
            (f"{issuer}{_WELL_KNOWN}", _discovery_doc(issuer=issuer)),
            (f"{DISCOVERY_URL}?p=B2C_1_signin", _discovery_doc()),
        ]:
            with respx.mock:
                respx.get(url).respond(json=doc)
                oauth_resolve_provider_urls.cache_clear()
                endpoints = await oauth_resolve_provider_urls(url)
            assert endpoints.token_endpoint == "https://auth.example.com/token"
            assert endpoints.issuer == doc["issuer"]

    @pytest.mark.anyio
    @respx.mock
    async def test_nonstandard_discovery_url(self):
        """Nothing exact can be derived, but another host is still refused."""
        url = "https://auth.example.com/custom/discovery.json"
        route = respx.get(url)

        route.respond(json=_discovery_doc(issuer="https://unrelated.example.com"))
        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="origin"):
            await oauth_resolve_provider_urls(url)

        no_issuer = _discovery_doc()
        del no_issuer["issuer"]
        route.respond(json=no_issuer)
        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="issuer"):
            await oauth_resolve_provider_urls(url)

        route.respond(json=_discovery_doc(issuer="https://auth.example.com/t1"))
        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(url)
        assert endpoints.issuer == "https://auth.example.com/t1"

    @pytest.mark.anyio
    @respx.mock
    async def test_http_token_and_userinfo_urls_rejected_before_request(self):
        with pytest.raises(ValueError, match="token_url must use https"):
            await oauth_exchange_code(
                token_url="http://auth.example.com/token",
                code="authcode123",
                client_id="client-id",
                client_secret="client-secret",
                redirect_uri="https://app.example.com/callback",
            )
        with pytest.raises(ValueError, match="userinfo_url must use https"):
            await oauth_fetch_userinfo(
                userinfo_url="http://auth.example.com/userinfo",
                access_token="tok123",
            )

        assert len(respx.calls) == 0

    @pytest.mark.anyio
    @respx.mock
    async def test_http_loopback_exchange_and_userinfo_allowed(self):
        respx.post("http://localhost:8080/token").respond(
            json={"access_token": "tok123"}
        )
        respx.get("http://127.0.0.1:8080/userinfo").respond(json={"sub": "user-1"})

        token = await oauth_exchange_code(
            token_url="http://localhost:8080/token",
            code="authcode123",
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri="http://localhost:8000/callback",
        )
        result = await oauth_fetch_userinfo(
            userinfo_url="http://127.0.0.1:8080/userinfo",
            access_token=token["access_token"],
        )
        assert result == {"sub": "user-1"}


class TestExchangeCode:
    TOKEN_URL = "https://auth.example.com/token"

    async def _exchange(self, **kwargs):
        kwargs.setdefault("token_url", self.TOKEN_URL)
        kwargs.setdefault("code", "authcode123")
        kwargs.setdefault("client_id", "my-client")
        kwargs.setdefault("client_secret", "my-secret")
        kwargs.setdefault("redirect_uri", "https://app.example.com/callback")
        return await oauth_exchange_code(**kwargs)

    @pytest.mark.anyio
    @respx.mock
    async def test_posts_correct_token_request(self):
        route = respx.post(self.TOKEN_URL).respond(
            json={
                "access_token": "tok123",
                "refresh_token": "refresh456",
                "id_token": "idtok789",
                "scope": "openid email",
            }
        )

        token = await self._exchange()

        assert token["access_token"] == "tok123"
        assert token["refresh_token"] == "refresh456"
        assert token["id_token"] == "idtok789"
        body = parse_qs(route.calls.last.request.content.decode())
        assert body["grant_type"] == ["authorization_code"]
        assert body["code"] == ["authcode123"]
        assert body["client_id"] == ["my-client"]
        assert body["client_secret"] == ["my-secret"]
        assert body["redirect_uri"] == ["https://app.example.com/callback"]
        assert "code_verifier" not in body

        code_verifier, _ = oauth_generate_pkce_pair()
        await self._exchange(code_verifier=code_verifier)
        body = parse_qs(route.calls.last.request.content.decode())
        assert body["code_verifier"] == [code_verifier]

    @pytest.mark.anyio
    @respx.mock
    async def test_borrowed_client_is_reused_and_left_open(self):
        route = respx.post(self.TOKEN_URL).respond(json={"access_token": "tok123"})

        async with httpx.AsyncClient() as client:
            token = await self._exchange(client=client)
            assert token["access_token"] == "tok123"
            assert not client.is_closed
        assert route.call_count == 1

    @pytest.mark.anyio
    @respx.mock
    async def test_client_secret_basic_uses_authorization_header(self):
        route = respx.post(self.TOKEN_URL).respond(json={"access_token": "tok123"})

        await self._exchange(token_endpoint_auth_method="client_secret_basic")

        request = route.calls.last.request
        expected = base64.b64encode(b"my-client:my-secret").decode()
        assert request.headers["Authorization"] == f"Basic {expected}"
        body = parse_qs(request.content.decode())
        assert "client_secret" not in body

    @pytest.mark.anyio
    @respx.mock
    async def test_token_type(self):
        route = respx.post(self.TOKEN_URL)
        route.respond(json={"access_token": "tok123", "token_type": "Bearer"})
        assert (await self._exchange())["access_token"] == "tok123"

        for token_type in ["mac", 1]:
            route.respond(json={"access_token": "tok123", "token_type": token_type})
            with pytest.raises(OAuthExchangeError, match="unsupported token_type"):
                await self._exchange()

    @pytest.mark.anyio
    @respx.mock
    async def test_required_scopes(self):
        route = respx.post(self.TOKEN_URL)
        route.respond(json={"access_token": "tok123", "scope": "openid email profile"})
        token = await self._exchange(required_scopes="openid email")
        assert token["access_token"] == "tok123"

        route.respond(json={"access_token": "tok123", "scope": "openid"})
        with pytest.raises(OAuthExchangeError, match="required scopes"):
            await self._exchange(required_scopes="openid email profile")

        route.respond(json={"access_token": "tok123", "scope": ["openid"]})
        with pytest.raises(OAuthExchangeError, match="required scopes"):
            await self._exchange(required_scopes="openid")

    @pytest.mark.anyio
    @respx.mock
    async def test_failed_exchange_raises_exchange_error(self):
        route = respx.post(self.TOKEN_URL)
        for response in [
            httpx.Response(400, json={"error": "invalid_grant"}),
            httpx.Response(200, content=b"<html>not json</html>"),
            httpx.ConnectTimeout("connection timed out"),
        ]:
            route.mock(side_effect=[response])
            with pytest.raises(OAuthExchangeError):
                await self._exchange()


class TestFetchUserinfo:
    USERINFO_URL = "https://auth.example.com/userinfo"

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_payload_and_sends_bearer_header(self):
        route = respx.get(self.USERINFO_URL).respond(
            json={"sub": "user-1", "email": "alice@example.com"}
        )

        result = await oauth_fetch_userinfo(
            userinfo_url=self.USERINFO_URL, access_token="tok123"
        )

        assert result == {"sub": "user-1", "email": "alice@example.com"}
        assert route.calls.last.request.headers["Authorization"] == "Bearer tok123"

    @pytest.mark.anyio
    @respx.mock
    async def test_borrowed_client_is_reused_and_left_open(self):
        route = respx.get(self.USERINFO_URL).respond(json={"sub": "user-1"})

        async with httpx.AsyncClient() as client:
            for _ in range(2):
                result = await oauth_fetch_userinfo(
                    userinfo_url=self.USERINFO_URL,
                    access_token="tok123",
                    client=client,
                )
            assert result == {"sub": "user-1"}
            assert not client.is_closed
        assert route.call_count == 2

    @pytest.mark.anyio
    @respx.mock
    async def test_failed_fetch_raises_userinfo_error(self):
        route = respx.get(self.USERINFO_URL)
        for response, match in [
            (httpx.Response(500), "failed to fetch"),
            (httpx.ReadTimeout("read timed out"), None),
            (httpx.Response(200, content=b"<html>not json</html>"), "not valid JSON"),
        ]:
            route.mock(side_effect=[response])
            with pytest.raises(OAuthUserinfoError, match=match):
                await oauth_fetch_userinfo(
                    userinfo_url=self.USERINFO_URL, access_token="tok123"
                )


class TestPkce:
    def test_generate_pkce_pair(self):
        code_verifier, code_challenge = oauth_generate_pkce_pair()
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        assert code_challenge == expected
        assert 43 <= len(code_verifier) <= 128
        assert "=" not in code_challenge
        assert "+" not in code_challenge
        assert "/" not in code_challenge
        assert oauth_generate_pkce_pair() != oauth_generate_pkce_pair()

    def test_authorization_redirect_carries_the_challenge(self):
        def params(**kwargs):
            response = _authorization_redirect(**kwargs)
            return parse_qs(urlparse(response.headers["location"]).query)

        _, code_challenge = oauth_generate_pkce_pair()
        sent = params(code_challenge=code_challenge)
        assert sent["code_challenge"] == [code_challenge]
        assert sent["code_challenge_method"] == ["S256"]

        sent = params()
        assert "code_challenge" not in sent
        assert "code_challenge_method" not in sent


def _raw_state(payload) -> str:
    """Encode an arbitrary JSON payload as a state parameter."""
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


class TestDecodeStateOpenRedirectGuard:
    TOKEN = "test-state-token"
    APP = ("app.example.com",)

    def _decode(self, destination, *allowed_hosts):
        """Decode *destination*; with no allowlist argument, the default applies."""
        return self._decode_state(
            oauth_encode_state(destination, self.TOKEN), *allowed_hosts
        )

    def _decode_state(self, state, *allowed_hosts):
        kwargs = {"allowed_hosts": allowed_hosts[0]} if allowed_hosts else {}
        return oauth_decode_state(
            state, expected_state_token=self.TOKEN, fallback="/fallback", **kwargs
        )

    def test_allowed_destinations(self):
        assert self._decode("/dashboard?tab=1", ()) == "/dashboard?tab=1"
        assert self._decode("/dashboard") == "/dashboard"
        assert (
            self._decode("https://app.example.com/x", self.APP)
            == "https://app.example.com/x"
        )
        # allowed_hosts=None opts out: validation is left to the caller.
        assert (
            self._decode("https://anywhere.example.com/x", None)
            == "https://anywhere.example.com/x"
        )

    def test_rejected_destinations_fall_back(self):
        for destination, allowed in [
            ("https://app.example.com/x", ()),
            ("https://evil.example.com/x", self.APP),
            ("//evil.example.com/x", self.APP),
            # Browsers normalize "/\\evil.com" into a scheme-relative redirect.
            ("/\\evil.example.com", self.APP),
            # Browsers strip tabs/newlines, turning "/\\t/evil.com" into "//evil.com".
            ("/\t/evil.example.com", self.APP),
            ("/\n/evil.example.com", self.APP),
            ("javascript:alert(1)", self.APP),
            ("dashboard", self.APP),
            ("http://[::1", self.APP),
        ]:
            assert self._decode(destination, allowed) == "/fallback", destination

        # Secure by default: absolute destinations need an explicit allowlist.
        assert self._decode("https://anywhere.example.com/x") == "/fallback"
        for payload in [{"n": self.TOKEN, "d": {"url": "/x"}}, {"n": self.TOKEN}]:
            assert self._decode_state(_raw_state(payload)) == "/fallback"

    def test_bad_payload_raises(self):
        for payload in [{"n": 12345, "d": "/x"}, ["not", "a", "dict"]]:
            with pytest.raises(OAuthStateError):
                self._decode_state(_raw_state(payload))


class TestRequireExtra:
    def test_raises_with_install_instruction(self):
        from fastapi_multiauth._imports import require_extra

        with pytest.raises(ImportError, match=r"fastapi-multiauth\[oauth\]"):
            require_extra("httpx-oauth", "oauth")


class TestPathParity:
    """2.0: same request → same result directly and via MultiAuth.

    Any divergence between the two call modes is an authorization bug: a
    credential skipped by MultiAuth on source A could fall through to B.
    """

    def _statuses(self, source, *, headers=None, cookies=None):
        def direct(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(source)):
                return user

        def multi(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(MultiAuth(source))):
                return user

        direct_resp = TestClient(_app(direct)).get(
            "/me", headers=headers, cookies=cookies
        )
        multi_resp = TestClient(_app(multi)).get(
            "/me", headers=headers, cookies=cookies
        )
        return direct_resp, multi_resp

    def test_bearer_parity(self):
        bearer = HTTPBearerAuth(simple_validator)
        for authorization in [
            None,
            f"Bearer {VALID_TOKEN}",
            f"bearer {VALID_TOKEN}",  # SR-M3: scheme case-insensitive
            f"BEARER {VALID_TOKEN}",
            "Bearer",  # no space, no token
            "Bearer ",  # SR-M4: empty credential
            "Basic dXNlcjpwYXNz",  # different scheme
            f"Token {VALID_TOKEN}",
        ]:
            headers = {"Authorization": authorization} if authorization else None
            direct_resp, multi_resp = self._statuses(bearer, headers=headers)
            assert direct_resp.status_code == multi_resp.status_code, authorization
            if direct_resp.status_code == 200:
                assert direct_resp.json() == multi_resp.json()

        # SR-M3 regression: lowercase scheme authenticates (RFC 7235).
        direct_resp, _ = self._statuses(
            bearer, headers={"Authorization": f"bearer {VALID_TOKEN}"}
        )
        assert direct_resp.status_code == 200

    def test_bearer_prefix_parity(self):
        async def accept_all(credential: str) -> dict:
            return {"token": credential}

        bearer = HTTPBearerAuth(accept_all, prefix="user_")
        for authorization in [
            "Bearer user_abc",
            "Bearer user",  # partial prefix
            "Bearer org_abc",
        ]:
            direct_resp, multi_resp = self._statuses(
                bearer, headers={"Authorization": authorization}
            )
            assert direct_resp.status_code == multi_resp.status_code, authorization

    def test_cookie_and_api_key_parity(self):
        async def key_validator(value: str) -> dict:
            if value != "s3cr3t":
                raise UnauthorizedError()
            return {"key": value}

        cookie = APIKeyCookieAuth("session", cookie_validator)
        api_key = APIKeyHeaderAuth("X-API-Key", key_validator)
        for source, headers in [
            (cookie, None),
            (cookie, {"Cookie": "session="}),
            (cookie, {"Cookie": f"session={VALID_COOKIE}"}),
            (api_key, None),
            (api_key, {"X-API-Key": ""}),
            (api_key, {"X-API-Key": "s3cr3t"}),
        ]:
            direct_resp, multi_resp = self._statuses(source, headers=headers)
            assert direct_resp.status_code == multi_resp.status_code, headers

    def test_empty_api_key_never_reaches_validator(self):
        """SR-M4 regression: an empty header value is absent, not validated."""
        received: list[str] = []

        async def capturing(value: str) -> dict:
            received.append(value)
            return {"key": value}

        auth = APIKeyHeaderAuth("X-API-Key", capturing)
        direct_resp, multi_resp = self._statuses(auth, headers={"X-API-Key": ""})
        assert direct_resp.status_code == 401
        assert multi_resp.status_code == 401
        assert received == []


class TestMalformedAuthorizationHeader:
    """Tampering battery for the Authorization header (single path)."""

    def test_malformed_header_returns_401(self):
        client = _client(HTTPBearerAuth(simple_validator))
        for authorization in [
            "Bearer",  # scheme only
            "Bearer ",  # empty token
            "Bearer  ",  # whitespace token
            f"Bearer{VALID_TOKEN}",  # no space
            "NotBearer token",
            "",
        ]:
            response = client.get("/me", headers={"Authorization": authorization})
            assert response.status_code == 401, authorization

        response = client.get(
            "/me", headers={"Authorization": f"Bearer  {VALID_TOKEN} "}
        )
        assert response.status_code == 200

    def test_duplicate_authorization_headers_use_first(self):
        """Duplicate headers: first one wins on both paths (parity-safe)."""
        bearer = HTTPBearerAuth(simple_validator)
        headers = [
            ("Authorization", f"Bearer {VALID_TOKEN}"),
            ("Authorization", "Bearer wrong"),
        ]
        direct_status = _client(bearer).get("/me", headers=headers).status_code
        multi_status = (
            _client(MultiAuth(bearer)).get("/me", headers=headers).status_code
        )
        assert direct_status == multi_status == 200


class TestWWWAuthenticate:
    """SR-L3: 401 responses carry a WWW-Authenticate challenge (RFC 7235 §4.1)."""

    def test_bearer_challenge(self):
        client = _client(HTTPBearerAuth(simple_validator))
        for headers in [{}, {"Authorization": "Bearer wrong"}]:
            response = client.get("/me", headers=headers)
            assert response.status_code == 401
            assert response.headers["WWW-Authenticate"] == "Bearer"

        # A validator-provided WWW-Authenticate is not overwritten.
        async def strict_validator(credential: str) -> dict:
            raise UnauthorizedError(
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
            )

        response = _client(HTTPBearerAuth(strict_validator)).get(
            "/me", headers={"Authorization": "Bearer whatever"}
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    def test_api_key_401_has_no_challenge(self):
        """No registered HTTP auth scheme exists for cookies or API keys."""
        for auth in [
            APIKeyCookieAuth("session", cookie_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
        ]:
            response = _client(auth).get("/me")
            assert response.status_code == 401
            assert "WWW-Authenticate" not in response.headers

    def test_multiauth_challenge(self):
        """A 401 from the matched source carries that source's challenge."""
        for multi, headers in [
            (
                MultiAuth(
                    HTTPBearerAuth(simple_validator),
                    APIKeyCookieAuth("session", cookie_validator),
                ),
                None,
            ),
            (
                MultiAuth(
                    HTTPBearerAuth(simple_validator, prefix="user_"),
                    HTTPBearerAuth(simple_validator, prefix="org_"),
                ),
                None,
            ),
            (
                MultiAuth(
                    APIKeyCookieAuth("session", cookie_validator),
                    HTTPBearerAuth(simple_validator),
                ),
                {"Authorization": "Bearer wrong"},
            ),
        ]:
            response = _client(multi).get("/me", headers=headers)
            assert response.status_code == 401
            assert response.headers["WWW-Authenticate"] == "Bearer"


class TestHttpSemantics:
    """2.3: 401 = absent/invalid credentials, 403 = authenticated but denied."""

    def test_absent_credentials_return_401(self):
        for auth in [
            HTTPBearerAuth(simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
            MultiAuth(HTTPBearerAuth(simple_validator)),
        ]:
            assert _client(auth).get("/me").status_code == 401

    def test_forbidden_error_returns_403(self):
        """A validator can signal 'authenticated but not allowed' with 403."""

        async def admin_only(credential: str) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            raise ForbiddenError("admin role required")

        response = _client(HTTPBearerAuth(admin_only)).get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 403
        assert "WWW-Authenticate" not in response.headers


class TestOpenAPIDocumentation:
    """SR-L5 + Swagger 'Authorize' audit: every scheme is documented."""

    def _openapi(self, auth) -> dict:
        return _client(auth).get("/openapi.json").json()

    def _declared(self, spec) -> set[str]:
        return {
            name for entry in spec["paths"]["/me"]["get"]["security"] for name in entry
        }

    def test_each_scheme_documented(self):
        spec = self._openapi(HTTPBearerAuth(simple_validator))
        schemes = spec["components"]["securitySchemes"]
        assert schemes["HTTPBearer"]["scheme"] == "bearer"
        assert {"HTTPBearer": []} in spec["paths"]["/me"]["get"]["security"]

        for auth, scheme_name, location, name in [
            (
                APIKeyCookieAuth("session", cookie_validator),
                "APIKeyCookie_session",
                "cookie",
                "session",
            ),
            (
                APIKeyHeaderAuth("X-API-Key", simple_validator),
                "APIKeyHeader_X-API-Key",
                "header",
                "X-API-Key",
            ),
            (
                APIKeyQueryAuth("api_key", simple_validator),
                "APIKeyQuery_api_key",
                "query",
                "api_key",
            ),
        ]:
            scheme = self._openapi(auth)["components"]["securitySchemes"][scheme_name]
            assert scheme["type"] == "apiKey"
            assert scheme["in"] == location
            assert scheme["name"] == name

    def test_multiauth_documents_all_schemes(self):
        """SR-L5 regression: two sources of the same type keep both schemes."""
        spec = self._openapi(
            MultiAuth(
                HTTPBearerAuth(simple_validator),
                APIKeyCookieAuth("session", cookie_validator),
            )
        )
        schemes = spec["components"]["securitySchemes"]
        assert "HTTPBearer" in schemes
        assert "APIKeyCookie_session" in schemes
        assert {"HTTPBearer", "APIKeyCookie_session"} <= self._declared(spec)

        spec = self._openapi(
            MultiAuth(
                HTTPBearerAuth(
                    simple_validator, prefix="user_", scheme_name="UserToken"
                ),
                HTTPBearerAuth(simple_validator, prefix="org_", scheme_name="OrgToken"),
            )
        )
        schemes = spec["components"]["securitySchemes"]
        assert "UserToken" in schemes
        assert "OrgToken" in schemes
        assert {"UserToken", "OrgToken"} <= self._declared(spec)

        # Distinct default scheme names: both header schemes documented.
        spec = self._openapi(
            MultiAuth(
                APIKeyHeaderAuth("X-API-Key", simple_validator),
                APIKeyHeaderAuth("X-Org-Key", simple_validator),
            )
        )
        schemes = spec["components"]["securitySchemes"]
        assert schemes["APIKeyHeader_X-API-Key"]["name"] == "X-API-Key"
        assert schemes["APIKeyHeader_X-Org-Key"]["name"] == "X-Org-Key"


_DESCRIBED_SOURCES = [
    (lambda d: HTTPBasicAuth(simple_validator, description=d), "HTTPBasic"),
    (lambda d: HTTPBearerAuth(simple_validator, description=d), "HTTPBearer"),
    (
        lambda d: APIKeyHeaderAuth("X-API-Key", simple_validator, description=d),
        "APIKeyHeader_X-API-Key",
    ),
    (
        lambda d: APIKeyQueryAuth("api_key", simple_validator, description=d),
        "APIKeyQuery_api_key",
    ),
    (
        lambda d: APIKeyCookieAuth("session", cookie_validator, description=d),
        "APIKeyCookie_session",
    ),
    (
        lambda d: OAuth2PasswordBearerAuth(
            simple_validator, token_url="/token", description=d
        ),
        "OAuth2PasswordBearer",
    ),
    (
        lambda d: OAuth2AuthorizationCodeBearerAuth(
            simple_validator,
            authorization_url="https://idp.example/authorize",
            token_url="https://idp.example/token",
            description=d,
        ),
        "OAuth2AuthorizationCodeBearer",
    ),
    (
        lambda d: OpenIdConnectAuth(
            simple_validator,
            openid_connect_url="https://idp.example/.well-known/openid-configuration",
            description=d,
        ),
        "OpenIdConnect",
    ),
]


class TestSchemeDescription:
    """description= (and bearer_format=) reach the OpenAPI security scheme object."""

    @staticmethod
    def _scheme(auth, name: str) -> dict:
        return _client(auth).app.openapi()["components"]["securitySchemes"][name]

    def test_description_is_published(self):
        """A default None must not surface as \"description\": null."""
        for build, scheme_name in _DESCRIBED_SOURCES:
            scheme = self._scheme(build("Who may call this"), scheme_name)
            assert scheme["description"] == "Who may call this", scheme_name
            assert "description" not in self._scheme(build(None), scheme_name)

    def test_bearer_format_is_published(self):
        auth = HTTPBearerAuth(simple_validator, bearer_format="JWT")
        assert self._scheme(auth, "HTTPBearer")["bearerFormat"] == "JWT"
        assert "bearerFormat" not in self._scheme(
            HTTPBearerAuth(simple_validator), "HTTPBearer"
        )


class TestSchemeIsNotAPerRequestDependency:
    """Doc-only schemes reach OpenAPI without being resolved on every request."""

    def test_only_sources_after_the_first_resolve_a_scheme(self, monkeypatch):
        """The first source's scheme rides on MultiAuth's own dependency."""
        resolved: list[str] = []

        async def counting(self, request: Request) -> None:
            resolved.append(self.scheme_name)

        monkeypatch.setattr(_DocOnlyScheme, "__call__", counting)

        def call(auth) -> list[str]:
            resolved.clear()
            response = _client(auth).get(
                "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
            )
            assert response.status_code == 200
            return list(resolved)

        assert call(HTTPBearerAuth(simple_validator)) == []
        multi = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
        )
        assert call(multi) == ["APIKeyHeader_X-API-Key", "APIKeyCookie_session"]


class TestTokenHelpers:
    """2.2: store the hash, never the token."""

    def test_hash_and_verify(self):
        assert hash_token("user_abc") == hashlib.sha256(b"user_abc").hexdigest()
        assert hash_token("user_abc") != hash_token("abc")
        assert verify_token_hash("user_other", hash_token("user_secret")) is False

        bearer = HTTPBearerAuth(simple_validator, prefix="user_")
        token = bearer.generate_token()
        stored = hash_token(token)
        assert verify_token_hash(token, stored) is True
        assert not verify_token_hash(bearer.generate_token(), stored)


class TestSecurityInvariants:
    """'What's already good' from the 2026-06-09 review, locked by tests."""

    @pytest.mark.anyio
    async def test_schemes_are_documentation_only(self):
        """The OpenAPI scheme dependency never executes its own parsing.

        Covers the old auto_error=False invariant and more: even schemes that
        raise on malformed credentials regardless of auto_error (HTTPBasic)
        must be inert — extract() is the only authentication path.
        """
        request = _request(authorization="Basic !!!not-base64")
        sources = [
            HTTPBearerAuth(simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
            HTTPBasicAuth(simple_validator),
        ]
        for source in sources:
            scheme = cast(Any, source.scheme)
            assert scheme is not None
            assert await scheme(request) is None

    def test_generated_tokens_are_urlsafe_and_unique(self):
        bearer = HTTPBearerAuth(simple_validator)
        tokens = {bearer.generate_token() for _ in range(32)}
        assert len(tokens) == 32
        for token in tokens:
            assert "+" not in token and "/" not in token and "=" not in token
        assert len({oauth_generate_state_token() for _ in range(32)}) == 32

    def test_cookie_expiry_is_inside_signed_payload(self):
        """The timestamp is covered by the signature: it cannot be extended."""
        secret = COOKIE_SECRET
        auth = APIKeyCookieAuth("session", cookie_validator, secret_key=secret, ttl=60)
        signed = auth._sign(VALID_COOKIE)
        value, timestamp, signature = signed.rsplit(".", 2)
        # Replaying with a modified timestamp must fail verification.
        forged = f"{value}.{'X' + timestamp[1:]}.{signature}"
        with pytest.raises(UnauthorizedError):
            auth._verify(forged)

    @pytest.mark.anyio
    async def test_authenticate_rechecks_prefix(self):
        """Defense in depth: authenticate() itself rejects a wrong prefix."""
        bearer = HTTPBearerAuth(simple_validator, prefix="user_")
        with pytest.raises(UnauthorizedError):
            await bearer.authenticate("org_token")


# ---------------------------------------------------------------------------
# Milestone 3
# ---------------------------------------------------------------------------

_RSA_KEY_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_KEY_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid: str | None, **overrides) -> dict:
    entry = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    entry.update({"kid": kid, "alg": "RS256", "use": "sig"})
    entry.update(overrides)
    return {k: v for k, v in entry.items() if v is not None}


def _jwks_validator(jwks_url: str, **kwargs) -> JWTValidator:
    """JWKS-mode validator; tests not about ``aud`` opt out of the check."""
    kwargs.setdefault("audience", JWTValidator.ANY_AUDIENCE)
    return JWTValidator(jwks_url=jwks_url, **kwargs)


def _claims(**overrides) -> dict:
    claims = {"sub": "user-1", "exp": int(time.time()) + 300}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


JWT_SECRET = "unit-test-jwt-secret-32-bytes-min!!!"


def _hs_token(claims=None, *, secret=JWT_SECRET, **encode_kwargs) -> str:
    return pyjwt.encode(claims or _claims(), secret, algorithm="HS256", **encode_kwargs)


def _forged_token(alg: str, *, kid: str | None = "key1", claims=None) -> str:
    """Token with an attacker-chosen 'alg' header and a junk signature."""

    def segment(payload: dict) -> str:
        raw = json.dumps(payload).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    return f"{segment(header)}.{segment(claims or _claims())}.AAAA"


def _auth_client(validator) -> TestClient:
    return _client(HTTPBearerAuth(validator))


def _status(client: TestClient, token: str, path: str = "/me") -> int:
    return client.get(path, headers={"Authorization": f"Bearer {token}"}).status_code


class TestJWTValidatorConfig:
    def test_misconfiguration_rejected(self):
        cases: list[tuple[dict[str, Any], str]] = [
            (
                {"secret": JWT_SECRET, "jwks_url": "https://idp.example.com/jwks"},
                "exactly one",
            ),
            ({}, "exactly one"),
            ({"secret": "short"}, "at least 32"),
            ({"jwks_url": "http://idp.example.com/jwks"}, "jwks_url must use https"),
            # Key-confusion guard: a public key must never act as an HMAC secret.
            (
                {
                    "jwks_url": "https://idp.example.com/jwks",
                    "algorithms": ["RS256", "HS256"],
                },
                "key-confusion",
            ),
        ]
        for kwargs, match in cases:
            with pytest.raises(ValueError, match=match):
                JWTValidator(**kwargs)
        for audience in [None, "", []]:
            with pytest.raises(ValueError, match="audience is required.*ANY_AUDIENCE"):
                JWTValidator(jwks_url="https://idp.example.com/jwks", audience=audience)
        for leeway in [-1, math.inf, math.nan]:
            with pytest.raises(ValueError, match="leeway"):
                JWTValidator(secret=JWT_SECRET, leeway=leeway)

    def test_valid_configuration_accepted(self):
        _jwks_validator("http://localhost:8080/jwks")
        JWTValidator(secret=JWT_SECRET)
        assert repr(JWTValidator.ANY_AUDIENCE) == "JWTValidator.ANY_AUDIENCE"


class TestJWTValidatorSymmetric:
    def test_valid_token_returns_claims(self):
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {_hs_token()}"})
        assert response.status_code == 200
        assert response.json()["sub"] == "user-1"

    def test_time_claims(self):
        expired = _hs_token(_claims(exp=int(time.time()) - 10))
        no_exp = _hs_token(_claims(exp=None))
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        assert _status(client, expired) == 401
        assert _status(client, _hs_token(_claims(nbf=int(time.time()) + 300))) == 401
        assert _status(client, no_exp) == 401

        assert (
            _status(_auth_client(JWTValidator(secret=JWT_SECRET, leeway=30)), expired)
            == 200
        )
        client = _auth_client(JWTValidator(secret=JWT_SECRET, required_claims=()))
        assert _status(client, no_exp) == 200

    def test_bad_tokens_rejected(self):
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        assert (
            _status(client, _hs_token(secret="other-secret-key-32-bytes-minimum!!!"))
            == 401
        )
        assert _status(client, "not.a.jwt") == 401

        # An allowlisted 'alg' the secret cannot satisfy is a 401, not a 500.
        validator = JWTValidator(secret=JWT_SECRET, algorithms=["HS256", "ES256"])
        assert _status(_auth_client(validator), _forged_token("ES256", kid=None)) == 401

    def test_audience_and_issuer_verified(self):
        client = _auth_client(JWTValidator(secret=JWT_SECRET, audience="my-api"))
        assert _status(client, _hs_token(_claims(aud="my-api"))) == 200
        assert _status(client, _hs_token(_claims(aud="other-api"))) == 401

        validator = JWTValidator(secret=JWT_SECRET, issuer="https://idp.example.com")
        client = _auth_client(validator)
        assert _status(client, _hs_token(_claims(iss="https://idp.example.com"))) == 200
        assert (
            _status(client, _hs_token(_claims(iss="https://evil.example.com"))) == 401
        )

    def test_claims_to_identity_hook(self):
        async def to_identity(claims: dict) -> dict:
            return {"id": claims["sub"], "via": "async"}

        for hook, expected in [
            (lambda claims: {"id": claims["sub"].upper()}, {"id": "USER-1"}),
            (to_identity, {"id": "user-1", "via": "async"}),
        ]:
            client = _auth_client(
                JWTValidator(secret=JWT_SECRET, claims_to_identity=hook)
            )
            response = client.get(
                "/me", headers={"Authorization": f"Bearer {_hs_token()}"}
            )
            assert response.json() == expected


class TestJWTValidatorScopes:
    def test_route_scopes_checked_against_the_claim(self):
        """RFC 6750: valid token without the required scope → 403, not 401."""
        for scopes_claim, claims, expected in [
            ("scope", {"scope": "read write admin"}, 200),
            ("scope", {"scope": "read"}, 403),
            ("scp", {"scp": ["read", "admin"]}, 200),
            ("roles", {"roles": ["viewer"]}, 403),
            ("scope", {}, 403),  # no scope claim at all
        ]:
            bearer = HTTPBearerAuth(
                JWTValidator(secret=JWT_SECRET, scopes_claim=scopes_claim)
            )

            def setup(app: FastAPI, bearer=bearer):
                @app.get("/admin")
                async def admin(user=Security(bearer, scopes=["admin"])):
                    return user

            client = TestClient(_app(setup))
            assert (
                _status(client, _hs_token(_claims(**claims)), "/admin") == expected
            ), claims

        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        assert _status(client, _hs_token()) == 200


class TestJWTValidatorJWKS:
    JWKS_URL = "https://idp.example.com/jwks"

    def _rs_token(self, private_key=_RSA_KEY_1, kid="key1", claims=None, **headers):
        return pyjwt.encode(
            claims or _claims(),
            private_key,
            algorithm="RS256",
            headers={"kid": kid, **headers} if kid else headers or None,
        )

    def _validator(self, **kwargs) -> JWTValidator:
        return _jwks_validator(self.JWKS_URL, **kwargs)

    @respx.mock
    def test_audience_check(self):
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        for audience, aud, expected in [
            ("my-api", "my-api", 200),
            ("my-api", "other-client", 401),
            ("my-api", None, 401),
            (JWTValidator.ANY_AUDIENCE, "other-client", 200),
        ]:
            client = _auth_client(self._validator(audience=audience))
            token = self._rs_token(claims=_claims(aud=aud))
            assert _status(client, token) == expected, (audience, aud)

    @respx.mock
    def test_valid_rs256_token_and_jwks_cached_between_requests(self):
        route = respx.get(self.JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1")]}
        )
        client = _auth_client(self._validator())
        for _ in range(3):
            response = client.get(
                "/me", headers={"Authorization": f"Bearer {self._rs_token()}"}
            )
            assert response.status_code == 200
            assert response.json()["sub"] == "user-1"
        assert route.call_count == 1

    @respx.mock
    def test_unknown_kid_triggers_refresh_and_succeeds(self):
        """Key rotation: a new kid forces one JWKS refetch."""
        route = respx.get(self.JWKS_URL)
        route.side_effect = [
            httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1")]}),
            httpx.Response(
                200,
                json={"keys": [_jwk(_RSA_KEY_1, "key1"), _jwk(_RSA_KEY_2, "key2")]},
            ),
        ]
        client = _auth_client(self._validator(jwks_refresh_cooldown=0))

        assert _status(client, self._rs_token()) == 200
        rotated = self._rs_token(private_key=_RSA_KEY_2, kid="key2")
        assert _status(client, rotated) == 200
        assert route.call_count == 2

    @respx.mock
    def test_unknown_kid_refresh_is_rate_limited(self):
        """Unauthenticated bogus kids cannot force a JWKS fetch per request."""
        route = respx.get(self.JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1")]}
        )
        bogus = self._rs_token(private_key=_RSA_KEY_2, kid="rogue")
        assert _status(_auth_client(self._validator()), bogus) == 401

        before = route.call_count
        client = _auth_client(self._validator())  # default 30 s cooldown
        assert _status(client, self._rs_token()) == 200
        for _ in range(5):
            assert _status(client, bogus) == 401
        # The forced refresh was within the cooldown window every time.
        assert route.call_count == before + 1

    @respx.mock
    def test_key_selection(self):
        """Ambiguous key resolution fails closed; 'alg' is inferred from kty."""
        route = respx.get(self.JWKS_URL)
        for keys, token, expected in [
            ([_jwk(_RSA_KEY_1, "key1")], self._rs_token(kid=None), 200),
            (
                [_jwk(_RSA_KEY_1, "key1"), _jwk(_RSA_KEY_2, "key2")],
                self._rs_token(kid=None),
                401,
            ),
            ([_jwk(_RSA_KEY_1, "key1", alg=None)], self._rs_token(), 200),
            (
                [_jwk(_RSA_KEY_2, "key1", use="enc"), _jwk(_RSA_KEY_1, "key1")],
                self._rs_token(),
                200,
            ),
            # A symmetric token can never satisfy an asymmetric validator.
            ([_jwk(_RSA_KEY_1, "key1")], _hs_token(headers={"kid": "key1"}), 401),
        ]:
            route.respond(json={"keys": keys})
            assert _status(_auth_client(self._validator()), token) == expected, keys

    @pytest.mark.anyio
    @respx.mock
    async def test_jwks_fetch_error_cold_start_returns_503(self):
        """A broken IdP with no cached keys surfaces as 503, not a 401."""
        route = respx.get(self.JWKS_URL)
        # With nothing cached to fall back on, an unusable 200 is still 503.
        for response in [httpx.Response(500), httpx.Response(200, json={"keys": []})]:
            route.mock(side_effect=[response])
            with pytest.raises(HTTPException) as exc_info:
                await self._validator()(self._rs_token())
            assert exc_info.value.status_code == 503

    @pytest.mark.anyio
    @respx.mock
    async def test_jwks_fetch_error_falls_back_to_cached_keys(self):
        """A provider blip after cache expiry must not break validation.

        A 200 carrying no usable key is a broken provider, like a 500 is.
        """
        route = respx.get(self.JWKS_URL)
        for broken in [
            httpx.Response(500),
            httpx.Response(200, json={"keys": []}),
            httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1", use="enc")]}),
            httpx.Response(200, json={"keys": [{"kty": "RSA", "kid": "key1"}]}),
        ]:
            route.reset()
            route.side_effect = [
                httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1")]}),
                broken,
            ]
            validator = self._validator(jwks_cache_ttl=0, jwks_refresh_cooldown=0)
            token = self._rs_token()
            assert (await validator(token))["sub"] == "user-1"
            # Cache is stale (ttl=0): the refetch fails, the cached keys serve.
            assert (await validator(token))["sub"] == "user-1"
            assert route.call_count == 2

    @pytest.mark.anyio
    @respx.mock
    async def test_failed_fetch_retries_are_rate_limited(self):
        """A down provider is not hammered once per request."""
        route = respx.get(self.JWKS_URL).respond(500)
        validator = self._validator()  # default 30 s cooldown
        for _ in range(3):
            with pytest.raises(HTTPException):
                await validator(self._rs_token())
        assert route.call_count == 1


class TestBasicAuth:
    @staticmethod
    def _header(username: str, password: str) -> dict:
        blob = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {blob}"}

    @staticmethod
    async def _validator(username: str, password: str) -> dict:
        if username != "alice" or password != "wonderland":
            raise UnauthorizedError()
        return {"user": username}

    def test_authenticates_the_credentials(self):
        client = _client(HTTPBasicAuth(self._validator))
        response = client.get("/me", headers=self._header("alice", "wonderland"))
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

        blob = base64.b64encode(b"alice:wonderland").decode()
        response = client.get("/me", headers={"Authorization": f"basic {blob}"})
        assert response.status_code == 200

        response = client.get("/me")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Basic"

        for headers in [
            self._header("alice", "nope"),
            {"Authorization": "Basic !!!"},
            {"Authorization": f"Basic {base64.b64encode(b'alicewonderland').decode()}"},
            {"Authorization": "Bearer token"},
        ]:
            assert client.get("/me", headers=headers).status_code == 401, headers

    def test_credential_edge_cases_reach_the_validator(self):
        received: list[tuple[str, str]] = []

        async def capturing(username: str, password: str) -> dict:
            received.append((username, password))
            return {"user": username, "pw": password}

        client = _client(HTTPBasicAuth(capturing))
        response = client.get("/me", headers=self._header("alice", ""))
        assert response.status_code == 200
        response = client.get("/me", headers=self._header("aliçé", "pässwörd"))
        assert response.status_code == 200
        assert response.json() == {"user": "aliçé", "pw": "pässwörd"}
        assert received == [("alice", ""), ("aliçé", "pässwörd")]

    def test_realm_in_challenge(self):
        """RFC 7230 §3.2.6: the realm is a quoted-string, so it must be escaped."""
        for realm, expected in [
            ("api", 'Basic realm="api"'),
            (r'ev"il\path', r'Basic realm="ev\"il\\path"'),
            # An unescaped quote would end the quoted-string and start new params.
            ('a", charset="UTF-8', r'Basic realm="a\", charset=\"UTF-8"'),
        ]:
            client = _client(HTTPBasicAuth(self._validator, realm=realm))
            challenge = client.get("/me").headers["WWW-Authenticate"]
            assert challenge == expected
            assert "charset" not in challenge.split('"')[0]

    def test_unsendable_realm_rejected_at_construction(self):
        """h11 refuses control characters; non-ASCII cannot survive a header."""
        for realm in [
            "x\r\nX-Injected: yes",
            "x\ny",
            "a\x00b",
            "a\x7fb",
            "a\tb",
            "café",
        ]:
            with pytest.raises(ValueError, match="printable US-ASCII"):
                HTTPBasicAuth(self._validator, realm=realm)

    def test_parity_with_multiauth(self):
        auth = HTTPBasicAuth(self._validator)
        cases = [
            None,
            self._header("alice", "wonderland"),
            self._header("alice", "nope"),
            {"Authorization": "Basic !!!"},
        ]
        for headers in cases:
            direct = _client(auth).get("/me", headers=headers)
            multi = _client(MultiAuth(auth)).get("/me", headers=headers)
            assert direct.status_code == multi.status_code

        spec = _client(auth).get("/openapi.json").json()
        scheme = spec["components"]["securitySchemes"]["HTTPBasic"]
        assert scheme["type"] == "http"
        assert scheme["scheme"] == "basic"

    def test_scopes_and_require_reach_the_validator(self):
        received: list[list[str]] = []

        async def scoped(username: str, password: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": username}

        auth = HTTPBasicAuth(scoped)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get("/admin", headers=self._header("alice", "x"))
        assert response.status_code == 200
        assert received == [["admin"]]

        async def role_basic(username: str, password: str, *, role: str) -> dict:
            return {"user": username, "role": role}

        auth = HTTPBasicAuth(role_basic)
        derived = auth.require(role="admin")
        assert derived is not auth
        response = _client(derived).get("/me", headers=self._header("alice", "x"))
        assert response.json() == {"user": "alice", "role": "admin"}

    @pytest.mark.anyio
    async def test_authenticate_unscoped(self):
        async def v(username: str, password: str) -> dict:
            return {"u": username, "p": password}

        auth = HTTPBasicAuth(v)
        blob = base64.b64encode(b"alice:pw").decode()
        assert await auth.authenticate(blob) == {"u": "alice", "p": "pw"}


class TestScopesConsolidation:
    """3.1: scope enforcement follows the same path in both call modes."""

    def test_scoped_parity_direct_vs_multiauth(self):
        received: list[tuple[str, list[str]]] = []

        async def scoped_validator(credential: str, scopes: list[str]) -> dict:
            received.append(("call", scopes))
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped_validator)

        def direct(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin", "billing"])):
                return user

        def multi(app: FastAPI):
            @app.get("/admin")
            async def admin(
                user=Security(MultiAuth(bearer), scopes=["admin", "billing"]),
            ):
                return user

        headers = {"Authorization": f"Bearer {VALID_TOKEN}"}
        direct_resp = TestClient(_app(direct)).get("/admin", headers=headers)
        multi_resp = TestClient(_app(multi)).get("/admin", headers=headers)
        assert direct_resp.status_code == multi_resp.status_code == 200
        assert received == [("call", ["admin", "billing"])] * 2


class TestCallableInstanceValidator:
    """_ensure_async regression: callable instances with async __call__."""

    def test_callable_shapes(self):
        """A sync wrapper returning a coroutine is awaited transparently."""

        class AsyncValidator:
            async def __call__(self, token: str) -> dict:
                if token != VALID_TOKEN:
                    raise UnauthorizedError()
                return {"via": "async-instance"}

        class SyncValidator:
            def __call__(self, token: str) -> dict:
                return {"via": "sync-instance"}

        def factory_validator(token: str):
            return simple_validator(token)  # returns a coroutine

        for validator, expected in [
            (AsyncValidator(), {"via": "async-instance"}),
            (SyncValidator(), {"via": "sync-instance"}),
            (factory_validator, {"user": "alice"}),
        ]:
            response = _auth_client(validator).get(
                "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
            )
            assert response.status_code == 200
            assert response.json() == expected

    @pytest.mark.anyio
    async def test_sync_validator_runs_in_worker_thread(self):
        """A blocking sync validator must not run on the event loop."""
        import threading

        from fastapi_multiauth.utils import ensure_async

        loop_thread = threading.get_ident()

        def validator(token: str) -> int:
            return threading.get_ident()

        assert await ensure_async(validator)("x") != loop_thread


class TestJWTValidatorJWKSRobustness:
    JWKS_URL = "https://idp.example.com/jwks"

    def test_default_alg_for_ec_curves(self):
        from fastapi_multiauth.jwt import _default_alg

        assert _default_alg({"kty": "EC", "crv": "P-256"}) == "ES256"
        assert _default_alg({"kty": "EC", "crv": "P-384"}) == "ES384"
        assert _default_alg({"kty": "EC", "crv": "P-521"}) == "ES512"
        assert _default_alg({"kty": "RSA"}) == "RS256"
        assert _default_alg({"kty": "OKP"}) is None
        assert _default_alg({}) is None

    @respx.mock
    def test_unusable_jwks_entries_never_break_valid_keys(self):
        """Broken or exotic entries in the JWKS never break valid keys.

        A kid-less token still finds the one key the validator can use.
        """
        route = respx.get(self.JWKS_URL)
        with_kid = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="RS256", headers={"kid": "key1"}
        )
        for keys, token in [
            (
                [
                    {"kty": "RSA", "alg": "RS256", "kid": "broken"},  # missing n/e
                    {"kty": "OKP", "kid": "exotic"},  # no alg, none inferable
                    "garbage",  # not even an object
                    42,
                    {"kty": "RSA", "alg": "RS256", "n": "AA", "e": "AQAB"},
                    {"kty": "RSA", "alg": "RS256", "n": 12345, "e": "AQAB"},
                    {"kty": "EC", "alg": "ES256", "crv": "P-256", "x": 1, "y": 2},
                    {"kty": "oct", "alg": "none", "k": "AA"},
                    _jwk(_RSA_KEY_1, "key1"),
                ],
                with_kid,
            ),
            (
                [_jwk(_RSA_KEY_1, None), _jwk(_RSA_KEY_2, None, alg="PS256")],
                pyjwt.encode(_claims(), _RSA_KEY_1, algorithm="RS256"),
            ),
        ]:
            route.respond(json={"keys": keys})
            client = _auth_client(_jwks_validator(self.JWKS_URL))
            assert _status(client, token) == 200

    @respx.mock
    def test_alg_header_must_match_the_jwks_key(self):
        """A cross-family 'alg' header against an RSA JWKS key is a 401, not a 500.

        An allowlisted alg other than the key's own is refused (PS256 vs RS256).
        """
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        client = _auth_client(_jwks_validator(self.JWKS_URL))
        assert _status(client, "not.a.jwt") == 401
        # A garbage token is rejected before any JWKS lookup.
        assert len(respx.calls) == 0
        assert _status(client, _forged_token("ES256")) == 401

        client = _auth_client(
            _jwks_validator(self.JWKS_URL, algorithms=["RS256", "PS256"])
        )
        token = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="PS256", headers={"kid": "key1"}
        )
        assert _status(client, token) == 401

    @pytest.mark.anyio
    @respx.mock
    async def test_unusable_jwks_document_returns_503(self):
        route = respx.get(self.JWKS_URL)
        token = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="RS256", headers={"kid": "key1"}
        )
        for document in [["not", "an", "object"], {"keys": "nope"}]:
            route.respond(json=document)
            with pytest.raises(HTTPException) as exc_info:
                await _jwks_validator(self.JWKS_URL)(token)
            assert exc_info.value.status_code == 503


class TestJWKSRefreshCoalescing:
    JWKS_URL = "https://idp.example.com/jwks"

    @pytest.mark.anyio
    @respx.mock
    async def test_concurrent_stale_refreshes_coalesce(self):
        """Two requests hitting a stale cache produce a single JWKS fetch.

        With no cooldown, the waiter still skips the fetch it waited behind.
        """
        import asyncio

        async def slow_jwks(request):
            await asyncio.sleep(0.05)
            return httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1")]})

        route = respx.get(self.JWKS_URL).mock(side_effect=slow_jwks)
        token = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="RS256", headers={"kid": "key1"}
        )
        for kwargs in [{}, {"jwks_refresh_cooldown": 0}]:
            route.reset()
            validator = _jwks_validator(self.JWKS_URL, **kwargs)
            first, second = await asyncio.gather(validator(token), validator(token))
            assert first["sub"] == second["sub"] == "user-1"
            assert route.call_count == 1


def test_multiauth_scopes_fail_closed_on_every_credential():
    """A source that cannot check scopes must not depend on which credential arrives."""

    def scoped(credential: str, scopes: list[str]) -> dict:
        if not set(scopes) <= {"admin"}:
            raise ForbiddenError()
        return {"who": credential}

    def unscoped(credential: str) -> dict:
        return {"who": credential}

    strong = HTTPBearerAuth(scoped)
    weak = APIKeyHeaderAuth("X-Legacy", unscoped)
    mixed = MultiAuth(strong, weak)

    def routes(app):
        @app.get("/scoped")
        async def scoped_route(user=Security(mixed, scopes=["admin"])):
            return user

        @app.get("/plain")
        async def plain_route(user=Security(mixed)):
            return user

    client = TestClient(_app(routes))

    # Both credentials fail the scoped route, not just the one that cannot check.
    with pytest.raises(RuntimeError, match="cannot enforce the security scopes"):
        client.get("/scoped", headers={"Authorization": "Bearer a"})
    with pytest.raises(RuntimeError, match="cannot enforce the security scopes"):
        client.get("/scoped", headers={"X-Legacy": "a"})

    # A route declaring no scopes is unaffected: mixing sources stays legal.
    assert client.get("/plain", headers={"Authorization": "Bearer a"}).json() == {
        "who": "a"
    }
    assert client.get("/plain", headers={"X-Legacy": "a"}).json() == {"who": "a"}


def test_multiauth_scopes_pass_when_every_source_can_check():
    def scoped(credential: str, scopes: list[str]) -> dict:
        if not set(scopes) <= {"admin"}:
            raise ForbiddenError()
        return {"who": credential}

    auth = MultiAuth(HTTPBearerAuth(scoped), APIKeyHeaderAuth("X-Key", scoped))

    def routes(app):
        @app.get("/scoped")
        async def scoped_route(user=Security(auth, scopes=["admin"])):
            return user

        @app.get("/denied")
        async def denied_route(user=Security(auth, scopes=["other"])):
            return user

    client = TestClient(_app(routes))
    assert client.get("/scoped", headers={"Authorization": "Bearer a"}).json() == {
        "who": "a"
    }
    assert client.get("/scoped", headers={"X-Key": "a"}).json() == {"who": "a"}
    assert client.get("/denied", headers={"X-Key": "a"}).status_code == 403


class TestOptionalAuth:
    """optional(): absent credential yields None, invalid one still raises."""

    @staticmethod
    def _routes(auth):
        def setup(app: FastAPI):
            @app.get("/maybe")
            async def maybe(user=Security(auth.optional())):
                return {"user": user}

            @app.get("/strict")
            async def strict(user=Security(auth)):
                return {"user": user}

        return setup

    def test_optional_bearer(self):
        app = _app(self._routes(HTTPBearerAuth(simple_validator)))
        client = TestClient(app)

        assert client.get("/maybe").json() == {"user": None}
        assert (
            client.get("/maybe", headers={"Authorization": "Bearer wrong"}).status_code
            == 401
        )
        response = client.get(
            "/maybe", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.json() == {"user": {"user": "alice"}}
        # The original source stays strict.
        assert client.get("/strict").status_code == 401

        schema = app.openapi()["paths"]["/maybe"]["get"]
        assert schema["security"] == [{"HTTPBearer": []}]

    def test_multiauth_none_only_when_no_source_matches(self):
        auth = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
        )
        client = TestClient(_app(self._routes(auth)))

        assert client.get("/maybe").json() == {"user": None}
        assert client.get("/maybe", headers={"X-API-Key": VALID_TOKEN}).json() == {
            "user": {"user": "alice"}
        }
        assert client.get("/maybe", headers={"X-API-Key": "wrong"}).status_code == 401

    def test_scoped_optional_route_fails_for_every_caller(self):
        """An anonymous caller cannot satisfy scopes, so the combination is refused."""

        def scoped(credential: str, scopes: list[str]) -> dict:
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped)
        # MultiAuth refuses the combination before any source is tried.
        multi = MultiAuth(HTTPBearerAuth(scoped), APIKeyHeaderAuth("X-API-Key", scoped))

        # Scopes reach a nested optional() source via SecurityScopes, not the top edge.
        def repository(user=Security(bearer.optional())):
            return {"repo": user}

        def setup(app: FastAPI):
            @app.get("/bearer")
            async def r1(user=Security(bearer.optional(), scopes=["admin"])):
                return user

            @app.get("/multi")
            async def r2(user=Security(multi.optional(), scopes=["admin"])):
                return user

            @app.get("/nested")
            async def r3(repo=Security(repository, scopes=["admin"])):
                return repo

        client = TestClient(_app(setup))
        bearer_header = {"Authorization": f"Bearer {VALID_TOKEN}"}
        for path, headers, match in [
            ("/bearer", None, "security scopes"),
            ("/bearer", bearer_header, "security scopes"),
            ("/multi", None, r"optional\(\) but this route"),
            ("/multi", {"X-API-Key": VALID_TOKEN}, r"optional\(\) but this route"),
            ("/nested", bearer_header, "security scopes"),
            ("/nested", None, "security scopes"),
        ]:
            with pytest.raises(RuntimeError, match=match):
                client.get(path, headers=headers)

    def test_optional_survives_require_in_either_order(self):
        """require() rebuilds a MultiAuth, which must not silently drop optional()."""
        auth = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyHeaderAuth("X-API-Key", simple_validator),
        )

        for source in (auth.optional().require(), auth.require().optional()):

            def setup(app: FastAPI, source=source):
                @app.get("/maybe")
                async def maybe(user=Security(source)):
                    return {"user": user}

            assert TestClient(_app(setup)).get("/maybe").json() == {"user": None}

    def test_require_and_optional_compose_in_either_order(self):
        """Anonymous is allowed, but a credential that is sent must still qualify."""
        kinds = {"svc": "service", "usr": "user"}

        def validate(token: str, kind: str | None = None) -> dict:
            actual = kinds.get(token)
            if actual is None:
                raise UnauthorizedError()
            if kind is not None and actual != kind:
                raise ForbiddenError()
            return {"kind": actual}

        bearer = HTTPBearerAuth(validate)

        for source in (
            bearer.require(kind="service").optional(),
            bearer.optional().require(kind="service"),
        ):

            def setup(app: FastAPI, source=source):
                @app.get("/status")
                async def status(caller=Security(source)):
                    return {"caller": caller}

            client = TestClient(_app(setup))
            bearer_header = {"Authorization": "Bearer svc"}

            assert client.get("/status").json() == {"caller": None}
            assert client.get("/status", headers=bearer_header).json() == {
                "caller": {"kind": "service"}
            }
            assert (
                client.get(
                    "/status", headers={"Authorization": "Bearer usr"}
                ).status_code
                == 403
            )
            assert (
                client.get(
                    "/status", headers={"Authorization": "Bearer nope"}
                ).status_code
                == 401
            )


class TestAuthenticatedAtHook:
    """The instant a source reports for fresh(), read directly."""

    def test_authenticated_at(self):
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )
        instant = auth.authenticated_at(auth._sign(VALID_COOKIE))
        assert instant is not None
        assert abs(instant - time.time()) < 5

        # A source that cannot date the credential reports no instant.
        assert auth.authenticated_at("forged") is None
        unsigned = APIKeyCookieAuth("session", cookie_validator)
        assert unsigned.authenticated_at(VALID_COOKIE) is None
        assert _HeaderAuth(secret="s3cr3t").authenticated_at("s3cr3t") is None

    def test_a_custom_source_dates_and_levels_its_own_credentials(self):
        """Overriding the readers lets fresh() and stepped_up() run without one."""
        proven = {
            "recent": (time.time(), "mfa"),
            "old": (time.time() - 600, "mfa"),
            "weak": (time.time(), "pwd"),
        }

        class _ProvenAuth(_HeaderAuth):
            async def authenticate(self, credential: str) -> dict:
                if credential not in proven:
                    raise UnauthorizedError()
                return {"token": credential}

            def authenticated_at(self, credential: str) -> float:
                return proven[credential][0]

            def authenticated_acr(self, credential: str) -> str:
                return proven[credential][1]

        client = _client(_ProvenAuth("unused").fresh(300).stepped_up(["mfa"]))
        for token, status in [("recent", 200), ("old", 401), ("weak", 401)]:
            response = client.get("/me", headers={"X-Token": token})
            assert response.status_code == status, token


class TestFreshness:
    """fresh(): a credential proven too long ago gets an RFC 9470 step-up 401."""

    STEP_UP: ClassVar[str] = (
        'Bearer error="insufficient_user_authentication", '
        'error_description="More recent authentication is required", '
        'max_age="300"'
    )
    BEARER: ClassVar[dict[str, str]] = {"Authorization": f"Bearer {VALID_TOKEN}"}

    @staticmethod
    def _cookie(**kwargs) -> APIKeyCookieAuth:
        return APIKeyCookieAuth(
            "session",
            cookie_validator,
            secret_key=COOKIE_SECRET,
            secure=False,
            **kwargs,
        )

    @staticmethod
    def _routes(auth, dep):
        def setup(app: FastAPI):
            @app.get("/sensitive")
            async def sensitive(user=Security(dep)):
                return {"user": user}

            @app.get("/me")
            async def me(user=Security(auth)):
                return {"user": user}

        return setup

    def _client(self, auth, max_age: float = 300, **kwargs) -> TestClient:
        return TestClient(_app(self._routes(auth, auth.fresh(max_age, **kwargs))))

    @staticmethod
    def _dated_bearer(proven_at) -> HTTPBearerAuth:
        """A bearer source whose identity carries when the factor was proven."""

        async def validate(token: str) -> dict:
            return {**await simple_validator(token), "proven_at": proven_at}

        return HTTPBearerAuth(validate)

    def _probe_client(self, proven_at, **kwargs) -> TestClient:
        """Guarded client whose window is read off the identity."""
        return self._client(
            self._dated_bearer(proven_at),
            authenticated_at=lambda identity: identity["proven_at"],
            **kwargs,
        )

    def _get(self, client: TestClient):
        """The guarded route, reached with the standard bearer token."""
        return client.get("/sensitive", headers=self.BEARER)

    @staticmethod
    def _later(seconds: float = 600):
        """Move the clock past the 300s window."""
        return patch("time.time", return_value=time.time() + seconds)

    def test_cookie_freshness(self):
        """The apiKey scheme has none to carry, so the body holds the signal.

        Freshness gates the sensitive route, it does not end the session.
        """
        auth = self._cookie()
        client = self._client(auth)
        signed = auth._sign(VALID_COOKIE)

        response = client.get("/sensitive", cookies={"session": signed})
        assert response.status_code == 200
        assert response.json() == {"user": {"session": VALID_COOKIE}}

        with self._later():
            response = client.get("/sensitive", cookies={"session": signed})
            assert client.get("/me", cookies={"session": signed}).status_code == 200

        assert response.status_code == 401
        assert response.json()["detail"] == "Insufficient user authentication"
        assert "WWW-Authenticate" not in response.headers

        # The sid payload layout does not hide the timestamp.
        auth = APIKeyCookieAuth(
            "session",
            sid_validator,
            secret_key=COOKIE_SECRET,
            session_id=True,
            secure=False,
        )
        client = self._client(auth)
        signed = auth._sign(f"sid123.{VALID_COOKIE}")

        assert client.get("/sensitive", cookies={"session": signed}).status_code == 200
        with self._later():
            assert (
                client.get("/sensitive", cookies={"session": signed}).status_code == 401
            )

    def test_the_re_auth_loop_restores_freshness(self):
        """set_cookie mints a new instant, so re-auth fixes the 401 without a login."""
        auth = self._cookie()

        def setup(app: FastAPI):
            @app.post("/re-auth")
            async def re_auth(response: Response):
                auth.set_cookie(response, VALID_COOKIE)
                return {"ok": True}

            @app.get("/sensitive")
            async def sensitive(user=Security(auth.fresh(300))):
                return {"user": user}

        client = TestClient(_app(setup))
        client.cookies.set("session", auth._sign(VALID_COOKIE))

        with self._later():
            assert client.get("/sensitive").status_code == 401
            assert client.post("/re-auth").status_code == 200
            assert client.get("/sensitive").status_code == 200

    def test_an_invalid_credential_is_not_reported_as_stale(self):
        """A credential that does not validate is refused as invalid: re-auth
        would not help it."""
        client = self._client(self._cookie())
        response = client.get("/sensitive", cookies={"session": "forged"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized"

        client = self._probe_client(time.time() - 600)
        response = client.get("/sensitive", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized"
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_a_stale_bearer_gets_the_step_up_challenge(self):
        response = self._get(self._probe_client(time.time() - 600))

        assert response.status_code == 401
        assert response.json()["detail"] == "Insufficient user authentication"
        assert response.headers["WWW-Authenticate"] == self.STEP_UP

    def test_a_realm_stays_inside_its_quoted_string(self):
        """RFC 7235: further auth-params follow a comma, and RFC 7230 §3.2.6:
        the escaped realm cannot terminate the quoted-string."""

        async def validate(username: str, password: str) -> dict:
            return {"user": username, "proven_at": time.time() - 600}

        for realm, expected_prefix in [
            ("api", 'Basic realm="api", '),
            ('api", max_age="99999', 'Basic realm="api\\", max_age=\\"99999", '),
        ]:
            basic = HTTPBasicAuth(validate, realm=realm)
            client = self._client(
                basic, authenticated_at=lambda identity: identity["proven_at"]
            )
            challenge = client.get(
                "/sensitive", headers=TestBasicAuth._header("alice", "pw")
            ).headers["WWW-Authenticate"]
            assert challenge.startswith(expected_prefix)
            assert challenge.endswith('max_age="300"')

    def test_a_probe_may_report_any_instant_shape(self):
        for shape in [
            lambda at: at,
            int,
            lambda at: datetime.fromtimestamp(at, UTC),
            # A naive datetime is read as UTC.
            lambda at: datetime.fromtimestamp(at, UTC).replace(tzinfo=None),
        ]:
            for age, status in [(0, 200), (600, 401)]:
                instant = shape(time.time() - age)
                assert self._get(self._probe_client(instant)).status_code == status

        bearer = self._dated_bearer(time.time())

        async def proven_at(identity) -> float:
            return identity["proven_at"]

        client = self._client(bearer, authenticated_at=proven_at)
        assert self._get(client).status_code == 200

    def test_an_unusable_instant_fails_closed(self):
        """No instant means not fresh, never 'assume fresh'."""
        for instant in [None, "yesterday", True, math.nan, math.inf, 10**400]:
            assert self._get(self._probe_client(instant)).status_code == 401, instant

    def test_leeway_tolerates_clock_skew_either_way(self):
        """A skewed clock cannot keep a credential fresh indefinitely."""
        for offset, leeway, status in [
            (-310, 0, 401),
            (-310, 30, 200),
            (20, 0, 401),
            (20, 30, 200),
            (365 * 86400, 30, 401),
        ]:
            client = self._probe_client(time.time() + offset, leeway=leeway)
            assert self._get(client).status_code == status, (offset, leeway)

    def test_a_source_that_cannot_date_a_credential_refuses_fresh(self):
        for auth in [
            HTTPBearerAuth(simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
        ]:
            with pytest.raises(ValueError, match="cannot date a credential"):
                auth.fresh(300)

        # A source that cannot be dated would be the way around the window.
        auth = MultiAuth(self._cookie(), HTTPBearerAuth(simple_validator))
        with pytest.raises(
            ValueError, match=r"HTTPBearerAuth cannot date.*fresh\(\) on each source"
        ):
            auth.fresh(300)

    def test_the_window_is_validated(self):
        cases: list[tuple[dict[str, Any], str]] = [
            ({"max_age": 0}, "max_age must be a positive"),
            ({"max_age": math.nan}, "max_age must be a positive"),
            ({"max_age": math.inf}, "max_age must be a positive"),
            ({"max_age": 300, "leeway": -1}, "leeway must be a finite, non-negative"),
            (
                {"max_age": 300, "leeway": math.nan},
                "leeway must be a finite, non-negative",
            ),
            (
                {"max_age": 300, "leeway": math.inf},
                "leeway must be a finite, non-negative",
            ),
        ]
        for kwargs, message in cases:
            with pytest.raises(ValueError, match=message):
                self._cookie().fresh(**kwargs)

        with pytest.raises(ValueError, match="already has a freshness window"):
            self._cookie().fresh(60).fresh(300)

        auth = MultiAuth(self._cookie().fresh(60), self._dated_bearer(time.time()))
        with pytest.raises(
            ValueError, match="APIKeyCookieAuth already has a freshness window"
        ):
            auth.fresh(300, authenticated_at=lambda identity: identity["proven_at"])

    def test_fresh_and_optional_are_refused_in_either_order(self):
        for auth in [self._cookie(), MultiAuth(self._cookie())]:
            with pytest.raises(ValueError, match="cannot be both optional"):
                auth.fresh(300).optional()
            with pytest.raises(ValueError, match="cannot be both optional"):
                auth.optional().fresh(300)

    def test_fresh_and_require_compose_in_either_order(self):
        def validate(value: str, *, role: str) -> dict:
            return {"session": value, "role": role}

        auth = APIKeyCookieAuth(
            "session", validate, secret_key=COOKIE_SECRET, secure=False
        )
        signed = auth._sign(VALID_COOKIE)
        for composed in [
            auth.fresh(300).require(role="admin"),
            auth.require(role="admin").fresh(300),
        ]:
            client = TestClient(_app(self._routes(auth, composed)))
            response = client.get("/sensitive", cookies={"session": signed})
            assert response.json() == {
                "user": {"session": VALID_COOKIE, "role": "admin"}
            }
            with self._later():
                response = client.get("/sensitive", cookies={"session": signed})
                assert response.status_code == 401

    def test_openapi_still_declares_the_scheme(self):
        auth = self._cookie()
        app = _app(self._routes(auth, auth.fresh(300)))

        assert app.openapi()["paths"]["/sensitive"]["get"]["security"] == [
            {"APIKeyCookie_session": []}
        ]

    def test_the_window_reaches_an_exception_handler(self):
        """A handler rendering its own body reads max_age instead of the message.

        Existing 401 handling keeps catching it.
        """
        assert issubclass(StaleCredentialError, UnauthorizedError)
        assert StaleCredentialError().status_code == 401
        assert StaleCredentialError().max_age is None

        auth = self._cookie()
        app = _app(self._routes(auth, auth.fresh(300)))

        @app.exception_handler(StaleCredentialError)
        async def handler(request: Request, exc: StaleCredentialError):
            return JSONResponse({"reauth_within": exc.max_age}, status_code=401)

        client = TestClient(app)
        signed = auth._sign(VALID_COOKIE)

        with self._later():
            response = client.get("/sensitive", cookies={"session": signed})

        assert response.json() == {"reauth_within": 300}

    def test_multiauth_enforces_freshness_on_the_matched_source(self):
        cookie = self._cookie()
        other = APIKeyCookieAuth(
            "admin_session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )
        client = self._client(MultiAuth(cookie, other))
        signed = cookie._sign(VALID_COOKIE)

        assert client.get("/sensitive", cookies={"session": signed}).status_code == 200
        with self._later():
            assert (
                client.get("/sensitive", cookies={"session": signed}).status_code == 401
            )

        # A probe can date every source, so fresh() accepts the mix.
        auth = MultiAuth(self._dated_bearer(time.time() - 600), self._cookie())
        client = self._client(
            auth, authenticated_at=lambda identity: identity.get("proven_at")
        )
        response = self._get(client)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == self.STEP_UP


class TestFreshnessWithJWT:
    """The OIDC auth_time claim is the instant for a JWT, not iat."""

    def test_auth_time_dates_the_login(self):
        """iat is not a substitute: it dates the token, not the login."""
        client = _client(
            HTTPBearerAuth(JWTValidator(secret=JWT_SECRET)).fresh(
                300, authenticated_at=lambda claims: claims.get("auth_time")
            )
        )
        recent = _hs_token(_claims(auth_time=int(time.time()) - 10))
        assert _status(client, recent) == 200
        assert _status(client, _hs_token(_claims(iat=int(time.time())))) == 401

        old = _hs_token(_claims(auth_time=int(time.time()) - 600))
        response = client.get("/me", headers={"Authorization": f"Bearer {old}"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Insufficient user authentication"
        assert response.headers["WWW-Authenticate"] == TestFreshness.STEP_UP


class TestOAuth2Sources:
    """The oauth2/OIDC sources: bearer extraction, oauth2 OpenAPI metadata."""

    SCOPES: ClassVar[dict[str, str]] = {
        "admin": "Administer everything",
        "billing": "Read invoices",
    }

    def _password(self, validator=None):
        return OAuth2PasswordBearerAuth(
            validator or simple_validator, token_url="/token", scopes=self.SCOPES
        )

    def test_password_bearer(self):
        client = _client(self._password())
        assert client.get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        ).json() == {"user": "alice"}
        assert (
            client.get("/me", headers={"Authorization": "Bearer wrong"}).status_code
            == 401
        )
        assert client.get("/me").status_code == 401

        schemes = client.app.openapi()["components"]["securitySchemes"]
        assert schemes["OAuth2PasswordBearer"] == {
            "type": "oauth2",
            "flows": {"password": {"scopes": self.SCOPES, "tokenUrl": "/token"}},
        }

    def test_authorization_code_and_openid_connect_publish_their_flows(self):
        auth = OAuth2AuthorizationCodeBearerAuth(
            simple_validator,
            authorization_url="https://idp.example/authorize",
            token_url="https://idp.example/token",
            refresh_url="https://idp.example/refresh",
            scopes=self.SCOPES,
        )

        client = _client(auth)
        scheme = client.app.openapi()["components"]["securitySchemes"][
            "OAuth2AuthorizationCodeBearer"
        ]
        assert scheme["type"] == "oauth2"
        assert scheme["flows"]["authorizationCode"] == {
            "authorizationUrl": "https://idp.example/authorize",
            "tokenUrl": "https://idp.example/token",
            "refreshUrl": "https://idp.example/refresh",
            "scopes": self.SCOPES,
        }
        assert client.get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        ).json() == {"user": "alice"}

        auth = OpenIdConnectAuth(
            simple_validator,
            openid_connect_url="https://idp.example/.well-known/openid-configuration",
        )

        client = _client(auth)
        assert client.app.openapi()["components"]["securitySchemes"][
            "OpenIdConnect"
        ] == {
            "type": "openIdConnect",
            "openIdConnectUrl": "https://idp.example/.well-known/openid-configuration",
        }

        # The raw header would be "Bearer <token>"; the source hands over the token.
        assert client.get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        ).json() == {"user": "alice"}
        assert (
            client.get("/me", headers={"Authorization": VALID_TOKEN}).status_code == 401
        )

    def test_scopes_reach_the_validator_and_appear_on_the_route(self):
        received: list[list[str]] = []

        def scoped(credential: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": "alice"}

        auth = self._password(scoped)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        app = _app(setup)
        response = TestClient(app).get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert received == [["admin"]]
        assert app.openapi()["paths"]["/admin"]["get"]["security"] == [
            {"OAuth2PasswordBearer": ["admin"]}
        ]

    def test_composes_with_multiauth_and_optional(self):
        auth = MultiAuth(
            self._password(), APIKeyHeaderAuth("X-API-Key", simple_validator)
        )

        def setup(app: FastAPI):
            @app.get("/maybe")
            async def maybe(user=Security(auth.optional())):
                return {"user": user}

        client = TestClient(_app(setup))
        assert client.get("/maybe").json() == {"user": None}
        assert client.get("/maybe", headers={"X-API-Key": VALID_TOKEN}).json() == {
            "user": {"user": "alice"}
        }
        assert client.get(
            "/maybe", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        ).json() == {"user": {"user": "alice"}}

    def test_route_scope_outside_the_catalogue_is_refused(self):
        """A published catalogue is a claim: a typo must not reach the validator.

        The misconfiguration must surface for anonymous callers too.
        """
        seen: list[list[str]] = []

        def scoped(credential: str, scopes: list[str]) -> dict:
            seen.append(scopes)
            return {"user": "alice"}

        auth = self._password(scoped)
        multi = MultiAuth(self._password(), APIKeyHeaderAuth("X-Key", simple_validator))

        def setup(app: FastAPI):
            @app.get("/typo")
            async def typo(user=Security(auth, scopes=["admni"])):
                return user

            @app.get("/known")
            async def known(user=Security(auth, scopes=["admin", "billing"])):
                return user

            @app.get("/multi-typo")
            async def multi_typo(user=Security(multi, scopes=["admni"])):
                return user

        client = TestClient(_app(setup))
        header = {"Authorization": f"Bearer {VALID_TOKEN}"}

        for headers in [header, None]:
            with pytest.raises(
                RuntimeError, match="does not publish the security scopes"
            ):
                client.get("/typo", headers=headers)
        with pytest.raises(RuntimeError, match="does not publish the security scopes"):
            client.get("/multi-typo", headers={"X-Key": VALID_TOKEN})
        assert seen == [], "the validator must never see an undeclared scope"

        assert client.get("/known", headers=header).status_code == 200
        assert seen == [["admin", "billing"]]

    def test_a_source_without_a_catalogue_accepts_any_scope(self):
        """No catalogue is no claim: the other sources keep working unchanged."""

        def scoped(credential: str, scopes: list[str]) -> dict:
            return {"scopes": scopes}

        for auth in (
            HTTPBearerAuth(scoped),
            OpenIdConnectAuth(
                scoped, openid_connect_url="https://idp.example/.well-known"
            ),
            OAuth2PasswordBearerAuth(scoped, token_url="/token"),
        ):

            def setup(app: FastAPI, auth=auth):
                @app.get("/anything")
                async def anything(user=Security(auth, scopes=["whatever"])):
                    return user

            response = TestClient(_app(setup)).get(
                "/anything", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
            )
            assert response.json() == {"scopes": ["whatever"]}


class TestWebSocket:
    """Sources guard WebSocket routes: the handshake is the request."""

    @staticmethod
    def _client(auth) -> TestClient:
        def setup(app: FastAPI):
            @app.websocket("/ws")
            async def ws(websocket: WebSocket, user=Security(auth)):
                await websocket.accept()
                await websocket.send_json({"user": user})
                await websocket.close()

        return TestClient(_app(setup))

    @staticmethod
    def _denial(client: TestClient, **kwargs) -> WebSocketDenialResponse:
        with (
            pytest.raises(WebSocketDenialResponse) as exc_info,
            client.websocket_connect("/ws", **kwargs),
        ):
            pass
        return exc_info.value

    def test_the_handshake_is_authenticated(self):
        client = self._client(HTTPBearerAuth(simple_validator))

        with client.websocket_connect(
            "/ws", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        ) as websocket:
            assert websocket.receive_json() == {"user": {"user": "alice"}}

        for headers in [{}, {"Authorization": "Bearer wrong"}]:
            denial = self._denial(client, headers=headers)
            assert denial.status_code == 401
            assert denial.headers["WWW-Authenticate"] == "Bearer"

        async def validator(credential: str) -> dict:
            raise ForbiddenError()

        denial = self._denial(
            self._client(HTTPBearerAuth(validator)),
            headers={"Authorization": f"Bearer {VALID_TOKEN}"},
        )
        assert denial.status_code == 403

    def test_multiauth(self):
        auth = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyQueryAuth("api_key", simple_validator),
        )
        with self._client(auth).websocket_connect(
            f"/ws?api_key={VALID_TOKEN}"
        ) as websocket:
            assert websocket.receive_json() == {"user": {"user": "alice"}}

        auth = MultiAuth(
            HTTPBearerAuth(simple_validator), HTTPBasicAuth(simple_validator)
        )
        denial = self._denial(self._client(auth))
        assert denial.status_code == 401
        assert denial.headers["WWW-Authenticate"] == "Bearer, Basic"

    def test_optional_and_cookie_sources(self):
        client = self._client(HTTPBearerAuth(simple_validator).optional())
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_json() == {"user": None}

        client = self._client(APIKeyCookieAuth("session", cookie_validator))
        with client.websocket_connect(
            "/ws", headers={"Cookie": f"session={VALID_COOKIE}"}
        ) as websocket:
            assert websocket.receive_json() == {"user": {"session": VALID_COOKIE}}

    def test_scopes_and_the_websocket_reach_the_validator(self):
        seen: list[object] = []

        async def validator(credential: str, scopes: list[str], request=None) -> dict:
            seen.append(request)
            return {"scopes": scopes}

        bearer = HTTPBearerAuth(validator)

        def setup(app: FastAPI):
            @app.websocket("/ws")
            async def ws(websocket: WebSocket, user=Security(bearer, scopes=["chat"])):
                await websocket.accept()
                await websocket.send_json(user)
                await websocket.close()

        client = TestClient(_app(setup))
        with client.websocket_connect(
            "/ws", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        ) as websocket:
            assert websocket.receive_json() == {"scopes": ["chat"]}

        assert len(seen) == 1
        assert isinstance(seen[0], WebSocket)


class TestAuthSurface:
    """`auth_surface()` answers what guards what, from the routes themselves."""

    @staticmethod
    def _scoped(credential: str, scopes: list[str]) -> dict:
        return {"user": "alice", "scopes": scopes}

    def _oauth(self) -> OAuth2PasswordBearerAuth:
        return OAuth2PasswordBearerAuth(
            self._scoped,
            token_url="/token",
            scopes={"admin": "Admin", "billing": "Billing"},
        )

    @staticmethod
    def _find(app: FastAPI, path: str):
        found = [route for route in auth_surface(app) if route.path == path]
        assert len(found) == 1, f"{path} not reported exactly once: {found}"
        return found[0]

    def test_an_unguarded_route_is_reported_as_unguarded(self):
        def setup(app: FastAPI):
            @app.get("/open")
            async def open_route():
                return {}

        route = self._find(_app(setup), "/open")
        assert route.unguarded is True
        assert route.alternatives == ()
        assert route.scopes == ()
        assert route.methods == ("GET",)

        paths = [route.path for route in auth_surface(_app())]
        assert paths == [], f"only endpoint routes belong in the surface: {paths}"

    def test_a_route_hidden_from_the_schema_is_still_reported(self):
        """The OpenAPI document omits it, which is why the walk uses app.routes."""
        auth = self._oauth()

        def setup(app: FastAPI):
            @app.get("/hidden", include_in_schema=False)
            async def hidden():
                return {}

            @app.get("/hidden-guarded", include_in_schema=False)
            async def hidden_guarded(user=Security(auth)):
                return {}

        app = _app(setup)
        assert "/hidden" not in app.openapi()["paths"]

        hidden = self._find(app, "/hidden")
        assert hidden.include_in_schema is False
        assert hidden.unguarded is True

        guarded = self._find(app, "/hidden-guarded")
        assert guarded.include_in_schema is False
        assert guarded.unguarded is False

    def test_multiauth_sources_are_separate_alternatives_with_their_own_scopes(self):
        auth = MultiAuth(self._oauth(), APIKeyHeaderAuth("X-Key", self._scoped))

        def setup(app: FastAPI):
            @app.get("/multi")
            async def multi(user=Security(auth, scopes=["admin"])):
                return user

        route = self._find(_app(setup), "/multi")
        assert route.unguarded is False
        assert len(route.alternatives) == 2, "the sources are OR-ed, not AND-ed"
        assert [
            (requirement.scheme_name, requirement.source, requirement.scopes)
            for (requirement,) in route.alternatives
        ] == [
            ("OAuth2PasswordBearer", "OAuth2PasswordBearerAuth", ("admin",)),
            ("APIKeyHeader_X-Key", "APIKeyHeaderAuth", ("admin",)),
        ]

    def test_separate_security_dependencies_are_one_and_ed_alternative(self):
        """Both credentials are required, which the OpenAPI security list cannot say."""
        oauth = self._oauth()
        key = APIKeyHeaderAuth("X-Key", self._scoped)

        def setup(app: FastAPI):
            @app.get("/both")
            async def both(a=Security(oauth, scopes=["admin"]), b=Security(key)):
                return {}

            @app.get("/either")
            async def either(user=Security(MultiAuth(oauth, key), scopes=["admin"])):
                return {}

        app = _app(setup)
        both = self._find(app, "/both")
        either = self._find(app, "/either")

        document = app.openapi()["paths"]
        assert [
            list(requirement) for requirement in document["/both"]["get"]["security"]
        ] == [
            list(requirement) for requirement in document["/either"]["get"]["security"]
        ], "the document reports AND-ed schemes the same way it reports OR-ed ones"

        assert [len(alternative) for alternative in both.alternatives] == [2]
        assert [len(alternative) for alternative in either.alternatives] == [1, 1]

    def test_mixed_and_ed_and_or_ed_dependencies_keep_their_scopes_apart(self):
        """The route-level scope list stays true of every single alternative."""
        oauth = self._oauth()
        key = APIKeyHeaderAuth("X-Key", self._scoped)
        mtls = OAuth2PasswordBearerAuth(
            self._scoped,
            token_url="/mtls",
            scopes={"internal": "Internal"},
            scheme_name="Mtls",
        )

        def setup(app: FastAPI):
            @app.get("/mixed")
            async def mixed(
                a=Security(MultiAuth(oauth, key), scopes=["billing"]),
                b=Security(mtls, scopes=["internal"]),
            ):
                return {}

        route = self._find(_app(setup), "/mixed")
        assert route.scopes == ("billing", "internal")
        assert [
            [(requirement.scheme_name, requirement.scopes) for requirement in alt]
            for alt in route.alternatives
        ] == [
            [("OAuth2PasswordBearer", ("billing",)), ("Mtls", ("internal",))],
            [("APIKeyHeader_X-Key", ("billing",)), ("Mtls", ("internal",))],
        ]

    def test_optional_on_a_multiauth_member_does_not_open_the_route(self):
        """MultiAuth rejects a credential-less request whatever its members say."""
        auth = MultiAuth(
            HTTPBearerAuth(self._scoped).optional(),
            APIKeyHeaderAuth("X-Key", self._scoped),
        )

        def setup(app: FastAPI):
            @app.get("/members")
            async def members(user=Security(auth)):
                return {}

        route = self._find(_app(setup), "/members")
        assert route.unguarded is False
        assert all(
            requirement.optional is False
            for alternative in route.alternatives
            for requirement in alternative
        )

    def test_an_optional_source_leaves_the_route_reachable_anonymously(self):
        auth = HTTPBearerAuth(self._scoped)
        key = APIKeyHeaderAuth("X-Key", self._scoped)

        def setup(app: FastAPI):
            @app.get("/maybe")
            async def maybe(user=Security(auth.optional())):
                return {}

            @app.get("/maybe-and-key")
            async def maybe_and_key(a=Security(auth.optional()), b=Security(key)):
                return {}

        app = _app(setup)
        maybe = self._find(app, "/maybe")
        assert maybe.unguarded is True, "an anonymous caller reaches the endpoint"
        assert maybe.alternatives[0][0].optional is True

        both = self._find(app, "/maybe-and-key")
        assert both.unguarded is False, "the API key is still required"

    def test_dependencies_on_routers_and_behind_depends_are_found(self):
        auth = self._oauth()

        def setup(app: FastAPI):
            router = APIRouter(
                prefix="/api", dependencies=[Security(auth, scopes=["billing"])]
            )

            @router.get("/invoices")
            async def invoices():
                return {}

            app.include_router(router)

        route = self._find(_app(setup), "/api/invoices")
        assert route.unguarded is False
        assert route.scopes == ("billing",)
        assert route.alternatives[0][0].scopes == ("billing",)

        auth = HTTPBearerAuth(self._scoped)

        def current_user(user=Security(auth)):
            return user

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Depends(current_user)):
                return user

        route = self._find(_app(setup), "/me")
        assert route.unguarded is False
        assert route.alternatives[0][0].scheme_name == "HTTPBearer"

    def test_a_websocket_route_is_reported_with_no_methods_and_its_guards(self):
        def setup(app: FastAPI):
            @app.websocket("/ws")
            async def ws(websocket: Request):
                return None

        route = self._find(_app(setup), "/ws")
        assert route.methods == ()
        assert route.unguarded is True
        assert route.include_in_schema is False

        inner_guard = HTTPBearerAuth(simple_validator, scheme_name="Inner")
        router_guard = HTTPBearerAuth(simple_validator, scheme_name="Router")
        inner = APIRouter()

        @inner.websocket("/ws")
        async def ws(websocket: WebSocket, user=Security(inner_guard)):
            return None

        mid = APIRouter()
        mid.include_router(
            inner, prefix="/inner", dependencies=[Security(router_guard)]
        )
        app = FastAPI()
        app.include_router(mid, prefix="/api")

        route = self._find(app, "/api/inner/ws")
        assert route.methods == ()
        assert route.include_in_schema is False
        assert route.unguarded is False
        assert [[req.scheme_name for req in alt] for alt in route.alternatives] == [
            ["Router", "Inner"]
        ]

    def test_routes_are_read_flat_before_route_contexts_existed(self):
        """FastAPI before 0.137.2 has no iter_route_contexts(): app.routes is flat."""

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(HTTPBearerAuth(simple_validator))):
                return user

        app = _app(setup)
        with patch.object(routing, "iter_route_contexts", None, create=True):
            route = self._find(app, "/me")
        assert route.methods == ("GET",)
        assert route.alternatives[0][0].scheme_name == "HTTPBearer"

    def test_a_source_without_an_openapi_scheme_still_guards_the_route(self):
        """AuthSource is the public extension point; a scheme is optional on it."""
        auth = _HeaderAuth(VALID_TOKEN)

        def setup(app: FastAPI):
            @app.get("/custom")
            async def custom(user=Security(auth)):
                return user

        app = _app(setup)
        assert TestClient(app).get("/custom").status_code == 401

        route = self._find(app, "/custom")
        assert route.unguarded is False, "the route rejects anonymous callers"
        assert route.alternatives == (
            (
                SchemeRequirement(
                    scheme_name=None,
                    source="_HeaderAuth",
                    scopes=(),
                    optional=False,
                ),
            ),
        )

    def _multi(self) -> MultiAuth:
        return MultiAuth(
            HTTPBearerAuth(self._scoped), APIKeyHeaderAuth("X-Key", self._scoped)
        )

    @staticmethod
    def _layered(outer, inner, router_scopes=(), route_scopes=()):
        def setup(app: FastAPI):
            router = APIRouter(
                dependencies=[Security(outer, scopes=list(router_scopes))]
            )

            @router.get("/layered")
            async def layered(user=Security(inner, scopes=list(route_scopes))):
                return {}

            app.include_router(router)

        return setup

    @staticmethod
    def _shape(route) -> list[list[tuple[str, tuple[str, ...]]]]:
        return [[(req.source, req.scopes) for req in alt] for alt in route.alternatives]

    def test_a_source_layered_twice_is_counted_once_with_unioned_scopes(self):
        """FastAPI builds one dependant per path, so a layered source repeats."""
        auth = self._multi()

        route = self._find(_app(self._layered(auth, auth)), "/layered")
        assert len(route.alternatives) == 2, "one alternative per source, not 2**2"

        # Both positions run, so one credential has to satisfy all of them.
        auth = self._multi()
        setup = self._layered(auth, auth, ["billing"], ["admin"])

        route = self._find(_app(setup), "/layered")
        assert self._shape(route) == [
            [("HTTPBearerAuth", ("billing", "admin"))],
            [("APIKeyHeaderAuth", ("billing", "admin"))],
        ], "no bearer-here-api-key-there alternative can ever be satisfied"

    def test_layered_sources_fold_only_when_equivalent(self):
        """Two MultiAuth over the same members in order resolve identically."""
        bearer = HTTPBearerAuth(self._scoped)
        api_key = APIKeyHeaderAuth("X-Key", self._scoped)
        setup = self._layered(
            MultiAuth(bearer, api_key),
            MultiAuth(bearer, api_key),
            ["billing"],
            ["admin"],
        )

        route = self._find(_app(setup), "/layered")
        assert self._shape(route) == [
            [("HTTPBearerAuth", ("billing", "admin"))],
            [("APIKeyHeaderAuth", ("billing", "admin"))],
        ], "reusing one object or building two must report the same surface"

        # Order decides which member wins, so these resolve differently.
        bearer = HTTPBearerAuth(self._scoped)
        api_key = APIKeyHeaderAuth("X-Key", self._scoped)
        setup = self._layered(
            MultiAuth(bearer, api_key), MultiAuth(api_key, bearer), ["billing"]
        )

        route = self._find(_app(setup), "/layered")
        assert len(route.alternatives) == 4, "both positions pick independently"

    def test_foreign_schemes_are_read_by_their_own_optionality(self):
        """A foreign SecurityBase need not spell its optionality as auto_error."""

        class _OpaqueScheme(SecurityBase):
            def __init__(self):
                self.scheme_name = "Opaque"
                self.model = APIKey(**{"in": APIKeyIn.header}, name="X-Opaque")

            async def __call__(self, request: Request) -> str | None:
                return request.headers.get("X-Opaque")

        def setup(app: FastAPI):
            @app.get("/opaque")
            async def opaque(credential=Security(_OpaqueScheme())):
                return {}

        app = _app(setup)
        assert TestClient(app).get("/opaque").status_code == 200

        route = self._find(app, "/opaque")
        assert route.alternatives[0][0].optional is None, "nothing declares it"
        assert route.unguarded is True, "an unreadable guard must not pass the gate"

        # Plain fastapi.security schemes carry auto_error, not our flag.
        def setup(app: FastAPI):
            @app.get("/soft")
            async def soft(credentials=Security(HTTPBearer(auto_error=False))):
                return {}

        app = _app(setup)
        assert TestClient(app).get("/soft").status_code == 200

        route = self._find(app, "/soft")
        assert route.unguarded is True, "an anonymous caller reaches the endpoint"
        assert route.alternatives[0][0].optional is True


ISSUER = "https://idp.example.com"
CLIENT_ID = "my-client"
ID_JWKS_URL = "https://idp.example.com/jwks"


def _at_hash(access_token: str, digest=hashlib.sha256) -> str:
    half = digest(access_token.encode()).digest()
    half = half[: len(half) // 2]
    return base64.urlsafe_b64encode(half).rstrip(b"=").decode()


def _id_claims(**overrides) -> dict:
    return _claims(
        **{"iss": ISSUER, "aud": CLIENT_ID, "iat": int(time.time()), **overrides}
    )


def _id_token(claims=None, *, key=_RSA_KEY_1, kid="key1", algorithm="RS256"):
    return pyjwt.encode(
        claims or _id_claims(), key, algorithm=algorithm, headers={"kid": kid}
    )


class TestValidateIDToken:
    """oauth_validate_id_token(): OIDC Core §3.1.3.7 on the callback."""

    @pytest.fixture(autouse=True)
    def _fresh_key_cache(self):
        _id_key_set.cache_clear()
        yield
        _id_key_set.cache_clear()

    @staticmethod
    def _jwks(*entries):
        return respx.get(ID_JWKS_URL).respond(
            json={"keys": list(entries) or [_jwk(_RSA_KEY_1, "key1")]}
        )

    @staticmethod
    async def _validate(token, **kwargs):
        kwargs.setdefault("issuer", ISSUER)
        kwargs.setdefault("jwks_uri", ID_JWKS_URL)
        kwargs.setdefault("client_id", CLIENT_ID)
        return await oauth_validate_id_token(token, **kwargs)

    async def _refused(self, token, match, **kwargs):
        with pytest.raises(OAuthIDTokenError, match=match):
            await self._validate(token, **kwargs)

    @pytest.mark.anyio
    @respx.mock
    async def test_valid_token_returns_its_claims(self):
        route = self._jwks()
        for _ in range(3):
            claims = await self._validate(_id_token())
            assert claims["sub"] == "user-1"
            assert claims["aud"] == CLIENT_ID
        # Keys are cached across callbacks.
        assert route.call_count == 1

    @pytest.mark.anyio
    @respx.mock
    async def test_bad_signature(self):
        await self._refused("not-a-jwt", "malformed")
        self._jwks()
        await self._refused(_id_token(key=_RSA_KEY_2), "failed validation")
        token = pyjwt.encode(
            _id_claims(), JWT_SECRET, algorithm="HS256", headers={"kid": "key1"}
        )
        await self._refused(token, "failed validation")

    @pytest.mark.anyio
    @respx.mock
    async def test_unknown_kid_is_refused_after_one_refresh(self):
        route = self._jwks()
        await self._refused(_id_token(kid="rotated"), "unknown key")
        assert route.call_count == 1

    @pytest.mark.anyio
    @respx.mock
    async def test_unknown_kid_found_after_rotation(self):
        route = respx.get(ID_JWKS_URL)
        route.side_effect = [
            httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1")]}),
            httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_2, "key2")]}),
        ]
        await self._validate(_id_token())
        _id_key_set(
            ID_JWKS_URL, ("RS256", "ES256"), DEFAULT_TIMEOUT
        )._refresh_cooldown = 0
        claims = await self._validate(_id_token(key=_RSA_KEY_2, kid="key2"))
        assert claims["sub"] == "user-1"

    @pytest.mark.anyio
    @respx.mock
    async def test_claims_checks(self):
        self._jwks()
        for claims, match in [
            (_id_claims(aud="other-client"), "failed validation"),
            (_id_claims(aud=["other-client", "third"]), "failed validation"),
            (_id_claims(iss="https://evil.example.com"), "failed validation"),
            (_id_claims(exp=int(time.time()) - 60), "failed validation"),
            (_id_claims(iat=int(time.time()) + 3600), "failed validation"),
            (_id_claims(sub=None), "failed validation"),
            (_id_claims(iat=None), "failed validation"),
            (_id_claims(azp="other-client"), "another client"),
        ]:
            await self._refused(_id_token(claims), match)

    @pytest.mark.anyio
    @respx.mock
    async def test_accepted_claims(self):
        self._jwks()
        token = _id_token(_id_claims(aud=[CLIENT_ID, "api"], azp=CLIENT_ID))
        assert (await self._validate(token))["azp"] == CLIENT_ID

        token = _id_token(_id_claims(exp=int(time.time()) - 5))
        assert (await self._validate(token, leeway=30))["sub"] == "user-1"

    @pytest.mark.anyio
    @respx.mock
    async def test_nonce(self):
        self._jwks()
        token = _id_token(_id_claims(nonce="n-123"))
        assert (await self._validate(token, nonce="n-123"))["nonce"] == "n-123"

        # The nonce is not checked unless asked.
        token = _id_token(_id_claims(nonce="anything"))
        assert (await self._validate(token))["sub"] == "user-1"

        for claims, expected in [
            (_id_claims(nonce="other"), "n-123"),
            (_id_claims(), "n-123"),
            (_id_claims(nonce=123), "n-123"),
            (_id_claims(nonce=""), ""),
        ]:
            await self._refused(_id_token(claims), "nonce", nonce=expected)

    @pytest.mark.anyio
    @respx.mock
    async def test_at_hash_uses_the_header_alg(self):
        route = respx.get(ID_JWKS_URL)
        for alg, digest in [
            ("RS256", hashlib.sha256),
            ("RS384", hashlib.sha384),
            ("RS512", hashlib.sha512),
        ]:
            route.respond(json={"keys": [_jwk(_RSA_KEY_1, "key1", alg=alg)]})
            token = _id_token(
                _id_claims(at_hash=_at_hash("at-1", digest)), algorithm=alg
            )
            claims = await self._validate(token, access_token="at-1", algorithms=[alg])
            assert claims["sub"] == "user-1"

    @pytest.mark.anyio
    @respx.mock
    async def test_at_hash_for_an_alg_without_a_hash(self):
        """EdDSA defines no hash for at_hash: refused, not guessed."""
        key = ed25519.Ed25519PrivateKey.generate()
        entry = json.loads(OKPAlgorithm.to_jwk(key.public_key()))
        self._jwks({**entry, "kid": "ed1", "alg": "EdDSA", "use": "sig"})
        token = _id_token(
            _id_claims(at_hash=_at_hash("at-1")), key=key, kid="ed1", algorithm="EdDSA"
        )
        assert (await self._validate(token, algorithms=["EdDSA"]))["sub"] == "user-1"
        await self._refused(
            token,
            "cannot be checked for alg 'EdDSA'",
            access_token="at-1",
            algorithms=["EdDSA"],
        )

    @pytest.mark.anyio
    @respx.mock
    async def test_at_hash_refused(self):
        """A SHA-512 at_hash under an RS256 header does not pass."""
        self._jwks()
        for at_hash, access_token in [
            (_at_hash("at-1"), "at-2"),
            (_at_hash("at-1", hashlib.sha512), "at-1"),
            (_at_hash("at-1"), "at-é"),
        ]:
            token = _id_token(_id_claims(at_hash=at_hash))
            await self._refused(
                token, "at_hash does not match", access_token=access_token
            )
        await self._refused(_id_token(), "no at_hash", access_token="at-1")

    @pytest.mark.anyio
    @respx.mock
    async def test_unreachable_jwks(self):
        respx.get(ID_JWKS_URL).respond(500)
        await self._refused(_id_token(), "cannot be fetched")

    @pytest.mark.anyio
    async def test_misconfiguration_raises_value_error(self):
        assert issubclass(OAuthIDTokenError, OAuthError)
        for kwargs, match in [
            ({"jwks_uri": "http://idp.example.com/jwks"}, "https"),
            ({"algorithms": ["HS256"]}, "symmetric"),
            ({"algorithms": []}, "at least one"),
            ({"issuer": ""}, "issuer"),
            ({"client_id": ""}, "client_id"),
            ({"leeway": -1}, "leeway"),
            ({"leeway": math.nan}, "leeway"),
        ]:
            with pytest.raises(ValueError, match=match):
                await self._validate(_id_token(), **kwargs)


class TestNonce:
    def test_generate_nonce_is_random_and_url_safe(self):
        first, second = oauth_generate_nonce(), oauth_generate_nonce()
        assert first != second
        assert len(first) >= 43
        assert set(first) <= set(string.ascii_letters + string.digits + "-_")

    def test_redirect_carries_the_nonce(self):
        response = _authorization_redirect(nonce="n-123")
        params = parse_qs(urlparse(response.headers["location"]).query)
        assert params["nonce"] == ["n-123"]

        response = _authorization_redirect()
        assert "nonce" not in parse_qs(urlparse(response.headers["location"]).query)


class TestChecksumTokens:
    """checksum_token_generator() / verify_token_checksum(): a cheap pre-filter."""

    ALPHANUMERIC: ClassVar[str] = string.ascii_letters + string.digits

    def test_round_trip_and_entropy(self):
        for nbytes in [1, 16, 32, 64]:
            token = checksum_token_generator(nbytes)
            assert verify_token_checksum(token)
            body = token[:-6]
            assert len(body) == math.ceil(nbytes * 8 / math.log2(62))
            assert len(body) * math.log2(62) >= nbytes * 8

        # The default is 256 bits.
        assert len(checksum_token_generator()) == 43 + 6
        tokens = {checksum_token_generator() for _ in range(50)}
        assert len(tokens) == 50
        assert all(set(token) <= set(self.ALPHANUMERIC) for token in tokens)

        with pytest.raises(ValueError, match="positive"):
            checksum_token_generator(0)

    def test_every_single_char_corruption_is_rejected(self):
        token = checksum_token_generator()
        for i, char in enumerate(token):
            for replacement in "0aZ":
                if replacement != char:
                    corrupted = token[:i] + replacement + token[i + 1 :]
                    assert not verify_token_checksum(corrupted), (i, replacement)
        assert not verify_token_checksum(token[:-1])
        assert not verify_token_checksum(token + "0")

    def test_prefix_is_stripped_before_the_check(self):
        token = f"user_{checksum_token_generator()}"
        assert verify_token_checksum(token, prefix="user_")
        assert not verify_token_checksum(token)
        assert not verify_token_checksum(token, prefix="org_")

    def test_junk_is_rejected(self):
        for token in [
            "",
            "abc",
            "abcdef",  # checksum only
            "a" * 49,
            "a b" * 20,
            "é" * 49,
            f"{'a' * 42}-123456",
        ]:
            assert not verify_token_checksum(token), token

    def test_plugs_into_http_bearer_auth(self):
        lookups: list[str] = []

        async def validate(token: str) -> dict:
            if not verify_token_checksum(token, prefix="user_"):
                raise UnauthorizedError()
            lookups.append(hash_token(token))
            return {"user": "alice"}

        bearer = HTTPBearerAuth(
            validate, prefix="user_", token_generator=checksum_token_generator
        )
        token = bearer.generate_token()
        assert token.startswith("user_")
        client = _client(bearer)

        ok = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        typo = token[:-1] + ("0" if token[-1] != "0" else "1")
        bad = client.get("/me", headers={"Authorization": f"Bearer {typo}"})

        assert (ok.status_code, bad.status_code) == (200, 401)
        assert len(lookups) == 1


class TestTOTP:
    """totp_verify() and the enrolment helpers: RFC 6238 with replay refusal."""

    NOW: ClassVar[int] = 1_700_000_010
    STEP: ClassVar[int] = NOW // 30
    SECRET: ClassVar[str] = "JBSWY3DPEHPK3PXP"

    @pytest.fixture(autouse=True)
    def _frozen_clock(self):
        with patch("time.time", return_value=self.NOW):
            yield

    def _code(self, offset: int = 0) -> str:
        return pyotp.TOTP(self.SECRET).at(self.NOW + 30 * offset)

    def test_rfc_6238_sha1_vectors(self):
        secret = base64.b32encode(b"12345678901234567890").decode()
        for at, expected in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ]:
            with patch("time.time", return_value=at):
                assert totp_verify(secret, expected[-6:], window=0) == at // 30

    def test_last_step_refuses_a_used_or_older_code(self):
        for offset, last_step, expected in [
            (0, None, self.STEP),
            (0, self.STEP, None),
            (0, self.STEP - 1, self.STEP),
            (-1, self.STEP - 1, None),
            (-1, self.STEP, None),
            (1, self.STEP, self.STEP + 1),
        ]:
            code = self._code(offset)
            assert totp_verify(self.SECRET, code, last_step=last_step) == expected

    def test_window(self):
        for offset in (-1, 1):
            assert totp_verify(self.SECRET, self._code(offset)) == self.STEP + offset
            assert totp_verify(self.SECRET, self._code(offset), window=0) is None
        for offset in (-2, 2):
            assert totp_verify(self.SECRET, self._code(offset)) is None
            assert (
                totp_verify(self.SECRET, self._code(offset), window=2)
                == self.STEP + offset
            )

    def test_malformed_codes_are_refused(self):
        code = self._code()
        for bad in ["", code[:-1], code + "0", "abcdef", "\u0661" * 6, f"{code[:5]}x"]:
            assert totp_verify(self.SECRET, bad) is None, bad
        assert totp_verify(self.SECRET, f" {code[:3]} {code[3:]} ") == self.STEP

    def test_secret_is_read_leniently_and_refused_when_not_base32(self):
        for spelling in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSWY3DPEHPK3PXP====",
        ]:
            assert totp_verify(spelling, self._code()) == self.STEP
        for bad in ["", "not base32!", "JBSWY3DPEHPK3PX1"]:
            with pytest.raises(ValueError, match="base32"):
                totp_verify(bad, self._code())

    def test_secrets_shorter_than_80_bits_are_refused(self):
        for short in ["AA", "JBSWY3DPEHPK3PX"]:
            with pytest.raises(ValueError, match="at least 80 bits"):
                totp_verify(short, "000000")
            with pytest.raises(ValueError, match="at least 80 bits"):
                totp_provisioning_uri(short, "alice", "Acme")

    def test_window_must_be_a_non_negative_integer(self):
        for window in [-1, True, 1.5]:
            with pytest.raises(ValueError, match="window"):
                totp_verify(self.SECRET, "000000", window=window)  # ty: ignore[invalid-argument-type]

    def test_generate_secret(self):
        secrets_ = {totp_generate_secret() for _ in range(20)}
        assert len(secrets_) == 20
        for secret in secrets_:
            assert len(secret) == 32
            assert len(base64.b32decode(secret)) == 20

    def test_provisioning_uri_follows_the_key_uri_format(self):
        uri = totp_provisioning_uri(self.SECRET, "alice@example.com", "Acme Corp")
        assert uri == (
            "otpauth://totp/Acme%20Corp:alice%40example.com"
            "?secret=JBSWY3DPEHPK3PXP&issuer=Acme%20Corp"
        )
        for account, issuer in [
            ("a:b", "Acme"),
            ("alice", "Ac:me"),
            ("", "Acme"),
            ("alice", ""),
        ]:
            with pytest.raises(ValueError, match="colon"):
                totp_provisioning_uri(self.SECRET, account, issuer)
        with pytest.raises(ValueError, match="base32"):
            totp_provisioning_uri("not base32!", "alice", "Acme")

    def test_provisioning_uri_escapes_a_slash_in_the_label(self):
        uri = totp_provisioning_uri(self.SECRET, "ops/alice", "Acme/Prod")
        assert uri.startswith("otpauth://totp/Acme%2FProd:ops%2Falice?")
        reference = pyotp.parse_uri(uri)
        assert (reference.name, reference.issuer) == ("ops/alice", "Acme/Prod")

    def test_interoperates_with_pyotp(self):
        secret = totp_generate_secret()
        uri = totp_provisioning_uri(secret, "alice@example.com", "Acme Corp")
        reference = pyotp.parse_uri(uri)
        assert isinstance(reference, pyotp.TOTP)
        assert (reference.secret, reference.name, reference.issuer) == (
            secret,
            "alice@example.com",
            "Acme Corp",
        )
        assert totp_verify(secret, reference.at(self.NOW)) == self.STEP


def _bearer_scope(token: str) -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    }


class TestAuthenticationMethodReference:
    IANA_REGISTRY: ClassVar[set[str]] = {
        "face", "fpt", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp", "pin",
        "pop", "pwd", "rba", "retina", "sc", "sms", "swk", "tel", "user", "vbm",
        "wia",
    }  # fmt: skip

    def test_values_match_the_registry_and_compare_as_strings(self):
        assert {member.value for member in AuthenticationMethodReference} == (
            self.IANA_REGISTRY
        )
        claims = {"amr": ["pwd", "otp"]}
        assert AuthenticationMethodReference.PASSWORD in claims["amr"]
        assert AuthenticationMethodReference.ONE_TIME_PASSWORD == "otp"
        assert AuthenticationMethodReference("hwk").name == "HARDWARE_KEY"


class TestStepUpChallenge:
    def test_formatting(self):
        cases: list[tuple[dict[str, Any], str]] = [
            ({"max_age": 300}, 'max_age="300"'),
            ({"acr_values": ("gold",)}, 'acr_values="gold"'),
            ({"acr_values": ("gold", "urn:silver")}, 'acr_values="gold urn:silver"'),
            (
                {"acr_values": ("gold", "silver"), "max_age": 60},
                'acr_values="gold silver", max_age="60"',
            ),
        ]
        for kwargs, expected in cases:
            headers = step_up_challenge("Bearer", "Why", **kwargs)
            assert headers == {
                "WWW-Authenticate": (
                    'Bearer error="insufficient_user_authentication", '
                    f'error_description="Why", {expected}'
                )
            }

    def test_the_base_challenge(self):
        """A challenge with params gets a comma; no challenge, no header."""
        headers = step_up_challenge('Basic realm="api"', "Why", acr_values=("gold",))
        assert headers is not None
        assert headers["WWW-Authenticate"].startswith(
            'Basic realm="api", error="insufficient_user_authentication"'
        )
        assert step_up_challenge(None, "Why", acr_values=("gold",)) is None


class TestSteppedUp:
    """stepped_up(): "authenticate more strongly", RFC 9470 acr_values."""

    BEARER: ClassVar[dict[str, str]] = {"Authorization": f"Bearer {VALID_TOKEN}"}
    ACR_CHALLENGE: ClassVar[str] = (
        'Bearer error="insufficient_user_authentication", '
        'error_description="A different authentication level is required", '
        'acr_values="gold silver"'
    )

    @staticmethod
    def _bearer(acr: Any = "gold", proven_at: float | None = None) -> HTTPBearerAuth:
        async def validate(token: str) -> dict:
            return {
                **await simple_validator(token),
                "acr": acr,
                "proven_at": time.time() if proven_at is None else proven_at,
            }

        return HTTPBearerAuth(validate)

    @staticmethod
    def _gold(source):
        return source.stepped_up(["gold", "silver"], acr=lambda user: user["acr"])

    @staticmethod
    def _fresh(source):
        return source.fresh(300, authenticated_at=lambda user: user["proven_at"])

    def _get(self, dep):
        return _client(dep).get("/me", headers=self.BEARER)

    def test_an_accepted_level_passes(self):
        for acr in ["gold", "silver"]:
            assert self._get(self._gold(self._bearer(acr))).status_code == 200

        async def acr(user):
            return user["acr"]

        dep = self._bearer("gold").stepped_up(["gold"], acr=acr)
        assert self._get(dep).status_code == 200

        # An enum level matches its string.
        class Level(StrEnum):
            GOLD = "gold"

        dep = self._bearer(Level.GOLD).stepped_up(["gold"], acr=lambda u: u["acr"])
        assert self._get(dep).status_code == 200

    def test_any_other_level_gets_the_challenge(self):
        for acr in ["bronze", None, 7, ["gold"]]:
            response = self._get(self._gold(self._bearer(acr)))
            assert response.status_code == 401, acr
            assert response.json() == {"detail": "Insufficient user authentication"}
            assert response.headers["www-authenticate"] == self.ACR_CHALLENGE

    @pytest.mark.anyio
    async def test_the_error_carries_the_requirement(self):
        dep = self._gold(self._bearer("bronze"))
        with pytest.raises(InsufficientAuthenticationError) as exc_info:
            await dep.dispatch(Request(_bearer_scope(VALID_TOKEN)), [])
        assert not isinstance(exc_info.value, StaleCredentialError)
        assert exc_info.value.acr_values == ("gold", "silver")
        assert exc_info.value.max_age is None

        # A stale error carries both requirements.
        dep = self._fresh(self._gold(self._bearer("gold", proven_at=0)))
        with pytest.raises(StaleCredentialError) as exc_info:
            await dep.dispatch(Request(_bearer_scope(VALID_TOKEN)), [])
        assert isinstance(exc_info.value, InsufficientAuthenticationError)
        assert (exc_info.value.max_age, exc_info.value.acr_values) == (
            300,
            ("gold", "silver"),
        )

    def test_an_invalid_credential_is_refused_as_invalid(self):
        dep = self._gold(self._bearer("bronze"))
        response = _client(dep).get("/me", headers={"Authorization": "Bearer nope"})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_a_cookie_source_answers_in_the_body(self):
        async def validate(value: str) -> dict:
            return {**await cookie_validator(value), "acr": "bronze"}

        auth = APIKeyCookieAuth(
            "session", validate, secret_key=COOKIE_SECRET, secure=False
        )
        dep = auth.stepped_up(["gold"], acr=lambda user: user["acr"])
        response = _client(dep).get(
            "/me", cookies={"session": auth._sign(VALID_COOKIE)}
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Insufficient user authentication"}
        assert "www-authenticate" not in response.headers

    def test_composes_with_fresh_into_one_challenge(self):
        source = self._bearer("bronze")
        for dep in [self._gold(self._fresh(source)), self._fresh(self._gold(source))]:
            response = self._get(dep)
            assert response.status_code == 401
            assert response.headers["www-authenticate"] == (
                f'{self.ACR_CHALLENGE}, max_age="300"'
            )

        # A stale credential on a stepped-up route.
        dep = self._fresh(self._gold(self._bearer("gold", proven_at=0)))
        response = self._get(dep)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == (
            'Bearer error="insufficient_user_authentication", '
            'error_description="More recent authentication is required", '
            'acr_values="gold silver", max_age="300"'
        )

    def test_one_handler_catches_both_refusals(self):
        bronze = self._gold(self._bearer("bronze"))
        stale = self._fresh(self._bearer("gold", proven_at=0))

        def setup(app: FastAPI):
            @app.exception_handler(InsufficientAuthenticationError)
            async def handler(request: Request, exc: InsufficientAuthenticationError):
                return JSONResponse(
                    {"max_age": exc.max_age, "acr_values": exc.acr_values},
                    status_code=401,
                )

            @app.get("/bronze")
            async def a(user=Security(bronze)):
                return user

            @app.get("/stale")
            async def b(user=Security(stale)):
                return user

        client = TestClient(_app(setup))
        assert client.get("/bronze", headers=self.BEARER).json() == {
            "max_age": None,
            "acr_values": ["gold", "silver"],
        }
        assert client.get("/stale", headers=self.BEARER).json() == {
            "max_age": 300,
            "acr_values": None,
        }

    def test_derived_sources(self):
        """The original source stays unguarded; require() keeps the levels."""
        source = self._bearer("bronze")
        self._gold(source)
        assert self._get(source).status_code == 200

        async def validate(token: str, *, role: str) -> dict:
            return {"role": role, "acr": "bronze"}

        dep = self._gold(HTTPBearerAuth(validate)).require(role="admin")
        assert self._get(dep).status_code == 401

    def test_misuse_is_refused(self):
        source = self._bearer()
        with pytest.raises(ValueError, match=r"optional\(\) and stepped_up\(\)"):
            self._gold(source).optional()
        with pytest.raises(ValueError, match=r"optional\(\) and stepped_up\(\)"):
            self._gold(source.optional())
        with pytest.raises(ValueError, match="already has acr_values"):
            self._gold(self._gold(self._bearer()))

        auth = MultiAuth(self._bearer())
        with pytest.raises(ValueError, match=r"stepped_up\(\)"):
            self._gold(auth).optional()
        with pytest.raises(ValueError, match=r"stepped_up\(\)"):
            self._gold(auth.optional())
        with pytest.raises(ValueError, match="HTTPBearerAuth already has acr_values"):
            self._gold(MultiAuth(self._gold(self._bearer())))

    def test_acr_values_must_fit_the_challenge(self):
        cases: list[tuple[Any, type[Exception]]] = [
            ("gold", TypeError),  # a bare string
            ([], ValueError),
            ([""], ValueError),
            (["gold silver"], ValueError),
            (['gold"'], ValueError),
            (["gold\\"], ValueError),
            (["gold\t"], ValueError),
            (["oré"], ValueError),
            ([7], ValueError),
        ]
        for acr_values, error in cases:
            with pytest.raises(error):
                self._bearer().stepped_up(acr_values, acr=lambda user: user["acr"])

    def test_multiauth_applies_the_levels_to_every_source(self):
        async def cookie_validate(value: str) -> dict:
            return {**await cookie_validator(value), "acr": "bronze"}

        cookie = APIKeyCookieAuth(
            "session", cookie_validate, secret_key=COOKIE_SECRET, secure=False
        )
        auth = self._gold(MultiAuth(self._bearer("gold"), cookie))
        client = _client(auth)
        assert client.get("/me", headers=self.BEARER).status_code == 200
        response = client.get("/me", cookies={"session": cookie._sign(VALID_COOKIE)})
        assert response.status_code == 401

    def test_reads_acr_off_jwt_claims(self):
        validator = JWTValidator(secret=JWT_SECRET)
        dep = HTTPBearerAuth(validator).stepped_up(
            ["urn:mfa"], acr=lambda claims: claims.get("acr")
        )
        client = _client(dep)
        for acr, expected in (("urn:mfa", 200), ("urn:pwd", 401), (None, 401)):
            token = _hs_token(_claims(acr=acr))
            response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == expected, acr


class TestCookieAssurance:
    """acr/amr signed into the cookie: stepped_up() without an acr= reader."""

    AMR = AuthenticationMethodReference

    @staticmethod
    def _client(auth: APIKeyCookieAuth, **set_cookie: Any) -> TestClient:
        """One cookie jar: /login sets *set_cookie*, /mfa needs acr "mfa"."""
        strong = auth.stepped_up(["mfa"])

        def setup(app: FastAPI):
            @app.get("/login")
            async def login(response: Response):
                auth.set_cookie(response, VALID_COOKIE, **set_cookie)
                return {"ok": True}

            @app.get("/whoami")
            async def whoami(request: Request):
                return {"acr": auth.acr_of(request), "amr": auth.amr_of(request)}

            @app.get("/me")
            async def me(user=Security(auth)):
                return user

            @app.get("/mfa")
            async def mfa(user=Security(strong)):
                return user

        return TestClient(_app(setup))

    def test_the_level_travels_in_the_cookie(self):
        with self._client(
            _signed_cookie_auth(),
            acr="mfa",
            amr=[self.AMR.PASSWORD, self.AMR.ONE_TIME_PASSWORD],
        ) as client:
            client.get("/login")
            assert client.get("/mfa").json() == {"session": VALID_COOKIE}
            assert client.get("/whoami").json() == {"acr": "mfa", "amr": ["pwd", "otp"]}

        with self._client(_signed_cookie_auth(), acr="pwd") as client:
            client.get("/login")
            assert client.get("/me").status_code == 200
            response = client.get("/mfa")
            assert response.status_code == 401
            assert response.json() == {"detail": "Insufficient user authentication"}
            assert client.get("/whoami").json() == {"acr": "pwd", "amr": None}

        with self._client(_signed_cookie_auth()) as client:
            client.get("/login")
            assert client.get("/me").status_code == 200
            assert client.get("/mfa").status_code == 401
            assert client.get("/whoami").json() == {"acr": None, "amr": None}

    def test_survives_a_session_id_and_dotted_values(self):
        async def validate(value: str, *, session_id: str) -> dict:
            return {"session": value, "sid": session_id}

        auth = APIKeyCookieAuth(
            "session", validate, secret_key=COOKIE_SECRET, session_id=True, secure=False
        )
        response = Response()
        sid = auth.set_cookie(response, "user.42:v3", acr="urn:mfa.v2", amr=["hwk"])
        client = _client(auth.stepped_up(["urn:mfa.v2"]))
        response = client.get("/me", cookies={"session": _cookie_value(response)})
        assert response.json() == {"session": "user.42:v3", "sid": sid}

    def test_a_cookie_from_before_acr_and_amr_is_refused(self):
        """Pre-acr cookies are signed under another salt: they fail closed."""
        legacy = _stock_signer(COOKIE_SECRET).sign(VALID_COOKIE.encode()).decode()
        auth = _signed_cookie_auth()
        client = self._client(auth)
        client.cookies.set("session", legacy)
        assert client.get("/me").status_code == 401
        assert client.get("/whoami").json() == {"acr": None, "amr": None}

        legacy_sid = _stock_signer(COOKIE_SECRET, salt="session.sid")
        legacy_sid = legacy_sid.sign(f"abc.{VALID_COOKIE}".encode()).decode()
        sid_auth = APIKeyCookieAuth(
            "session",
            sid_validator,
            secret_key=COOKIE_SECRET,
            session_id=True,
            secure=False,
        )
        response = _client(sid_auth).get("/me", cookies={"session": legacy_sid})
        assert response.status_code == 401

    def test_the_guards_reuse_the_verified_cookie(self, monkeypatch):
        """fresh() and stepped_up() read the cookie checked by authentication."""
        unsigned: list[bytes] = []
        unsign = TimestampSigner.unsign

        def counting(self, signed_value, *args, **kwargs):
            unsigned.append(signed_value)
            return unsign(self, signed_value, *args, **kwargs)

        monkeypatch.setattr(TimestampSigner, "unsign", counting)
        auth = _signed_cookie_auth()
        client = _client(auth.fresh(300).stepped_up(["mfa"]))
        for acr, status in [("mfa", 200), ("pwd", 401), (None, 401)]:
            response = Response()
            auth.set_cookie(response, VALID_COOKIE, acr=acr)
            unsigned.clear()
            cookies = {"session": _cookie_value(response)}
            assert client.get("/me", cookies=cookies).status_code == status, acr
            assert len(unsigned) == 1, acr

    def test_an_override_without_the_request_still_meets_the_guards(self):
        """Without the request, the guards verify the cookie again."""

        class _StaleCookieAuth(APIKeyCookieAuth):
            async def authenticate_scoped(  # ty: ignore[invalid-method-override]
                self, credential: str, scopes: list[str]
            ) -> Any:
                return await super().authenticate_scoped(credential, scopes)

        auth = _StaleCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        )
        client = _client(auth.fresh(300).stepped_up(["mfa"]))
        for acr, status in [("mfa", 200), ("pwd", 401)]:
            response = Response()
            auth.set_cookie(response, VALID_COOKIE, acr=acr)
            cookies = {"session": _cookie_value(response)}
            assert client.get("/me", cookies=cookies).status_code == status, acr

    def test_the_level_cannot_be_forged(self):
        auth = _signed_cookie_auth()
        response = Response()
        auth.set_cookie(response, VALID_COOKIE, acr="pwd")
        rest = _cookie_value(response).partition(".")[2]
        raised = base64.urlsafe_b64encode(b'{"acr":"mfa"}').rstrip(b"=").decode()
        other = Response()
        APIKeyCookieAuth(
            "admin", cookie_validator, secret_key=COOKIE_SECRET, secure=False
        ).set_cookie(other, VALID_COOKIE, acr="mfa")
        other_signed = _cookie_value(other)
        client = self._client(auth)
        for forged in [f"{raised}.{rest}", other_signed, ""]:
            client.cookies.set("session", forged)
            assert client.get("/mfa").status_code == 401, forged
            assert client.get("/whoami").json() == {"acr": None, "amr": None}

        with self._client(_signed_cookie_auth(ttl=60), acr="mfa") as client:
            client.get("/login")
            with patch("time.time", return_value=time.time() + 61):
                assert client.get("/whoami").json() == {"acr": None, "amr": None}
                assert client.get("/mfa").status_code == 401

    def test_an_acr_reader_still_wins(self):
        async def validate(value: str) -> dict:
            return {**await cookie_validator(value), "acr": "mfa"}

        auth = APIKeyCookieAuth(
            "session", validate, secret_key=COOKIE_SECRET, secure=False
        )
        dep = auth.stepped_up(["mfa"], acr=lambda user: user["acr"])
        cookie = {"session": auth._sign(VALID_COOKIE)}
        assert _client(dep).get("/me", cookies=cookie).status_code == 200

        dep = MultiAuth(auth).stepped_up(["mfa"])
        assert _client(dep).get("/me", cookies=cookie).status_code == 401

    def test_misuse_is_refused(self):
        unsigned = APIKeyCookieAuth("session", cookie_validator)
        assert unsigned.authenticated_acr(VALID_COOKIE) is None
        assert HTTPBearerAuth(simple_validator).authenticated_acr(VALID_TOKEN) is None
        with pytest.raises(RuntimeError, match="secret_key"):
            unsigned._unsign(VALID_COOKIE)
        with pytest.raises(ValueError, match="acr and amr require secret_key"):
            unsigned.set_cookie(Response(), VALID_COOKIE, acr="mfa")
        with pytest.raises(ValueError, match="acr and amr require secret_key"):
            unsigned.set_cookie(Response(), VALID_COOKIE, amr=["pwd"])
        with pytest.raises(ValueError, match=r"APIKeyCookieAuth cannot read"):
            unsigned.stepped_up(["mfa"])
        with pytest.raises(ValueError, match=r"HTTPBearerAuth cannot read"):
            HTTPBearerAuth(simple_validator).stepped_up(["mfa"])
        with pytest.raises(
            ValueError,
            match=r"HTTPBearerAuth cannot read.*stepped_up\(\) on each source",
        ):
            MultiAuth(
                _signed_cookie_auth(), HTTPBearerAuth(simple_validator)
            ).stepped_up(["mfa"])

        cases: list[tuple[dict[str, Any], type[Exception]]] = [
            ({"amr": "pwd"}, TypeError),
            ({"amr": []}, ValueError),
            ({"amr": ["pwd otp"]}, ValueError),
            ({"amr": [7]}, ValueError),
            ({"acr": ""}, ValueError),
            ({"acr": "gold silver"}, ValueError),
            ({"acr": 'gold"'}, ValueError),
            ({"acr": "oré"}, ValueError),
        ]
        for kwargs, error in cases:
            with pytest.raises(error):
                _signed_cookie_auth().set_cookie(Response(), VALID_COOKIE, **kwargs)


class TestCookieCsrf:
    """csrf=True: cookie requests from another origin are refused with a 403."""

    TRUSTED = "https://app.example.com"
    CROSS_SITE: ClassVar[dict[str, str]] = {"Sec-Fetch-Site": "cross-site"}

    def _client(self, auth: APIKeyCookieAuth) -> TestClient:
        def setup(app: FastAPI):
            @app.api_route(
                "/me",
                methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
            )
            async def me(user=Security(auth)):
                return user

            @app.websocket("/ws")
            async def ws(websocket: WebSocket, user=Security(auth)):
                await websocket.accept()
                await websocket.send_json(user)
                await websocket.close()

        client = TestClient(_app(setup))
        client.cookies.set("session", auth._sign(VALID_COOKIE))
        return client

    def _status(self, client: TestClient, method: str = "POST", **headers: str) -> int:
        return client.request(method, "/me", headers=headers).status_code

    def test_same_origin_requests_pass(self):
        client = self._client(_signed_cookie_auth(csrf=True))
        for headers in [
            {"Sec-Fetch-Site": "same-origin"},
            {"Sec-Fetch-Site": "none"},
            {"Origin": "http://testserver"},
            {"Origin": "http://TestServer"},
        ]:
            for method in ["POST", "PUT", "PATCH", "DELETE"]:
                assert self._status(client, method, **headers) == 200, headers

    def test_cross_origin_requests_are_refused(self):
        client = self._client(_signed_cookie_auth(csrf=True))
        for headers in [
            {"Sec-Fetch-Site": "cross-site"},
            {"Sec-Fetch-Site": "same-site"},
            {"Sec-Fetch-Site": "cross-site", "Origin": "http://testserver"},
            {"Origin": "https://evil.example"},
            {"Origin": "http://testserver.evil.example"},
            {"Origin": "http://testserver:8080"},
            {"Origin": "null"},
            {"Origin": "http://[::1"},
            {},
        ]:
            for method in ["POST", "PUT", "PATCH", "DELETE"]:
                assert self._status(client, method, **headers) == 403, headers
            response = client.post("/me", headers=headers)
            assert response.json() == {"detail": "Forbidden"}

    def test_safe_methods_are_not_checked(self):
        client = self._client(_signed_cookie_auth(csrf=True))
        for method in ["GET", "HEAD", "OPTIONS"]:
            assert self._status(client, method, **self.CROSS_SITE) == 200
            assert self._status(client, method) == 200

    def test_trusted_origins_pass(self):
        client = self._client(
            _signed_cookie_auth(csrf=True, trusted_origins=["HTTPS://App.Example.com"])
        )
        assert self._status(client, Origin=self.TRUSTED, **self.CROSS_SITE) == 200
        assert self._status(client, Origin=self.TRUSTED) == 200
        assert (
            self._status(
                client, Origin=f"{self.TRUSTED}.evil.example", **self.CROSS_SITE
            )
            == 403
        )
        assert (
            self._status(client, Origin="http://app.example.com", **self.CROSS_SITE)
            == 403
        )

        client = self._client(
            _signed_cookie_auth(
                csrf=True, trusted_origins=["https://app.example.com:443"]
            )
        )
        assert self._status(client, Origin=self.TRUSTED, **self.CROSS_SITE) == 200
        client = self._client(
            _signed_cookie_auth(
                csrf=True, trusted_origins=["http://app.example.com:8443"]
            )
        )
        assert (
            self._status(
                client, Origin="http://app.example.com:8443", **self.CROSS_SITE
            )
            == 200
        )

    def test_an_invalid_cookie_is_refused_as_invalid(self):
        client = self._client(_signed_cookie_auth(csrf=True))
        client.cookies.set("session", "forged")
        assert self._status(client, **self.CROSS_SITE) == 401
        client.cookies.clear()
        assert self._status(client, **self.CROSS_SITE) == 401

    def test_off_by_default(self):
        client = self._client(_signed_cookie_auth())
        assert self._status(client, **self.CROSS_SITE) == 200
        assert self._status(client) == 200

    def test_websocket_handshakes_are_checked(self):
        client = self._client(
            _signed_cookie_auth(csrf=True, trusted_origins=[self.TRUSTED])
        )
        for headers in [{"Origin": self.TRUSTED}, {"Origin": "http://testserver"}]:
            with client.websocket_connect("/ws", headers=headers) as websocket:
                assert websocket.receive_json() == {"session": VALID_COOKIE}
        for headers in [{"Origin": "https://evil.example"}, {}]:
            with (
                pytest.raises(WebSocketDenialResponse) as exc_info,
                client.websocket_connect("/ws", headers=headers),
            ):
                pass
            assert exc_info.value.status_code == 403

    @pytest.mark.anyio
    async def test_no_request_fails_closed(self):
        auth = _signed_cookie_auth(csrf=True)
        with pytest.raises(ForbiddenError):
            await auth.authenticate(auth._sign(VALID_COOKIE))

    def test_refusals_are_logged(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        client = self._client(_signed_cookie_auth(csrf=True))
        self._status(client, **self.CROSS_SITE)
        self._status(client)
        assert [(r.auth_reason, r.auth_status) for r in caplog.records] == [
            ("cross_origin", 403),
            ("missing_origin", 403),
        ]

    def test_auth_surface_reports_the_check(self):
        def setup(app: FastAPI):
            for path, auth in [
                ("/csrf", _signed_cookie_auth(csrf=True)),
                ("/cookie", _signed_cookie_auth()),
                ("/bearer", HTTPBearerAuth(simple_validator)),
            ]:
                app.add_api_route(
                    path, lambda user=Security(auth): user, methods=["POST"]
                )

        surface = {route.path: route for route in auth_surface(_app(setup))}
        assert [
            surface[path].alternatives[0][0].csrf
            for path in ("/csrf", "/cookie", "/bearer")
        ] == [
            True,
            False,
            None,
        ]

    def test_misconfiguration_rejected(self):
        with pytest.raises(ValueError, match="trusted_origins requires csrf=True"):
            _signed_cookie_auth(trusted_origins=[self.TRUSTED])
        with pytest.raises(TypeError, match="not a string"):
            _signed_cookie_auth(csrf=True, trusted_origins=self.TRUSTED)
        for origin in [
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://app.example.com?x=1",
            "https://user@app.example.com",
            "app.example.com",
            "ftp://app.example.com",
            "null",
            "*",
        ]:
            with pytest.raises(ValueError, match="trusted_origins entry"):
                _signed_cookie_auth(csrf=True, trusted_origins=[origin])


WEBHOOK_SECRET = "webhook-secret-of-16-bytes-or-more"


def _hmac_hex(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class TestHMACSignatureAuth:
    """Signed webhooks: HMAC-SHA256 of the raw body, timestamp optional."""

    # Three header layouts, configured as their senders document them.
    GITHUB: ClassVar[dict[str, Any]] = {
        "header": "X-Hub-Signature-256",
        "prefix": "sha256=",
    }
    STRIPE: ClassVar[dict[str, Any]] = {
        "header": "Stripe-Signature",
        "signature_key": "v1",
        "timestamp_key": "t",
    }
    SLACK: ClassVar[dict[str, Any]] = {
        "header": "X-Slack-Signature",
        "prefix": "v0=",
        "timestamp_header": "X-Slack-Request-Timestamp",
        "signed_message": "v0:{timestamp}:{body}",
    }
    GENERIC: ClassVar[dict[str, Any]] = {
        "header": "X-Signature",
        "prefix": "sha256=",
        "timestamp_header": "X-Timestamp",
    }

    # GitHub's and Slack's published test vectors.
    GITHUB_SECRET = "It's a Secret to Everybody"
    GITHUB_SIGNATURE = (
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    )
    SLACK_SECRET = "8f742231b10e8888abcd99yyyzzz85a5"
    SLACK_TIMESTAMP = 1531420618
    SLACK_BODY = (
        "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow"
        "&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA"
        "&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url="
        "https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554"
        "%2F96rGlfmibIGlgcZRskXaIFfN"
        "&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
    )
    SLACK_SIGNATURE = (
        "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
    )

    @staticmethod
    def _client(source) -> TestClient:
        class Event(BaseModel):
            action: str

        def setup(app: FastAPI):
            @app.post("/hook")
            async def hook(body: bytes = Security(source)):
                return {"body": body.decode()}

            @app.post("/typed", dependencies=[Security(source)])
            async def typed(event: Event):
                return {"action": event.action}

        return TestClient(_app(setup))

    @staticmethod
    def _stamped(body: bytes, t: int | str | None = None) -> tuple[str, str]:
        """A timestamp and the hex signature of `{timestamp}.{body}`."""
        t = str(int(time.time()) if t is None else t)
        return t, _hmac_hex(WEBHOOK_SECRET, f"{t}.".encode() + body)

    def test_github_layout(self):
        client = self._client(HMACSignatureAuth(self.GITHUB_SECRET, **self.GITHUB))
        upper = "sha256=" + self.GITHUB_SIGNATURE.removeprefix("sha256=").upper()
        for signature in [self.GITHUB_SIGNATURE, upper]:
            response = client.post(
                "/hook",
                content=b"Hello, World!",
                headers={"X-Hub-Signature-256": signature},
            )
            assert response.json() == {"body": "Hello, World!"}

    def test_slack_layout(self):
        client = self._client(HMACSignatureAuth(self.SLACK_SECRET, **self.SLACK))
        headers = {
            "X-Slack-Signature": self.SLACK_SIGNATURE,
            "X-Slack-Request-Timestamp": str(self.SLACK_TIMESTAMP),
        }
        with patch("time.time", return_value=self.SLACK_TIMESTAMP + 10):
            response = client.post("/hook", content=self.SLACK_BODY, headers=headers)
        assert response.json() == {"body": self.SLACK_BODY}
        with patch("time.time", return_value=self.SLACK_TIMESTAMP + 301):
            response = client.post("/hook", content=self.SLACK_BODY, headers=headers)
        assert response.status_code == 401

    def test_stripe_layout(self):
        source = HMACSignatureAuth(
            ["whsec_new-secret-of-16-bytes", WEBHOOK_SECRET], **self.STRIPE
        )
        client = self._client(source)
        body = b'{"type": "invoice.paid"}'
        t, signature = self._stamped(body)
        zeros = "0" * 64
        for header in [
            f"t={t},v1={signature}",
            f"t={t}, v1={zeros}, v1={signature}, v0=x",
        ]:
            response = client.post(
                "/hook", content=body, headers={"Stripe-Signature": header}
            )
            assert response.json() == {"body": body.decode()}, header
        old_t, old_signature = self._stamped(body, int(time.time()) - 301)
        for header in [
            f"t={old_t},v1={old_signature}",
            f"t={t},t={t},v1={signature}",
            f"v1={signature}",
            f"t={t}",
            "garbage",
        ]:
            response = client.post(
                "/hook", content=body, headers={"Stripe-Signature": header}
            )
            assert response.status_code == 401, header

    def test_the_route_can_still_parse_the_body(self):
        source = HMACSignatureAuth(WEBHOOK_SECRET, **self.GITHUB)
        body = b'{"action": "opened"}'
        response = self._client(source).post(
            "/typed",
            content=body,
            headers={
                "X-Hub-Signature-256": f"sha256={_hmac_hex(WEBHOOK_SECRET, body)}",
                "Content-Type": "application/json",
            },
        )
        assert response.json() == {"action": "opened"}

    def test_the_timestamp_is_signed(self):
        client = self._client(HMACSignatureAuth(WEBHOOK_SECRET, **self.GENERIC))
        body = b"payload"
        t, signature = self._stamped(body)
        headers = {"X-Signature": f"sha256={signature}", "X-Timestamp": t}
        assert client.post("/hook", content=body, headers=headers).status_code == 200
        body_only = {
            **headers,
            "X-Signature": f"sha256={_hmac_hex(WEBHOOK_SECRET, body)}",
        }
        assert client.post("/hook", content=body, headers=body_only).status_code == 401
        twice = [
            ("X-Signature", f"sha256={signature}"),
            ("X-Timestamp", t),
            ("X-Timestamp", t),
        ]
        assert client.post("/hook", content=body, headers=twice).status_code == 401

    def test_refusals_are_logged_with_their_reason(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        client = self._client(HMACSignatureAuth(WEBHOOK_SECRET, **self.GENERIC))
        body = b"payload"
        t, signature = self._stamped(body)
        good = f"sha256={signature}"
        cases = [
            ({"X-Signature": good, "X-Timestamp": t}, b"tampered", "invalid_signature"),
            (
                {"X-Signature": good.replace("sha256=", "sha1="), "X-Timestamp": t},
                body,
                "malformed",
            ),
            ({"X-Signature": good}, body, "malformed"),
            ({"X-Signature": good, "X-Timestamp": "soon"}, body, "malformed"),
            ({"X-Signature": good, "X-Timestamp": "0"}, body, "expired"),
            ({"X-Signature": good, "X-Timestamp": "9" * 400}, body, "malformed"),
            (
                {"X-Signature": "sha256=not-hex", "X-Timestamp": t},
                body,
                "invalid_signature",
            ),
            ({"X-Signature": "sha256=", "X-Timestamp": t}, body, "invalid_signature"),
        ]
        for headers, content, reason in cases:
            caplog.clear()
            response = client.post("/hook", content=content, headers=headers)
            assert response.status_code == 401, headers
            assert "www-authenticate" not in response.headers
            assert [r.auth_reason for r in caplog.records] == [reason], headers
        other = HMACSignatureAuth("another-secret-of-16-bytes", **self.GENERIC)
        response = self._client(other).post(
            "/hook", content=body, headers={"X-Signature": good, "X-Timestamp": t}
        )
        assert response.status_code == 401
        assert client.post("/hook", content=body).status_code == 401

    def test_replays_are_refused(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        seen: dict[str, float] = {}

        async def remember(signature: str, expires_at: float) -> bool:
            if signature in seen:
                return False
            seen[signature] = expires_at
            return True

        source = HMACSignatureAuth(
            WEBHOOK_SECRET, replay_check=remember, **self.GENERIC
        )
        client = self._client(source)
        body = b"payment.succeeded"
        t, signature = self._stamped(body)
        headers = {"X-Signature": f"sha256={signature.upper()}", "X-Timestamp": t}
        tampered = client.post("/hook", content=b"tampered", headers=headers)
        assert tampered.status_code == 401
        assert seen == {}
        assert client.post("/hook", content=body, headers=headers).status_code == 200
        assert seen == {signature: int(t) + 300}
        caplog.clear()
        assert client.post("/hook", content=body, headers=headers).status_code == 401
        assert [r.auth_reason for r in caplog.records] == ["replay"]
        t2, signature2 = self._stamped(body, int(t) + 1)
        headers = {"X-Signature": f"sha256={signature2}", "X-Timestamp": t2}
        assert client.post("/hook", content=body, headers=headers).status_code == 200

    def test_misuse_is_refused(self):
        source = HMACSignatureAuth(WEBHOOK_SECRET, **self.GITHUB)

        def setup(app: FastAPI):
            @app.post("/scoped")
            async def scoped(body=Security(source, scopes=["admin"])):
                return {}

            @app.post("/multi")
            async def multi(body=Security(MultiAuth(source), scopes=["admin"])):
                return {}

            @app.websocket("/ws")
            async def ws(websocket: WebSocket, body=Security(source)):
                await websocket.accept()

            async def consume(request: Request):
                async for _ in request.stream():
                    pass

            @app.post("/consumed", dependencies=[Depends(consume), Security(source)])
            async def consumed():
                return {}

        client = TestClient(_app(setup))
        headers = {"X-Hub-Signature-256": f"sha256={'0' * 64}"}
        for path in ["/scoped", "/multi"]:
            with pytest.raises(
                RuntimeError, match="cannot enforce the security scopes"
            ):
                client.post(path, headers=headers)
        with (
            pytest.raises(RuntimeError, match="signs the request body"),
            client.websocket_connect("/ws", headers=headers),
        ):
            pass
        with pytest.raises(RuntimeError, match="already consumed it"):
            client.post("/consumed", content=b"command=deploy", headers=headers)

    def test_misconfiguration_rejected(self):
        secret_keys: list[Any] = ["short", [], [WEBHOOK_SECRET, "short"]]
        for secret_key in secret_keys:
            with pytest.raises(ValueError, match="secret_key"):
                HMACSignatureAuth(secret_key, header="X-Signature")
        for tolerance in [0, -1, math.inf, math.nan]:
            with pytest.raises(ValueError, match="tolerance"):
                HMACSignatureAuth(
                    WEBHOOK_SECRET, header="X-Signature", tolerance=tolerance
                )
        cases: list[tuple[dict[str, Any], str]] = [
            ({"prefix": "sha256=", "signature_key": "v1"}, "two header layouts"),
            ({"timestamp_key": "t"}, "requires signature_key"),
            (
                {
                    "signature_key": "v1",
                    "timestamp_key": "t",
                    "timestamp_header": "X-T",
                },
                "one of timestamp_key or timestamp_header",
            ),
            ({"replay_check": lambda signature, expires_at: True}, "needs a timestamp"),
            ({"signed_message": "{body}.signed"}, "must end with"),
            ({"signed_message": "{body}{body}"}, "must end with"),
            ({"signed_message": "{timestamp}.{body}"}, "exactly when a timestamp"),
            ({"timestamp_header": "X-T", "signed_message": "{body}"}, "exactly when"),
            (
                {"timestamp_header": "X-T", "signed_message": "{ts}.{body}"},
                "exactly when",
            ),
            (
                {
                    "timestamp_header": "X-T",
                    "signed_message": "{timestamp}.{id}.{body}",
                },
                "only knows",
            ),
        ]
        for kwargs, match in cases:
            with pytest.raises(ValueError, match=match):
                HMACSignatureAuth(WEBHOOK_SECRET, header="X-Signature", **kwargs)

    def test_openapi(self):
        schemes = (
            self._client(HMACSignatureAuth(WEBHOOK_SECRET, **self.STRIPE))
            .get("/openapi.json")
            .json()["components"]["securitySchemes"]
        )
        assert schemes == {
            "APIKeyHeader_Stripe-Signature": {
                "type": "apiKey",
                "in": "header",
                "name": "Stripe-Signature",
            }
        }


class TestIntrospectionValidator:
    """RFC 7662: opaque tokens checked by the provider, answers cached."""

    URL = "https://idp.example.com/introspect"

    @staticmethod
    def _active(**overrides) -> dict:
        return {
            "active": True,
            "sub": "user-1",
            "aud": "my-api",
            "scope": "read write",
            "exp": int(time.time()) + 300,
            **overrides,
        }

    def _validator(self, **kwargs) -> IntrospectionValidator:
        kwargs.setdefault("audience", "my-api")
        return IntrospectionValidator(
            url=self.URL, client_id="my-api", client_secret="api-secret", **kwargs
        )

    @respx.mock
    def test_an_active_token_passes(self):
        route = respx.post(self.URL).respond(json=self._active())
        validator = IntrospectionValidator(
            url=self.URL,
            client_id="my:api",
            client_secret="s:c r%t",
            audience="my-api",
        )
        response = _auth_client(validator).get(
            "/me", headers={"Authorization": "Bearer opaque-token"}
        )
        assert response.json()["sub"] == "user-1"
        request = route.calls.last.request
        assert parse_qs(request.content.decode()) == {
            "token": ["opaque-token"],
            "token_type_hint": ["access_token"],
        }
        scheme, _, encoded = request.headers["authorization"].partition(" ")
        assert scheme == "Basic"
        assert base64.b64decode(encoded) == b"my%3Aapi:s%3Ac+r%25t"

    @respx.mock
    def test_active_answers_are_cached(self):
        route = respx.post(self.URL).respond(json=self._active())
        client = _auth_client(self._validator())
        for _ in range(3):
            assert _status(client, "token-a") == 200
        assert route.call_count == 1
        assert _status(client, "token-b") == 200
        assert route.call_count == 2

        with patch("time.monotonic", return_value=time.monotonic() + 61):
            assert _status(client, "token-a") == 200
        assert route.call_count == 3

        route.reset()
        route.respond(json=self._active(exp=int(time.time()) + 5))
        client = _auth_client(self._validator())
        _status(client, "short-lived")
        with patch("time.monotonic", return_value=time.monotonic() + 6):
            _status(client, "short-lived")
        assert route.call_count == 2

        for kwargs, tokens, calls in [
            ({"cache_ttl": 0}, ["a", "a"], 2),
            ({"cache_size": 1}, ["a", "b", "a"], 3),
        ]:
            route.reset()
            route.respond(json=self._active())
            client = _auth_client(self._validator(**kwargs))
            for token in tokens:
                _status(client, token)
            assert route.call_count == calls, kwargs

    @respx.mock
    def test_an_inactive_token_is_refused_and_not_cached(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        route = respx.post(self.URL)
        client = _auth_client(self._validator())
        for answer in [
            {"active": False},
            {"sub": "user-1"},
            self._active(active="true"),
        ]:
            caplog.clear()
            route.respond(json=answer)
            response = client.get("/me", headers={"Authorization": "Bearer t"})
            assert response.status_code == 401, answer
            assert response.headers["www-authenticate"] == "Bearer"
            assert [r.auth_reason for r in caplog.records] == ["inactive"]
        assert route.call_count == 3

    @respx.mock
    def test_an_unusable_endpoint_answers_503(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        route = respx.post(self.URL)
        client = _auth_client(self._validator())
        for outcome in [
            httpx.Response(500),
            httpx.ConnectTimeout("slow"),
            httpx.Response(200, text="not json"),
            httpx.Response(200, content=b'{"active": "\xff"}'),
            httpx.Response(200, json=["active"]),
            httpx.Response(401),
        ]:
            caplog.clear()
            route.side_effect = [outcome]
            response = client.get("/me", headers={"Authorization": "Bearer t"})
            assert response.status_code == 503, outcome
            assert response.json() == {
                "detail": "Authentication temporarily unavailable"
            }
            reasons = [getattr(r, "auth_reason", None) for r in caplog.records]
            assert reasons[-1] == "introspection_unavailable"
        assert "refused the client credentials" in caplog.text

    @respx.mock
    def test_claims_are_checked(self):
        route = respx.post(self.URL)
        now = int(time.time())
        for kwargs, answer, expected in [
            ({}, self._active(aud="other-api"), 401),
            ({}, self._active(aud=None), 401),
            ({}, self._active(aud=[{"x": 1}]), 401),
            ({}, self._active(aud=["other-api", "my-api"]), 200),
            ({"audience": ["my-api", "admin-api"]}, self._active(aud="admin-api"), 200),
            (
                {"audience": IntrospectionValidator.ANY_AUDIENCE},
                self._active(aud=None),
                200,
            ),
            (
                {"issuer": "https://idp.example.com"},
                self._active(iss="https://evil.example"),
                401,
            ),
            (
                {"issuer": "https://idp.example.com"},
                self._active(iss="https://idp.example.com"),
                200,
            ),
            ({}, self._active(exp=now - 10), 401),
            ({"leeway": 30}, self._active(exp=now - 10), 200),
            ({}, self._active(exp="soon"), 401),
            ({}, self._active(nbf=now + 60), 401),
            ({}, self._active(nbf=None), 401),
            ({}, self._active(nbf=now - 60), 200),
            ({}, self._active(typ="Refresh"), 401),
            ({}, self._active(typ="Offline"), 401),
            ({}, self._active(typ="ID"), 401),
            ({}, self._active(typ="Bearer"), 200),
            ({}, self._active(token_use="refresh_token"), 401),
            ({}, self._active(token_use="access_token"), 200),
            ({}, self._active(token_type="Bearer"), 200),
        ]:
            route.respond(json=answer)
            client = _auth_client(self._validator(**kwargs))
            assert _status(client, "t") == expected, (kwargs, answer)

    @respx.mock
    def test_scopes_and_identity(self):
        respx.post(self.URL).respond(
            json=self._active(acr="mfa", auth_time=int(time.time()))
        )
        source = HTTPBearerAuth(self._validator(claims_to_identity=lambda c: c["sub"]))

        def setup(app: FastAPI):
            @app.get("/read")
            async def read(user=Security(source, scopes=["read"])):
                return user

            @app.get("/admin")
            async def admin(user=Security(source, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        headers = {"Authorization": "Bearer t"}
        assert client.get("/read", headers=headers).json() == "user-1"
        assert client.get("/admin", headers=headers).status_code == 403

        strong = HTTPBearerAuth(self._validator()).stepped_up(
            ["mfa"], acr=lambda claims: claims.get("acr")
        )
        recent = HTTPBearerAuth(self._validator()).fresh(
            300, authenticated_at=lambda claims: claims.get("auth_time")
        )
        for dep in [strong, recent]:
            assert _client(dep).get("/me", headers=headers).status_code == 200

    def _slow_endpoint(self, answer: dict) -> list[httpx.Request]:
        """Answer introspections slowly with `answer`; return the requests sent."""
        import asyncio

        sent: list[httpx.Request] = []

        async def slow(request):
            sent.append(request)
            await asyncio.sleep(0.05)
            return httpx.Response(200, json=answer)

        respx.post(self.URL).mock(side_effect=slow)
        return sent

    @pytest.mark.anyio
    @respx.mock
    async def test_concurrent_requests_share_one_introspection(self):
        import asyncio

        for answer, kwargs in [
            (self._active(), {}),
            (self._active(), {"cache_ttl": 0}),
            ({"active": False}, {}),
        ]:
            sent = self._slow_endpoint(answer)
            validator = self._validator(**kwargs)
            results = await asyncio.gather(
                *(validator("t") for _ in range(3)), return_exceptions=True
            )
            assert len(sent) == 1, answer
            if answer["active"]:
                assert all(
                    isinstance(r, dict) and r["sub"] == "user-1" for r in results
                )
            else:
                assert all(isinstance(r, UnauthorizedError) for r in results)
                assert len({id(r) for r in results}) == 3

    @pytest.mark.anyio
    @respx.mock
    async def test_a_cancelled_introspection_lets_the_waiters_retry(self):
        import asyncio

        sent = self._slow_endpoint(self._active())
        validator = self._validator()
        leader = asyncio.ensure_future(validator("t"))
        while not sent:
            await asyncio.sleep(0)
        follower = asyncio.ensure_future(validator("t"))
        await asyncio.sleep(0)
        leader.cancel()
        assert (await follower)["sub"] == "user-1"
        assert len(sent) == 2

    @respx.mock
    def test_changing_the_identity_leaves_the_cache_alone(self):
        respx.post(self.URL).respond(json=self._active(groups=["staff"]))

        def escalate(claims: dict) -> dict:
            claims["scope"] += " admin"
            claims["groups"].append("root")
            return claims

        source = HTTPBearerAuth(self._validator(claims_to_identity=escalate))

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(source, scopes=["admin"])):
                return user

            @app.get("/me")
            async def me(user=Security(source)):
                return user

        client = TestClient(_app(setup))
        headers = {"Authorization": "Bearer t"}
        for _ in range(2):
            assert client.get("/me", headers=headers).json()["groups"] == [
                "staff",
                "root",
            ]
            assert client.get("/admin", headers=headers).status_code == 403

    @respx.mock
    def test_a_borrowed_client_is_reused(self):
        respx.post(self.URL).respond(json=self._active())
        http = httpx.AsyncClient()
        client = _auth_client(self._validator(client=http))
        assert _status(client, "t") == 200
        assert not http.is_closed

    def test_misconfiguration_rejected(self):
        with pytest.raises(ValueError, match="https"):
            IntrospectionValidator(
                url="http://idp.example.com/introspect",
                client_id="a",
                client_secret="b",
                audience="my-api",
            )
        IntrospectionValidator(
            url="http://localhost:8080/introspect",
            client_id="a",
            client_secret="b",
            audience="my-api",
        )
        with pytest.raises(ValueError, match="audience is required"):
            IntrospectionValidator(url=self.URL, client_id="a", client_secret="b")
        for name in ["leeway", "cache_ttl"]:
            for value in [-1, math.inf, math.nan]:
                with pytest.raises(ValueError, match=name):
                    self._validator(**{name: value})
        with pytest.raises(ValueError, match="cache_size"):
            self._validator(cache_size=0)


_EC_KEY = ec.generate_private_key(ec.SECP256R1())
_EC_KEY_2 = ec.generate_private_key(ec.SECP256R1())
_ED_KEY = ed25519.Ed25519PrivateKey.generate()


def _public_jwk(key) -> dict:
    public = key.public_key()
    if isinstance(public, ec.EllipticCurvePublicKey):
        return json.loads(ECAlgorithm.to_jwk(public))
    if isinstance(public, rsa.RSAPublicKey):
        return json.loads(RSAAlgorithm.to_jwk(public))
    return json.loads(OKPAlgorithm.to_jwk(public))


def _ath(token: str) -> str:
    digest = hashlib.sha256(token.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class TestDPoP:
    """RFC 9449: the token only works with a proof signed by the key it is bound to."""

    URL = "http://testserver/me"
    ALGS = "ES256 RS256 PS256 EdDSA"
    PROOF_CHALLENGE = f'DPoP error="invalid_dpop_proof", algs="{ALGS}"'

    @staticmethod
    def _token(key=_EC_KEY, **claims) -> str:
        cnf = {"jkt": _jwk_thumbprint(_public_jwk(key))}
        return _hs_token(_claims(cnf=cnf, **claims))

    @staticmethod
    def _proof(
        token: str,
        key: Any = _EC_KEY,
        *,
        alg: str = "ES256",
        drop: tuple[str, ...] = (),
        **overrides: Any,
    ) -> str:
        header = {
            "typ": overrides.pop("typ", "dpop+jwt"),
            "jwk": overrides.pop("jwk") if "jwk" in overrides else _public_jwk(key),
        }
        claims = {
            "jti": secrets.token_urlsafe(),
            "htm": "GET",
            "htu": TestDPoP.URL,
            "iat": int(time.time()),
            "ath": _ath(token),
            **overrides,
        }
        for name in drop:
            claims.pop(name, None)
        header = {name: value for name, value in header.items() if value is not None}
        return pyjwt.encode(claims, key, algorithm=alg, headers=header)

    @staticmethod
    def _source(validator: Any = None, **kwargs) -> HTTPDPoPAuth:
        kwargs.setdefault("replay_check", HTTPDPoPAuth.NO_REPLAY_CHECK)
        return HTTPDPoPAuth(validator or JWTValidator(secret=JWT_SECRET), **kwargs)

    @staticmethod
    def _get(client: TestClient, token: str, proof: str | None, scheme="DPoP"):
        headers = {"Authorization": f"{scheme} {token}"}
        if proof is not None:
            headers["DPoP"] = proof
        return client.get("/me", headers=headers)

    def test_a_bound_token_with_its_proof_passes(self):
        client = _client(self._source())
        for key, alg in [
            (_EC_KEY, "ES256"),
            (_RSA_KEY_1, "RS256"),
            (_RSA_KEY_1, "PS256"),
            (_ED_KEY, "EdDSA"),
        ]:
            token = self._token(key)
            response = self._get(client, token, self._proof(token, key, alg=alg))
            assert response.json()["sub"] == "user-1", alg
        token = self._token()
        for htu in ["http://TESTSERVER:80/me?page=2#top", "HTTP://testserver/me"]:
            response = self._get(client, token, self._proof(token, htu=htu))
            assert response.status_code == 200, htu

    def test_the_challenge_and_openapi(self):
        client = _client(self._source())
        response = client.get("/me")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == f'DPoP algs="{self.ALGS}"'
        token = self._token()
        response = self._get(client, token, self._proof(token), scheme="Bearer")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == f'DPoP algs="{self.ALGS}"'
        schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]
        assert schemes == {"DPoP": {"type": "http", "scheme": "DPoP"}}

    def test_invalid_proofs_are_refused(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        client = _client(self._source())
        token = self._token()
        now = int(time.time())
        ec_384 = ec.generate_private_key(ec.SECP384R1())
        no_y = {k: v for k, v in _public_jwk(_EC_KEY).items() if k != "y"}
        cases: dict[str, str | None] = {
            "missing": None,
            "not a jwt": "not-a-jwt",
            "typ": self._proof(token, typ="JWT"),
            "no typ": self._proof(token, typ=None),
            "symmetric": self._proof(
                token, JWT_SECRET, alg="HS256", jwk={"kty": "oct", "k": "c2VjcmV0"}
            ),
            "kty type": self._proof(token, jwk={**_public_jwk(_EC_KEY), "kty": ["EC"]}),
            "unlisted alg": self._proof(token, ec_384, alg="ES384"),
            "no jwk": self._proof(token, jwk=None),
            "private jwk": self._proof(
                token, jwk=json.loads(ECAlgorithm.to_jwk(_EC_KEY))
            ),
            "oct jwk": self._proof(token, jwk={"kty": "oct", "k": "c2VjcmV0"}),
            "incomplete jwk": self._proof(token, jwk=no_y),
            "jwk of another key": self._proof(token, jwk=_public_jwk(_EC_KEY_2)),
            "jwk of another type": self._proof(token, jwk=_public_jwk(_RSA_KEY_1)),
            "htm": self._proof(token, htm="POST"),
            "htu path": self._proof(token, htu="http://testserver/admin"),
            "htu host": self._proof(token, htu="http://evil.example/me"),
            "htu port": self._proof(token, htu="http://testserver:8080/me"),
            "htu garbage": self._proof(token, htu="http://[::1/me"),
            "htu relative": self._proof(token, htu="/me"),
            "htu type": self._proof(token, htu=7),
            "stale": self._proof(token, iat=now - 120),
            "future": self._proof(token, iat=now + 60),
            "iat type": self._proof(token, iat="now"),
            "ath": self._proof(token, ath=_ath("another-token")),
            "ath type": self._proof(token, ath=7),
            "empty jti": self._proof(token, jti=""),
            "jti type": self._proof(token, jti=7),
            **{
                f"no {c}": self._proof(token, drop=(c,))
                for c in ("jti", "htm", "htu", "iat", "ath")
            },
        }
        for case, proof in cases.items():
            caplog.clear()
            response = self._get(client, token, proof)
            assert response.status_code == 401, case
            assert response.headers["www-authenticate"] == self.PROOF_CHALLENGE, case
            assert [r.auth_reason for r in caplog.records] == ["invalid_dpop_proof"], (
                case
            )

        proof = self._proof(token)
        response = client.get(
            "/me",
            headers=[
                ("Authorization", f"DPoP {token}"),
                ("DPoP", proof),
                ("DPoP", proof),
            ],
        )
        assert response.status_code == 401

    def test_the_token_must_be_bound_to_the_proof_key(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        client = _client(self._source())
        for token in [self._token(_EC_KEY_2), _hs_token(_claims())]:
            caplog.clear()
            response = self._get(client, token, self._proof(token))
            assert response.status_code == 401
            assert response.headers["www-authenticate"] == self.PROOF_CHALLENGE
            assert [r.auth_reason for r in caplog.records] == ["dpop_key_mismatch"]

        token = self._token()
        user = JWTValidator(
            secret=JWT_SECRET,
            claims_to_identity=lambda c: {"id": c["sub"], "key": c["cnf"]["jkt"]},
        )
        proof = self._proof(token)
        assert self._get(_client(self._source(user)), token, proof).status_code == 401

        async def jkt(identity: dict) -> str:
            return identity["key"]

        reader = self._source(user, jkt=jkt)
        response = self._get(_client(reader), token, self._proof(token))
        assert response.json() == {
            "id": "user-1",
            "key": _jwk_thumbprint(_public_jwk(_EC_KEY)),
        }

    def test_bearer_sources_refuse_a_bound_token(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        validator = JWTValidator(secret=JWT_SECRET)
        token = self._token()
        sources = [
            HTTPBearerAuth(validator),
            OAuth2PasswordBearerAuth(validator, token_url="/token"),
            OAuth2AuthorizationCodeBearerAuth(
                validator, authorization_url="/authorize", token_url="/token"
            ),
            OpenIdConnectAuth(validator, openid_connect_url="/.well-known/openid"),
        ]
        for source in sources:
            caplog.clear()
            response = self._get(_client(source), token, None, scheme="Bearer")
            assert response.status_code == 401, type(source).__name__
            assert response.headers["www-authenticate"] == "Bearer"
            assert [r.auth_reason for r in caplog.records] == ["dpop_bound"]

        mtls = _hs_token(
            _claims(cnf={"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"})
        )
        for source, bound, expected in [
            (HTTPBearerAuth(validator), mtls, 200),
            (HTTPBearerAuth(validator, allow_dpop_bound=True), token, 200),
            (
                OpenIdConnectAuth(
                    validator, openid_connect_url="/oidc", allow_dpop_bound=True
                ),
                token,
                200,
            ),
            (HTTPBearerAuth(validator).require(), token, 401),
        ]:
            response = self._get(_client(source), bound, None, scheme="Bearer")
            assert response.status_code == expected

    def test_replays_are_refused(self, caplog):
        caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        seen: dict[str, float] = {}

        def remember(jti: str, expires_at: float) -> bool:
            if jti in seen:
                return False
            seen[jti] = expires_at
            return True

        validate = JWTValidator(secret=JWT_SECRET)
        refusals = [UnauthorizedError()]

        async def flaky(token: str) -> dict:
            if refusals:
                raise refusals.pop()
            return await validate(token)

        client = _client(self._source(flaky, replay_check=remember))
        token = self._token()
        iat = int(time.time())
        proof = self._proof(token, iat=iat, jti="proof-1")
        assert self._get(client, token, proof).status_code == 401
        assert seen == {}
        assert self._get(client, token, proof).status_code == 200
        assert seen == {"proof-1": iat + 65}
        caplog.clear()
        response = self._get(client, token, proof)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == self.PROOF_CHALLENGE
        assert [r.auth_reason for r in caplog.records] == ["dpop_replay"]

        async def never_seen(jti: str, expires_at: float) -> bool:
            return True

        client = _client(self._source(replay_check=never_seen))
        for _ in range(2):
            assert self._get(client, token, proof).status_code == 200

    def test_public_origin(self):
        def setup(app: FastAPI):
            for path, source in [
                ("/me", self._source(public_origin="https://API.example.com")),
                ("/direct", self._source()),
            ]:
                app.add_api_route(path, lambda user=Security(source): user)

        client = TestClient(_app(setup), base_url="http://internal:8000")
        token = self._token()
        public = self._proof(token, htu="https://api.example.com/me")
        internal = self._proof(token, htu="http://internal:8000/me")
        assert self._get(client, token, public).status_code == 200
        assert self._get(client, token, internal).status_code == 401
        headers = {"Authorization": f"DPoP {token}"}
        for htu, expected in [
            ("https://api.example.com/direct", 401),
            ("http://internal:8000/direct", 200),
        ]:
            headers["DPoP"] = self._proof(token, htu=htu)
            assert client.get("/direct", headers=headers).status_code == expected

    def test_htu_names_the_path_as_the_client_sent_it(self):
        source = self._source()
        public = self._source(public_origin="https://api.example.com")

        def setup(app: FastAPI):
            app.add_api_route("/files/{name:path}", lambda user=Security(source): user)
            app.add_api_route("/public/{name}", lambda user=Security(public): user)

        token = self._token()
        for root_path in ["", "/api"]:
            client = TestClient(_app(setup), root_path=root_path)
            base = f"http://testserver{root_path}"
            for path, htu, expected in [
                ("/files/abc", "/files/abc", 200),
                ("/files/a%20b", "/files/a%20b", 200),
                ("/files/caf%C3%A9", "/files/caf%C3%A9", 200),
                ("/files/caf%C3%A9", "/files/caf%c3%a9", 200),
                ("/files/caf%C3%A9", "/files/café", 200),
                ("/files/a~b", "/files/a%7Eb", 200),
                ("/files/a%3Fb", "/files/a%3Fb", 200),
                ("/files/a%2Fb", "/files/a%2Fb", 200),
                ("/files/a%2Fb", "/files/a/b", 401),
                ("/files/a%20b", "/files/a+b", 401),
            ]:
                headers = {
                    "Authorization": f"DPoP {token}",
                    "DPoP": self._proof(token, htu=base + htu),
                }
                response = client.get(root_path + path, headers=headers)
                assert response.status_code == expected, (root_path, path, htu)
            headers["DPoP"] = self._proof(
                token, htu=f"https://api.example.com{root_path}/public/a%20b"
            )
            response = client.get(f"{root_path}/public/a%20b", headers=headers)
            assert response.status_code == 200, root_path

    def test_composes_with_fresh(self):
        dep = self._source().fresh(
            300, authenticated_at=lambda claims: claims["auth_time"]
        )
        token = self._token(auth_time=0)
        response = self._get(_client(dep), token, self._proof(token))
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == (
            f'DPoP algs="{self.ALGS}", error="insufficient_user_authentication", '
            'error_description="More recent authentication is required", max_age="300"'
        )

    @pytest.mark.anyio
    async def test_without_a_usable_request_url(self):
        source = self._source()
        token = self._token()
        with pytest.raises(UnauthorizedError):
            await source.authenticate(token)
        for htu in [self.URL, "/"]:
            proof = self._proof(token, htu=htu)
            request = _request(authorization=f"DPoP {token}", dpop=proof)
            with pytest.raises(UnauthorizedError):
                await source.dispatch(request, [])

    def test_proof_keys_are_parsed_once_per_key(self, monkeypatch):
        parsed: list[str | None] = []
        pyjwk = pyjwt.PyJWK

        def counting(jwk, algorithm=None):
            parsed.append(algorithm)
            return pyjwk(jwk, algorithm=algorithm)

        monkeypatch.setattr(pyjwt, "PyJWK", counting)
        monkeypatch.setattr("fastapi_multiauth.sources.dpop._KEY_CACHE_SIZE", 2)
        p256, p256_2, ed = (_EC_KEY, "ES256"), (_EC_KEY_2, "ES256"), (_ED_KEY, "EdDSA")
        for keys, calls in [
            ([p256, p256, p256], 1),
            ([p256, p256_2, p256, p256_2], 2),
            ([p256, p256_2, ed, p256], 4),
        ]:
            parsed.clear()
            client = _client(self._source())
            for key, alg in keys:
                token = self._token(key)
                response = self._get(client, token, self._proof(token, key, alg=alg))
                assert response.status_code == 200, alg
            assert len(parsed) == calls, keys

        # A key that does not parse, or whose proof does not verify, takes
        # no slot from the cached ones.
        parsed.clear()
        client = _client(self._source())
        token, token_2 = self._token(), self._token(_EC_KEY_2)
        malformed = self._proof(token, jwk={**_public_jwk(_EC_KEY), "x": "AAAA"})
        forged = [
            self._proof(token, jwk=_public_jwk(ec.generate_private_key(ec.SECP256R1())))
            for _ in range(3)
        ]
        for bound, proof, status in [
            (token, self._proof(token), 200),
            (token_2, self._proof(token_2, _EC_KEY_2), 200),
            (token, malformed, 401),
            (token, malformed, 401),
            *[(token, proof, 401) for proof in forged],
            (token, self._proof(token), 200),
            (token_2, self._proof(token_2, _EC_KEY_2), 200),
        ]:
            assert self._get(client, bound, proof).status_code == status
        assert len(parsed) == 7

    def test_thumbprint_matches_rfc_7638(self):
        jwk = {
            "kty": "RSA",
            "e": "AQAB",
            "alg": "RS256",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
        }
        assert _jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    def test_misconfiguration_rejected(self):
        validator = JWTValidator(secret=JWT_SECRET)
        with pytest.raises(ValueError, match="replay_check is required"):
            HTTPDPoPAuth(validator)
        assert repr(HTTPDPoPAuth.NO_REPLAY_CHECK) == "HTTPDPoPAuth.NO_REPLAY_CHECK"
        with pytest.raises(TypeError, match="not a string"):
            self._source(algorithms="ES256")
        with pytest.raises(ValueError, match="at least one"):
            self._source(algorithms=[])
        for alg in ["HS256", "none", "XX999"]:
            with pytest.raises(ValueError, match="cannot sign a DPoP proof"):
                self._source(algorithms=[alg])
        for proof_max_age in [0, -1, math.inf]:
            with pytest.raises(ValueError, match="proof_max_age"):
                self._source(proof_max_age=proof_max_age)
        for leeway in [-1, math.nan]:
            with pytest.raises(ValueError, match="leeway"):
                self._source(leeway=leeway)
        for origin in [
            "https://api.example.com/",
            "https://api.example.com/v1",
            "api.example.com",
            "https://user@api.example.com",
            "https://api.example.com:99999",
        ]:
            with pytest.raises(ValueError, match="public_origin"):
                self._source(public_origin=origin)


SECRET_CREDENTIAL = "s3cr3t-credential-value"


class TestSecurityLogging:
    """One PII-free record per decision, under fastapi_multiauth.*."""

    @pytest.fixture(autouse=True)
    def _capture(self, caplog):
        caplog.set_level(logging.DEBUG, logger="fastapi_multiauth")
        self.caplog = caplog

    def _decisions(self) -> list[Any]:
        return [r for r in self.caplog.records if hasattr(r, "auth_reason")]

    def _only(self) -> Any:
        records = self._decisions()
        assert len(records) == 1, [r.getMessage() for r in records]
        return records[0]

    def _assert_no_leak(self, *secrets_: str) -> None:
        for record in self.caplog.records:
            dumped = f"{record.getMessage()} {record.__dict__!r}"
            for secret in (SECRET_CREDENTIAL, *secrets_):
                assert secret not in dumped

    def _assert_refusal(
        self, logger_name, source, reason, status, level=logging.WARNING
    ):
        record = self._only()
        assert record.name == logger_name
        assert record.levelno == level
        assert (record.auth_source, record.auth_reason, record.auth_status) == (
            source,
            reason,
            status,
        )
        assert record.getMessage() == f"{source}: {reason}"
        self._assert_no_leak()
        return record

    @staticmethod
    def _bearer_header(token: str = SECRET_CREDENTIAL) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_the_package_logger_has_a_null_handler(self):
        handlers = logging.getLogger("fastapi_multiauth").handlers
        assert any(isinstance(h, logging.NullHandler) for h in handlers)

    def test_success_and_anonymous_are_logged_at_debug(self):
        async def validate(token: str) -> dict:
            return {"email": "alice@example.com"}

        _client(HTTPBearerAuth(validate)).get("/me", headers=self._bearer_header())
        record = self._only()
        assert record.levelno == logging.DEBUG
        assert record.name == "fastapi_multiauth.sources.bearer"
        assert (record.auth_reason, record.auth_status) == ("authenticated", None)
        assert record.auth_scheme == "HTTPBearer"
        self._assert_no_leak("alice@example.com")

        self.caplog.clear()
        _client(HTTPBearerAuth(simple_validator).optional()).get("/me")
        record = self._only()
        assert (record.levelno, record.auth_reason) == (logging.DEBUG, "anonymous")

    def test_success_builds_no_record_when_debug_is_off(self):
        self.caplog.set_level(logging.WARNING, logger="fastapi_multiauth")
        bearer_logger = logging.getLogger("fastapi_multiauth.sources.bearer")
        with patch.object(bearer_logger, "log") as log:
            _client(HTTPBearerAuth(simple_validator)).get(
                "/me", headers=self._bearer_header(VALID_TOKEN)
            )
        log.assert_not_called()

    def test_a_missing_credential_is_logged_at_info(self):
        _client(HTTPBearerAuth(simple_validator)).get("/me")
        self._assert_refusal(
            "fastapi_multiauth.sources.bearer",
            "HTTPBearerAuth",
            "missing_credential",
            401,
            level=logging.INFO,
        )

    def test_validator_refusals(self):
        for status_code, reason in [
            (401, "rejected"),
            (403, "forbidden"),
            (429, "error"),
        ]:

            async def validate(token: str, status_code=status_code) -> dict:
                raise HTTPException(status_code=status_code, detail="alice@example.com")

            self.caplog.clear()
            _client(HTTPBearerAuth(validate)).get("/me", headers=self._bearer_header())
            self._assert_refusal(
                "fastapi_multiauth.sources.bearer",
                "HTTPBearerAuth",
                reason,
                status_code,
            )
            self._assert_no_leak("alice@example.com")

    def test_cookie_refusals(self):
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=COOKIE_SECRET, secure=False, ttl=60
        )
        _client(auth).get("/me", cookies={"session": SECRET_CREDENTIAL})
        record = self._assert_refusal(
            "fastapi_multiauth.sources.cookie",
            "APIKeyCookieAuth",
            "invalid_signature",
            401,
        )
        assert record.auth_scheme == "APIKeyCookie_session"

        self.caplog.clear()
        cookie = auth._sign(VALID_COOKIE)
        with patch("time.time", return_value=time.time() + 120):
            _client(auth).get("/me", cookies={"session": cookie})
        self._assert_refusal(
            "fastapi_multiauth.sources.cookie", "APIKeyCookieAuth", "expired", 401
        )
        self._assert_no_leak(cookie, VALID_COOKIE)

    def test_a_malformed_basic_blob(self):
        for blob in ["!!!", base64.b64encode(SECRET_CREDENTIAL.encode()).decode()]:
            self.caplog.clear()
            _client(HTTPBasicAuth(simple_validator)).get(
                "/me", headers={"Authorization": f"Basic {blob}"}
            )
            self._assert_refusal(
                "fastapi_multiauth.sources.basic", "HTTPBasicAuth", "malformed", 401
            )
            self._assert_no_leak(blob)

    def test_each_module_logs_under_its_own_name(self):
        for source, logger_name in [
            (APIKeyHeaderAuth("X-Key", simple_validator), "sources.header"),
            (APIKeyQueryAuth("key", simple_validator), "sources.query"),
            (
                OAuth2PasswordBearerAuth(simple_validator, token_url="/token"),
                "sources.oauth2",
            ),
            (_HeaderAuth(VALID_TOKEN), "abc"),
        ]:
            self.caplog.clear()
            _client(source).get(
                f"/me?key={SECRET_CREDENTIAL}",
                headers={
                    "X-Key": SECRET_CREDENTIAL,
                    "X-Token": SECRET_CREDENTIAL,
                    **self._bearer_header(),
                },
            )
            record = self._only()
            assert record.name == f"fastapi_multiauth.{logger_name}"
            assert record.auth_reason == "rejected"
            self._assert_no_leak()

    def test_step_up_refusals(self):
        for dep, reason in [
            (
                HTTPBearerAuth(simple_validator).fresh(
                    300, authenticated_at=lambda _: 0
                ),
                "stale",
            ),
            (
                HTTPBearerAuth(simple_validator).stepped_up(
                    ["gold"], acr=lambda _: "x"
                ),
                "insufficient_acr",
            ),
        ]:
            self.caplog.clear()
            _client(dep).get("/me", headers=self._bearer_header(VALID_TOKEN))
            self._assert_refusal(
                "fastapi_multiauth.sources.bearer", "HTTPBearerAuth", reason, 401
            )

    def test_multiauth(self):
        auth = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyHeaderAuth("X-Key", simple_validator),
        )
        client = _client(auth)
        client.get("/me")
        record = self._assert_refusal(
            "fastapi_multiauth.sources.multi",
            "MultiAuth",
            "missing_credential",
            401,
            level=logging.INFO,
        )
        assert record.auth_scheme is None

        # It logs once, as the matched source.
        self.caplog.clear()
        client.get("/me", headers={"X-Key": SECRET_CREDENTIAL})
        self._assert_refusal(
            "fastapi_multiauth.sources.header", "APIKeyHeaderAuth", "rejected", 401
        )

    def test_jwt_refusals_carry_the_pyjwt_reason(self):
        validator = JWTValidator(secret=JWT_SECRET, audience=CLIENT_ID, issuer=ISSUER)
        client = _client(HTTPBearerAuth(validator))
        for token, reason in [
            (_hs_token(_id_claims(exp=int(time.time()) - 60)), "expired"),
            (_hs_token(_id_claims(nbf=int(time.time()) + 3600)), "not_yet_valid"),
            (_hs_token(_id_claims(aud="other")), "invalid_audience"),
            (_hs_token(_id_claims(iss="https://evil.example")), "invalid_issuer"),
            (_hs_token(_id_claims(exp=None)), "missing_claim"),
            (
                _hs_token(_id_claims(), secret="another-jwt-secret-32-bytes-min!!"),
                "invalid_signature",
            ),
            (SECRET_CREDENTIAL, "invalid_token"),
        ]:
            self.caplog.clear()
            client.get("/me", headers=self._bearer_header(token))
            self._assert_refusal(
                "fastapi_multiauth.sources.bearer", "HTTPBearerAuth", reason, 401
            )
            self._assert_no_leak(token)

    def test_jwt_insufficient_scope(self):
        validator = JWTValidator(secret=JWT_SECRET)
        bearer = HTTPBearerAuth(validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin"])):
                return user

        token = _hs_token(_claims(scope="read"))
        TestClient(_app(setup)).get("/admin", headers=self._bearer_header(token))
        self._assert_refusal(
            "fastapi_multiauth.sources.bearer",
            "HTTPBearerAuth",
            "insufficient_scope",
            403,
        )

    @respx.mock
    def test_jwks_refusals(self):
        route = respx.get(ID_JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1")]}
        )
        for token, reason in [
            ("not.a-jwt", "malformed"),
            (_id_token(kid="nope"), "unknown_key"),
        ]:
            self.caplog.clear()
            _auth_client(_jwks_validator(ID_JWKS_URL)).get(
                "/me", headers=self._bearer_header(token)
            )
            assert self._only().auth_reason == reason
            self._assert_no_leak(token)

        self.caplog.clear()
        route.respond(500)
        token = _id_token()
        _auth_client(_jwks_validator(ID_JWKS_URL)).get(
            "/me", headers=self._bearer_header(token)
        )
        decisions = self._decisions()
        assert [(r.auth_reason, r.auth_status) for r in decisions] == [
            ("jwks_unavailable", 503)
        ]
        self._assert_no_leak(token)
