"""Tests for fastapi_multiauth."""

import base64
import hashlib
import json
import time
from typing import Any, cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Security
from jwt.algorithms import RSAAlgorithm
from fastapi.testclient import TestClient

from fastapi_multiauth.exceptions import UnauthorizedError
from fastapi_multiauth import (
    APIKeyHeaderAuth,
    APIKeyQueryAuth,
    AuthSource,
    HTTPBasicAuth,
    HTTPBearerAuth,
    APIKeyCookieAuth,
    ForbiddenError,
    JWTValidator,
    MultiAuth,
    hash_token,
    verify_token_hash,
)
from fastapi_multiauth.oauth import (
    OAuthDiscoveryError,
    OAuthExchangeError,
    OAuthUserinfoError,
    OIDCEndpoints,
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_encode_state,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
    oauth_resolve_provider_urls,
)


def _app(*routes_setup_fns):
    """Build a minimal FastAPI test app."""
    app = FastAPI()
    for fn in routes_setup_fns:
        fn(app)
    return app


VALID_TOKEN = "secret"
VALID_COOKIE = "session123"


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
    def test_valid_token_returns_identity(self):
        bearer = HTTPBearerAuth(simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_missing_header_returns_401(self):
        bearer = HTTPBearerAuth(simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me")
        assert response.status_code == 401

    def test_invalid_token_returns_401(self):
        bearer = HTTPBearerAuth(simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401

    def test_kwargs_forwarded_to_validator(self):
        bearer = HTTPBearerAuth(role_validator, role="admin")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_prefix_matching_passes_full_token(self):
        """Token with matching prefix: full token (with prefix) is passed to validator."""
        received: list[str] = []

        async def capturing_validator(credential: str) -> dict:
            received.append(credential)
            return {"user": "alice"}

        bearer = HTTPBearerAuth(capturing_validator, prefix="user_")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": "Bearer user_abc123"})
        assert response.status_code == 200
        # Prefix is kept — validator receives the full token as stored in DB
        assert received == ["user_abc123"]

    def test_prefix_mismatch_returns_401(self):
        bearer = HTTPBearerAuth(simple_validator, prefix="user_")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": "Bearer org_abc123"})
        assert response.status_code == 401

    @pytest.mark.anyio
    async def test_extract_no_header(self):
        from starlette.requests import Request

        bearer = HTTPBearerAuth(simple_validator)
        scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
        request = Request(scope)
        assert await bearer.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_empty_token(self):
        from starlette.requests import Request

        bearer = HTTPBearerAuth(simple_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer ")],
        }
        request = Request(scope)
        assert await bearer.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_no_prefix(self):
        from starlette.requests import Request

        bearer = HTTPBearerAuth(simple_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer mytoken")],
        }
        request = Request(scope)
        assert await bearer.extract(request) == "mytoken"

    @pytest.mark.anyio
    async def test_extract_prefix_match(self):
        from starlette.requests import Request

        bearer = HTTPBearerAuth(simple_validator, prefix="user_")
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer user_abc")],
        }
        request = Request(scope)
        assert await bearer.extract(request) == "user_abc"

    @pytest.mark.anyio
    async def test_extract_prefix_no_match(self):
        from starlette.requests import Request

        bearer = HTTPBearerAuth(simple_validator, prefix="user_")
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer org_abc")],
        }
        request = Request(scope)
        assert await bearer.extract(request) is None

    def test_generate_token_no_prefix(self):
        bearer = HTTPBearerAuth(simple_validator)
        token = bearer.generate_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_with_prefix(self):
        bearer = HTTPBearerAuth(simple_validator, prefix="user_")
        token = bearer.generate_token()
        assert token.startswith("user_")

    def test_generate_token_uniqueness(self):
        bearer = HTTPBearerAuth(simple_validator)
        assert bearer.generate_token() != bearer.generate_token()

    def test_generate_token_is_valid_credential(self):
        """A generated token (with prefix) is accepted by the same auth source."""
        stored: list[str] = []

        async def storing_validator(credential: str) -> dict:
            stored.append(credential)
            return {"token": credential}

        bearer = HTTPBearerAuth(storing_validator, prefix="user_")
        token = bearer.generate_token()

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert stored == [token]


class TestCookieAuth:
    def test_valid_cookie_returns_identity(self):
        cookie_auth = APIKeyCookieAuth("session", cookie_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(cookie_auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE}

    def test_missing_cookie_returns_401(self):
        cookie_auth = APIKeyCookieAuth("session", cookie_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(cookie_auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me")
        assert response.status_code == 401

    def test_invalid_cookie_returns_401(self):
        cookie_auth = APIKeyCookieAuth("session", cookie_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(cookie_auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", cookies={"session": "wrong"})
        assert response.status_code == 401

    def test_kwargs_forwarded_to_validator(self):
        async def session_validator(value: str, *, scope: str) -> dict:
            if value != VALID_COOKIE:
                raise UnauthorizedError()
            return {"session": value, "scope": scope}

        cookie_auth = APIKeyCookieAuth("session", session_validator, scope="read")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(cookie_auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE, "scope": "read"}

    @pytest.mark.anyio
    async def test_extract_no_cookie(self):
        from starlette.requests import Request

        auth = APIKeyCookieAuth("session", cookie_validator)
        scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
        request = Request(scope)
        assert await auth.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_cookie_present(self):
        from starlette.requests import Request

        auth = APIKeyCookieAuth("session", cookie_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"cookie", b"session=abc")],
        }
        request = Request(scope)
        assert await auth.extract(request) == "abc"


class TestAPIKeyHeaderAuth:
    def test_valid_key_returns_identity(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_missing_header_returns_401(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me")
        assert response.status_code == 401

    def test_invalid_key_returns_401(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"X-API-Key": "wrong"})
        assert response.status_code == 401

    def test_kwargs_forwarded_to_validator(self):
        auth = APIKeyHeaderAuth("X-API-Key", role_validator, role="admin")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_require_forwards_kwargs(self):
        auth = APIKeyHeaderAuth("X-API-Key", role_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth.require(role="admin"))):
                return user

        client = TestClient(_app(setup))
        response = client.get("/admin", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_require_preserves_name(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        derived = auth.require(role="admin")
        assert derived._name == "X-API-Key"

    def test_require_does_not_mutate_original(self):
        auth = APIKeyHeaderAuth("X-API-Key", role_validator, role="user")
        auth.require(role="admin")
        assert auth._kwargs == {"role": "user"}

    def test_in_multi_auth(self):
        """APIKeyHeaderAuth.authenticate() is exercised inside MultiAuth."""
        bearer = HTTPBearerAuth(simple_validator)
        api_key = APIKeyHeaderAuth("X-API-Key", simple_validator)
        multi = MultiAuth(bearer, api_key)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        # No bearer → falls through to API key header
        response = client.get("/me", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_is_auth_source(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        assert isinstance(auth, AuthSource)

    @pytest.mark.anyio
    async def test_extract_no_header(self):
        from starlette.requests import Request

        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
        request = Request(scope)
        assert await auth.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_empty_header(self):
        from starlette.requests import Request

        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-api-key", b"")],
        }
        request = Request(scope)
        assert await auth.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_key_present(self):
        from starlette.requests import Request

        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-api-key", b"mykey")],
        }
        request = Request(scope)
        assert await auth.extract(request) == "mykey"


class TestAPIKeyQueryAuth:
    def test_valid_key_returns_identity(self):
        auth = APIKeyQueryAuth("api_key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", params={"api_key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_missing_param_returns_401(self):
        auth = APIKeyQueryAuth("api_key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me")
        assert response.status_code == 401

    def test_invalid_key_returns_401(self):
        auth = APIKeyQueryAuth("api_key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", params={"api_key": "wrong"})
        assert response.status_code == 401

    def test_kwargs_forwarded_to_validator(self):
        auth = APIKeyQueryAuth("api_key", role_validator, role="admin")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", params={"api_key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_in_multi_auth(self):
        """APIKeyQueryAuth.authenticate() is exercised inside MultiAuth."""
        bearer = HTTPBearerAuth(simple_validator)
        query = APIKeyQueryAuth("api_key", simple_validator)
        multi = MultiAuth(bearer, query)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        # No bearer → falls through to API key query param
        response = client.get("/me", params={"api_key": VALID_TOKEN})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_is_auth_source(self):
        auth = APIKeyQueryAuth("api_key", simple_validator)
        assert isinstance(auth, AuthSource)

    @pytest.mark.anyio
    async def test_extract_no_param(self):
        from starlette.requests import Request

        auth = APIKeyQueryAuth("api_key", simple_validator)
        scope = {"type": "http", "method": "GET", "path": "/", "query_string": b""}
        request = Request(scope)
        assert await auth.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_empty_param(self):
        from starlette.requests import Request

        auth = APIKeyQueryAuth("api_key", simple_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"api_key=",
        }
        request = Request(scope)
        assert await auth.extract(request) is None

    @pytest.mark.anyio
    async def test_extract_key_present(self):
        from starlette.requests import Request

        auth = APIKeyQueryAuth("api_key", simple_validator)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"api_key=mykey",
        }
        request = Request(scope)
        assert await auth.extract(request) == "mykey"


class TestMultiAuth:
    def test_first_source_matches(self):
        bearer = HTTPBearerAuth(simple_validator)
        cookie = APIKeyCookieAuth("session", cookie_validator)
        multi = MultiAuth(bearer, cookie)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_second_source_matches_when_first_absent(self):
        bearer = HTTPBearerAuth(simple_validator)
        cookie = APIKeyCookieAuth("session", cookie_validator)
        multi = MultiAuth(bearer, cookie)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        # No Authorization header — falls through to cookie
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE}

    def test_no_source_matches_returns_401(self):
        bearer = HTTPBearerAuth(simple_validator)
        cookie = APIKeyCookieAuth("session", cookie_validator)
        multi = MultiAuth(bearer, cookie)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me")
        assert response.status_code == 401

    def test_invalid_credential_does_not_fallthrough(self):
        """If a credential is found but invalid, the next source is NOT tried."""
        second_called: list[bool] = []

        async def tracking_validator(credential: str) -> dict:
            second_called.append(True)
            return {"from": "second"}

        bearer = HTTPBearerAuth(simple_validator)  # raises on wrong token
        cookie = APIKeyCookieAuth("session", tracking_validator)
        multi = MultiAuth(bearer, cookie)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
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
        multi = MultiAuth(user_bearer, org_bearer)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))

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

    def test_rejects_non_auth_source_at_construction(self):
        with pytest.raises(TypeError, match="AuthSource"):
            MultiAuth(HTTPBearerAuth(role_validator), object())  # ty: ignore[invalid-argument-type]

    def test_rejects_nested_multi_auth(self):
        inner = MultiAuth(HTTPBearerAuth(role_validator))
        with pytest.raises(TypeError, match="nested"):
            MultiAuth(inner)  # ty: ignore[invalid-argument-type]

    def test_require_returns_new_multi_auth(self):
        from fastapi_multiauth.sources import MultiAuth as MultiAuthClass

        bearer = HTTPBearerAuth(role_validator)
        multi = MultiAuth(bearer)
        derived = multi.require(role="admin")
        assert isinstance(derived, MultiAuthClass)
        assert derived is not multi

    def test_require_forwards_kwargs_to_sources(self):
        """multi.require() propagates to all sources that support it."""
        bearer = HTTPBearerAuth(role_validator)
        multi = MultiAuth(bearer)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(multi.require(role="admin"))):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_require_skips_sources_without_require(self):
        """Sources without require() are passed through unchanged."""
        header_auth = _HeaderAuth(secret="s3cr3t")
        multi = MultiAuth(header_auth)
        derived = multi.require(role="admin")
        assert derived._sources[0] is header_auth

    def test_require_does_not_mutate_original(self):
        bearer = HTTPBearerAuth(role_validator, role="user")
        multi = MultiAuth(bearer)
        multi.require(role="admin")
        assert bearer._kwargs == {"role": "user"}

    def test_require_mixed_sources(self):
        """require() applies to sources with require(), skips those without."""
        from typing import cast

        bearer = HTTPBearerAuth(role_validator)
        header_auth = _HeaderAuth(secret="s3cr3t")
        multi = MultiAuth(bearer, header_auth)
        derived = multi.require(role="admin")
        # bearer got require() applied, header_auth passed through
        assert cast(HTTPBearerAuth, derived._sources[0])._kwargs == {"role": "admin"}
        assert derived._sources[1] is header_auth


class TestRequire:
    def test_bearer_require_forwards_kwargs(self):
        """require() creates a new instance that passes merged kwargs to validator."""
        bearer = HTTPBearerAuth(role_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer.require(role="admin"))):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}

    def test_bearer_require_overrides_existing_kwarg(self):
        """require() kwargs override kwargs set at instantiation."""
        bearer = HTTPBearerAuth(role_validator, role="user")

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer.require(role="admin"))):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json()["role"] == "admin"

    def test_bearer_require_preserves_prefix(self):
        """require() keeps the prefix of the original instance."""
        bearer = HTTPBearerAuth(role_validator, prefix="user_")
        derived = bearer.require(role="admin")
        assert derived._prefix == "user_"

    def test_bearer_require_does_not_mutate_original(self):
        """require() returns a new instance — original kwargs are unchanged."""
        bearer = HTTPBearerAuth(role_validator, role="user")
        bearer.require(role="admin")
        assert bearer._kwargs == {"role": "user"}

    def test_cookie_require_forwards_kwargs(self):
        async def scoped_validator(value: str, *, scope: str) -> dict:
            if value != VALID_COOKIE:
                raise UnauthorizedError()
            return {"session": value, "scope": scope}

        cookie = APIKeyCookieAuth("session", scoped_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(cookie.require(scope="admin"))):
                return user

        client = TestClient(_app(setup))
        response = client.get("/admin", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert response.json() == {"session": VALID_COOKIE, "scope": "admin"}

    def test_cookie_require_preserves_name(self):
        cookie = APIKeyCookieAuth("session", cookie_validator)
        derived = cookie.require(scope="admin")
        assert derived._name == "session"

    def test_bearer_require_in_multi_auth(self):
        """require() instances work seamlessly inside MultiAuth."""
        PREFIXED_TOKEN = f"user_{VALID_TOKEN}"

        async def prefixed_role_validator(credential: str, *, role: str) -> dict:
            if credential != PREFIXED_TOKEN:
                raise UnauthorizedError()
            return {"user": "alice", "role": role}

        bearer = HTTPBearerAuth(prefixed_role_validator, prefix="user_")
        multi = MultiAuth(bearer.require(role="admin"))

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {PREFIXED_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json() == {"user": "alice", "role": "admin"}


class TestSyncValidators:
    """Sync (non-async) validators — covers the sync path in _call_validator."""

    def test_bearer_sync_validator(self):
        def sync_validator(credential: str) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            return {"user": "alice"}

        bearer = HTTPBearerAuth(sync_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_sync_validator_via_authenticate(self):
        """authenticate() with sync validator (MultiAuth path)."""

        def sync_validator(credential: str) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            return {"user": "alice"}

        bearer = HTTPBearerAuth(sync_validator)
        multi = MultiAuth(bearer)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}


class TestCookieAuthSigned:
    """APIKeyCookieAuth with signed cookies (secret_key path, itsdangerous format)."""

    SECRET = "unit-test-secret-key-32-bytes-minimum!"

    def _client(self, auth) -> TestClient:
        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        return TestClient(_app(setup))

    def test_valid_signed_cookie_via_set_cookie(self):
        """set_cookie signs the value; the signed cookie is verified on read."""
        from fastapi import Response

        # secure=False for test client which runs over plain HTTP
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
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

    def test_set_cookie_has_secure_flag_by_default(self):
        """set_cookie includes Secure flag when secure=True (the default)."""
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth("session", cookie_validator, secret_key=self.SECRET)
        response = StarletteResponse()
        auth.set_cookie(response, "value")
        assert "secure" in response.headers["set-cookie"].lower()

    def test_set_cookie_no_secure_flag_when_disabled(self):
        """set_cookie omits Secure flag when secure=False (local dev)."""
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        response = StarletteResponse()
        auth.set_cookie(response, "value")
        assert "secure" not in response.headers["set-cookie"].lower()

    def test_set_cookie_defaults_httponly_samesite_lax(self):
        """Review invariant: cookie defaults are HttpOnly + SameSite=lax."""
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth("session", cookie_validator, secret_key=self.SECRET)
        response = StarletteResponse()
        auth.set_cookie(response, "value")
        header = response.headers["set-cookie"].lower()
        assert "httponly" in header
        assert "samesite=lax" in header

    def test_set_cookie_custom_samesite_domain_path(self):
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth(
            "session",
            cookie_validator,
            secret_key=self.SECRET,
            samesite="strict",
            domain="example.com",
            path="/app",
        )
        response = StarletteResponse()
        auth.set_cookie(response, "value")
        header = response.headers["set-cookie"].lower()
        assert "samesite=strict" in header
        assert "domain=example.com" in header
        assert "path=/app" in header

    def test_delete_cookie_keeps_cookie_attributes(self):
        """delete_cookie clears the cookie on the same domain/path it was set."""
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth(
            "session",
            cookie_validator,
            secret_key=self.SECRET,
            domain="example.com",
            path="/app",
        )
        response = StarletteResponse()
        auth.delete_cookie(response)
        header = response.headers["set-cookie"].lower()
        assert "session" in header
        assert "domain=example.com" in header
        assert "path=/app" in header

    def test_tampered_value_returns_401(self):
        """Altering the signed payload invalidates the signature."""
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        client = self._client(auth)
        signed = auth._sign(VALID_COOKIE)
        payload, _, rest = signed.partition(".")
        tampered = f"forged{payload[6:]}.{rest}"
        response = client.get("/me", cookies={"session": tampered})
        assert response.status_code == 401

    def test_truncated_cookie_returns_401(self):
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        client = self._client(auth)
        signed = auth._sign(VALID_COOKIE)
        response = client.get("/me", cookies={"session": signed[:-5]})
        assert response.status_code == 401

    def test_signature_from_other_key_returns_401(self):
        """A cookie signed with a different secret is rejected."""
        other = APIKeyCookieAuth(
            "session",
            cookie_validator,
            secret_key="another-secret-key-32-bytes-or-more!!",
        )
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        client = self._client(auth)
        response = client.get("/me", cookies={"session": other._sign(VALID_COOKIE)})
        assert response.status_code == 401

    def test_unsigned_raw_value_returns_401(self):
        """A bare (unsigned) value is rejected when signing is enabled."""
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        client = self._client(auth)
        response = client.get("/me", cookies={"session": VALID_COOKIE})
        assert response.status_code == 401

    def test_expired_signed_cookie_returns_401(self):
        """A signed cookie older than ttl is rejected; a fresh one accepted."""
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, ttl=60, secure=False
        )
        client = self._client(auth)
        signed = auth._sign(VALID_COOKIE)

        response = client.get("/me", cookies={"session": signed})
        assert response.status_code == 200

        with patch("time.time", return_value=time.time() + 61):
            response = client.get("/me", cookies={"session": signed})
        assert response.status_code == 401

    def test_cookie_signed_for_other_name_returns_401(self):
        """Same secret_key, different cookie name → signature must not transfer."""
        session_auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        admin_auth = APIKeyCookieAuth(
            "admin_session", cookie_validator, secret_key=self.SECRET
        )

        client = self._client(session_auth)
        # A cookie minted by the admin_session instance, replayed under the
        # session cookie name, must be rejected despite the shared secret.
        forged = admin_auth._sign(VALID_COOKIE)
        response = client.get("/me", cookies={"session": forged})
        assert response.status_code == 401

        # Control: the same value signed by the session instance is accepted.
        response = client.get(
            "/me", cookies={"session": session_auth._sign(VALID_COOKIE)}
        )
        assert response.status_code == 200

    def test_empty_cookie_value_returns_401(self):
        """A present-but-empty cookie is treated as absent, not validated."""
        auth = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.SECRET, secure=False
        )
        client = self._client(auth)
        response = client.get("/me", headers={"Cookie": "session="})
        assert response.status_code == 401

    def test_sign_without_secret_key_raises(self):
        """Calling _sign on an instance without secret_key raises RuntimeError."""
        auth = APIKeyCookieAuth("session", cookie_validator)
        with pytest.raises(RuntimeError, match="secret_key"):
            auth._sign("data")

    def test_set_cookie_without_secret(self):
        """set_cookie without secret_key writes the raw value."""
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth("session", cookie_validator)
        response = StarletteResponse()
        auth.set_cookie(response, "rawvalue")
        assert "session=rawvalue" in response.headers["set-cookie"]

    def test_delete_cookie(self):
        """delete_cookie produces a Set-Cookie header that clears the session."""
        from starlette.responses import Response as StarletteResponse

        auth = APIKeyCookieAuth("session", cookie_validator)
        response = StarletteResponse()
        auth.delete_cookie(response)
        assert "session" in response.headers["set-cookie"]


class TestCookieSecretValidation:
    """SR-M5: weak secret_key configurations must fail at startup."""

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="secret_key"):
            APIKeyCookieAuth("session", cookie_validator, secret_key="")

    def test_short_key_rejected(self):
        with pytest.raises(ValueError, match="at least 32"):
            APIKeyCookieAuth("session", cookie_validator, secret_key="short")

    def test_empty_sequence_rejected(self):
        with pytest.raises(ValueError, match="at least one key"):
            APIKeyCookieAuth("session", cookie_validator, secret_key=[])

    def test_short_key_in_sequence_rejected(self):
        good = "unit-test-secret-key-32-bytes-minimum!"
        with pytest.raises(ValueError, match="at least 32"):
            APIKeyCookieAuth("session", cookie_validator, secret_key=[good, "short"])

    def test_exactly_32_byte_key_accepted(self):
        APIKeyCookieAuth("session", cookie_validator, secret_key="x" * 32)

    def test_no_secret_key_accepted(self):
        APIKeyCookieAuth("session", cookie_validator)

    @pytest.mark.parametrize("ttl", [0, -1])
    def test_non_positive_ttl_rejected(self, ttl):
        with pytest.raises(ValueError, match="ttl"):
            APIKeyCookieAuth("session", cookie_validator, secret_key="x" * 32, ttl=ttl)


class TestCookieKeyRotation:
    """secret_key rotation: first key signs, every key verifies."""

    OLD = "old-rotation-secret-key-32-bytes-min!"
    NEW = "new-rotation-secret-key-32-bytes-min!"

    def _client(self, auth) -> TestClient:
        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        return TestClient(_app(setup))

    def test_old_cookie_still_valid_after_rotation(self):
        old_auth = APIKeyCookieAuth("session", cookie_validator, secret_key=self.OLD)
        rotated = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=[self.NEW, self.OLD], secure=False
        )
        client = self._client(rotated)
        response = client.get("/me", cookies={"session": old_auth._sign(VALID_COOKIE)})
        assert response.status_code == 200

    def test_new_cookies_signed_with_first_key(self):
        rotated = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=[self.NEW, self.OLD]
        )
        new_only = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=self.NEW, secure=False
        )
        client = self._client(new_only)
        response = client.get("/me", cookies={"session": rotated._sign(VALID_COOKIE)})
        assert response.status_code == 200

    def test_removed_key_rejected(self):
        old_auth = APIKeyCookieAuth("session", cookie_validator, secret_key=self.OLD)
        new_only = APIKeyCookieAuth(
            "session", cookie_validator, secret_key=[self.NEW], secure=False
        )
        client = self._client(new_only)
        response = client.get("/me", cookies={"session": old_auth._sign(VALID_COOKIE)})
        assert response.status_code == 401


class TestSecurityScopes:
    """Scopes declared via Security(..., scopes=[...]) are enforced, not ignored."""

    def test_scopes_declared_without_scopes_param_raises(self):
        """Fail closed: validator can't receive scopes → RuntimeError, not silent authz skip."""
        bearer = HTTPBearerAuth(simple_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        with pytest.raises(RuntimeError, match="security scopes"):
            client.get("/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"})

    def test_scopes_passed_to_bearer_validator(self):
        received: list[list[str]] = []

        async def scoped_validator(credential: str, scopes: list[str]) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            received.append(scopes)
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin", "billing"])):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert received == [["admin", "billing"]]

    def test_no_scopes_declared_passes_empty_list(self):
        received: list[list[str]] = []

        async def scoped_validator(credential: str, *, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert received == [[]]

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

    def test_scopes_passed_to_cookie_validator(self):
        received: list[list[str]] = []

        async def scoped_validator(value: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"session": value}

        auth = APIKeyCookieAuth("session", scoped_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get("/admin", cookies={"session": VALID_COOKIE})
        assert response.status_code == 200
        assert received == [["admin"]]

    def test_cookie_scopes_declared_without_scopes_param_raises(self):
        auth = APIKeyCookieAuth("session", cookie_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        with pytest.raises(RuntimeError, match="security scopes"):
            client.get("/admin", cookies={"session": VALID_COOKIE})

    def test_scopes_passed_to_api_key_validator(self):
        received: list[list[str]] = []

        async def scoped_validator(api_key: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": "alice"}

        auth = APIKeyHeaderAuth("X-API-Key", scoped_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get("/admin", headers={"X-API-Key": VALID_TOKEN})
        assert response.status_code == 200
        assert received == [["admin"]]

    def test_api_key_scopes_declared_without_scopes_param_raises(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        with pytest.raises(RuntimeError, match="security scopes"):
            client.get("/admin", headers={"X-API-Key": VALID_TOKEN})

    def test_multi_auth_forwards_scopes_to_matched_source(self):
        received: list[list[str]] = []

        async def scoped_validator(credential: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped_validator)
        cookie = APIKeyCookieAuth("session", cookie_validator)
        multi = MultiAuth(bearer, cookie)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(multi, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert received == [["admin"]]

    def test_multi_auth_scopes_fail_closed_on_unscoped_source(self):
        bearer = HTTPBearerAuth(simple_validator)
        multi = MultiAuth(bearer)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(multi, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        with pytest.raises(RuntimeError, match="security scopes"):
            client.get("/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"})

    def test_custom_source_default_fails_closed(self):
        """AuthSource.authenticate_scoped default raises when scopes are declared."""
        auth = _HeaderAuth(secret="s3cr3t")

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(auth, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        with pytest.raises(RuntimeError, match="security scopes"):
            client.get("/admin", headers={"X-Token": "s3cr3t"})

    @pytest.mark.parametrize(
        "factory",
        [
            lambda: HTTPBearerAuth(simple_validator, scopes=["admin"]),
            lambda: APIKeyCookieAuth("session", cookie_validator, scopes=["admin"]),
            lambda: APIKeyHeaderAuth("X-API-Key", simple_validator, scopes=["admin"]),
        ],
        ids=["bearer", "cookie", "api-key"],
    )
    def test_scopes_kwarg_rejected_at_init(self, factory):
        """'scopes' is reserved for route-declared scopes — fail at startup."""
        with pytest.raises(ValueError, match="reserved"):
            factory()

    def test_scopes_kwarg_rejected_via_require(self):
        """require() goes through __init__, so the same guard applies."""
        bearer = HTTPBearerAuth(simple_validator)
        with pytest.raises(ValueError, match="reserved"):
            bearer.require(scopes=["admin"])

    def test_accepts_scopes_non_introspectable_callable(self):
        """Callables without an inspectable signature are treated as scope-less."""
        from typing import Any, Callable, cast

        from fastapi_multiauth.abc import _accepts_scopes

        not_introspectable = cast(Callable[..., Any], object())
        assert _accepts_scopes(not_introspectable) is False

    @pytest.mark.anyio
    async def test_bearer_authenticate_passes_no_scopes(self):
        """authenticate() remains the scope-less entry point."""
        bearer = HTTPBearerAuth(simple_validator)
        assert await bearer.authenticate(VALID_TOKEN) == {"user": "alice"}

    @pytest.mark.anyio
    async def test_cookie_authenticate_passes_no_scopes(self):
        auth = APIKeyCookieAuth("session", cookie_validator)
        assert await auth.authenticate(VALID_COOKIE) == {"session": VALID_COOKIE}

    @pytest.mark.anyio
    async def test_api_key_authenticate_passes_no_scopes(self):
        auth = APIKeyHeaderAuth("X-API-Key", simple_validator)
        assert await auth.authenticate(VALID_TOKEN) == {"user": "alice"}

    def test_sync_validator_with_scopes(self):
        received: list[list[str]] = []

        def sync_scoped_validator(credential: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": "alice"}

        bearer = HTTPBearerAuth(sync_scoped_validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert received == [["admin"]]


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


class TestAuthSource:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            AuthSource()

    def test_builtin_classes_are_auth_sources(self):
        bearer = HTTPBearerAuth(simple_validator)
        cookie = APIKeyCookieAuth("session", cookie_validator)
        api_key = APIKeyHeaderAuth("X-API-Key", simple_validator)
        assert isinstance(bearer, AuthSource)
        assert isinstance(cookie, AuthSource)
        assert isinstance(api_key, AuthSource)

    def test_custom_source_standalone_valid(self):
        """Default __call__ wires extract + authenticate via Request injection."""
        auth = _HeaderAuth(secret="s3cr3t")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"X-Token": "s3cr3t"})
        assert response.status_code == 200
        assert response.json() == {"token": "s3cr3t"}

    def test_custom_source_standalone_missing_credential(self):
        auth = _HeaderAuth(secret="s3cr3t")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me")  # no X-Token header
        assert response.status_code == 401

    def test_custom_source_standalone_invalid_credential(self):
        auth = _HeaderAuth(secret="s3cr3t")

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        client = TestClient(_app(setup))
        response = client.get("/me", headers={"X-Token": "wrong"})
        assert response.status_code == 401

    def test_custom_source_in_multi_auth(self):
        """Custom AuthSource works transparently inside MultiAuth."""
        header_auth = _HeaderAuth(secret="s3cr3t")
        bearer = HTTPBearerAuth(simple_validator)
        multi = MultiAuth(bearer, header_auth)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(multi)):
                return user

        client = TestClient(_app(setup))

        # Bearer matches first
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

        # No bearer → falls through to custom header source
        response = client.get("/me", headers={"X-Token": "s3cr3t"})
        assert response.status_code == 200
        assert response.json() == {"token": "s3cr3t"}


class TestEncodeDecodeOAuthState:
    def test_encode_returns_base64url_string(self):
        result = oauth_encode_state("https://example.com/dashboard", "test-state-token")
        assert isinstance(result, str)
        assert "+" not in result
        assert "/" not in result

    def test_round_trip(self):
        url = "/after-login?next=/home"
        state_token = "test-state-token"
        assert (
            oauth_decode_state(
                oauth_encode_state(url, state_token),
                expected_state_token=state_token,
                fallback="/",
            )
            == url
        )

    def test_decode_none_returns_fallback(self):
        assert (
            oauth_decode_state(None, expected_state_token="any", fallback="/home")
            == "/home"
        )

    def test_decode_null_string_returns_fallback(self):
        assert (
            oauth_decode_state("null", expected_state_token="any", fallback="/home")
            == "/home"
        )

    def test_decode_invalid_base64_returns_fallback(self):
        assert (
            oauth_decode_state(
                "!!!notbase64!!!", expected_state_token="any", fallback="/home"
            )
            == "/home"
        )

    def test_decode_handles_missing_padding(self):
        url = "/dashboard/x"
        state_token = "test-state-token"
        encoded = oauth_encode_state(url, state_token).rstrip("=")
        assert (
            oauth_decode_state(encoded, expected_state_token=state_token, fallback="/")
            == url
        )

    def test_decode_wrong_state_token_returns_fallback(self):
        url = "https://example.com/dashboard"
        encoded = oauth_encode_state(url, "correct-token")
        assert (
            oauth_decode_state(
                encoded, expected_state_token="wrong-token", fallback="/"
            )
            == "/"
        )

    def test_generate_state_token_is_random(self):
        assert oauth_generate_state_token() != oauth_generate_state_token()


class TestBuildAuthorizationRedirect:
    def test_returns_redirect_response(self):
        from fastapi.responses import RedirectResponse

        response = oauth_build_authorization_redirect(
            "https://auth.example.com/authorize",
            client_id="my-client",
            scopes="openid email",
            redirect_uri="https://app.example.com/callback",
            destination="https://app.example.com/dashboard",
            state_token="test-state-token",
        )
        assert isinstance(response, RedirectResponse)

    def test_redirect_location_contains_all_params(self):
        state_token = "test-state-token"
        response = oauth_build_authorization_redirect(
            "https://auth.example.com/authorize",
            client_id="my-client",
            scopes="openid email",
            redirect_uri="https://app.example.com/callback",
            destination="https://app.example.com/dashboard",
            state_token=state_token,
        )
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

    def test_redirects_with_303_see_other(self):
        """303 forces a GET even when the login route was a POST form."""
        response = oauth_build_authorization_redirect(
            "https://auth.example.com/authorize",
            client_id="my-client",
            scopes="openid",
            redirect_uri="https://app.example.com/callback",
            destination="/",
            state_token="test-state-token",
        )
        assert response.status_code == 303

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


DISCOVERY_URL = "https://auth.example.com/.well-known/openid-configuration"


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
    async def test_returns_required_endpoints(self):
        respx.get(DISCOVERY_URL).respond(json=_discovery_doc())

        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)

        assert isinstance(endpoints, OIDCEndpoints)
        assert endpoints.authorization_endpoint == "https://auth.example.com/authorize"
        assert endpoints.token_endpoint == "https://auth.example.com/token"
        assert endpoints.userinfo_endpoint == "https://auth.example.com/userinfo"
        assert endpoints.issuer == "https://auth.example.com"
        assert endpoints.jwks_uri is None
        assert endpoints.end_session_endpoint is None

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_optional_endpoints(self):
        respx.get(DISCOVERY_URL).respond(
            json=_discovery_doc(
                jwks_uri="https://auth.example.com/jwks",
                end_session_endpoint="https://auth.example.com/logout",
            )
        )

        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)

        assert endpoints.jwks_uri == "https://auth.example.com/jwks"
        assert endpoints.end_session_endpoint == "https://auth.example.com/logout"

    @pytest.mark.anyio
    @respx.mock
    async def test_userinfo_endpoint_none_when_absent(self):
        respx.get(DISCOVERY_URL).respond(json=_discovery_doc(userinfo=False))

        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)

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
    async def test_http_error_raises_discovery_error(self):
        respx.get(DISCOVERY_URL).respond(500)

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="failed to fetch"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_network_timeout_raises_discovery_error(self):
        respx.get(DISCOVERY_URL).mock(
            side_effect=httpx.ConnectTimeout("connection timed out")
        )

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="failed to fetch"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_invalid_json_raises_discovery_error(self):
        respx.get(DISCOVERY_URL).respond(content=b"<html>not json</html>")

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="not valid JSON"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_non_object_document_raises_discovery_error(self):
        respx.get(DISCOVERY_URL).respond(json=["not", "an", "object"])

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="not a JSON object"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_missing_token_endpoint_raises_discovery_error(self):
        doc = _discovery_doc()
        del doc["token_endpoint"]
        respx.get(DISCOVERY_URL).respond(json=doc)

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="missing the 'token_endpoint'"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_non_string_endpoint_raises_discovery_error(self):
        respx.get(DISCOVERY_URL).respond(json=_discovery_doc(token_endpoint=123))

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="must be a string URL"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)


class TestOAuthHttpsEnforcement:
    """client_secret / codes / tokens must never travel over plaintext HTTP."""

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
    @pytest.mark.parametrize(
        "endpoint",
        [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "end_session_endpoint",
        ],
    )
    async def test_http_endpoint_in_discovery_document_rejected(self, endpoint):
        respx.get(DISCOVERY_URL).respond(
            json=_discovery_doc(**{endpoint: "http://attacker.example.com/endpoint"})
        )

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match=f"{endpoint} must use https"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
    async def test_http_loopback_discovery_allowed(self, host):
        """Local development IdPs over plain HTTP keep working."""
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
    @respx.mock
    async def test_issuer_mismatch_rejected(self):
        """OIDC Discovery §4.3: the document must claim the expected issuer."""
        respx.get(DISCOVERY_URL).respond(
            json=_discovery_doc(issuer="https://attacker.example.com")
        )

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="issuer"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_missing_issuer_rejected(self):
        doc = _discovery_doc()
        del doc["issuer"]
        respx.get(DISCOVERY_URL).respond(json=doc)

        oauth_resolve_provider_urls.cache_clear()
        with pytest.raises(OAuthDiscoveryError, match="issuer"):
            await oauth_resolve_provider_urls(DISCOVERY_URL)

    @pytest.mark.anyio
    @respx.mock
    async def test_issuer_trailing_slash_accepted(self):
        """Auth0-style issuers carry a trailing slash — still the same issuer."""
        respx.get(DISCOVERY_URL).respond(
            json=_discovery_doc(issuer="https://auth.example.com/")
        )

        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)
        assert endpoints.token_endpoint == "https://auth.example.com/token"

    @pytest.mark.anyio
    @respx.mock
    async def test_issuer_with_path_accepted(self):
        """Keycloak/Microsoft-style issuers include a path component."""
        issuer = "https://auth.example.com/realms/myrealm"
        respx.get(f"{issuer}/.well-known/openid-configuration").respond(
            json=_discovery_doc(issuer=issuer)
        )

        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(
            f"{issuer}/.well-known/openid-configuration"
        )
        assert endpoints.token_endpoint == "https://auth.example.com/token"

    @pytest.mark.anyio
    @respx.mock
    async def test_nonstandard_discovery_url_skips_issuer_check(self):
        """No expected issuer can be derived from a non-standard layout."""
        respx.get("https://auth.example.com/custom/discovery.json").respond(
            json=_discovery_doc(issuer="https://unrelated.example.com")
        )

        oauth_resolve_provider_urls.cache_clear()
        endpoints = await oauth_resolve_provider_urls(
            "https://auth.example.com/custom/discovery.json"
        )
        assert endpoints.token_endpoint == "https://auth.example.com/token"

    @pytest.mark.anyio
    @respx.mock
    async def test_exchange_http_token_url_rejected_before_request(self):
        with pytest.raises(ValueError, match="token_url must use https"):
            await oauth_exchange_code(
                token_url="http://auth.example.com/token",
                code="authcode123",
                client_id="client-id",
                client_secret="client-secret",
                redirect_uri="https://app.example.com/callback",
            )

        assert len(respx.calls) == 0

    @pytest.mark.anyio
    @respx.mock
    async def test_userinfo_http_url_rejected_before_request(self):
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
    async def test_returns_full_token_payload(self):
        respx.post(self.TOKEN_URL).respond(
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

    @pytest.mark.anyio
    @respx.mock
    async def test_posts_correct_token_request(self):
        route = respx.post(self.TOKEN_URL).respond(json={"access_token": "tok123"})

        await self._exchange()

        body = parse_qs(route.calls.last.request.content.decode())
        assert body["grant_type"] == ["authorization_code"]
        assert body["code"] == ["authcode123"]
        assert body["client_id"] == ["my-client"]
        assert body["client_secret"] == ["my-secret"]
        assert body["redirect_uri"] == ["https://app.example.com/callback"]
        assert "code_verifier" not in body

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
    async def test_pkce_code_verifier_sent_to_token_endpoint(self):
        route = respx.post(self.TOKEN_URL).respond(json={"access_token": "tok123"})

        code_verifier, _ = oauth_generate_pkce_pair()
        await self._exchange(code_verifier=code_verifier)

        body = parse_qs(route.calls.last.request.content.decode())
        assert body["code_verifier"] == [code_verifier]

    @pytest.mark.anyio
    @respx.mock
    async def test_raises_on_unsupported_token_type(self):
        respx.post(self.TOKEN_URL).respond(
            json={"access_token": "tok123", "token_type": "mac"}
        )

        with pytest.raises(OAuthExchangeError, match="unsupported token_type"):
            await self._exchange()

    @pytest.mark.anyio
    @respx.mock
    async def test_non_string_token_type_raises_exchange_error(self):
        respx.post(self.TOKEN_URL).respond(
            json={"access_token": "tok123", "token_type": 1}
        )

        with pytest.raises(OAuthExchangeError, match="unsupported token_type"):
            await self._exchange()

    @pytest.mark.anyio
    @respx.mock
    async def test_non_string_scope_fails_required_scopes_closed(self):
        respx.post(self.TOKEN_URL).respond(
            json={"access_token": "tok123", "scope": ["openid"]}
        )

        with pytest.raises(OAuthExchangeError, match="required scopes"):
            await self._exchange(required_scopes="openid")

    @pytest.mark.anyio
    @respx.mock
    async def test_accepts_bearer_token_type_case_insensitive(self):
        respx.post(self.TOKEN_URL).respond(
            json={"access_token": "tok123", "token_type": "Bearer"}
        )

        token = await self._exchange()
        assert token["access_token"] == "tok123"

    @pytest.mark.anyio
    @respx.mock
    async def test_raises_when_required_scopes_not_granted(self):
        respx.post(self.TOKEN_URL).respond(
            json={"access_token": "tok123", "scope": "openid"}
        )

        with pytest.raises(OAuthExchangeError, match="required scopes"):
            await self._exchange(required_scopes="openid email profile")

    @pytest.mark.anyio
    @respx.mock
    async def test_passes_when_all_required_scopes_granted(self):
        respx.post(self.TOKEN_URL).respond(
            json={"access_token": "tok123", "scope": "openid email profile"}
        )

        token = await self._exchange(required_scopes="openid email")
        assert token["access_token"] == "tok123"

    @pytest.mark.anyio
    @respx.mock
    async def test_provider_error_raises_exchange_error(self):
        respx.post(self.TOKEN_URL).respond(400, json={"error": "invalid_grant"})

        with pytest.raises(OAuthExchangeError):
            await self._exchange()

    @pytest.mark.anyio
    @respx.mock
    async def test_malformed_token_response_raises_exchange_error(self):
        respx.post(self.TOKEN_URL).respond(content=b"<html>not json</html>")

        with pytest.raises(OAuthExchangeError):
            await self._exchange()

    @pytest.mark.anyio
    @respx.mock
    async def test_timeout_raises_exchange_error(self):
        respx.post(self.TOKEN_URL).mock(
            side_effect=httpx.ConnectTimeout("connection timed out")
        )

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
    async def test_http_error_raises_userinfo_error(self):
        respx.get(self.USERINFO_URL).respond(500)

        with pytest.raises(OAuthUserinfoError, match="failed to fetch"):
            await oauth_fetch_userinfo(
                userinfo_url=self.USERINFO_URL, access_token="tok123"
            )

    @pytest.mark.anyio
    @respx.mock
    async def test_timeout_raises_userinfo_error(self):
        respx.get(self.USERINFO_URL).mock(
            side_effect=httpx.ReadTimeout("read timed out")
        )

        with pytest.raises(OAuthUserinfoError):
            await oauth_fetch_userinfo(
                userinfo_url=self.USERINFO_URL, access_token="tok123"
            )

    @pytest.mark.anyio
    @respx.mock
    async def test_invalid_json_raises_userinfo_error(self):
        respx.get(self.USERINFO_URL).respond(content=b"<html>not json</html>")

        with pytest.raises(OAuthUserinfoError, match="not valid JSON"):
            await oauth_fetch_userinfo(
                userinfo_url=self.USERINFO_URL, access_token="tok123"
            )


class TestGeneratePkcePair:
    def test_challenge_is_s256_of_verifier(self):
        code_verifier, code_challenge = oauth_generate_pkce_pair()
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        assert code_challenge == expected

    def test_verifier_length_within_rfc7636_bounds(self):
        code_verifier, _ = oauth_generate_pkce_pair()
        assert 43 <= len(code_verifier) <= 128

    def test_challenge_is_urlsafe_without_padding(self):
        _, code_challenge = oauth_generate_pkce_pair()
        assert "=" not in code_challenge
        assert "+" not in code_challenge
        assert "/" not in code_challenge

    def test_pairs_are_random(self):
        assert oauth_generate_pkce_pair() != oauth_generate_pkce_pair()


class TestAuthorizationRedirectPkce:
    def _params(self, **kwargs):
        response = oauth_build_authorization_redirect(
            "https://auth.example.com/authorize",
            client_id="my-client",
            scopes="openid",
            redirect_uri="https://app.example.com/callback",
            destination="/dashboard",
            state_token="test-state-token",
            **kwargs,
        )
        return parse_qs(urlparse(response.headers["location"]).query)

    def test_code_challenge_sent_with_s256_method(self):
        _, code_challenge = oauth_generate_pkce_pair()
        params = self._params(code_challenge=code_challenge)
        assert params["code_challenge"] == [code_challenge]
        assert params["code_challenge_method"] == ["S256"]

    def test_no_pkce_params_by_default(self):
        params = self._params()
        assert "code_challenge" not in params
        assert "code_challenge_method" not in params


def _raw_state(payload) -> str:
    """Encode an arbitrary JSON payload as a state parameter."""
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


class TestDecodeStateOpenRedirectGuard:
    TOKEN = "test-state-token"

    def _decode(self, destination, allowed_hosts):
        return oauth_decode_state(
            oauth_encode_state(destination, self.TOKEN),
            expected_state_token=self.TOKEN,
            fallback="/fallback",
            allowed_hosts=allowed_hosts,
        )

    def test_relative_path_allowed_with_empty_allowlist(self):
        assert self._decode("/dashboard?tab=1", ()) == "/dashboard?tab=1"

    def test_absolute_url_rejected_with_empty_allowlist(self):
        assert self._decode("https://app.example.com/x", ()) == "/fallback"

    def test_absolute_url_allowed_when_host_in_allowlist(self):
        assert (
            self._decode("https://app.example.com/x", ("app.example.com",))
            == "https://app.example.com/x"
        )

    def test_absolute_url_rejected_when_host_not_in_allowlist(self):
        assert self._decode("https://evil.example.com/x", ("app.example.com",)) == (
            "/fallback"
        )

    def test_scheme_relative_url_rejected(self):
        assert self._decode("//evil.example.com/x", ("app.example.com",)) == (
            "/fallback"
        )

    def test_backslash_path_rejected(self):
        """Browsers normalize "/\\evil.com" into a scheme-relative redirect."""
        assert self._decode("/\\evil.example.com", ("app.example.com",)) == "/fallback"

    def test_non_http_scheme_rejected(self):
        assert self._decode("javascript:alert(1)", ("app.example.com",)) == "/fallback"

    def test_path_without_leading_slash_rejected(self):
        assert self._decode("dashboard", ("app.example.com",)) == "/fallback"

    def test_explicit_none_disables_guard(self):
        """allowed_hosts=None opts out: validation is left to the caller."""
        assert (
            self._decode("https://anywhere.example.com/x", None)
            == "https://anywhere.example.com/x"
        )

    def test_default_allows_relative_paths(self):
        state = oauth_encode_state("/dashboard", self.TOKEN)
        assert (
            oauth_decode_state(
                state, expected_state_token=self.TOKEN, fallback="/fallback"
            )
            == "/dashboard"
        )

    def test_default_rejects_absolute_urls(self):
        """Secure by default: absolute destinations need an explicit allowlist."""
        state = oauth_encode_state("https://anywhere.example.com/x", self.TOKEN)
        assert (
            oauth_decode_state(
                state, expected_state_token=self.TOKEN, fallback="/fallback"
            )
            == "/fallback"
        )

    def test_non_string_destination_rejected(self):
        state = _raw_state({"n": self.TOKEN, "d": {"url": "/x"}})
        assert (
            oauth_decode_state(
                state, expected_state_token=self.TOKEN, fallback="/fallback"
            )
            == "/fallback"
        )

    def test_non_string_state_token_rejected(self):
        state = _raw_state({"n": 12345, "d": "/x"})
        assert (
            oauth_decode_state(
                state, expected_state_token=self.TOKEN, fallback="/fallback"
            )
            == "/fallback"
        )

    def test_non_dict_payload_rejected(self):
        state = _raw_state(["not", "a", "dict"])
        assert (
            oauth_decode_state(
                state, expected_state_token=self.TOKEN, fallback="/fallback"
            )
            == "/fallback"
        )


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

    @pytest.mark.parametrize(
        "authorization",
        [
            None,
            f"Bearer {VALID_TOKEN}",
            f"bearer {VALID_TOKEN}",  # SR-M3: scheme case-insensitive
            f"BEARER {VALID_TOKEN}",
            "Bearer",  # no space, no token
            "Bearer ",  # SR-M4: empty credential
            "Basic dXNlcjpwYXNz",  # different scheme
            f"Token {VALID_TOKEN}",
        ],
    )
    def test_bearer_parity(self, authorization):
        bearer = HTTPBearerAuth(simple_validator)
        headers = {"Authorization": authorization} if authorization else None
        direct_resp, multi_resp = self._statuses(bearer, headers=headers)
        assert direct_resp.status_code == multi_resp.status_code
        if direct_resp.status_code == 200:
            assert direct_resp.json() == multi_resp.json()

    @pytest.mark.parametrize(
        "authorization",
        [
            "Bearer user_abc",
            "Bearer user",  # partial prefix
            "Bearer org_abc",
        ],
    )
    def test_bearer_prefix_parity(self, authorization):
        async def accept_all(credential: str) -> dict:
            return {"token": credential}

        bearer = HTTPBearerAuth(accept_all, prefix="user_")
        direct_resp, multi_resp = self._statuses(
            bearer, headers={"Authorization": authorization}
        )
        assert direct_resp.status_code == multi_resp.status_code

    @pytest.mark.parametrize(
        "cookie_header", [None, "session=", f"session={VALID_COOKIE}"]
    )
    def test_cookie_parity(self, cookie_header):
        auth = APIKeyCookieAuth("session", cookie_validator)
        headers = {"Cookie": cookie_header} if cookie_header else None
        direct_resp, multi_resp = self._statuses(auth, headers=headers)
        assert direct_resp.status_code == multi_resp.status_code

    @pytest.mark.parametrize("api_key", [None, "", "s3cr3t"])
    def test_api_key_parity(self, api_key):
        async def key_validator(value: str) -> dict:
            if value != "s3cr3t":
                raise UnauthorizedError()
            return {"key": value}

        auth = APIKeyHeaderAuth("X-API-Key", key_validator)
        headers = {"X-API-Key": api_key} if api_key is not None else None
        direct_resp, multi_resp = self._statuses(auth, headers=headers)
        assert direct_resp.status_code == multi_resp.status_code

    def test_bearer_case_insensitive_scheme_accepted(self):
        """SR-M3 regression: lowercase scheme authenticates (RFC 7235)."""
        bearer = HTTPBearerAuth(simple_validator)
        direct_resp, _ = self._statuses(
            bearer, headers={"Authorization": f"bearer {VALID_TOKEN}"}
        )
        assert direct_resp.status_code == 200

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

    def _get(self, authorization: str):
        bearer = HTTPBearerAuth(simple_validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        return TestClient(_app(setup)).get(
            "/me", headers={"Authorization": authorization}
        )

    @pytest.mark.parametrize(
        "authorization",
        [
            "Bearer",  # scheme only
            "Bearer ",  # empty token
            "Bearer  ",  # whitespace token
            f"Bearer{VALID_TOKEN}",  # no space
            "NotBearer token",
            "",
        ],
    )
    def test_malformed_header_returns_401(self, authorization):
        assert self._get(authorization).status_code == 401

    def test_extra_whitespace_around_token_tolerated(self):
        assert self._get(f"Bearer  {VALID_TOKEN} ").status_code == 200

    def test_duplicate_authorization_headers_use_first(self):
        """Duplicate headers: first one wins on both paths (parity-safe)."""
        bearer = HTTPBearerAuth(simple_validator)

        def direct(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(bearer)):
                return user

        def multi(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(MultiAuth(bearer))):
                return user

        headers = [
            ("Authorization", f"Bearer {VALID_TOKEN}"),
            ("Authorization", "Bearer wrong"),
        ]
        direct_status = TestClient(_app(direct)).get("/me", headers=headers).status_code
        multi_status = TestClient(_app(multi)).get("/me", headers=headers).status_code
        assert direct_status == multi_status == 200


class TestWWWAuthenticate:
    """SR-L3: 401 responses carry a WWW-Authenticate challenge (RFC 7235 §4.1)."""

    def _client(self, auth) -> TestClient:
        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        return TestClient(_app(setup))

    def test_bearer_missing_credentials_has_challenge(self):
        response = self._client(HTTPBearerAuth(simple_validator)).get("/me")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_bearer_invalid_token_has_challenge(self):
        response = self._client(HTTPBearerAuth(simple_validator)).get(
            "/me", headers={"Authorization": "Bearer wrong"}
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_validator_custom_challenge_preserved(self):
        """A validator-provided WWW-Authenticate is not overwritten."""

        async def strict_validator(credential: str) -> dict:
            raise UnauthorizedError(
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
            )

        response = self._client(HTTPBearerAuth(strict_validator)).get(
            "/me", headers={"Authorization": "Bearer whatever"}
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    def test_cookie_401_has_no_challenge(self):
        """No registered HTTP auth scheme exists for cookies."""
        response = self._client(APIKeyCookieAuth("session", cookie_validator)).get(
            "/me"
        )
        assert response.status_code == 401
        assert "WWW-Authenticate" not in response.headers

    def test_api_key_401_has_no_challenge(self):
        response = self._client(APIKeyHeaderAuth("X-API-Key", simple_validator)).get(
            "/me"
        )
        assert response.status_code == 401
        assert "WWW-Authenticate" not in response.headers

    def test_multiauth_emits_bearer_challenge(self):
        multi = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
        )
        response = self._client(multi).get("/me")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_multiauth_deduplicates_challenges(self):
        multi = MultiAuth(
            HTTPBearerAuth(simple_validator, prefix="user_"),
            HTTPBearerAuth(simple_validator, prefix="org_"),
        )
        response = self._client(multi).get("/me")
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_multiauth_matched_source_challenge_on_invalid(self):
        """A 401 from the matched source carries that source's challenge."""
        multi = MultiAuth(
            APIKeyCookieAuth("session", cookie_validator),
            HTTPBearerAuth(simple_validator),
        )
        response = self._client(multi).get(
            "/me", headers={"Authorization": "Bearer wrong"}
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"


class TestHttpSemantics:
    """2.3: 401 = absent/invalid credentials, 403 = authenticated but denied."""

    def _client(self, auth) -> TestClient:
        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        return TestClient(_app(setup))

    @pytest.mark.parametrize(
        "auth_factory",
        [
            lambda: HTTPBearerAuth(simple_validator),
            lambda: APIKeyCookieAuth("session", cookie_validator),
            lambda: APIKeyHeaderAuth("X-API-Key", simple_validator),
            lambda: MultiAuth(HTTPBearerAuth(simple_validator)),
        ],
    )
    def test_absent_credentials_return_401(self, auth_factory):
        response = self._client(auth_factory()).get("/me")
        assert response.status_code == 401

    def test_forbidden_error_returns_403(self):
        """A validator can signal 'authenticated but not allowed' with 403."""

        async def admin_only(credential: str) -> dict:
            if credential != VALID_TOKEN:
                raise UnauthorizedError()
            raise ForbiddenError("admin role required")

        response = self._client(HTTPBearerAuth(admin_only)).get(
            "/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 403
        assert "WWW-Authenticate" not in response.headers


class TestOpenAPIDocumentation:
    """SR-L5 + Swagger 'Authorize' audit: every scheme is documented."""

    def _openapi(self, auth) -> dict:
        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        return TestClient(_app(setup)).get("/openapi.json").json()

    def test_bearer_scheme_documented(self):
        spec = self._openapi(HTTPBearerAuth(simple_validator))
        schemes = spec["components"]["securitySchemes"]
        assert schemes["HTTPBearer"]["scheme"] == "bearer"
        assert {"HTTPBearer": []} in spec["paths"]["/me"]["get"]["security"]

    def test_cookie_scheme_documented(self):
        spec = self._openapi(APIKeyCookieAuth("session", cookie_validator))
        scheme = spec["components"]["securitySchemes"]["APIKeyCookie_session"]
        assert scheme["type"] == "apiKey"
        assert scheme["in"] == "cookie"
        assert scheme["name"] == "session"

    def test_api_key_scheme_documented(self):
        spec = self._openapi(APIKeyHeaderAuth("X-API-Key", simple_validator))
        scheme = spec["components"]["securitySchemes"]["APIKeyHeader_X-API-Key"]
        assert scheme["type"] == "apiKey"
        assert scheme["in"] == "header"
        assert scheme["name"] == "X-API-Key"

    def test_query_scheme_documented(self):
        spec = self._openapi(APIKeyQueryAuth("api_key", simple_validator))
        scheme = spec["components"]["securitySchemes"]["APIKeyQuery_api_key"]
        assert scheme["type"] == "apiKey"
        assert scheme["in"] == "query"
        assert scheme["name"] == "api_key"

    def test_multiauth_documents_all_schemes(self):
        multi = MultiAuth(
            HTTPBearerAuth(simple_validator),
            APIKeyCookieAuth("session", cookie_validator),
        )
        spec = self._openapi(multi)
        schemes = spec["components"]["securitySchemes"]
        assert "HTTPBearer" in schemes
        assert "APIKeyCookie_session" in schemes
        declared = {
            name for entry in spec["paths"]["/me"]["get"]["security"] for name in entry
        }
        assert {"HTTPBearer", "APIKeyCookie_session"} <= declared

    def test_multiauth_same_type_documents_both_schemes(self):
        """SR-L5 regression: two sources of the same type keep both schemes."""
        multi = MultiAuth(
            HTTPBearerAuth(simple_validator, prefix="user_", scheme_name="UserToken"),
            HTTPBearerAuth(simple_validator, prefix="org_", scheme_name="OrgToken"),
        )
        spec = self._openapi(multi)
        schemes = spec["components"]["securitySchemes"]
        assert "UserToken" in schemes
        assert "OrgToken" in schemes
        declared = {
            name for entry in spec["paths"]["/me"]["get"]["security"] for name in entry
        }
        assert {"UserToken", "OrgToken"} <= declared

    def test_multiauth_two_api_key_headers_documented(self):
        """Distinct default scheme names: both header schemes documented."""
        multi = MultiAuth(
            APIKeyHeaderAuth("X-API-Key", simple_validator),
            APIKeyHeaderAuth("X-Org-Key", simple_validator),
        )
        spec = self._openapi(multi)
        schemes = spec["components"]["securitySchemes"]
        assert schemes["APIKeyHeader_X-API-Key"]["name"] == "X-API-Key"
        assert schemes["APIKeyHeader_X-Org-Key"]["name"] == "X-Org-Key"


class TestTokenHelpers:
    """2.2: store the hash, never the token."""

    def test_hash_token_is_sha256_hex(self):
        assert hash_token("user_abc") == hashlib.sha256(b"user_abc").hexdigest()

    def test_hash_includes_prefix(self):
        assert hash_token("user_abc") != hash_token("abc")

    def test_verify_token_hash_accepts_matching(self):
        token = "user_secret-token"
        assert verify_token_hash(token, hash_token(token)) is True

    def test_verify_token_hash_rejects_wrong_token(self):
        assert verify_token_hash("user_other", hash_token("user_secret")) is False

    def test_generate_hash_verify_roundtrip(self):
        bearer = HTTPBearerAuth(simple_validator, prefix="user_")
        token = bearer.generate_token()
        stored = hash_token(token)
        assert verify_token_hash(token, stored)
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
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Basic !!!not-base64")],
        }
        request = Request(scope)
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

    def test_state_tokens_are_urlsafe_and_unique(self):
        tokens = {oauth_generate_state_token() for _ in range(32)}
        assert len(tokens) == 32

    def test_cookie_expiry_is_inside_signed_payload(self):
        """The timestamp is covered by the signature: it cannot be extended."""
        secret = "unit-test-secret-key-32-bytes-minimum!"
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


def _jwk(private_key, kid: str, **overrides) -> dict:
    entry = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    entry.update({"kid": kid, "alg": "RS256", "use": "sig"})
    entry.update(overrides)
    return {k: v for k, v in entry.items() if v is not None}


def _claims(**overrides) -> dict:
    claims = {"sub": "user-1", "exp": int(time.time()) + 300}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


JWT_SECRET = "unit-test-jwt-secret-32-bytes-min!!!"


def _hs_token(claims=None, *, secret=JWT_SECRET, **encode_kwargs) -> str:
    return pyjwt.encode(claims or _claims(), secret, algorithm="HS256", **encode_kwargs)


def _auth_client(validator) -> TestClient:
    bearer = HTTPBearerAuth(validator)

    def setup(app: FastAPI):
        @app.get("/me")
        async def me(user=Security(bearer)):
            return user

    return TestClient(_app(setup))


class TestJWTValidatorConfig:
    def test_secret_and_jwks_url_rejected(self):
        with pytest.raises(ValueError, match="exactly one"):
            JWTValidator(secret=JWT_SECRET, jwks_url="https://idp.example.com/jwks")

    def test_neither_secret_nor_jwks_url_rejected(self):
        with pytest.raises(ValueError, match="exactly one"):
            JWTValidator()

    def test_short_secret_rejected(self):
        with pytest.raises(ValueError, match="at least 32"):
            JWTValidator(secret="short")

    def test_http_jwks_url_rejected(self):
        with pytest.raises(ValueError, match="jwks_url must use https"):
            JWTValidator(jwks_url="http://idp.example.com/jwks")

    def test_loopback_http_jwks_url_accepted(self):
        JWTValidator(jwks_url="http://localhost:8080/jwks")

    def test_symmetric_algorithms_with_jwks_rejected(self):
        """Key-confusion guard: a public key must never act as an HMAC secret."""
        with pytest.raises(ValueError, match="key-confusion"):
            JWTValidator(
                jwks_url="https://idp.example.com/jwks",
                algorithms=["RS256", "HS256"],
            )


class TestJWTValidatorSymmetric:
    def test_valid_token_returns_claims(self):
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {_hs_token()}"})
        assert response.status_code == 200
        assert response.json()["sub"] == "user-1"

    def test_expired_token_rejected(self):
        token = _hs_token(_claims(exp=int(time.time()) - 10))
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_leeway_tolerates_clock_skew(self):
        token = _hs_token(_claims(exp=int(time.time()) - 10))
        client = _auth_client(JWTValidator(secret=JWT_SECRET, leeway=30))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    def test_not_yet_valid_token_rejected(self):
        token = _hs_token(_claims(nbf=int(time.time()) + 300))
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_token_without_exp_rejected_by_default(self):
        token = _hs_token(_claims(exp=None))
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_required_claims_configurable(self):
        token = _hs_token(_claims(exp=None))
        client = _auth_client(JWTValidator(secret=JWT_SECRET, required_claims=()))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    def test_wrong_signature_rejected(self):
        token = _hs_token(secret="other-secret-key-32-bytes-minimum!!!")
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_garbage_token_rejected(self):
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": "Bearer not.a.jwt"})
        assert response.status_code == 401

    def test_audience_verified(self):
        validator = JWTValidator(secret=JWT_SECRET, audience="my-api")
        client = _auth_client(validator)

        good = _hs_token(_claims(aud="my-api"))
        assert (
            client.get("/me", headers={"Authorization": f"Bearer {good}"}).status_code
            == 200
        )
        bad = _hs_token(_claims(aud="other-api"))
        assert (
            client.get("/me", headers={"Authorization": f"Bearer {bad}"}).status_code
            == 401
        )

    def test_issuer_verified(self):
        validator = JWTValidator(secret=JWT_SECRET, issuer="https://idp.example.com")
        client = _auth_client(validator)

        good = _hs_token(_claims(iss="https://idp.example.com"))
        assert (
            client.get("/me", headers={"Authorization": f"Bearer {good}"}).status_code
            == 200
        )
        bad = _hs_token(_claims(iss="https://evil.example.com"))
        assert (
            client.get("/me", headers={"Authorization": f"Bearer {bad}"}).status_code
            == 401
        )

    def test_claims_to_identity_sync_hook(self):
        validator = JWTValidator(
            secret=JWT_SECRET,
            claims_to_identity=lambda claims: {"id": claims["sub"].upper()},
        )
        client = _auth_client(validator)
        response = client.get("/me", headers={"Authorization": f"Bearer {_hs_token()}"})
        assert response.json() == {"id": "USER-1"}

    def test_claims_to_identity_async_hook(self):
        async def to_identity(claims: dict) -> dict:
            return {"id": claims["sub"], "via": "async"}

        validator = JWTValidator(secret=JWT_SECRET, claims_to_identity=to_identity)
        client = _auth_client(validator)
        response = client.get("/me", headers={"Authorization": f"Bearer {_hs_token()}"})
        assert response.json() == {"id": "user-1", "via": "async"}


class TestJWTValidatorScopes:
    def _scoped_client(self, validator, scopes: list[str]) -> TestClient:
        bearer = HTTPBearerAuth(validator)

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=scopes)):
                return user

        return TestClient(_app(setup))

    def test_scope_string_claim_grants_access(self):
        token = _hs_token(_claims(scope="read write admin"))
        client = self._scoped_client(JWTValidator(secret=JWT_SECRET), ["admin"])
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    def test_missing_scope_returns_403(self):
        """RFC 6750: valid token without the required scope → 403, not 401."""
        token = _hs_token(_claims(scope="read"))
        client = self._scoped_client(JWTValidator(secret=JWT_SECRET), ["admin"])
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403

    def test_scp_list_claim(self):
        token = _hs_token(_claims(scp=["read", "admin"]))
        validator = JWTValidator(secret=JWT_SECRET, scopes_claim="scp")
        client = self._scoped_client(validator, ["admin"])
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    def test_roles_list_claim(self):
        token = _hs_token(_claims(roles=["viewer"]))
        validator = JWTValidator(secret=JWT_SECRET, scopes_claim="roles")
        client = self._scoped_client(validator, ["admin"])
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403

    def test_absent_scopes_claim_fails_closed(self):
        token = _hs_token()  # no scope claim at all
        client = self._scoped_client(JWTValidator(secret=JWT_SECRET), ["admin"])
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403

    def test_route_without_scopes_skips_check(self):
        token = _hs_token()
        client = _auth_client(JWTValidator(secret=JWT_SECRET))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200


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
        return JWTValidator(jwks_url=self.JWKS_URL, **kwargs)

    @respx.mock
    def test_valid_rs256_token(self):
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        client = _auth_client(self._validator())
        response = client.get(
            "/me", headers={"Authorization": f"Bearer {self._rs_token()}"}
        )
        assert response.status_code == 200
        assert response.json()["sub"] == "user-1"

    @respx.mock
    def test_jwks_cached_between_requests(self):
        route = respx.get(self.JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1")]}
        )
        client = _auth_client(self._validator())
        for _ in range(3):
            response = client.get(
                "/me", headers={"Authorization": f"Bearer {self._rs_token()}"}
            )
            assert response.status_code == 200
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

        first = client.get(
            "/me", headers={"Authorization": f"Bearer {self._rs_token()}"}
        )
        assert first.status_code == 200

        rotated = self._rs_token(private_key=_RSA_KEY_2, kid="key2")
        second = client.get("/me", headers={"Authorization": f"Bearer {rotated}"})
        assert second.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_unknown_kid_refresh_is_rate_limited(self):
        """Unauthenticated bogus kids cannot force a JWKS fetch per request."""
        route = respx.get(self.JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1")]}
        )
        client = _auth_client(self._validator())  # default 30 s cooldown

        valid = self._rs_token()
        assert (
            client.get("/me", headers={"Authorization": f"Bearer {valid}"}).status_code
            == 200
        )

        bogus = self._rs_token(private_key=_RSA_KEY_2, kid="rogue")
        for _ in range(5):
            response = client.get("/me", headers={"Authorization": f"Bearer {bogus}"})
            assert response.status_code == 401
        # The forced refresh was within the cooldown window every time.
        assert route.call_count == 1

    @respx.mock
    def test_unknown_kid_after_refresh_rejected(self):
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        client = _auth_client(self._validator())
        token = self._rs_token(private_key=_RSA_KEY_2, kid="rogue")
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    @respx.mock
    def test_token_without_kid_single_key(self):
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        client = _auth_client(self._validator())
        token = self._rs_token(kid=None)
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @respx.mock
    def test_token_without_kid_multiple_keys_rejected(self):
        """Ambiguous key resolution fails closed."""
        respx.get(self.JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1"), _jwk(_RSA_KEY_2, "key2")]}
        )
        client = _auth_client(self._validator())
        token = self._rs_token(kid=None)
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    @respx.mock
    def test_jwks_entry_without_alg_gets_default(self):
        """Some IdPs omit 'alg' in JWKS entries — inferred from kty."""
        respx.get(self.JWKS_URL).respond(
            json={"keys": [_jwk(_RSA_KEY_1, "key1", alg=None)]}
        )
        client = _auth_client(self._validator())
        response = client.get(
            "/me", headers={"Authorization": f"Bearer {self._rs_token()}"}
        )
        assert response.status_code == 200

    @respx.mock
    def test_encryption_keys_skipped(self):
        respx.get(self.JWKS_URL).respond(
            json={
                "keys": [
                    _jwk(_RSA_KEY_2, "key1", use="enc"),
                    _jwk(_RSA_KEY_1, "key1"),
                ]
            }
        )
        client = _auth_client(self._validator())
        response = client.get(
            "/me", headers={"Authorization": f"Bearer {self._rs_token()}"}
        )
        assert response.status_code == 200

    @respx.mock
    def test_hs256_token_rejected_against_jwks(self):
        """A symmetric token can never satisfy an asymmetric validator."""
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        client = _auth_client(self._validator())
        token = _hs_token(headers={"kid": "key1"})
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    @pytest.mark.anyio
    @respx.mock
    async def test_jwks_fetch_error_cold_start_returns_503(self):
        """A broken IdP with no cached keys surfaces as 503, not a 401."""
        respx.get(self.JWKS_URL).respond(500)
        validator = self._validator()
        with pytest.raises(HTTPException) as exc_info:
            await validator(self._rs_token())
        assert exc_info.value.status_code == 503

    @pytest.mark.anyio
    @respx.mock
    async def test_jwks_fetch_error_falls_back_to_cached_keys(self):
        """A provider blip after cache expiry must not break validation."""
        route = respx.get(self.JWKS_URL)
        route.side_effect = [
            httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1")]}),
            httpx.Response(500),
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
    def _client(self, auth) -> TestClient:
        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        return TestClient(_app(setup))

    @staticmethod
    def _header(username: str, password: str) -> dict:
        blob = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {blob}"}

    @staticmethod
    async def _validator(username: str, password: str) -> dict:
        if username != "alice" or password != "wonderland":
            raise UnauthorizedError()
        return {"user": username}

    def test_valid_credentials(self):
        client = self._client(HTTPBasicAuth(self._validator))
        response = client.get("/me", headers=self._header("alice", "wonderland"))
        assert response.status_code == 200
        assert response.json() == {"user": "alice"}

    def test_wrong_password_returns_401(self):
        client = self._client(HTTPBasicAuth(self._validator))
        response = client.get("/me", headers=self._header("alice", "nope"))
        assert response.status_code == 401

    def test_missing_header_401_with_challenge(self):
        client = self._client(HTTPBasicAuth(self._validator))
        response = client.get("/me")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Basic"

    def test_realm_in_challenge(self):
        client = self._client(HTTPBasicAuth(self._validator, realm="api"))
        response = client.get("/me")
        assert response.headers["WWW-Authenticate"] == 'Basic realm="api"'

    def test_scheme_case_insensitive(self):
        client = self._client(HTTPBasicAuth(self._validator))
        blob = base64.b64encode(b"alice:wonderland").decode()
        response = client.get("/me", headers={"Authorization": f"basic {blob}"})
        assert response.status_code == 200

    def test_invalid_base64_returns_401(self):
        client = self._client(HTTPBasicAuth(self._validator))
        response = client.get("/me", headers={"Authorization": "Basic !!!"})
        assert response.status_code == 401

    def test_missing_colon_returns_401(self):
        client = self._client(HTTPBasicAuth(self._validator))
        blob = base64.b64encode(b"alicewonderland").decode()
        response = client.get("/me", headers={"Authorization": f"Basic {blob}"})
        assert response.status_code == 401

    def test_empty_password_reaches_validator(self):
        received: list[tuple[str, str]] = []

        async def capturing(username: str, password: str) -> dict:
            received.append((username, password))
            return {"user": username}

        client = self._client(HTTPBasicAuth(capturing))
        response = client.get("/me", headers=self._header("alice", ""))
        assert response.status_code == 200
        assert received == [("alice", "")]

    def test_utf8_credentials(self):
        async def utf8_validator(username: str, password: str) -> dict:
            return {"user": username, "pw": password}

        client = self._client(HTTPBasicAuth(utf8_validator))
        response = client.get("/me", headers=self._header("aliçé", "pässwörd"))
        assert response.status_code == 200
        assert response.json() == {"user": "aliçé", "pw": "pässwörd"}

    def test_wrong_scheme_returns_401(self):
        client = self._client(HTTPBasicAuth(self._validator))
        response = client.get("/me", headers={"Authorization": "Bearer token"})
        assert response.status_code == 401

    def test_parity_with_multiauth(self):
        auth = HTTPBasicAuth(self._validator)
        cases = [
            None,
            self._header("alice", "wonderland"),
            self._header("alice", "nope"),
            {"Authorization": "Basic !!!"},
        ]
        for headers in cases:
            direct = self._client(auth).get("/me", headers=headers)
            multi = self._client(MultiAuth(auth)).get("/me", headers=headers)
            assert direct.status_code == multi.status_code

    def test_openapi_scheme_documented(self):
        auth = HTTPBasicAuth(self._validator)

        def setup(app: FastAPI):
            @app.get("/me")
            async def me(user=Security(auth)):
                return user

        spec = TestClient(_app(setup)).get("/openapi.json").json()
        scheme = spec["components"]["securitySchemes"]["HTTPBasic"]
        assert scheme["type"] == "http"
        assert scheme["scheme"] == "basic"

    def test_scopes_forwarded_to_validator(self):
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

    def test_require_returns_new_instance(self):
        async def role_basic(username: str, password: str, *, role: str) -> dict:
            return {"user": username, "role": role}

        auth = HTTPBasicAuth(role_basic)
        derived = auth.require(role="admin")
        assert derived is not auth
        client = self._client(derived)
        response = client.get("/me", headers=self._header("alice", "x"))
        assert response.json() == {"user": "alice", "role": "admin"}


class TestScopesConsolidation:
    """3.1: scope enforcement follows the same path in both call modes."""

    def test_multiauth_forwards_scopes_to_validator(self):
        received: list[list[str]] = []

        async def scoped_validator(credential: str, scopes: list[str]) -> dict:
            received.append(scopes)
            return {"user": "alice"}

        multi = MultiAuth(HTTPBearerAuth(scoped_validator))

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(multi, scopes=["admin", "billing"])):
                return user

        client = TestClient(_app(setup))
        response = client.get(
            "/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"}
        )
        assert response.status_code == 200
        assert received == [["admin", "billing"]]

    def test_multiauth_fails_closed_without_scopes_support(self):
        """SR-H1 regression, MultiAuth flavor: never silently skip scopes."""
        multi = MultiAuth(HTTPBearerAuth(simple_validator))

        def setup(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(multi, scopes=["admin"])):
                return user

        client = TestClient(_app(setup))
        with pytest.raises(RuntimeError, match="security scopes"):
            client.get("/admin", headers={"Authorization": f"Bearer {VALID_TOKEN}"})

    def test_scoped_parity_direct_vs_multiauth(self):
        received: list[tuple[str, list[str]]] = []

        async def scoped_validator(credential: str, scopes: list[str]) -> dict:
            received.append(("call", scopes))
            return {"user": "alice"}

        bearer = HTTPBearerAuth(scoped_validator)

        def direct(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(bearer, scopes=["admin"])):
                return user

        def multi(app: FastAPI):
            @app.get("/admin")
            async def admin(user=Security(MultiAuth(bearer), scopes=["admin"])):
                return user

        headers = {"Authorization": f"Bearer {VALID_TOKEN}"}
        direct_resp = TestClient(_app(direct)).get("/admin", headers=headers)
        multi_resp = TestClient(_app(multi)).get("/admin", headers=headers)
        assert direct_resp.status_code == multi_resp.status_code == 200
        assert received == [("call", ["admin"]), ("call", ["admin"])]


class TestCallableInstanceValidator:
    """_ensure_async regression: callable instances with async __call__."""

    def test_async_callable_instance(self):
        class Validator:
            async def __call__(self, token: str) -> dict:
                if token != VALID_TOKEN:
                    raise UnauthorizedError()
                return {"via": "async-instance"}

        client = _auth_client(Validator())
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200
        assert response.json() == {"via": "async-instance"}

    def test_sync_callable_instance(self):
        class Validator:
            def __call__(self, token: str) -> dict:
                return {"via": "sync-instance"}

        client = _auth_client(Validator())
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.json() == {"via": "sync-instance"}

    def test_sync_callable_returning_awaitable(self):
        """A sync wrapper returning a coroutine is awaited transparently."""

        def factory_validator(token: str):
            return simple_validator(token)  # returns a coroutine

        client = _auth_client(factory_validator)
        response = client.get("/me", headers={"Authorization": f"Bearer {VALID_TOKEN}"})
        assert response.status_code == 200


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
    def test_garbage_token_rejected_before_jwks_lookup(self):
        respx.get(self.JWKS_URL).respond(json={"keys": [_jwk(_RSA_KEY_1, "key1")]})
        client = _auth_client(JWTValidator(jwks_url=self.JWKS_URL))
        response = client.get("/me", headers={"Authorization": "Bearer not.a.jwt"})
        assert response.status_code == 401
        assert len(respx.calls) == 0

    @respx.mock
    def test_malformed_jwks_entries_skipped(self):
        """Broken or exotic entries in the JWKS never break valid keys."""
        respx.get(self.JWKS_URL).respond(
            json={
                "keys": [
                    {"kty": "RSA", "alg": "RS256", "kid": "broken"},  # missing n/e
                    {"kty": "OKP", "kid": "exotic"},  # no alg, none inferable
                    "garbage",  # not even an object
                    42,
                    _jwk(_RSA_KEY_1, "key1"),
                ]
            }
        )
        client = _auth_client(JWTValidator(jwks_url=self.JWKS_URL))
        token = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="RS256", headers={"kid": "key1"}
        )
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.anyio
    @pytest.mark.parametrize("document", [["not", "an", "object"], {"keys": "nope"}])
    @respx.mock
    async def test_unusable_jwks_document_returns_503(self, document):
        respx.get(self.JWKS_URL).respond(json=document)
        validator = JWTValidator(jwks_url=self.JWKS_URL)
        token = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="RS256", headers={"kid": "key1"}
        )
        with pytest.raises(HTTPException) as exc_info:
            await validator(token)
        assert exc_info.value.status_code == 503


class TestBasicAuthDirect:
    @pytest.mark.anyio
    async def test_authenticate_unscoped(self):
        async def v(username: str, password: str) -> dict:
            return {"u": username, "p": password}

        auth = HTTPBasicAuth(v)
        blob = base64.b64encode(b"alice:pw").decode()
        assert await auth.authenticate(blob) == {"u": "alice", "p": "pw"}


class TestJWKSRefreshCoalescing:
    JWKS_URL = "https://idp.example.com/jwks"

    @pytest.mark.anyio
    @respx.mock
    async def test_concurrent_stale_refreshes_coalesce(self):
        """Two requests hitting a stale cache produce a single JWKS fetch."""
        import asyncio

        fetches = 0

        async def slow_jwks(request):
            nonlocal fetches
            fetches += 1
            await asyncio.sleep(0.05)
            return httpx.Response(200, json={"keys": [_jwk(_RSA_KEY_1, "key1")]})

        respx.get(self.JWKS_URL).mock(side_effect=slow_jwks)
        validator = JWTValidator(jwks_url=self.JWKS_URL)
        token = pyjwt.encode(
            _claims(), _RSA_KEY_1, algorithm="RS256", headers={"kid": "key1"}
        )

        first, second = await asyncio.gather(validator(token), validator(token))
        assert first["sub"] == second["sub"] == "user-1"
        assert fetches == 1
