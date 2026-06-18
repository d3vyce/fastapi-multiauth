# FastAPI MultiAuth

Composable authentication sources for FastAPI: bring your own validator, combine multiple schemes with `MultiAuth`, and get correct OpenAPI documentation by construction.

[![CI](https://github.com/d3vyce/fastapi-multiauth/actions/workflows/ci.yml/badge.svg)](https://github.com/d3vyce/fastapi-multiauth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/d3vyce/fastapi-multiauth/graph/badge.svg)](https://codecov.io/gh/d3vyce/fastapi-multiauth)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

**Documentation**: [https://fastapi-multiauth.d3vyce.fr](https://fastapi-multiauth.d3vyce.fr)

**Source Code**: [https://github.com/d3vyce/fastapi-multiauth](https://github.com/d3vyce/fastapi-multiauth)

---

`fastapi-multiauth` is the composable layer between the raw primitives of `fastapi.security` and opinionated frameworks like fastapi-users or AuthX. You provide the validator; the library handles extraction, scheme combination, and OpenAPI declaration. No database coupling, no user model, no ready-made login routes.

## Installation

```bash
uv add fastapi-multiauth
```

Optional extras pull in their dependencies on demand:

```bash
uv add "fastapi-multiauth[jwt]"     # JWTValidator (PyJWT)
uv add "fastapi-multiauth[oauth]"   # OAuth 2.0 / OIDC helpers (httpx-oauth)
uv add "fastapi-multiauth[jwt,oauth]"
```

## Quick Start

```python
from fastapi import FastAPI, Security
from fastapi_multiauth import HTTPBearerAuth, APIKeyCookieAuth, MultiAuth, UnauthorizedError

async def validate_token(token: str) -> dict:
    user = await lookup_user_by_token(token)
    if user is None:
        raise UnauthorizedError()
    return user

async def validate_session(value: str) -> dict:
    return await lookup_user_by_session(value)

bearer = HTTPBearerAuth(validate_token, prefix="user_")
session = APIKeyCookieAuth("session", validate_session, secret_key="...")

# Accept either an API token or a web session on the same route.
auth = MultiAuth(bearer, session)

app = FastAPI()

@app.get("/me")
async def me(user=Security(auth)):
    return user
```

## Features

- **BYO validator**: every source wraps a sync or async callable you provide; the library never touches your user model or database.
- **`MultiAuth`**: try several sources in order on a single route (e.g. web session cookie + API bearer token), with all schemes documented in OpenAPI.
- **Built-in sources**: covering the standard `fastapi.security` schemes:
    - **`HTTPBearerAuth`**: bearer tokens with optional Stripe-style `user_`/`org_` prefixes to route different token types to different validators, plus `generate_token()` for secure token creation.
    - **`APIKeyCookieAuth`**: cookie sessions with optional HMAC-SHA256 signing (via [itsdangerous](https://itsdangerous.palletsprojects.com/)), embedded expiry, and key rotation.
    - **`APIKeyHeaderAuth`**: `X-API-Key`-style schemes, with **`APIKeyQueryAuth`** for legacy clients that can only pass a query parameter.
    - **`HTTPBasicAuth`**: `validator(username, password)` with `WWW-Authenticate` realm support.
- **Token hashing helpers**: `hash_token`/`verify_token_hash` package the "store the hash, never the token" pattern with constant-time comparison.
- **JWT validation** (`fastapi-multiauth[jwt]` extra): `JWTValidator` for `HTTPBearerAuth`: HS256 or provider JWKS (Keycloak/Auth0/Entra/Authentik) with TTL caching and rotation-aware `kid` refresh, `aud`/`iss`/`exp` checks, configurable scope claims, and a `claims_to_identity` hook.
- **Security scopes**: `Security(auth, scopes=[...])` forwards the declared scopes to validators that accept a `scopes` parameter.
- **Correct HTTP semantics**: 401 with `WWW-Authenticate` challenges ([RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235)) and 403 via `ForbiddenError`.
- **OAuth 2.0 / OIDC helpers** (`fastapi-multiauth[oauth]` extra): async discovery with TTL caching, HTTPS enforcement, CSRF-protected `state` encoding, PKCE (S256), and code exchange delegated to [httpx-oauth](https://github.com/frankie567/httpx-oauth).

## Comparison

An honest map of where `fastapi-multiauth` sits. It is the composable layer between the raw primitives of `fastapi.security` and opinionated user frameworks. If you want ready-made `/register`/`/login` routes and a user model, you want a different tool.

|  | `fastapi.security` (native) | **fastapi-multiauth** | [fastapi-users](https://github.com/fastapi-users/fastapi-users) | [AuthX](https://github.com/yezz123/authx) | [Authlib](https://authlib.org/) |
|---|---|---|---|---|---|
| Credential extraction + OpenAPI | ✅ | ✅ | ✅ | ✅ | ➖ |
| Bring-your-own validator | manual | ✅ | ❌ (own user model) | partial | manual |
| Multiple schemes on one route | manual | ✅ `MultiAuth` | ❌ | ❌ | ❌ |
| Signed cookie sessions (rotation, name-binding) | ❌ | ✅ | ✅ (own format) | ✅ (JWT in cookie) | ❌ |
| Opaque API tokens (prefixes, hash helpers) | ❌ | ✅ | ✅ (DB-backed) | ❌ | ❌ |
| JWT validation (HS + JWKS) | ❌ | ✅ `JWTValidator` | ✅ | ✅ | ✅ |
| JWT **issuance** / refresh | ❌ | ❌ | ✅ | ✅ | ✅ |
| Scope enforcement (fail-closed) | manual | ✅ | partial | ✅ | manual |
| OAuth login client helpers (PKCE, state) | ❌ | ✅ | ✅ (per-provider) | ❌ | ✅ (full client) |
| OAuth2/OIDC **server** | ❌ | ❌ | ❌ | ❌ | ✅ |
| User model, register/login/reset routes | ❌ | ❌ | ✅ | ❌ | ❌ |
| Database coupling | none | none | SQLAlchemy/Beanie | none | none |
| Maintenance status | active | active | maintenance mode | active | active |

When to pick what:

- **`fastapi.security` alone**: one scheme, simple validator, no sessions. The primitives are fine, this library just saves you the boilerplate around them.
- **fastapi-multiauth**: you own the user store and just need request-time auth: bring your own validator, combine several schemes on one route with `MultiAuth`, validate opaque tokens or JWTs, and get correct OpenAPI for free. No user model, no issued tokens, no database coupling.
- **fastapi-users**: you want batteries included (user table, password reset, verified-email flow) and accept its user model. Note it is in maintenance mode.
- **AuthX**: your session model is "login issues a JWT pair, refresh endpoint rotates it". This library validates JWTs but will never issue them.
- **Authlib**: you are building an OAuth2/OIDC *server*, or need a full-featured OAuth client beyond the login flow.

## FAQ

### Can I use it with sync validators?

Yes, every source accepts sync or async callables (including callable class instances) and awaits them correctly.

### Why don't my route scopes show in Swagger UI?

The OpenAPI specification only allows scope lists on `oauth2`/`openIdConnect` schemes; for `http`/`apiKey` schemes the array must be empty. Enforcement happens at runtime regardless; see [Usage → Security scopes](usage.md#security-scopes).

## License

This project is licensed under the [MIT License](https://github.com/d3vyce/fastapi-multiauth/blob/main/LICENSE).
