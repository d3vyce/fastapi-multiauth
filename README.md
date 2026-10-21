# FastAPI MultiAuth

Composable authentication sources for FastAPI: bring your own validator, combine multiple schemes with `MultiAuth`, and get correct OpenAPI documentation by construction.

[![CI](https://github.com/d3vyce/fastapi-multiauth/actions/workflows/ci.yml/badge.svg)](https://github.com/d3vyce/fastapi-multiauth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/d3vyce/fastapi-multiauth/graph/badge.svg)](https://codecov.io/gh/d3vyce/fastapi-multiauth)
[![CodSpeed Badge](https://img.shields.io/endpoint?url=https://app.codspeed.io//badge.json)](https://app.codspeed.io//d3vyce/fastapi-multiauth?utm_source=badge)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

**Documentation**: [https://fastapi-multiauth.d3vyce.fr](https://fastapi-multiauth.d3vyce.fr)

**Source Code**: [https://github.com/d3vyce/fastapi-multiauth](https://github.com/d3vyce/fastapi-multiauth)

---

You write the function that decides who a credential belongs to; the library extracts the credential, combines schemes, and declares them in OpenAPI. No user model, no database coupling, no ready-made login routes.

## Installation

```bash
uv add fastapi-multiauth
uv add "fastapi-multiauth[jwt]"    # JWTValidator
uv add "fastapi-multiauth[oauth]"  # OAuth 2.0 / OIDC login helpers
```

## Quick start

```python
from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
USERS = {"1": {"id": "1", "name": "alice"}}
TOKENS = {"user_alice-token": "1"}


async def validate_token(token: str) -> dict:
    if token not in TOKENS:
        raise UnauthorizedError()
    return USERS[TOKENS[token]]


async def validate_session(user_id: str) -> dict:
    return USERS[user_id]


bearer = HTTPBearerAuth(validate_token, prefix="user_")
session = APIKeyCookieAuth("session", validate_session, secret_key=SECRET_KEY)
auth = MultiAuth(bearer, session)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(auth)):
    return user
```

## Features

- **Every standard scheme**: bearer tokens with Stripe-style prefixes, signed cookie sessions, API keys, HTTP Basic, OAuth 2.0 and OpenID Connect.
- **`MultiAuth`**: several schemes on one route, all documented in OpenAPI, plus `optional()` for routes that also serve anonymous callers.
- **Stateless sessions**: HMAC-signed cookies with expiry, key rotation, and opt-in revocable session ids.
- **Tokens done right**: secure generation, hash-only storage, checksums, and `JWTValidator` for provider JWTs (JWKS, rotation, `aud`/`iss`).
- **Scopes and step-up**: fail-closed scope checks, and `fresh()` / `stepped_up()` with RFC 9470 challenges for sensitive routes.
- **OAuth login helpers**: discovery, CSRF `state`, PKCE, code exchange and ID token validation.
- **Observable**: reason-coded security logs and `auth_surface(app)` to audit what guards every route.

See the [comparison](https://fastapi-multiauth.d3vyce.fr/comparison/) for how it sits next to `fastapi.security`, fastapi-users, AuthX and Authlib, and the [security model](https://fastapi-multiauth.d3vyce.fr/security-model/) for what it guarantees.

## License

This project is licensed under the [MIT License](LICENSE).
