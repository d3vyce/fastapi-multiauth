# FastAPI MultiAuth

Composable authentication sources for FastAPI: bring your own validator, combine multiple schemes with `MultiAuth`, and get correct OpenAPI documentation by construction.

[![CI](https://github.com/d3vyce/fastapi-multiauth/actions/workflows/ci.yml/badge.svg)](https://github.com/d3vyce/fastapi-multiauth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/d3vyce/fastapi-multiauth/graph/badge.svg)](https://codecov.io/gh/d3vyce/fastapi-multiauth)
[![CodSpeed Badge](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/d3vyce/fastapi-multiauth?utm_source=badge)
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
uv add "fastapi-multiauth[jwt]"    # JWTValidator, HTTPDPoPAuth
uv add "fastapi-multiauth[oauth]"  # OAuth 2.0 / OIDC login helpers
```

## Quick start

```python
import os

from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
    hash_token,
)

SECRET_KEY = os.environ["SECRET_KEY"]
USERS = {"1": {"id": "1", "name": "alice"}}
TOKENS = {hash_token("user_alice-token"): "1"}


async def validate_token(token: str) -> dict:
    user_id = TOKENS.get(hash_token(token))
    if user_id is None:
        raise UnauthorizedError()
    return USERS[user_id]


async def validate_session(user_id: str) -> dict:
    if user_id not in USERS:
        raise UnauthorizedError()
    return USERS[user_id]


bearer = HTTPBearerAuth(validator=validate_token, prefix="user_")
session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
auth = MultiAuth(bearer, session)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(auth)):
    return user
```

Set `SECRET_KEY` to at least 32 random bytes, for example the output of `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

## Features

- **Every standard scheme**: bearer tokens with Stripe-style prefixes, signed cookie sessions, API keys, HTTP Basic, OAuth 2.0 and OpenID Connect.
- **`MultiAuth`**: several schemes on one route, all documented in OpenAPI, plus `optional()` for routes that also serve anonymous callers.
- **Stateless sessions**: HMAC-signed cookies with expiry, key rotation, opt-in revocable session ids, and `csrf=True` to refuse cross-origin requests.
- **Tokens done right**: secure generation, hash-only storage, checksums, `JWTValidator` for provider JWTs (JWKS, rotation, `aud`/`iss`), `IntrospectionValidator` for opaque ones, and `HTTPDPoPAuth` for tokens bound to the client's key.
- **Signed webhooks**: `HMACSignatureAuth` checks the sender's signature over the raw body, with timestamp tolerance and secret rotation.
- **Scopes and step-up**: fail-closed scope checks, and `fresh()` / `stepped_up()` with RFC 9470 challenges for sensitive routes.
- **Second factor**: TOTP helpers that refuse a replayed code, and the login level signed into the session cookie.
- **OAuth login helpers**: discovery, CSRF `state`, PKCE, code exchange and ID token validation.
- **Observable**: reason-coded security logs and `auth_surface(app)` to audit what guards every route.

See the [comparison](https://fastapi-multiauth.d3vyce.fr/guide/comparison/) for how it sits next to `fastapi.security`, fastapi-users, AuthX and Authlib, and the [security model](https://fastapi-multiauth.d3vyce.fr/security-model/) for what it guarantees.

## Contributing

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately, as the [security policy](SECURITY.md) describes.

## License

This project is licensed under the [MIT License](LICENSE).
