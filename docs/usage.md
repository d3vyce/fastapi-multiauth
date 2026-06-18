# Usage

## The validator contract

Every source wraps a callable you provide. It can be sync or async, receives the extracted credential as its first argument, and returns the authenticated identity (any object: a dict, a `User` model, …). To reject a credential, raise `UnauthorizedError` (or any `HTTPException`):

```python
from fastapi_multiauth import UnauthorizedError

async def validate_token(token: str) -> User:
    user = await db.get_user_by_token(token)
    if user is None:
        raise UnauthorizedError()
    return user
```

Extra keyword arguments passed at instantiation are forwarded to the validator on every call:

```python
admin_bearer = HTTPBearerAuth(validate_token, role=Role.ADMIN)
```

The same applies per route: `.require(**kwargs)` returns a copy of the source with extra (or overriding) kwargs, without mutating the original. Configure the source once, then tighten individual endpoints where needed:

```python
bearer = HTTPBearerAuth(validate_token)

@app.get("/admin")
async def admin(user=Security(bearer.require(role=Role.ADMIN))):
    return user
```

Use the right status code: `UnauthorizedError` (401) when the credential is absent or invalid, `ForbiddenError` (403) when the identity is valid but lacks permission. 401 responses from bearer sources automatically carry the `WWW-Authenticate: Bearer` challenge required by [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235); `MultiAuth` advertises the union of its sources' challenges.

## Sources

The library ships one request-time source per standard `fastapi.security` scheme. Each extracts a credential from the request and hands it to your validator (the contract above); returning `None` when the credential is absent lets `MultiAuth` fall through to the next source.

### Bearer tokens

```python
from fastapi import FastAPI, Security
from fastapi_multiauth import HTTPBearerAuth

bearer = HTTPBearerAuth(validate_token)

app = FastAPI()

@app.get("/me")
async def me(user=Security(bearer)):
    return user
```

#### Token prefixes

Use prefixes to run several token types side by side (Stripe-style `user_` / `org_`). Only tokens starting with the prefix are matched, and the prefix is **kept** in the value passed to the validator:

```python
user_bearer = HTTPBearerAuth(validate_user_token, prefix="user_")
org_bearer = HTTPBearerAuth(validate_org_token, prefix="org_")
```

#### Generating and storing tokens

`generate_token()` returns 256 bits of CSPRNG entropy (43 url-safe chars by default), with the source's prefix prepended; a recognizable prefix also lets secret-scanning tools flag leaked tokens. Store the **hash**, never the token:

```python
from fastapi_multiauth import hash_token, verify_token_hash

token = user_bearer.generate_token()   # "user_Xk3...": show it to the user once
await db.save_api_token(user_id, token_hash=hash_token(token))

async def validate_user_token(token: str) -> User:
    row = await db.get_api_token(token_hash=hash_token(token))
    if row is None:
        raise UnauthorizedError()
    return row.user
```

Look tokens up by their SHA-256 hash (no salt needed: the token itself is high-entropy, unlike a password), or compare explicitly with `verify_token_hash(token, stored_hash)`, a constant-time comparison.

### Cookie sessions

`APIKeyCookieAuth` reads a cookie and hands its value to your validator. With a `secret_key`, the cookie is signed (HMAC-SHA256 via [itsdangerous](https://itsdangerous.palletsprojects.com/), salted with the cookie name) with an embedded timestamp checked against `ttl`: a stateless, tamper-proof session without any database entry:

```python
from fastapi_multiauth import APIKeyCookieAuth

session = APIKeyCookieAuth(
    "session",
    validate_session,
    secret_key=settings.SECRET_KEY,  # ≥ 32 bytes, enforced at startup
    ttl=86400,
    samesite="lax",   # default; also: domain=..., path=...
)

@app.post("/login")
async def login(response: Response, credentials: LoginForm):
    user = await check_password(credentials)
    session.set_cookie(response, str(user.id))
    return {"ok": True}

@app.post("/logout")
async def logout(response: Response):
    session.delete_cookie(response)
    return {"ok": True}
```

#### Key rotation

Pass a sequence of keys to rotate a secret without logging everyone out. The **first** key signs new cookies; **every** key verifies:

```python
session = APIKeyCookieAuth(
    "session",
    validate_session,
    secret_key=[settings.NEW_KEY, settings.OLD_KEY],
)
```

Deploy with both keys, wait until `ttl` has passed, then drop the old key.

Cookies are bound to their name: two `APIKeyCookieAuth` instances sharing a `secret_key` (e.g. `session` and `admin_session`) can never accept each other's cookies.

!!! warning "Signed cookies are not revocable"
    A signed stateless cookie stays valid until its `ttl` expires: there is no server-side entry to delete, and `delete_cookie` only clears the one browser it responds to. If you need individual session revocation, back your validator with a store and treat the cookie value as a session ID.

### API keys

`APIKeyHeaderAuth` reads the named header and hands its value to your validator. There is no `WWW-Authenticate` challenge (the `apiKey` scheme defines none), and an absent or empty header yields `None` so `MultiAuth` can fall through:

```python
from fastapi_multiauth import APIKeyHeaderAuth

api_key = APIKeyHeaderAuth("X-API-Key", validate_api_key)
```

`APIKeyQueryAuth` is the same source for the query string (`?api_key=...`), for legacy clients that cannot set a header. Prefer the header where you can: query strings leak into access logs, browser history, and `Referer` headers.

```python
from fastapi_multiauth import APIKeyQueryAuth

api_key = APIKeyQueryAuth("api_key", validate_api_key)
```

### Basic auth

`HTTPBasicAuth` decodes the [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617) `Authorization: Basic` header (UTF-8 charset) and calls `validator(username, password)`. Compare secrets in constant time, never with `==`:

```python
import secrets
from fastapi_multiauth import HTTPBasicAuth, UnauthorizedError

async def validate_basic(username: str, password: str) -> dict:
    user = await db.get_user(username)
    if user is None or not secrets.compare_digest(
        hash_password(password), user.password_hash
    ):
        raise UnauthorizedError()
    return user

basic = HTTPBasicAuth(validate_basic, realm="api")
```

The `realm` shows up in the `WWW-Authenticate: Basic realm="api"` challenge on 401 responses, which is what makes browsers prompt for credentials.

## Combining sources with MultiAuth

`MultiAuth` tries each source in order and authenticates with the first one that finds a credential in the request. All underlying schemes are documented in OpenAPI:

```python
from fastapi_multiauth import MultiAuth

auth = MultiAuth(bearer, session)

@app.get("/me")
async def me(user=Security(auth)):
    return user
```

## Security scopes

Scopes declared on the route are forwarded to validators that declare a `scopes` parameter. If the validator does not support scopes and the route declares some, the request **fails closed** instead of silently skipping the check:

```python
async def validate_token(token: str, scopes: list[str]) -> User:
    user = await db.get_user_by_token(token)
    if user is None or not set(scopes) <= set(user.scopes):
        raise UnauthorizedError()
    return user

bearer = HTTPBearerAuth(validate_token)

@app.post("/challenges")
async def create(user=Security(bearer, scopes=["challenges:write"])):
    ...
```

!!! note "Scopes and OpenAPI"
    The OpenAPI specification only allows scope lists on `oauth2`/`openIdConnect` security schemes: for `http` and `apiKey` schemes the requirement array must be empty, so route scopes do not appear in `/docs` for bearer, cookie, or header sources. Enforcement is unaffected: scopes are checked at runtime on every call path (including `MultiAuth`), and a route declaring scopes with a validator that cannot check them fails closed.

## JWT validation

`JWTValidator` plugs into `HTTPBearerAuth` to validate JWTs issued by an identity provider. It requires the `jwt` extra:

```bash
uv add "fastapi-multiauth[jwt]"
```

For Keycloak / Auth0 / Entra ID / Authentik, point it at the provider's JWKS (the URL is also available from `oauth.oauth_resolve_provider_urls(...).jwks_uri`):

```python
from fastapi_multiauth import HTTPBearerAuth, JWTValidator

bearer = HTTPBearerAuth(
    JWTValidator(
        jwks_url="https://idp.example.com/realms/main/protocol/openid-connect/certs",
        audience="my-api",
        issuer="https://idp.example.com/realms/main",
    )
)

@app.get("/me")
async def me(claims=Security(bearer)):
    return claims
```

Signing keys are fetched over HTTPS with a timeout, cached for an hour, and refreshed once when a token carries an unknown `kid`: provider key rotation needs no restart. Symmetric mode is `JWTValidator(secret=...)` (HS256, secret ≥ 32 bytes); `HS*` algorithms are rejected in JWKS mode to close the classic key-confusion attack.

Every token is checked for signature, `exp`/`nbf`/`iat` (with configurable `leeway`), `aud`/`iss` when configured, and `exp` is **required** by default; pass `required_claims=()` if your provider really issues non-expiring tokens.

Scopes integrate with `Security(..., scopes=[...])`: the claim is configurable (`scope` space-separated string by default; `scp` or `roles` lists via `scopes_claim`), and a valid token missing a required scope gets a **403** ([RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) `insufficient_scope`), not a 401.

By default the source returns the validated **claims dict**. To return your own identity object instead (exactly like every other source's validator), pass `claims_to_identity`; the endpoint then receives whatever it returns:

```python
validator = JWTValidator(
    jwks_url=...,
    audience="my-api",
    scopes_claim="scp",
    claims_to_identity=lambda claims: User(id=claims["sub"], email=claims["email"]),
)
```

!!! note "Validation only"
    This library *validates* JWTs; it does not issue or refresh session JWTs. If you need a JWT session framework (login issues a token pair, refresh endpoint, …), use [AuthX](https://github.com/yezz123/authx).
