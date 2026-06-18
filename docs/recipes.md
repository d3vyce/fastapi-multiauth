# Recipes

Complete patterns lifted (and anonymized) from a production CTF platform using this library. Each recipe is self-contained; adapt the validator bodies to your storage.

## Web session + API tokens on the same routes

The flagship pattern: browser users authenticate with a signed session cookie, automation authenticates with a bearer token; same routes, same identity object out.

```python
from fastapi import FastAPI, Response, Security
from fastapi_multiauth import (
    HTTPBearerAuth, APIKeyCookieAuth, MultiAuth, UnauthorizedError, hash_token,
)

async def validate_session(user_id: str) -> User:
    user = await db.get_user(user_id)
    if user is None:
        raise UnauthorizedError()
    return user

async def validate_api_token(token: str) -> User:
    row = await db.get_api_token(token_hash=hash_token(token))
    if row is None or row.revoked:
        raise UnauthorizedError()
    return row.user

session = APIKeyCookieAuth("session", validate_session, secret_key=settings.SECRET_KEY)
api = HTTPBearerAuth(validate_api_token, prefix="user_")
auth = MultiAuth(api, session)  # bearer first: API clients never hit cookie parsing

app = FastAPI()

@app.get("/me")
async def me(user: User = Security(auth)):
    return user
```

## Stripe-style token prefixes

Different token populations, different validators, zero routing logic:

```python
user_tokens = HTTPBearerAuth(validate_user_token, prefix="user_")
org_tokens = HTTPBearerAuth(validate_org_token, prefix="org_")
auth = MultiAuth(user_tokens, org_tokens)

# Issuing: store the hash, hand out the token once:
@app.post("/tokens")
async def create_token(user: User = Security(session)):
    token = user_tokens.generate_token()           # "user_Xk3..."
    await db.save_api_token(user.id, hash_token(token))
    return {"token": token}  # the only time it is ever visible
```

A token `org_abc...` is invisible to `user_tokens` (prefix mismatch → tried by the next source), so each validator only ever sees its own population.

## Token revocation

```python
@app.delete("/tokens/{token_id}")
async def revoke_token(token_id: int, user: User = Security(session)):
    await db.revoke_api_token(token_id, owner=user.id)
    return {"ok": True}
```

Opaque tokens are looked up per request, so revocation is immediate; this is the property signed cookies and JWTs give up. Mix accordingly: short-lived signed sessions, revocable API tokens.

## Full OAuth login with PKCE

A complete login + callback pair; see [OAuth 2.0 / OIDC login](oauth.md) for the helper-by-helper walkthrough.

```python
from fastapi.responses import RedirectResponse
from fastapi_multiauth.oauth import (
    OAuthError,
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_exchange_code,
    oauth_fetch_userinfo,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
    oauth_resolve_provider_urls,
)

@app.get("/oauth/login")
async def oauth_login(request: Request, next: str = "/"):
    endpoints = await oauth_resolve_provider_urls(settings.OIDC_DISCOVERY_URL)
    state_token = oauth_generate_state_token()
    code_verifier, code_challenge = oauth_generate_pkce_pair()
    request.session["oauth_state"] = state_token
    request.session["oauth_verifier"] = code_verifier
    return oauth_build_authorization_redirect(
        endpoints.authorization_endpoint,
        client_id=settings.OIDC_CLIENT_ID,
        scopes="openid email profile",
        redirect_uri=settings.OIDC_REDIRECT_URI,
        destination=next,
        state_token=state_token,
        code_challenge=code_challenge,
    )

@app.get("/oauth/callback")
async def oauth_callback(request: Request, code: str, state: str | None = None):
    endpoints = await oauth_resolve_provider_urls(settings.OIDC_DISCOVERY_URL)
    destination = oauth_decode_state(
        state,
        expected_state_token=request.session.pop("oauth_state", ""),
        fallback="/",  # relative-only guard is the default
    )
    try:
        token = await oauth_exchange_code(
            token_url=endpoints.token_endpoint,
            code=code,
            client_id=settings.OIDC_CLIENT_ID,
            client_secret=settings.OIDC_CLIENT_SECRET,
            redirect_uri=settings.OIDC_REDIRECT_URI,
            required_scopes="openid email profile",
            code_verifier=request.session.pop("oauth_verifier", None),
        )
        userinfo = await oauth_fetch_userinfo(
            userinfo_url=endpoints.userinfo_endpoint,
            access_token=token["access_token"],
        )
    except OAuthError:
        return RedirectResponse("/login?error=oauth")

    user = await db.get_or_create_oauth_user(
        subject=userinfo["sub"], email=userinfo.get("email")
    )
    response = RedirectResponse(destination, status_code=303)
    session.set_cookie(response, str(user.id))
    return response
```

Dynamic providers (configured in the database at runtime) work the same way: `oauth_resolve_provider_urls` caches per discovery URL with a 1 h TTL; just make sure the URL comes from *your* configuration, never from request input.

## Logout

```python
@app.post("/logout")
async def logout(response: Response):
    session.delete_cookie(response)
    return {"ok": True}
```

This clears the cookie in that one browser. The signed cookie itself remains cryptographically valid until its `ttl` passes; if you need hard logout (stolen-cookie scenario), make the cookie value a server-side session ID and delete the session row here instead.

## Admin-only dependency with `require()`

```python
async def validate_session(user_id: str, *, role: str | None = None) -> User:
    user = await db.get_user(user_id)
    if user is None:
        raise UnauthorizedError()
    if role is not None and user.role != role:
        raise ForbiddenError()          # authenticated, but not allowed → 403
    return user

session = APIKeyCookieAuth("session", validate_session, secret_key=settings.SECRET_KEY)
admin_session = session.require(role="admin")

@app.get("/admin/stats")
async def stats(user: User = Security(admin_session)):
    ...
```
