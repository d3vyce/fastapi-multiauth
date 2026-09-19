# Recipes

Complete patterns lifted (and anonymized) from a production CTF platform using this library. Each recipe is self-contained; adapt the validator bodies to your storage.

## Web session + API tokens on the same routes

The flagship pattern: browser users authenticate with a signed session cookie, automation authenticates with a bearer token; same routes, same identity object out.

```python
from fastapi import FastAPI, Response, Security
from fastapi_multiauth import (
    HTTPBearerAuth,
    APIKeyCookieAuth,
    MultiAuth,
    UnauthorizedError,
    hash_token,
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
    token = user_tokens.generate_token()  # "user_Xk3..."
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

This clears the cookie in that one browser. The signed cookie itself remains cryptographically valid until its `ttl` passes; for hard logout (stolen-cookie scenario), enable [`session_id=True`](usage.md#per-session-identity) (your validator then declares a `session_id` parameter), pass the request to `delete_cookie`, and revoke the id it returns:

```python
@app.post("/logout")
async def logout(request: Request, response: Response):
    sid = session.delete_cookie(response, request)
    if sid:
        await db.revoke_session(sid)
    return {"ok": True}
```

## Admin-only dependency with `require()`

```python
async def validate_session(user_id: str, *, role: str | None = None) -> User:
    user = await db.get_user(user_id)
    if user is None:
        raise UnauthorizedError()
    if role is not None and user.role != role:
        raise ForbiddenError()  # authenticated, but not allowed → 403
    return user


session = APIKeyCookieAuth("session", validate_session, secret_key=settings.SECRET_KEY)
admin_session = session.require(role="admin")


@app.get("/admin/stats")
async def stats(user: User = Security(admin_session)): ...
```

## Auditing the auth surface

`auth_surface(app)` reports what guards every route, read from the routes themselves rather than from `app.openapi()`. Routes registered with `include_in_schema=False` are absent from the schema, and an unguarded hidden route is exactly what an audit is looking for.

```python
from fastapi_multiauth import auth_surface

for route in auth_surface(app):
    if route.unguarded:
        print(f"UNGUARDED {','.join(route.methods) or 'WS':6} {route.path}")
```

Entries in `route.alternatives` are OR-ed, and the schemes inside one entry are AND-ed. A `MultiAuth` dependency contributes one entry per source; several separate `Security()` dependencies land in the same entry because all of them run. The OpenAPI `security` list cannot tell those two cases apart, so do not merge the scope lists across entries: that would name scopes no single credential has to carry.

Fail a CI job on anything reachable without a credential:

```python
def test_no_unguarded_routes():
    allowed = {"/health", "/login", "/auth/callback"}
    unguarded = [
        r.path for r in auth_surface(app) if r.unguarded and r.path not in allowed
    ]
    assert not unguarded, unguarded
```

Rendering is yours; here it is as a [rich](https://rich.readthedocs.io/) tree:

```python
from rich.console import Console
from rich.markup import escape
from rich.tree import Tree

from fastapi_multiauth import auth_surface


def auth_tree(app) -> Tree:
    root = Tree("/")
    nodes = {(): root}
    for route in auth_surface(app):
        segments = tuple(route.path.strip("/").split("/"))
        for i, segment in enumerate(segments, 1):
            branch = segments[:i]
            if branch not in nodes:
                nodes[branch] = nodes[branch[:-1]].add(f"[bold]/{escape(segment)}[/]")
        ways = " | ".join(
            " + ".join(
                escape(f"{req.scheme_name}{list(req.scopes) or ''}")
                + ("?" if req.optional else "")
                for req in alternative
            )
            for alternative in route.alternatives
        )
        detail = f"[dim]{ways}[/]"
        if route.unguarded:
            detail = f"[red]unguarded[/] {detail}"
        if not route.include_in_schema:
            detail += " [dim](hidden)[/]"
        for method in route.methods or ("WS",):
            nodes[segments].add(f"[cyan]{method}[/]  {detail}")
    return root


Console().print(auth_tree(app))
```
