# OAuth 2.0 / OIDC login

The OAuth helpers implement the pieces of an authorization-code login flow that are annoying to get right (discovery, CSRF `state`, PKCE, code exchange) while you keep the routes. Unlike the [auth sources](usage.md), they don't validate an incoming request; they *obtain* a credential through the browser redirect flow, so they live in their own `fastapi_multiauth.oauth` namespace and require the `oauth` extra:

```bash
uv add "fastapi-multiauth[oauth]"
```

Every helper is documented in the [API reference](reference.md#oauth-helpers), and [Recipes](recipes.md#full-oauth-login-with-pkce) carries a copy-paste login + callback pair.

The full flow with PKCE, CSRF state, and the built-in open-redirect guard:

```python
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
    # Store both server-side (session or Redis), never in an unsigned cookie.
    request.session["oauth_state"] = state_token
    request.session["oauth_code_verifier"] = code_verifier
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
    expected = request.session.pop("oauth_state", "")  # single-use
    code_verifier = request.session.pop("oauth_code_verifier", None)
    # Open-redirect guard: by default only relative paths are accepted.
    destination = oauth_decode_state(
        state, expected_state_token=expected, fallback="/"
    )
    try:
        token = await oauth_exchange_code(
            token_url=endpoints.token_endpoint,
            code=code,
            client_id=settings.OIDC_CLIENT_ID,
            client_secret=settings.OIDC_CLIENT_SECRET,
            redirect_uri=settings.OIDC_REDIRECT_URI,
            required_scopes="openid email profile",
            code_verifier=code_verifier,
        )
        userinfo = await oauth_fetch_userinfo(
            userinfo_url=endpoints.userinfo_endpoint,
            access_token=token["access_token"],
        )
    except OAuthError:
        return RedirectResponse("/login?error=oauth")
    ...  # create your session from userinfo
```

`oauth_exchange_code` returns the full token response: `access_token` plus whatever the provider granted (`refresh_token`, `id_token`, `scope`, …), so refresh and ID-token flows stay possible. `oauth_resolve_provider_urls` returns an `OIDCEndpoints` named tuple that also carries `jwks_uri`, `end_session_endpoint`, and `issuer` when the provider advertises them. Providers that require HTTP Basic authentication on the token endpoint are supported via `oauth_exchange_code(..., token_endpoint_auth_method="client_secret_basic")`.

## Error handling

All flow errors derive from `OAuthError`, so a single `except` covers the callback; catch the specific classes when you need to react differently:

- `OAuthDiscoveryError`: the discovery document could not be fetched or is invalid (transport failure, malformed JSON, missing endpoints, issuer mismatch, non-HTTPS endpoints);
- `OAuthExchangeError`: the code exchange failed (provider rejection, timeout, malformed response, wrong `token_type`, missing required scopes);
- `OAuthUserinfoError`: the userinfo endpoint failed or returned garbage.

`ValueError` is reserved for caller mistakes: passing a non-HTTPS URL to any helper.

## PKCE

`oauth_generate_pkce_pair()` returns a `(code_verifier, code_challenge)` pair (RFC 7636, S256 only). The challenge travels to the provider in the authorization redirect; the verifier stays server-side and is replayed at the token exchange. PKCE is optional (some providers do not support it) but recommended for every client, including confidential ones: OAuth 2.1 and RFC 9700 require it.

## Open-redirect guard

`oauth_decode_state(..., allowed_hosts=...)` validates the destination embedded in `state` before you redirect to it:

- `allowed_hosts=()` (default): relative paths only, secure by default;
- `allowed_hosts=("app.example.com",)`: relative paths plus absolute http(s) URLs on the listed hosts;
- `allowed_hosts=None`: explicitly disables the check; you must validate the returned URL yourself.

Scheme-relative URLs (`//evil.com`), backslash tricks, and non-http(s) schemes (`javascript:`) always fall back.

!!! warning "Discovery URL is config-only"
    Never derive `discovery_url` from request input: it would open SSRF and cache-poisoning vectors. All OAuth endpoints must be HTTPS (loopback hosts are exempt for local development). Discovery results are cached for one hour, so provider-side endpoint changes are picked up without a restart.

!!! note "Why httpx-oauth internally?"
    The authorization-code exchange (including PKCE) is delegated to [httpx-oauth](https://github.com/frankie567/httpx-oauth) rather than re-implemented: less hand-written security-critical transport to maintain. What httpx-oauth does *not* provide stays in this library: async cached discovery, the CSRF + destination `state` encoding, the granted-scopes check (RFC 6749 §3.3), and the full userinfo payload (httpx-oauth's `get_id_email()` only returns id and email). All failures surface as `OAuthError` subclasses, so the dependency never leaks into your code.
