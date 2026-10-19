# OAuth 2.0 / OIDC login

The OAuth helpers implement the pieces of an authorization-code login flow that are annoying to get right (discovery, CSRF `state`, PKCE, code exchange) while you keep the routes. Unlike the [auth sources](usage.md), they don't validate an incoming request; they *obtain* a credential through the browser redirect flow, so they live in their own `fastapi_multiauth.oauth` namespace and require the `oauth` extra:

```bash
uv add "fastapi-multiauth[oauth]"
```

Every helper is documented in the [API reference](reference.md#oauth-helpers), and [Recipes](recipes.md#full-oauth-login-with-pkce) carries a copy-paste login + callback pair.

The full flow with PKCE, CSRF state, and the built-in open-redirect guard (the [ID token](#id-tokens) section adds the OpenID Connect `nonce` on top):

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
    try:
        # Raises OAuthStateError unless this session started the flow, so the
        # code is never exchanged on a forged callback. Open-redirect guard: by
        # default only relative paths are accepted.
        destination = oauth_decode_state(
            state, expected_state_token=expected, fallback="/"
        )
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

`oauth_exchange_code` returns the full token response: `access_token` plus whatever the provider granted (`refresh_token`, `id_token`, `scope`, …). An `id_token` is unverified until you pass it through [`oauth_validate_id_token`](#id-tokens). `oauth_resolve_provider_urls` returns an `OIDCEndpoints` named tuple that also carries `jwks_uri`, `end_session_endpoint`, and `issuer` when the provider advertises them. Providers that require HTTP Basic authentication on the token endpoint are supported via `oauth_exchange_code(..., token_endpoint_auth_method="client_secret_basic")`.

By default each call opens a fresh HTTPS connection. `oauth_exchange_code` and `oauth_fetch_userinfo` accept an optional `client=`: pass a long-lived `httpx.AsyncClient` (e.g. created in your app's lifespan) to reuse its connection pool across the two callback calls and avoid the extra TLS handshake. The client is borrowed, never closed, and its own configuration (timeouts included) governs the requests.

## ID tokens

The `id_token` in the token response is a claim about the user, signed by the provider. Trust nothing in it before `oauth_validate_id_token` has checked it ([OIDC Core §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)). It needs the `jwt` extra on top of `oauth`:

```bash
uv add "fastapi-multiauth[oauth,jwt]"
```

Send a `nonce` with the redirect and store it next to the state token, with the same single-use lifecycle:

```python
from fastapi_multiauth.oauth import oauth_generate_nonce, oauth_validate_id_token


@app.get("/oauth/login")
async def oauth_login(request: Request, next: str = "/"):
    endpoints = await oauth_resolve_provider_urls(settings.OIDC_DISCOVERY_URL)
    state_token = oauth_generate_state_token()
    nonce = oauth_generate_nonce()
    code_verifier, code_challenge = oauth_generate_pkce_pair()
    request.session["oauth_state"] = state_token
    request.session["oauth_nonce"] = nonce
    request.session["oauth_code_verifier"] = code_verifier
    return oauth_build_authorization_redirect(
        endpoints.authorization_endpoint,
        client_id=settings.OIDC_CLIENT_ID,
        scopes="openid email profile",
        redirect_uri=settings.OIDC_REDIRECT_URI,
        destination=next,
        state_token=state_token,
        code_challenge=code_challenge,
        nonce=nonce,
    )


@app.get("/oauth/callback")
async def oauth_callback(request: Request, code: str, state: str | None = None):
    endpoints = await oauth_resolve_provider_urls(settings.OIDC_DISCOVERY_URL)
    expected = request.session.pop("oauth_state", "")
    nonce = request.session.pop("oauth_nonce", "")  # "" never matches
    code_verifier = request.session.pop("oauth_code_verifier", None)
    try:
        destination = oauth_decode_state(
            state, expected_state_token=expected, fallback="/"
        )
        token = await oauth_exchange_code(
            token_url=endpoints.token_endpoint,
            code=code,
            client_id=settings.OIDC_CLIENT_ID,
            client_secret=settings.OIDC_CLIENT_SECRET,
            redirect_uri=settings.OIDC_REDIRECT_URI,
            code_verifier=code_verifier,
        )
        if endpoints.issuer is None or endpoints.jwks_uri is None:
            raise OAuthError("the provider does not advertise an issuer and a JWKS")
        claims = await oauth_validate_id_token(
            token.get("id_token", ""),  # absent: refused as malformed
            issuer=endpoints.issuer,
            jwks_uri=endpoints.jwks_uri,
            client_id=settings.OIDC_CLIENT_ID,
            nonce=nonce,
        )
    except OAuthError:
        return RedirectResponse("/login?error=oauth")
    ...  # create your session from claims["sub"]
```

Every ID token is checked for:

- a signature by a key from the provider's JWKS, with the `alg` header on the `algorithms` allowlist (`RS256` and `ES256` by default; `HS*` is refused) and bound to the key's own `alg`;
- `iss` equal to `issuer`, `client_id` among the `aud` values, and `azp` equal to `client_id` when present;
- `exp` and `iat` present and valid (with `leeway` for clock skew), and a `sub`;
- `nonce` equal to the stored one when `nonce=` is passed, compared in constant time. Pop it with a `""` default, as the state token: an empty `nonce` never matches, while `None` skips the check;
- `at_hash` when `access_token=` is passed: the token must carry one, and it must match the access token under the hash of the header's `alg`. Leave `access_token` out for providers that do not emit `at_hash` on the code flow.

The JWKS is cached and refreshed like [`JWTValidator`](usage.md#jwt-validation)'s: an hour of caching, one rate-limited refetch on an unknown `kid`, and the cached keys keep serving while the provider is down. The cache is keyed on `jwks_uri`, which must therefore come from configuration (here, from the discovery document), never from request input.

## Error handling

All flow errors derive from `OAuthError`, so a single `except` covers the callback; catch the specific classes when you need to react differently:

- `OAuthStateError`: the `state` CSRF check failed (no token stored for this session, `state` absent or malformed, or a different token). The callback did not come from a redirect this session started; never exchange the code;
- `OAuthDiscoveryError`: the discovery document could not be fetched or is invalid (transport failure, malformed JSON, missing endpoints, issuer mismatch, non-HTTPS endpoints);
- `OAuthExchangeError`: the code exchange failed (provider rejection, timeout, malformed response, wrong `token_type`, missing required scopes);
- `OAuthUserinfoError`: the userinfo endpoint failed or returned garbage;
- `OAuthIDTokenError`: the ID token failed validation (signature, unknown key, `iss`, `aud`, `azp`, lifetime, `nonce`, `at_hash`), or the provider's JWKS could not be fetched with nothing cached.

`ValueError` is reserved for caller mistakes: passing a non-HTTPS URL to any helper, or an empty `issuer`/`client_id` or an `HS*` algorithm to `oauth_validate_id_token`.

## PKCE

`oauth_generate_pkce_pair()` returns a `(code_verifier, code_challenge)` pair (RFC 7636, S256 only). The challenge travels to the provider in the authorization redirect; the verifier stays server-side and is replayed at the token exchange. PKCE is optional (some providers do not support it) but recommended for every client, including confidential ones: OAuth 2.1 and RFC 9700 require it.

## Open-redirect guard

`oauth_decode_state(..., allowed_hosts=...)` validates the destination embedded in `state` before you redirect to it:

- `allowed_hosts=()` (default): relative paths only, secure by default;
- `allowed_hosts=("app.example.com",)`: relative paths plus absolute http(s) URLs on the listed hosts;
- `allowed_hosts=None`: explicitly disables the check; you must validate the returned URL yourself.

Scheme-relative URLs (`//evil.com`), backslash tricks, and non-http(s) schemes (`javascript:`) always fall back.

`fallback` only covers a destination that is missing or refused once the CSRF check has passed. A failed CSRF check raises `OAuthStateError` instead, so call `oauth_decode_state` inside the same `try` as the code exchange.

!!! warning "Discovery URL is config-only"
    Never derive `discovery_url` from request input: it would open SSRF and cache-poisoning vectors. All OAuth endpoints must be HTTPS (loopback hosts are exempt for local development). Discovery results are cached for one hour, so provider-side endpoint changes are picked up without a restart.

!!! note "Why httpx-oauth internally?"
    The authorization-code exchange (including PKCE) is delegated to [httpx-oauth](https://github.com/frankie567/httpx-oauth) rather than re-implemented: less hand-written security-critical transport to maintain. What httpx-oauth does *not* provide stays in this library: async cached discovery, the CSRF + destination `state` encoding, the granted-scopes check (RFC 6749 §3.3), and the full userinfo payload (httpx-oauth's `get_id_email()` only returns id and email). All failures surface as `OAuthError` subclasses, so the dependency never leaks into your code.
