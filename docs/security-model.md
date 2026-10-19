# Security model

What this library protects, what it does not, and the properties you can rely on.

## Threat model

In scope, the library defends against:

- **Credential forgery and tampering**: signed cookies (HMAC-SHA256 via itsdangerous), JWT signature/claims verification, CSRF-verified OAuth `state`, PKCE, OIDC ID token validation with `nonce` and `at_hash`.
- **Cross-source confusion**: a cookie signed for one `APIKeyCookieAuth` is never accepted by another (per-name salt); a token skipped by one source in `MultiAuth` is evaluated by the others through the exact same code path it would take when used directly, so the two modes cannot diverge.
- **Downgrade and key-confusion**: OAuth/OIDC/JWKS endpoints must be HTTPS (loopback excepted for local development); `HS*` algorithms are rejected when validating against a public JWKS.
- **Open redirects**: the destination embedded in OAuth `state` is checked against an allowlist by default (relative paths only unless configured).
- **Timing side channels**: constant-time comparisons for the state token and token hashes; cookie signatures are verified by itsdangerous's constant-time comparison.
- **Silent misconfiguration**: empty/short cookie or JWT secrets, missing HTTPS, conflicting JWT key modes, a JWKS validator without `audience`, a `__Host-`/`__Secure-` cookie name the browser would drop, and scopes declared on a route without a validator able to check them all fail loudly (at startup or with a 500), never by skipping the check.

Out of scope, your responsibility:

- **The validator.** The library hands you a credential; deciding whether it is valid is your code. Use the packaged patterns: `hash_token`/ `verify_token_hash` for opaque tokens, `secrets.compare_digest` for Basic credentials.
- **Credential storage** (databases, password hashing: use argon2/bcrypt for passwords; SHA-256 is only appropriate for high-entropy opaque tokens).
- **Transport security** of your own app (deploy behind HTTPS; cookie `secure=True` is the default and should stay on).
- **Rate limiting / brute-force protection** on login endpoints.
- **CSRF on cookie-authenticated routes.** A cookie is ambient authority, and `SameSite=lax` (the default) leaves gaps: state-changing `GET`s, same-site attackers on a sibling subdomain, and `samesite="none"`. Unsafe methods behind `APIKeyCookieAuth` need a CSRF token, an `Origin`/`Sec-Fetch-Site` check, or `samesite="strict"`.

## Nothing is encrypted

Signed is not encrypted. The signed cookie payload and JWT claims are **readable by anyone who holds them** (base64, not ciphertext); signatures prevent *modification*, not *inspection*. Never put secrets in a cookie value or JWT claim.

## Signed cookie properties

- HMAC-SHA256 via `itsdangerous.TimestampSigner`, salt = `fastapi-multiauth.cookie.{name}` (`.sid` appended when `session_id=True`) → cookies are bound to their name and to their payload layout.
- The timestamp is inside the signed payload: expiry cannot be extended by the client.
- **Not revocable on their own**: a stolen cookie stays valid until `ttl` expires; `delete_cookie` only clears one browser. `session_id=True` mints a per-session id you can store and check in your validator, which is what makes revocation possible; the library stays stateless and never reads your store itself.
- **Rotate the id after a privilege change** (password change, elevation): mint with `set_cookie` before revoking the id `session_id_of(request)` returned, so a failure mid-way leaves the user signed in rather than leaving the old id valid.
- The session id is a bearer credential (128 bits of `secrets.token_urlsafe`): do not log it, and treat a leaked id as a leaked session.
- Keep `ttl` as short as the UX tolerates (default 24 h). Long-lived "remember me" sessions should be server-side sessions, not signed cookies.
- **Cookie shadowing.** Duplicate cookies resolve last-wins, so a party able to set cookies on a sibling subdomain can shadow the session cookie. The signature prevents forgery, so the outcome is a forced logout or fixation with the attacker's own session, never impersonation of another user. Name the cookie with the `__Host-` prefix, which a subdomain cannot set; the defaults satisfy it, and settings that break it (`domain=`, a `path` other than `/`, `secure=False`) are refused at startup.
- `secret_key` accepts a key list for rotation: first key signs, all verify. Rotate by prepending and waiting one `ttl` before removing the old key.

## JWT properties

- **Token substitution across clients.** In JWKS mode the provider's signing keys are shared by every client of the realm or tenant, so a valid signature only proves the provider issued the token, not that it was issued *for this API*. `audience` is therefore required with `jwks_url`; `JWTValidator.ANY_AUDIENCE` is the explicit, visible opt-out. On a multi-tenant key set (Entra ID) also set `issuer`, or a token from any tenant passes.
- In secret (HS256) mode the secret is yours alone, so `audience` stays optional.
- The token's `alg` header must be on the `algorithms` allowlist and match the JWKS key's own `alg`; JWKS entries whose `alg` is off the allowlist are never loaded, and `HS*` is refused in JWKS mode (key confusion).

## Opaque token properties

- `generate_token(nbytes=32)` → `secrets.token_urlsafe(nbytes)`, so 256 bits of CSPRNG entropy at the default `nbytes`; a lower `nbytes` lowers it accordingly. A custom `token_generator` owns the entropy instead, and the library cannot measure it. Use `secrets`, never `random`.
- Store only `hash_token(token)` (SHA-256 hex). Unsalted SHA-256 is correct *for these tokens* because they are unguessable; it is **not** acceptable for passwords.
- Prefixes (`user_`, `org_`) route token types to sources and make leaked tokens detectable by secret scanners.

## OAuth / OIDC flow requirements

- `discovery_url`, `authorization_url`, `token_url`, `userinfo_url`, `jwks_url` must be HTTPS (loopback hosts excepted). The discovery URL must be **config-only**: deriving it from request input opens SSRF and cache poisoning.
- The discovery document's `issuer` is always checked, and a document with no `issuer` is refused. On the standard `/.well-known/openid-configuration` path the expected issuer is derived from the URL exactly (query strings and fragments ignored, so provider-specific parameters such as Azure AD B2C's `?p=` do not weaken the check). A provider serving discovery from a non-standard path leaves nothing exact to derive, so the issuer is instead held to the origin the document was fetched from: still enough to refuse a document claiming to speak for another host.
- `state` carries a CSRF token (constant-time verified, single-use, pop it from the session before decoding) and the post-login destination (allowlist-checked by default). A failed check raises `OAuthStateError` rather than returning the fallback, so the documented callback never exchanges a code it did not ask for: without it, an attacker could log the victim into the attacker's account (login CSRF) on any provider that does not enforce PKCE.
- PKCE (S256) is supported and recommended for every client, including confidential ones (OAuth 2.1 / RFC 9700).
- **ID tokens are unverified until validated.** `oauth_exchange_code` returns the raw `id_token`; `oauth_validate_id_token` checks it per OIDC Core §3.1.3.7 (JWKS signature with the `alg` bound to the key and `HS*` refused, exact `iss`, `aud` and `azp`, `exp`/`iat`, `sub`). The `nonce` binds the token to this authorization request, so one captured from another login cannot be replayed; `at_hash` binds it to the access token issued alongside. Both are compared in constant time, and an empty expected `nonce` never matches.
- All network calls run under explicit timeouts (10 s default).

## HTTP semantics

- 401 = credential absent or invalid; 403 (`ForbiddenError`) = authenticated but insufficient (e.g. missing scopes, `JWTValidator` does this for you).
- 401 responses carry `WWW-Authenticate` challenges where a scheme exists (`Bearer`, `Basic realm="..."`); `MultiAuth` advertises the union.
