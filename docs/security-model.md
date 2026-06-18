# Security model

What this library protects, what it does not, and the properties you can rely on.

## Threat model

In scope, the library defends against:

- **Credential forgery and tampering**: signed cookies (HMAC-SHA256 via itsdangerous), JWT signature/claims verification, CSRF-verified OAuth `state`, PKCE.
- **Cross-source confusion**: a cookie signed for one `APIKeyCookieAuth` is never accepted by another (per-name salt); a token skipped by one source in `MultiAuth` is evaluated by the others through the exact same code path it would take when used directly, so the two modes cannot diverge.
- **Downgrade and key-confusion**: OAuth/OIDC/JWKS endpoints must be HTTPS (loopback excepted for local development); `HS*` algorithms are rejected when validating against a public JWKS.
- **Open redirects**: the destination embedded in OAuth `state` is checked against an allowlist by default (relative paths only unless configured).
- **Timing side channels**: constant-time comparisons for the state token and token hashes; cookie signatures are verified by itsdangerous's constant-time comparison.
- **Silent misconfiguration**: empty/short cookie or JWT secrets, missing HTTPS, conflicting JWT key modes, and scopes declared on a route without a validator able to check them all fail loudly (at startup or with a 500), never by skipping the check.

Out of scope, your responsibility:

- **The validator.** The library hands you a credential; deciding whether it is valid is your code. Use the packaged patterns: `hash_token`/ `verify_token_hash` for opaque tokens, `secrets.compare_digest` for Basic credentials.
- **Credential storage** (databases, password hashing: use argon2/bcrypt for passwords; SHA-256 is only appropriate for high-entropy opaque tokens).
- **Transport security** of your own app (deploy behind HTTPS; cookie `secure=True` is the default and should stay on).
- **Rate limiting / brute-force protection** on login endpoints.

## Nothing is encrypted

Signed is not encrypted. The signed cookie payload and JWT claims are **readable by anyone who holds them** (base64, not ciphertext); signatures prevent *modification*, not *inspection*. Never put secrets in a cookie value or JWT claim.

## Signed cookie properties

- HMAC-SHA256 via `itsdangerous.TimestampSigner`, salt = `fastapi-multiauth.cookie.{name}` → cookies are bound to their name.
- The timestamp is inside the signed payload: expiry cannot be extended by the client.
- **Not individually revocable**: a stolen cookie stays valid until `ttl` expires; `delete_cookie` only clears one browser. For revocation, store a session ID in the cookie and check a server-side store in the validator.
- Keep `ttl` as short as the UX tolerates (default 24 h). Long-lived "remember me" sessions should be server-side sessions, not signed cookies.
- `secret_key` accepts a key list for rotation: first key signs, all verify. Rotate by prepending and waiting one `ttl` before removing the old key.

## Opaque token properties

- `generate_token()` → 256 bits of CSPRNG entropy (`secrets.token_urlsafe`).
- Store only `hash_token(token)` (SHA-256 hex). Unsalted SHA-256 is correct *for these tokens* because they are unguessable; it is **not** acceptable for passwords.
- Prefixes (`user_`, `org_`) route token types to sources and make leaked tokens detectable by secret scanners.

## OAuth / OIDC flow requirements

- `discovery_url`, `token_url`, `userinfo_url`, `jwks_url` must be HTTPS (loopback hosts excepted). The discovery URL must be **config-only**: deriving it from request input opens SSRF and cache poisoning.
- The discovery document's `issuer` must match the URL it was fetched from.
- `state` carries a CSRF token (constant-time verified, single-use, delete it from the session after the callback) and the post-login destination (allowlist-checked by default).
- PKCE (S256) is supported and recommended for every client, including confidential ones (OAuth 2.1 / RFC 9700).
- All network calls run under explicit timeouts (10 s default).

## HTTP semantics

- 401 = credential absent or invalid; 403 (`ForbiddenError`) = authenticated but insufficient (e.g. missing scopes, `JWTValidator` does this for you).
- 401 responses carry `WWW-Authenticate` challenges where a scheme exists (`Bearer`, `Basic realm="..."`); `MultiAuth` advertises the union.
