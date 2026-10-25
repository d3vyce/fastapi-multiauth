---
icon: lucide/shield-half
---

# Security model

What the library takes care of, and what stays with you. To report a vulnerability, see the [security policy](https://github.com/d3vyce/fastapi-multiauth/security/policy).

## What the library handles

- **Tampering**: cookies are signed (HMAC-SHA256), JWTs and ID tokens are verified, OAuth `state` is checked against CSRF.
- **Confusion between sources**: a cookie signed for one cookie name is never accepted under another, and a JWKS-backed `JWTValidator` requires an `audience`.
- **Downgrades**: OAuth, OIDC and JWKS URLs must be HTTPS, and `HS*` algorithms are refused against a provider's keys.
- **Cross-site requests**: with [`csrf=True`](guide/cookie-sessions.md#csrf), a cookie source refuses requests sent from another origin.
- **Stolen tokens**: a [DPoP](guide/jwt-and-oauth2.md#sender-constrained-tokens-dpop)-bound token is refused without a fresh proof signed by its key.
- **Forged webhooks**: [`HMACSignatureAuth`](guide/webhooks.md) checks the sender's signature over the raw body, and refuses an old timestamp when the sender sends one.
- **Replayed one-time codes**: [`totp_verify`][fastapi_multiauth.totp_verify] refuses a code from a time step already used, given the `last_step` you stored.
- **Open redirects**: the post-login destination is checked, relative paths only by default.
- **Timing attacks**: secrets, tokens and signatures are compared in constant time.
- **Misconfiguration**: short secrets, plain-HTTP endpoints, scopes a validator cannot check, and cookie settings a browser would drop are refused loudly instead of being skipped.

## What stays with you

- **Your validator.** The library hands you a credential; deciding whether it is valid is your code.
- **Storage.** Hash passwords with argon2, scrypt or bcrypt. [`hash_token`][fastapi_multiauth.hash_token] (SHA-256) is for random tokens only.
- **HTTPS** for your own app.
- **TOTP secrets.** Encrypt them at rest: unlike a password, a TOTP secret cannot be stored as a hash. See the [two-factor recipe](recipes/two-factor.md).
- **Rate limiting** on login, one-time code and token endpoints. Refusals are [logged](guide/logging.md) so you can act on them.
- **CSRF** on cookie-authenticated routes, unless you turn on [`csrf=True`](guide/cookie-sessions.md#csrf). Either way, keep `GET` routes free of side effects.

## Good to know

- **Signed is not encrypted.** Anyone holding a cookie or a JWT can read its content. Never put a secret in it.
- **Signed cookies are not revocable on their own.** A stolen cookie stays valid until it expires. Turn on [`session_id=True`](guide/cookie-sessions.md#revocable-sessions) when you need to end a session.
- **ID tokens are untrusted until validated** with `oauth_validate_id_token`.
- **Introspection answers are cached.** A token revoked at the provider keeps working until its cached answer expires, `cache_ttl` seconds at most.
- **The discovery URL is configuration.** Never build it from request input.

## Status codes

| Status | Meaning |
| --- | --- |
| 401 | no credential, or an invalid one; carries a `WWW-Authenticate` challenge where the scheme has one |
| 401 `insufficient_user_authentication` | valid, but authenticated too long ago or too weakly ([step-up](guide/step-up.md)) |
| 403 | authenticated, but not allowed, or sent from another origin ([`csrf=True`](guide/cookie-sessions.md#csrf)) |
| 503 | a provider's keys cannot be fetched and none are cached, or its introspection endpoint is down; clients should retry |
