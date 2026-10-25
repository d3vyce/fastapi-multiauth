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
- **Forged webhooks**: [`HMACSignatureAuth`](guide/webhooks.md) checks the sender's signature over the raw body, and refuses an old timestamp when the sender sends one.
- **Open redirects**: the post-login destination is checked, relative paths only by default.
- **Timing attacks**: secrets, tokens and signatures are compared in constant time.
- **Misconfiguration**: short secrets, plain-HTTP endpoints, scopes a validator cannot check, and cookie settings a browser would drop are refused loudly instead of being skipped.

## What stays with you

- **Your validator.** The library hands you a credential; deciding whether it is valid is your code.
- **Storage.** Hash passwords with argon2, scrypt or bcrypt. [`hash_token`][fastapi_multiauth.hash_token] (SHA-256) is for random tokens only.
- **HTTPS** for your own app.
- **Rate limiting** on login and token endpoints. Refusals are [logged](guide/logging.md) so you can act on them.
- **CSRF** on cookie-authenticated routes, unless you turn on [`csrf=True`](guide/cookie-sessions.md#csrf). Either way, keep `GET` routes free of side effects.

## Good to know

- **Signed is not encrypted.** Anyone holding a cookie or a JWT can read its content. Never put a secret in it.
- **Signed cookies are not revocable on their own.** A stolen cookie stays valid until it expires. Turn on [`session_id=True`](guide/cookie-sessions.md#revocable-sessions) when you need to end a session.
- **ID tokens are untrusted until validated** with `oauth_validate_id_token`.
- **The discovery URL is configuration.** Never build it from request input.

## Status codes

| Status | Meaning |
| --- | --- |
| 401 | no credential, or an invalid one; carries a `WWW-Authenticate` challenge where the scheme has one |
| 401 `insufficient_user_authentication` | valid, but authenticated too long ago or too weakly ([step-up](guide/step-up.md)) |
| 403 | authenticated, but not allowed, or sent from another origin ([`csrf=True`](guide/cookie-sessions.md#csrf)) |
| 503 | a provider's keys cannot be fetched and none are cached; clients should retry |
