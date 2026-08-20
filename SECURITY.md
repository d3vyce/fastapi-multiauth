# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest 0.x release | ✅ |
| older releases | ❌ |

Until 1.0, only the latest released minor version receives security fixes.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately**. Do not open a public issue. Email **contact@d3vyce.fr** with:

- a description of the issue and its impact,
- a minimal reproduction (code snippet or request trace),
- the affected version(s), plus the extras installed (`jwt`, `oauth`) when the report concerns JWT validation or the OAuth flow helpers.

You will receive an acknowledgment within 7 days. Once a fix is released, the finding is credited in the release notes unless you prefer otherwise.

## Scope notes

- `fastapi-multiauth` validates credentials; it does not store them. Bugs in *your* validator (e.g. non-constant-time comparisons, missing scope checks) are out of scope. See the documentation for the recommended patterns (`hash_token`/`verify_token_hash`, scopes, signed cookies).
- Signed cookies are stateless by default: a stolen cookie stays valid until its `ttl` expires, and `delete_cookie` only clears one browser. That is documented behavior, not a vulnerability. Revocation is opt-in through `session_id=True`, which mints a per-session id your validator receives and `session_id_of(request)` reads back. The library never consults your store, so whether a revoked id is actually refused stays your validator's job.
- OAuth and userinfo calls accept an optional `httpx.AsyncClient` so a login flow can pool connections. When you supply one, its configuration governs the request: timeouts, redirect policy, proxies and TLS verification are yours, not the library's, and behavior caused by that client is out of scope. With no client supplied, the library builds its own with a 10 second timeout and no redirect following.
