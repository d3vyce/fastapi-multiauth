# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest 0.x release | ✅ |
| older releases | ❌ |

Until 1.0, only the latest released minor version receives security fixes.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue. Email **contact@d3vyce.fr** with:

- a description of the issue and its impact,
- a minimal reproduction (code snippet or request trace),
- the affected version(s).

You will receive an acknowledgment within 7 days. Once a fix is released, the
finding is credited in the release notes unless you prefer otherwise.

## Scope notes

- `fastapi-multiauth` validates credentials; it does not store them. Bugs in
  *your* validator (e.g. non-constant-time comparisons, missing scope checks)
  are out of scope — see the documentation for the recommended patterns
  (`hash_token`/`verify_token_hash`, scopes, signed cookies).
- Signed cookies are stateless by design: a stolen cookie remains valid until
  its `ttl` expires. This is documented behavior, not a vulnerability.
