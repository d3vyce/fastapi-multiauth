---
icon: lucide/git-compare
---

# Comparison

`fastapi-multiauth` sits between the raw primitives of `fastapi.security` and full user frameworks. If you want ready-made `/register` and `/login` routes and a user model, you want a different tool.

## Feature map

|  | `fastapi.security` | **fastapi-multiauth** | [fastapi-users](https://github.com/fastapi-users/fastapi-users) | [AuthX](https://github.com/yezz123/authx) | [Authlib](https://authlib.org/) |
|---|---|---|---|---|---|
| Credential extraction + OpenAPI | ✅ | ✅ | ✅ | ✅ | ➖ |
| Bring-your-own validator | manual | ✅ | ❌ own user model | partial | manual |
| Multiple schemes on one route | manual | ✅ `MultiAuth` | ❌ | ❌ | ❌ |
| Signed cookie sessions (rotation, name binding) | ❌ | ✅ | ✅ own format | ✅ JWT in cookie | ❌ |
| Opaque API tokens (prefixes, hash helpers) | ❌ | ✅ | ✅ DB-backed | ❌ | ❌ |
| JWT validation (HS256 and JWKS) | ❌ | ✅ `JWTValidator` | ✅ | ✅ | ✅ |
| JWT **issuance** and refresh | ❌ | ❌ | ✅ | ✅ | ✅ |
| Scope enforcement, fail-closed | manual | ✅ | partial | ✅ | manual |
| OAuth login client helpers (PKCE, state) | ❌ | ✅ | ✅ per provider | ❌ | ✅ full client |
| OAuth 2.0 / OIDC **server** | ❌ | ❌ | ❌ | ❌ | ✅ |
| User model, register/login/reset routes | ❌ | ❌ | ✅ | ❌ | ❌ |
| Database coupling | none | none | SQLAlchemy / Beanie | none | none |
| Maintenance status | active | active | maintenance mode | active | active |

## When to pick what

`fastapi.security` alone
:   One scheme, a simple check, no sessions. The primitives are fine; this library mostly saves you the boilerplate around them.

fastapi-multiauth
:   You own the user store and need request-time authentication: your validator, several schemes on one route, opaque tokens or JWTs from a provider, correct OpenAPI. No user model, no issued tokens, no database coupling.

fastapi-users
:   You want batteries included (user table, password reset, email verification) and accept its user model. It is in maintenance mode.

AuthX
:   Your session model is "login issues a JWT pair, a refresh endpoint rotates it". This library validates JWTs but never issues them.

Authlib
:   You are building an OAuth 2.0 / OIDC *server*, or need a full OAuth client beyond the login flow.
