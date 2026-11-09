---
icon: lucide/scan-eye
---

# Auditing

[`auth_surface(app)`][fastapi_multiauth.auth_surface] lists every route with what guards it, including routes hidden from the OpenAPI schema:

```python
--8<-- "docs_src/auditing/surface.py"
```

Each [`RouteAuth`][fastapi_multiauth.RouteAuth] tells you:

`unguarded`
:   `True` when a request without any credential reaches the route. A route FastAPI does not manage, such as `app.add_route()` or a mount, runs no dependency, so it is always unguarded. Mounted apps are not inspected: call `auth_surface()` on them too. A guard replaced in `app.dependency_overrides` counts as not running, so a test override left behind makes its routes unguarded.

`alternatives`
:   The ways in. Each entry is one way (OR); the schemes inside an entry must all pass (AND).

`scopes`
:   Every scope named on the route.

Each [`SchemeRequirement`][fastapi_multiauth.SchemeRequirement] in `alternatives` also says:

`csrf`
:   Whether it refuses cross-origin requests: `False` for a cookie source with [`csrf=False`](cookie-sessions.md#csrf).

`validated`
:   Whether a validator checks the credential. `False` for a plain `fastapi.security` scheme such as `HTTPBearer()`, which refuses a missing header but lets any value through, and for a guard replaced in `app.dependency_overrides`.

`overridden`
:   Whether `app.dependency_overrides` replaces the guard the route declares.

To fail CI on an unguarded route, see the [audit recipe](../recipes/audit-routes.md).
