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
:   `True` when a request without any credential reaches the route. A route FastAPI does not manage, such as `app.add_route()` or a mount, runs no dependency, so it is always unguarded. Mounted apps are not inspected: call `auth_surface()` on them too.

`alternatives`
:   The ways in. Each entry is one way (OR); the schemes inside an entry must all pass (AND).

`scopes`
:   Every scope named on the route.

Each [`SchemeRequirement`][fastapi_multiauth.SchemeRequirement] in `alternatives` also says whether it refuses cross-origin requests: `csrf` is `False` for a cookie source with [`csrf=False`](cookie-sessions.md#csrf).

To fail CI on an unguarded route, see the [audit recipe](../recipes/audit-routes.md).
