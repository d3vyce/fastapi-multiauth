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
:   `True` when a request without any credential reaches the route.

`alternatives`
:   The ways in. Each entry is one way (OR); the schemes inside an entry must all pass (AND).

`scopes`
:   Every scope named on the route.

To fail CI on an unguarded route, see the [audit recipe](../recipes/audit-routes.md).
