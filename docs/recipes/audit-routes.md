# Audit your routes

A test that fails when a route can be reached without a credential, hidden routes included:

```python
--8<-- "docs_src/recipes/test_audit_routes.py"
```

When someone adds a route and forgets to protect it, CI fails until the route gets a guard or is added to `PUBLIC` on purpose. See [Auditing](../guide/auditing.md) for what `auth_surface` reports.
