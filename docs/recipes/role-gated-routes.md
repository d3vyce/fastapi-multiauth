# Role-gated routes

One validator, one keyword argument, several levels of access.

```python
--8<-- "docs_src/recipes/role_gated_routes.py"
```

`session.require(role="admin")` is a copy of `session` that passes `role="admin"` to the validator. A signed-in user without the role gets a 403.
