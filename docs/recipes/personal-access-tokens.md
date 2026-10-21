# Personal access tokens

Users create, list and revoke their own API tokens, like on GitHub.

```python
--8<-- "docs_src/recipes/personal_access_tokens.py"
```

- Managing tokens requires the **session**, so a leaked token cannot create more tokens. Creating one also needs a [recent login](../guide/step-up.md).
- Tokens carry a checksum, so typos are refused before any lookup.
- The token is shown once; only its hash is kept.
