# Two-factor login

A password, then a code from an authenticator app (TOTP) or a recovery code. Built on [signed cookies](../guide/cookie-sessions.md) and [step-up](../guide/step-up.md).

```python
--8<-- "docs_src/recipes/two_factor.py"
```

- Once the password matches, `/login` sets a 5-minute `__Host-mfa-pending` cookie instead of the session. A signed cookie is bound to its name, so it is never accepted as `__Host-session`.
- [`totp_verify`][fastapi_multiauth.totp_verify] returns the time step it matched; storing it as `last_step` makes each code work once. `/2fa/confirm` stores it too, or the first login could replay the enrolment code.
- `claim_step` stores the step only if it is newer. In a database, make it one write, `UPDATE ... WHERE last_step IS NULL OR last_step < :step`, and refuse the login when no row changed; use up recovery codes the same way.
- Each guess has three chances in a million. `record_failure` locks `/login/verify` for 15 minutes after 5 wrong codes, counted per account: the attacker has the password, so a new pending cookie is one login away.
- `/login/verify` issues the session with `acr="mfa"`, which `stepped_up(["mfa"])` requires, so a password-only session never reaches `/payouts` or `/2fa/disable`.
- The methods tell the second factors apart: `otp` for an authenticator code, `mfa` alone for a recovery code, which RFC 8176 has no method for.
- Recovery codes carry 80 random bits, are shown once, stored with [`hash_token`][fastapi_multiauth.hash_token], and used up on login.
- Encrypt the TOTP secret at rest.
