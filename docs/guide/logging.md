---
icon: lucide/scroll-text
---

# Logging

Every authentication decision is logged through the standard `logging` module. Nothing is printed until your app configures logging:

```python
import logging

logging.getLogger("fastapi_multiauth").setLevel(logging.INFO)
```

Refusals are `WARNING`, missing credentials `INFO` (every anonymous visit makes one), successes `DEBUG`. Each module logs under its own name, such as `fastapi_multiauth.sources.cookie`, so you can tune one source at a time.

## Fields

Each record carries the decision in `extra`, ready for a JSON formatter:

| Attribute | Value |
| --- | --- |
| `auth_source` | the deciding source, e.g. `"APIKeyCookieAuth"` |
| `auth_scheme` | its OpenAPI scheme name |
| `auth_reason` | a reason code, below |
| `auth_status` | the HTTP status of a refusal, `None` on success |

Records never contain the credential, its hash, or the identity. Correlate with your access logs when you need to know *who*.

## Reason codes

| Reason | Meaning |
| --- | --- |
| `authenticated` | accepted |
| `anonymous` | an `optional()` route served a caller without a credential |
| `missing_credential` | no credential on a route that requires one |
| `invalid_signature` | a signed cookie, JWT or webhook failed its signature check |
| `expired` | a signed cookie past its `ttl`, a JWT past its `exp`, or a webhook timestamp outside its `tolerance` |
| `malformed` | a Basic header, JWT header or webhook signature header that does not parse |
| `stale` | outside the [`fresh()`](step-up.md#recent-login-fresh) window |
| `insufficient_acr` | below the [`stepped_up()`](step-up.md#strong-login-stepped_up) level |
| `cross_origin` | a cookie request from another origin, with [`csrf=True`](cookie-sessions.md#csrf) (403) |
| `missing_origin` | a cookie request carrying neither `Sec-Fetch-Site` nor `Origin`, with `csrf=True` (403) |
| `insufficient_scope` | a valid JWT missing a route scope (403) |
| `unknown_key` | a JWT signed with a key the provider does not publish |
| `jwks_unavailable` | the provider's keys cannot be fetched (503) |
| `inactive` | the introspection endpoint says the token is not active |
| `introspection_unavailable` | the introspection endpoint cannot be reached, or answers unusably (503) |
| `rejected`, `forbidden`, `error` | your validator raised a 401, a 403, or another error |

`JWTValidator` also reports `not_yet_valid`, `invalid_audience`, `invalid_issuer`, `missing_claim`, `invalid_algorithm` and `invalid_token`, and `IntrospectionValidator` the ones that apply to its answers.
