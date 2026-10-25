---
icon: lucide/webhook
---

# Signed webhooks

A webhook sender signs each request with a secret you share: an HMAC-SHA256 of the raw body, sent in a header. [`HMACSignatureAuth`][fastapi_multiauth.HMACSignatureAuth] checks it before your route runs:

```python
--8<-- "docs_src/webhooks/github.py"
```

The signature covers the exact bytes received, so the check runs on the raw body. Your route can still declare a JSON body parameter: FastAPI parses it from the same bytes. To take the verified bytes instead, write `body: bytes = Security(github)`.

Form bodies are the exception: FastAPI consumes the raw body to parse `Form()` and `File()` parameters, before the signature can be checked. Take the bytes from the source and parse them with `urllib.parse.parse_qs`, as the Slack route below does.

A missing, malformed or wrong signature gets a **401**. Signatures are compared in constant time, and the secret must be at least 16 random bytes.

## Senders

Senders differ in where they put the signature and what exactly they sign. Describe yours with the [constructor's arguments][fastapi_multiauth.HMACSignatureAuth]. Stripe and Slack, for instance:

```python
--8<-- "docs_src/webhooks/senders.py"
```

| Argument | For |
| --- | --- |
| `header` and `prefix` | one signature after a fixed prefix: GitHub's `sha256=<signature>`, Slack's `v0=<signature>` |
| `signature_key` and `timestamp_key` | a list of `key=value` items: Stripe's `t=<time>,v1=<signature>` |
| `timestamp_header` | a timestamp in its own header, as Slack sends it |
| `signed_message` | what the sender signs: `{timestamp}.{body}` by default with a timestamp, `{body}` without |

A timestamp must be part of `signed_message`, or anyone could replay a request with a fresh one: the constructor refuses that configuration.

## Replays

A signature proves who sent the body, not that it is the first time you see it. With a timestamp, a request older than `tolerance` (300 seconds by default) is refused, but a copy replayed within that window still passes. GitHub sends no timestamp at all. Make your handler idempotent, or deduplicate on the event id the sender provides, such as `X-GitHub-Delivery`.

## Rotating a secret

Pass a list: `secret_key=[new_secret, old_secret]` accepts either. Remove the old one once the sender only signs with the new one.
