import json
import os
from urllib.parse import parse_qs

from fastapi import FastAPI, Security

from fastapi_multiauth import HMACSignatureAuth

stripe = HMACSignatureAuth(
    secret_key=os.environ["STRIPE_WEBHOOK_SECRET"],
    header="Stripe-Signature",
    signature_key="v1",
    timestamp_key="t",
)
slack = HMACSignatureAuth(
    secret_key=os.environ["SLACK_SIGNING_SECRET"],
    header="X-Slack-Signature",
    prefix="v0=",
    timestamp_header="X-Slack-Request-Timestamp",
    signed_message="v0:{timestamp}:{body}",
)

app = FastAPI()


@app.post("/webhooks/stripe")
async def stripe_event(body: bytes = Security(stripe)):
    return {"type": json.loads(body)["type"]}


@app.post("/webhooks/slack")
async def slack_command(body: bytes = Security(slack)):
    form = parse_qs(body.decode())  # a form body: parse the verified bytes
    return {"command": form["command"][0]}
