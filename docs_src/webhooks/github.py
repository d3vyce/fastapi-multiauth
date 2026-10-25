import os

from fastapi import FastAPI, Security
from pydantic import BaseModel

from fastapi_multiauth import HMACSignatureAuth

github = HMACSignatureAuth(
    secret_key=os.environ["GITHUB_WEBHOOK_SECRET"],
    header="X-Hub-Signature-256",
    prefix="sha256=",
)


class Delivery(BaseModel):
    action: str


app = FastAPI()


@app.post("/webhooks/github", dependencies=[Security(github)])
async def github_event(delivery: Delivery):
    return {"action": delivery.action}
