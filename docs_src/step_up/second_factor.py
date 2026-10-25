import hmac
import os
from typing import Annotated

from fastapi import FastAPI, Request, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError
from fastapi_multiauth import AuthenticationMethodReference as AMR

SECRET_KEY = os.environ["SECRET_KEY"]
OTP_CODES = {"alice": "123456"}  # stands in for your TOTP check


class Code(BaseModel):
    code: str


async def validate_session(username: str) -> str:
    return username


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
StrongUser = Annotated[str, Security(session.stepped_up(["aal2"]))]

app = FastAPI()


def sign_in(response: Response, username: str) -> None:
    session.set_cookie(response, username, acr="aal1", amr=[AMR.PASSWORD])


@app.post("/login/otp")
async def verify_otp(
    body: Code, request: Request, response: Response, username: str = Security(session)
):
    expected = OTP_CODES.get(username)
    if expected is None or not hmac.compare_digest(body.code, expected):
        raise UnauthorizedError()
    methods = [*(session.amr_of(request) or ()), AMR.ONE_TIME_PASSWORD]
    session.set_cookie(response, username, acr="aal2", amr=methods)
    return {"ok": True}


@app.post("/payouts")
async def payout(username: StrongUser):
    return {"approved_by": username}
