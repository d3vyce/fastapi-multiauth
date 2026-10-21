from typing import Annotated

from fastapi import FastAPI, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = "change-me-please-32-bytes-minimum"
PASSWORDS = {"alice": "wonderland"}


class Password(BaseModel):
    password: str


async def validate_session(username: str) -> str:
    return username


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)
FreshUser = Annotated[str, Security(session.fresh(300))]

app = FastAPI()


@app.post("/me/re-auth")
async def re_auth(
    body: Password, response: Response, username: str = Security(session)
):
    if PASSWORDS.get(username) != body.password:
        raise UnauthorizedError()
    session.set_cookie(response, username)  # a new login time
    return {"ok": True}


@app.post("/me/password")
async def change_password(body: Password, username: FreshUser):
    PASSWORDS[username] = body.password
    return {"ok": True}
