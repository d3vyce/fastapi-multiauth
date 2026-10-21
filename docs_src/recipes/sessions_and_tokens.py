from typing import Annotated

from fastapi import FastAPI, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
    hash_token,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
USERS = {"alice": {"name": "alice", "password": "wonderland"}}
TOKEN_HASHES = {hash_token("user_alice-script-token"): "alice"}


class Credentials(BaseModel):
    username: str
    password: str


async def validate_session(username: str) -> dict:
    if username not in USERS:
        raise UnauthorizedError()
    return {"name": username}


async def validate_api_token(token: str) -> dict:
    username = TOKEN_HASHES.get(hash_token(token))
    if username is None:
        raise UnauthorizedError()
    return {"name": username}


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)
api_tokens = HTTPBearerAuth(validate_api_token, prefix="user_")
auth = MultiAuth(api_tokens, session)

CurrentUser = Annotated[dict, Security(auth)]

app = FastAPI()


@app.post("/login")
async def login(credentials: Credentials, response: Response):
    user = USERS.get(credentials.username)
    if user is None or user["password"] != credentials.password:
        raise UnauthorizedError()
    session.set_cookie(response, credentials.username)
    return {"ok": True}


@app.get("/me")
async def me(user: CurrentUser):
    return user
