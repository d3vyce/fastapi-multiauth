from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
USERS = {"1": {"id": "1", "name": "alice"}}
TOKENS = {"user_alice-token": "1"}


async def validate_token(token: str) -> dict:
    if token not in TOKENS:
        raise UnauthorizedError()
    return USERS[TOKENS[token]]


async def validate_session(user_id: str) -> dict:
    return USERS[user_id]


bearer = HTTPBearerAuth(validate_token, prefix="user_")
session = APIKeyCookieAuth("session", validate_session, secret_key=SECRET_KEY)
auth = MultiAuth(bearer, session)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(auth)):
    return user
