from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
TOKENS = {"user_alice-token": "alice"}


async def validate_token(token: str) -> str:
    if token not in TOKENS:
        raise UnauthorizedError()
    return TOKENS[token]


async def validate_session(username: str) -> str:
    return username


bearer = HTTPBearerAuth(validate_token, prefix="user_")
session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)
auth = MultiAuth(bearer, session)

app = FastAPI()


@app.get("/me")
async def me(username: str = Security(auth)):
    return {"username": username}
