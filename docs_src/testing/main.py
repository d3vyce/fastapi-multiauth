import os

from fastapi import FastAPI, Response, Security

from fastapi_multiauth import APIKeyCookieAuth, HTTPBearerAuth, UnauthorizedError

SECRET_KEY = os.environ["SECRET_KEY"]


async def validate_token(token: str) -> str:
    raise UnauthorizedError()


async def validate_session(username: str) -> str:
    return username


bearer = HTTPBearerAuth(validator=validate_token)
session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
admin = bearer.require(role="admin")

app = FastAPI()


@app.post("/login")
async def login(response: Response):
    session.set_cookie(response, "alice")
    return {"ok": True}


@app.get("/me")
async def me(username: str = Security(session)):
    return {"username": username}


@app.get("/admin")
async def admin_page(username: str = Security(admin)):
    return {"admin": username}
