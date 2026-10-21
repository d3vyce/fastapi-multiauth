from fastapi import FastAPI, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = "change-me-please-32-bytes-minimum"
USERS = {"alice": {"id": "1", "name": "alice", "password": "wonderland"}}


async def validate_session(user_id: str) -> dict:
    for user in USERS.values():
        if user["id"] == user_id:
            return {"id": user["id"], "name": user["name"]}
    raise UnauthorizedError()


class Credentials(BaseModel):
    username: str
    password: str


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)

app = FastAPI()


@app.post("/login")
async def login(credentials: Credentials, response: Response):
    user = USERS.get(credentials.username)
    if user is None or user["password"] != credentials.password:
        raise UnauthorizedError()
    session.set_cookie(response, user["id"])
    return {"ok": True}


@app.post("/logout")
async def logout(response: Response):
    session.delete_cookie(response)
    return {"ok": True}


@app.get("/me")
async def me(user: dict = Security(session)):
    return user
