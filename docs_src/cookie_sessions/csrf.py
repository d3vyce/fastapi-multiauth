import os

from fastapi import FastAPI, Security
from pydantic import BaseModel

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = os.environ["SECRET_KEY"]
USERS = {"1": {"id": "1", "email": "alice@example.com"}}


class Email(BaseModel):
    email: str


async def validate_session(user_id: str) -> dict:
    if user_id not in USERS:
        raise UnauthorizedError()
    return USERS[user_id]


session = APIKeyCookieAuth(
    name="__Host-session",
    validator=validate_session,
    secret_key=SECRET_KEY,
    csrf=True,
    trusted_origins=["https://app.example.com"],
)

app = FastAPI()


@app.post("/me/email")
async def change_email(body: Email, user: dict = Security(session)):
    user["email"] = body.email
    return user
