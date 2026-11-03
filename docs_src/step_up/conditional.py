import os
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Security
from pydantic import BaseModel

from fastapi_multiauth import (
    APIKeyCookieAuth,
    ForbiddenError,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
)

SECRET_KEY = os.environ["SECRET_KEY"]
ROLES = {"alice": "admin", "bob": "member"}
TOKENS = {"deploy-token": "alice"}
SESSIONS = {"alice": {"laptop", "phone"}, "bob": {"laptop"}}


async def validate_session(value: str) -> str:
    if value not in ROLES:
        raise UnauthorizedError()
    return value


async def validate_token(token: str) -> str:
    username = TOKENS.get(token)
    if username is None:
        raise UnauthorizedError()
    return username


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
auth = MultiAuth(HTTPBearerAuth(validate_token), session)
CurrentUser = Annotated[str, Security(auth)]
SessionUser = Annotated[str, Security(session)]

app = FastAPI()


class RoleChange(BaseModel):
    username: str
    role: str


@app.post("/users/role")
async def change_role(body: RoleChange, request: Request, username: CurrentUser):
    if ROLES[username] != "admin":
        raise ForbiddenError()
    if body.role == "admin" and session.authenticated(request):
        await session.ensure_fresh(request, max_age=300)
    ROLES[body.username] = body.role
    return {"ok": True}


@app.delete("/me/sessions")
async def sign_out_everywhere(
    username: SessionUser, _: None = Depends(session.fresh_guard(max_age=300))
):
    SESSIONS.pop(username, None)
    return {"ok": True}
