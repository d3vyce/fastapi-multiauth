from typing import Annotated

from fastapi import FastAPI, Security

from fastapi_multiauth import APIKeyCookieAuth, ForbiddenError, UnauthorizedError

SECRET_KEY = "change-me-please-32-bytes-minimum"
ROLES = {"alice": "admin", "bob": "member"}


async def validate_session(username: str, *, role: str | None = None) -> str:
    if username not in ROLES:
        raise UnauthorizedError()
    if role is not None and ROLES[username] != role:
        raise ForbiddenError()  # signed in, but not allowed: 403
    return username


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)

CurrentUser = Annotated[str, Security(session)]
AdminUser = Annotated[str, Security(session.require(role="admin"))]

app = FastAPI()


@app.get("/me")
async def me(username: CurrentUser):
    return {"username": username}


@app.get("/admin/stats")
async def stats(username: AdminUser):
    return {"users": len(ROLES)}
