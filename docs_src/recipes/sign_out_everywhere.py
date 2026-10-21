from typing import Annotated

from fastapi import FastAPI, Request, Response, Security

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = "change-me-please-32-bytes-minimum"
SESSIONS: dict[str, dict] = {}


async def validate_session(username: str, *, session_id: str) -> str:
    if session_id not in SESSIONS:
        raise UnauthorizedError()
    return username


session = APIKeyCookieAuth(
    "__Host-session",
    validate_session,
    secret_key=SECRET_KEY,
    session_id=True,
)
CurrentUser = Annotated[str, Security(session)]

app = FastAPI()


@app.post("/login")
async def login(username: str, request: Request, response: Response):
    session_id = session.set_cookie(response, username)
    assert session_id is not None
    SESSIONS[session_id] = {
        "username": username,
        "device": request.headers.get("user-agent", "unknown"),
    }
    return {"ok": True}


@app.get("/sessions")
async def list_sessions(request: Request, username: CurrentUser):
    current = session.session_id_of(request)
    return [
        {"device": row["device"], "current": session_id == current}
        for session_id, row in SESSIONS.items()
        if row["username"] == username
    ]


@app.post("/sessions/revoke-others")
async def revoke_others(request: Request, username: CurrentUser):
    current = session.session_id_of(request)
    for session_id, row in list(SESSIONS.items()):
        if row["username"] == username and session_id != current:
            del SESSIONS[session_id]
    return {"ok": True}


@app.post("/logout")
async def logout(request: Request, response: Response):
    session_id = session.delete_cookie(response, request)
    SESSIONS.pop(session_id or "", None)
    return {"ok": True}
