from fastapi import FastAPI, Request, Response, Security

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = "change-me-please-32-bytes-minimum"
REVOKED: set[str] = set()


async def validate_session(user_id: str, *, session_id: str) -> dict:
    if session_id in REVOKED:
        raise UnauthorizedError()
    return {"id": user_id}


session = APIKeyCookieAuth(
    "__Host-session",
    validate_session,
    secret_key=SECRET_KEY,
    session_id=True,
)

app = FastAPI()


@app.post("/login")
async def login(response: Response):
    session_id = session.set_cookie(response, "1")
    return {"session_id": session_id}


@app.post("/logout")
async def logout(request: Request, response: Response):
    session_id = session.delete_cookie(response, request)
    if session_id:
        REVOKED.add(session_id)
    return {"ok": True}


@app.get("/me")
async def me(user: dict = Security(session)):
    return user
