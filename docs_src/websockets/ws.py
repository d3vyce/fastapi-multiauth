import os

from fastapi import FastAPI, Security, WebSocket

from fastapi_multiauth import APIKeyCookieAuth

SECRET_KEY = os.environ["SECRET_KEY"]
ALLOWED_ORIGINS = {"https://app.example.com"}


async def validate_session(username: str) -> str:
    return username


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)

app = FastAPI()


@app.websocket("/ws")
async def ws(websocket: WebSocket, username: str = Security(session)):
    if websocket.headers.get("origin") not in ALLOWED_ORIGINS:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await websocket.send_json({"hello": username})
    await websocket.close()
