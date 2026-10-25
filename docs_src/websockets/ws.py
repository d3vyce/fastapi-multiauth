import os

from fastapi import FastAPI, Security, WebSocket

from fastapi_multiauth import APIKeyCookieAuth

SECRET_KEY = os.environ["SECRET_KEY"]


async def validate_session(username: str) -> str:
    return username


session = APIKeyCookieAuth(
    name="__Host-session",
    validator=validate_session,
    secret_key=SECRET_KEY,
    csrf=True,
    trusted_origins=["https://app.example.com"],
)

app = FastAPI()


@app.websocket("/ws")
async def ws(websocket: WebSocket, username: str = Security(session)):
    await websocket.accept()
    await websocket.send_json({"hello": username})
    await websocket.close()
