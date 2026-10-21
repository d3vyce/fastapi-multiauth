from fastapi import FastAPI, Security, WebSocket

from fastapi_multiauth import APIKeyCookieAuth

SECRET_KEY = "change-me-please-32-bytes-minimum"


async def validate_session(username: str) -> str:
    return username


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)

app = FastAPI()


@app.websocket("/ws")
async def ws(websocket: WebSocket, username: str = Security(session)):
    await websocket.accept()
    await websocket.send_json({"hello": username})
    await websocket.close()
