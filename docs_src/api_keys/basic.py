import os
import secrets

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBasicAuth, UnauthorizedError

METRICS_PASSWORD = os.environ["METRICS_PASSWORD"]


async def validate_basic(username: str, password: str) -> str:
    username_ok = secrets.compare_digest(username.encode(), b"prometheus")
    password_ok = secrets.compare_digest(password.encode(), METRICS_PASSWORD.encode())
    if not (username_ok and password_ok):
        raise UnauthorizedError()
    return username


basic = HTTPBasicAuth(validator=validate_basic, realm="metrics")

app = FastAPI()


@app.get("/metrics")
async def metrics(username: str = Security(basic)):
    return {"scraped_by": username}
