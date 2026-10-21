import secrets

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBasicAuth, UnauthorizedError

METRICS_PASSWORD = "scraper-password"


async def validate_basic(username: str, password: str) -> str:
    if username != "prometheus" or not secrets.compare_digest(
        password, METRICS_PASSWORD
    ):
        raise UnauthorizedError()
    return username


basic = HTTPBasicAuth(validate_basic, realm="metrics")

app = FastAPI()


@app.get("/metrics")
async def metrics(username: str = Security(basic)):
    return {"scraped_by": username}
