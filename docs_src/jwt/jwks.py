from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBearerAuth, JWTValidator

ISSUER = "https://idp.example.com/realms/main"

bearer = HTTPBearerAuth(
    validator=JWTValidator(
        jwks_url=f"{ISSUER}/protocol/openid-connect/certs",
        audience="my-api",
        issuer=ISSUER,
    ),
    bearer_format="JWT",
)

app = FastAPI()


@app.get("/me")
async def me(claims: dict = Security(bearer)):
    return {"sub": claims["sub"]}
