from fastapi import FastAPI, Security

from fastapi_multiauth import JWTValidator, OAuth2AuthorizationCodeBearerAuth

ISSUER = "https://idp.example.com/realms/main"

auth = OAuth2AuthorizationCodeBearerAuth(
    validator=JWTValidator(
        jwks_url=f"{ISSUER}/protocol/openid-connect/certs",
        audience="my-api",
        issuer=ISSUER,
    ),
    authorization_url=f"{ISSUER}/protocol/openid-connect/auth",
    token_url=f"{ISSUER}/protocol/openid-connect/token",
    scopes={"invoices:read": "Read invoices"},
)

app = FastAPI()


@app.get("/invoices")
async def invoices(claims: dict = Security(auth, scopes=["invoices:read"])):
    return {"sub": claims["sub"], "invoices": []}
