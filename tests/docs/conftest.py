import pytest
import respx

from . import idp


@pytest.fixture
def provider():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(idp.REALM_JWKS_URL).respond(json=idp.jwks())
        mock.get(idp.OIDC_JWKS_URL).respond(json=idp.jwks())
        mock.get(f"{idp.ISSUER}/.well-known/openid-configuration").respond(
            json=idp.discovery()
        )
        yield mock
