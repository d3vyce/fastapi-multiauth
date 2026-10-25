import os

import pytest
import respx

os.environ.setdefault("SECRET_KEY", "docs-test-secret-key-of-32-bytes-or-more")
os.environ.setdefault("FLOW_SECRET_KEY", "docs-test-flow-key-of-32-bytes-or-more")
os.environ.setdefault("OIDC_CLIENT_SECRET", "my-app-secret")
os.environ.setdefault("METRICS_PASSWORD", "scraper-password")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "docs-test-webhook-secret")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_docs-test-stripe-secret")
os.environ.setdefault("SLACK_SIGNING_SECRET", "docs-test-slack-signing-secret")
os.environ.setdefault("INTROSPECTION_CLIENT_SECRET", "introspection-secret")

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
