"""OAuth 2.0 and OpenID Connect authentication sources.

These validate the bearer token an OAuth 2.0 or OIDC provider already issued.
They declare no flow of their own: the URLs and scope catalogue they carry are
OpenAPI metadata, which is what lets `/docs` offer a real Authorize dialog
with per-scope checkboxes. The login flow that mints those tokens lives in
`fastapi_multiauth.oauth`.
"""

from collections.abc import Callable
from typing import Any

from fastapi.security import (
    OAuth2AuthorizationCodeBearer,
    OAuth2PasswordBearer,
    OpenIdConnect,
)

from .bearer import _BearerSource


class OAuth2PasswordBearerAuth(_BearerSource):
    """Authentication source for bearer tokens from a password-grant endpoint.

    The URL and scopes only describe the flow in OpenAPI.

    Args:
        validator: Sync or async callable returning the identity, or raising to refuse.
        token_url: URL of the token endpoint.
        scopes: Available scopes mapped to their descriptions. A route
            declaring a scope outside this catalogue is refused.
        allow_dpop_bound: Accept a DPoP-bound token (`cnf.jkt`) without its proof.
        scheme_name: Name of the security scheme in OpenAPI, `OAuth2PasswordBearer` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        token_url: str,
        scopes: dict[str, str] | None = None,
        allow_dpop_bound: bool = False,
        scheme_name: str | None = None,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._scope_catalogue = scopes
        super().__init__(
            validator,
            OAuth2PasswordBearer(
                tokenUrl=token_url,
                scopes=scopes,
                scheme_name=scheme_name,
                description=description,
                auto_error=False,
            ),
            allow_dpop_bound=allow_dpop_bound,
            **kwargs,
        )


class OAuth2AuthorizationCodeBearerAuth(_BearerSource):
    """Authentication source for bearer tokens from an authorization-code flow.

    The URLs and scopes only describe the flow in OpenAPI, which gives
    `/docs` a working Authorize dialog.

    Args:
        validator: Sync or async callable returning the identity, or raising to refuse.
        authorization_url: URL of the provider's authorization endpoint.
        token_url: URL of the provider's token endpoint.
        refresh_url: URL of the provider's refresh endpoint, if any.
        scopes: Available scopes mapped to their descriptions. A route
            declaring a scope outside this catalogue is refused.
        allow_dpop_bound: Accept a DPoP-bound token (`cnf.jkt`) without its proof.
        scheme_name: Name of the security scheme in OpenAPI, `OAuth2AuthorizationCodeBearer` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        authorization_url: str,
        token_url: str,
        refresh_url: str | None = None,
        scopes: dict[str, str] | None = None,
        allow_dpop_bound: bool = False,
        scheme_name: str | None = None,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._scope_catalogue = scopes
        super().__init__(
            validator,
            OAuth2AuthorizationCodeBearer(
                authorizationUrl=authorization_url,
                tokenUrl=token_url,
                refreshUrl=refresh_url,
                scopes=scopes,
                scheme_name=scheme_name,
                description=description,
                auto_error=False,
            ),
            allow_dpop_bound=allow_dpop_bound,
            **kwargs,
        )


class OpenIdConnectAuth(_BearerSource):
    """Authentication source for bearer tokens from an OpenID Connect provider.

    `/docs` reads the flow from the provider's discovery document.

    Args:
        validator: Sync or async callable returning the identity, or raising to refuse.
        openid_connect_url: URL of the provider's discovery document.
        allow_dpop_bound: Accept a DPoP-bound token (`cnf.jkt`) without its proof.
        scheme_name: Name of the security scheme in OpenAPI, `OpenIdConnect` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        openid_connect_url: str,
        allow_dpop_bound: bool = False,
        scheme_name: str | None = None,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            validator,
            OpenIdConnect(
                openIdConnectUrl=openid_connect_url,
                scheme_name=scheme_name,
                description=description,
                auto_error=False,
            ),
            allow_dpop_bound=allow_dpop_bound,
            **kwargs,
        )
