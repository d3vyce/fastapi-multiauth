"""OAuth 2.0 and OpenID Connect authentication sources.

These validate the bearer token an OAuth 2.0 or OIDC provider already issued.
They declare no flow of their own: the URLs and scope catalogue they carry are
OpenAPI metadata, which is what lets ``/docs`` offer a real Authorize dialog
with per-scope checkboxes. The login flow that mints those tokens lives in
:mod:`fastapi_multiauth.oauth`.
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
    """Bearer tokens issued by a password-grant token endpoint.

    Args:
        validator: Sync or async callable returning the identity.
        token_url: URL of the token endpoint, as advertised to OpenAPI.
        scopes: Catalogue of scope names mapped to their descriptions.
        scheme_name: OpenAPI security scheme name.
        description: Optional prose for the OpenAPI security scheme object.
        **kwargs: Extra keyword arguments forwarded to the validator.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        token_url: str,
        scopes: dict[str, str] | None = None,
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
            **kwargs,
        )


class OAuth2AuthorizationCodeBearerAuth(_BearerSource):
    """Bearer tokens issued by an authorization-code flow.

    Args:
        validator: Sync or async callable returning the identity.
        authorization_url: URL the Authorize dialog sends the user to.
        token_url: URL that exchanges the code for a token.
        refresh_url: Optional refresh endpoint.
        scopes: Catalogue of scope names mapped to their descriptions.
        scheme_name: OpenAPI security scheme name.
        description: Optional prose for the OpenAPI security scheme object.
        **kwargs: Extra keyword arguments forwarded to the validator.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        authorization_url: str,
        token_url: str,
        refresh_url: str | None = None,
        scopes: dict[str, str] | None = None,
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
            **kwargs,
        )


class OpenIdConnectAuth(_BearerSource):
    """Bearer tokens issued by an OpenID Connect provider.

    Args:
        validator: Sync or async callable returning the identity.
        openid_connect_url: The provider's ``.well-known`` discovery URL.
        scheme_name: OpenAPI security scheme name.
        description: Optional prose for the OpenAPI security scheme object.
        **kwargs: Extra keyword arguments forwarded to the validator.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        openid_connect_url: str,
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
            **kwargs,
        )
