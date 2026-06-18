"""API key query-string authentication source."""

from typing import Any, Callable

from fastapi import Request
from fastapi.security import APIKeyQuery

from ..abc import ValidatedAuthSource


class APIKeyQueryAuth(ValidatedAuthSource):
    """API key query-string authentication source (wraps ``APIKeyQuery`` for OpenAPI).

    The validator is called as ``await validator(api_key, **kwargs)``.

    .. warning::
        Credentials in the query string leak into access logs, browser history,
        and ``Referer`` headers. Prefer a header or cookie when you can; use this
        only for clients that cannot set headers.

    Args:
        name: Query parameter name that carries the API key (e.g. ``"api_key"``).
        validator: Sync or async callable returning the identity; raises
            :class:`~fastapi_multiauth.exceptions.UnauthorizedError` on failure.
        scheme_name: OpenAPI security scheme name (default ``APIKeyQuery_{name}``).
        **kwargs: Extra keyword arguments forwarded to the validator on every call.
    """

    def __init__(
        self,
        name: str,
        validator: Callable[..., Any],
        *,
        scheme_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._name = name
        super().__init__(
            validator,
            APIKeyQuery(
                name=name,
                auto_error=False,
                scheme_name=scheme_name or f"APIKeyQuery_{name}",
            ),
            **kwargs,
        )

    async def extract(self, request: Request) -> str | None:
        """Return the API key from the configured query parameter, or ``None`` when absent or empty."""
        return request.query_params.get(self._name) or None
