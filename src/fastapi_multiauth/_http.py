"""Shared HTTP transport hygiene for the OAuth and JWT modules."""

import json
from typing import Any
from urllib.parse import urlsplit

import httpx

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

DEFAULT_TIMEOUT = 10.0
"""Default timeout (seconds) applied to every HTTP call made by this library."""


def _require_https(url: str, description: str) -> str:
    """Reject non-string URLs and URLs that would send credentials over plaintext HTTP."""
    if not isinstance(url, str):
        raise ValueError(f"{description} must be a string URL (got {url!r})")
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and parsed.hostname in _LOOPBACK_HOSTS:
        return url
    raise ValueError(f"{description} must use https:// (got {url!r})")


async def _get_json(
    url: str,
    *,
    timeout: float,
    error_cls: type[Exception],
    description: str,
    headers: dict[str, str] | None = None,
) -> Any:
    """GET *url* and decode the JSON body, mapping failures to *error_cls*."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise error_cls(f"failed to fetch {description}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise error_cls(f"{description} is not valid JSON") from exc
