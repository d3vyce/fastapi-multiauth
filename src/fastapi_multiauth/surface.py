"""Introspection of an application's authentication surface."""

import dataclasses
import itertools
from collections.abc import Iterable
from typing import Any

from fastapi import FastAPI, routing
from fastapi.security.base import SecurityBase

from .abc import AuthSource
from .sources import MultiAuth


@dataclasses.dataclass(frozen=True, slots=True)
class SchemeRequirement:
    """One authentication scheme a route accepts, with the scopes it checks.

    Args:
        scheme_name: OpenAPI security scheme name, ``None`` for a source
            carrying no ``fastapi.security`` scheme.
        source: Name of the class enforcing it, e.g. ``"HTTPBearerAuth"``.
        scopes: Scopes this scheme must check for the route, in declaration
            order.
        optional: Whether an absent credential is accepted. Always ``False``
            inside a required :class:`MultiAuth`, which rejects a
            credential-less request whatever its members declare.
    """

    scheme_name: str | None
    source: str
    scopes: tuple[str, ...]
    optional: bool


@dataclasses.dataclass(frozen=True, slots=True)
class RouteAuth:
    """What guards one route.

    Args:
        path: Full routed path, including any router prefix.
        methods: HTTP methods, sorted; empty for a WebSocket route.
        alternatives: Ways to satisfy the route. Entries are OR-ed, the schemes
            within one are AND-ed: a :class:`MultiAuth` contributes one entry
            per source, separate ``Security()`` dependencies share an entry.
            Empty when nothing guards the route.
        scopes: Every scope named on the route, first-seen order. An inventory
            for filtering, not a requirement: what one credential must carry is
            the scope list of the entry in ``alternatives`` it satisfies.
        unguarded: Whether a credential-less request reaches the endpoint. True
            for a route with no security dependency, and for one whose every
            AND-ed position offers an ``optional()`` alternative.
        include_in_schema: Whether the route appears in ``app.openapi()``.
            ``False`` for ``include_in_schema=False`` and for WebSocket routes.
    """

    path: str
    methods: tuple[str, ...]
    alternatives: tuple[tuple[SchemeRequirement, ...], ...]
    scopes: tuple[str, ...]
    unguarded: bool
    include_in_schema: bool


def _dedupe(scopes: Iterable[str]) -> tuple[str, ...]:
    """Drop repeats from *scopes*, keeping first-seen order."""
    return tuple(dict.fromkeys(scopes))


def _declared_scopes(dependant: Any) -> tuple[str, ...]:
    """Return the scopes reaching *dependant* from the route and its parents."""
    return _dedupe(
        (
            *(dependant.parent_oauth_scopes or ()),
            *(dependant.own_oauth_scopes or ()),
        )
    )


def _requirements(
    sources: Iterable[Any], scopes: tuple[str, ...], optional: bool
) -> tuple[SchemeRequirement, ...]:
    """Describe each of *sources* as a requirement carrying *scopes*."""
    return tuple(
        SchemeRequirement(
            scheme_name=getattr(source, "scheme_name", None),
            source=type(source).__name__,
            scopes=scopes,
            optional=optional,
        )
        for source in sources
    )


def _auth_units(dependant: Any) -> list[tuple[SchemeRequirement, ...]]:
    """Collect the groups of interchangeable schemes a request must satisfy."""
    units: list[tuple[SchemeRequirement, ...]] = []
    for sub in dependant.dependencies:
        call = sub.call
        scopes = _declared_scopes(sub)
        if isinstance(call, MultiAuth):
            units.append(_requirements(call._sources, scopes, call._optional))
            continue
        if isinstance(call, (AuthSource, SecurityBase)):
            units.append(
                _requirements((call,), scopes, getattr(call, "_optional", False))
            )
        units.extend(_auth_units(sub))
    return units


def _routes_of(app: FastAPI) -> Iterable[Any]:
    """Yield the app's routes, expanding the lazily included routers of 0.141+."""
    expand = getattr(routing, "iter_route_contexts", None)
    return expand(app.routes) if expand else app.routes


def auth_surface(app: FastAPI) -> list[RouteAuth]:
    """Report the authentication requirements of every route in *app*.

    Args:
        app: The application to inspect. A mounted sub-application is opaque,
            so call this on the sub-application as well.

    Returns:
        One :class:`RouteAuth` per routed endpoint, in registration order.
        WebSocket routes are included with no methods; routes carrying no
        dependency tree, such as ``/docs``, are skipped.
    """
    surface: list[RouteAuth] = []
    for route in _routes_of(app):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        units = list(dict.fromkeys(_auth_units(dependant)))
        alternatives = tuple(itertools.product(*units)) if units else ()
        surface.append(
            RouteAuth(
                path=getattr(route, "path", None) or "",
                methods=tuple(sorted(getattr(route, "methods", None) or ())),
                alternatives=alternatives,
                scopes=_dedupe(
                    scope for unit in units for req in unit for scope in req.scopes
                ),
                unguarded=all(any(req.optional for req in unit) for unit in units),
                include_in_schema=bool(getattr(route, "include_in_schema", False)),
            )
        )
    return surface
