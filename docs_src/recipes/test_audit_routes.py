from fastapi_multiauth import auth_surface

from .sessions_and_tokens import app

PUBLIC = {"/login"}


def test_no_unguarded_routes():
    unguarded = [
        f"{','.join(route.methods) or 'WS'} {route.path}"
        for route in auth_surface(app)
        if route.unguarded and route.path not in PUBLIC
    ]
    assert not unguarded, unguarded
