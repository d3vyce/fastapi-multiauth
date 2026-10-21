from fastapi import FastAPI

from fastapi_multiauth import auth_surface


def print_surface(app: FastAPI) -> None:
    for route in auth_surface(app):
        methods = ",".join(route.methods) or "WS"
        flag = "UNGUARDED" if route.unguarded else ""
        print(f"{methods:8} {route.path:30} {flag}")
