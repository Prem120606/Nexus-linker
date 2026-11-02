from fastapi import HTTPException, Request
from starlette.requests import HTTPConnection

from app.services import auth_service

LOOPBACK = {"127.0.0.1", "::1"}


def client_ip(conn: HTTPConnection) -> str:
    return conn.client.host if conn.client else ""


def is_laptop(conn: HTTPConnection) -> bool:
    return client_ip(conn) in LOOPBACK


def laptop_only(request: Request):
    """Only a program running on the laptop itself (127.0.0.1) may call this."""
    if not is_laptop(request):
        raise HTTPException(403, "Only allowed on the laptop itself")


def caller(request: Request):
    """Who is calling: the laptop, or a paired phone. Anyone else gets 401."""
    if is_laptop(request):
        return {"side": "laptop", "name": "Laptop", "id": None}
    device = auth_service.require_device(request)
    return {"side": "phone", "name": device["name"], "id": device["id"]}
