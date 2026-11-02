"""Security gate that every request and WebSocket passes through BEFORE any route runs.

Blocks: traffic from outside the local network, DNS-rebinding (wrong Host header),
cross-site requests (CSRF), oversized bodies, request floods, and adds protective headers.
"""
import ipaddress
import logging
from urllib.parse import urlparse

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse

from app import config
from app.services import ratelimit

access_log = logging.getLogger("nexus.access")

UPLOAD_PATHS = {"/api/files/upload", "/api/files/share"}     # the only routes allowed big/streamed bodies
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

API_CSP = "default-src 'none'; frame-ancestors 'none'"
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()",
}


def host_allowed(host_header: str) -> bool:
    h = host_header.strip().lower()
    bare = h
    if bare.startswith("["):
        bare = bare[1:].split("]")[0]
    elif bare.count(":") == 1:
        bare = bare.split(":")[0]
    try:
        ipaddress.ip_address(bare)
        return config.ip_allowed(bare)
    except ValueError:
        return bare in config.ALLOWED_HOSTNAMES


class SecurityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        peer = scope["client"][0] if scope.get("client") else ""
        headers = Headers(scope=scope)
        is_ws = scope["type"] == "websocket"

        async def reject(status: int, detail: str, extra=None):
            if is_ws:
                await send({"type": "websocket.close", "code": 4403})
            else:
                resp = JSONResponse({"detail": detail}, status_code=status, headers=extra or {})
                await resp(scope, receive, wrap_send)

        status_box = {"code": 0}

        async def wrap_send(message):
            if message["type"] == "http.response.start":
                status_box["code"] = message["status"]
                h = MutableHeaders(scope=message)
                for k, v in BASE_HEADERS.items():
                    h.setdefault(k, v)
                path = scope["path"]
                if path.startswith("/api/"):
                    h.setdefault("Cache-Control", "no-store")
                    h.setdefault("Content-Security-Policy", API_CSP)
                elif path.startswith("/static/"):
                    h.setdefault("Cache-Control", "no-cache")
                else:
                    h.setdefault("Cache-Control", "no-store")
            await send(message)

        # 1) Only the local network may talk to us
        if not config.ip_allowed(peer):
            access_log.warning("blocked outside address %s", peer)
            return await reject(403, "Forbidden")

        # 2) Host header must be our own address or name (DNS-rebinding defense)
        if not host_allowed(headers.get("host", "")):
            access_log.warning("blocked bad Host header from %s", peer)
            return await reject(400, "Bad host")

        path = scope["path"]
        method = scope.get("method", "GET")
        loopback = peer in ("127.0.0.1", "::1")

        # 3) Flood protection per client address (the laptop itself is exempt)
        if not loopback and not ratelimit.allow("ip", peer, config.RATE_LIMIT_PER_MIN, 60):
            return await reject(429, "Too many requests. Slow down", {"Retry-After": "30"})

        if not is_ws:
            # 4) Cross-site request forgery: a web page on another site must not trigger actions
            if method in UNSAFE:
                origin = headers.get("origin")
                if origin and urlparse(origin).netloc.lower() != headers.get("host", "").lower():
                    return await reject(403, "Cross-origin request blocked")
                if headers.get("sec-fetch-site", "") == "cross-site":
                    return await reject(403, "Cross-site request blocked")

            # 5) Body size: only file transfers may be big; everything else is tiny
            if method in UNSAFE and path not in UPLOAD_PATHS:
                if "transfer-encoding" in headers:
                    return await reject(411, "Length required")
                cl = headers.get("content-length", "0")
                if not cl.isdigit() or int(cl) > config.JSON_BODY_LIMIT:
                    return await reject(413, "Request too large")

        async def logged_send(message):
            await wrap_send(message)
            if message["type"] == "http.response.start":
                code = status_box["code"]
                if code >= 400 or method in UNSAFE:     # path only, never the query string
                    access_log.info("%s %s %s -> %s", peer, method, path, code)

        await self.app(scope, receive, logged_send if not is_ws else send)
