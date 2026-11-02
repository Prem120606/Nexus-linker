import re
import secrets
import time

from fastapi import HTTPException, Request

from app import config
from app.database.db import get_conn
from app.services import audit_service, secrets_service

TEMP_SESSION_SECONDS = 8 * 3600             # 8 hours
TRUSTED_SESSION_SECONDS = 30 * 24 * 3600    # 30 days
_NAME_CLEAN = re.compile(r"[\x00-\x1f\x7f<>]")


def clean_device_name(name: str) -> str:
    return _NAME_CLEAN.sub("", name).strip()[:40] or "My Phone"


def create_session(name: str, trusted: bool, ip: str):
    """Make a new login. Returns (cookie value, lifetime in seconds)."""
    now = time.time()
    conn = get_conn()
    try:
        active = conn.execute("SELECT COUNT(*) FROM devices WHERE revoked = 0 AND expires_at > ?",
                              (now,)).fetchone()[0]
        if active >= config.MAX_DEVICES:
            raise HTTPException(409, "Too many paired devices. Revoke one on the laptop first")
        token = secrets.token_urlsafe(32)                    # 256 bits of randomness
        ttl = TRUSTED_SESSION_SECONDS if trusted else TEMP_SESSION_SECONDS
        with conn:
            conn.execute(
                "INSERT INTO devices (name, session_hash, trusted, created_at, expires_at, last_seen, last_ip) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, secrets_service.session_hash(token), int(trusted), now, now + ttl, now, ip))
    finally:
        conn.close()
    audit_service.log("device_paired", name, f"trusted={trusted} ip={ip}")
    return token, ttl


def find_device(token: str | None, ip: str | None = None):
    """Look up a session cookie. Returns the device row, or None. (Also used by WebSockets.)"""
    if not token or len(token) > 100:
        return None
    now = time.time()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM devices WHERE session_hash = ? AND revoked = 0 AND expires_at > ?",
            (secrets_service.session_hash(token), now)).fetchone()
        if row is not None and ip and (now - (row["last_seen"] or 0) > 60 or row["last_ip"] != ip):
            with conn:
                conn.execute("UPDATE devices SET last_seen = ?, last_ip = ? WHERE id = ?", (now, ip, row["id"]))
            if row["last_ip"] and row["last_ip"] != ip:
                audit_service.log("device_ip_changed", row["name"], f"{row['last_ip']} -> {ip}")
    finally:
        conn.close()
    return row


def require_device(request: Request):
    """Dependency: the lock on every protected route."""
    ip = request.client.host if request.client else None
    row = find_device(request.cookies.get(config.COOKIE_NAME), ip)
    if row is None:
        raise HTTPException(401, "Not paired, or the session ended")
    return row
