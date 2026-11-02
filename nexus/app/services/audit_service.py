"""Tamper-evident security log.

Every row stores a MAC of (previous row's MAC + this row). Editing or deleting a row in the
middle of the log breaks the chain, and /api/security/audit reports it.
"""
import re
import threading
import time

from app.database.db import get_conn
from app.services import secrets_service

_lock = threading.Lock()
_CLEAN = re.compile(r"[\x00-\x1f\x7f]")


def _clean(text: str, limit: int) -> str:
    return _CLEAN.sub(" ", str(text))[:limit]


def log(event: str, actor: str = "", detail: str = "") -> None:
    """Never pass secrets (tokens, codes, cookies) in here."""
    event, actor, detail = _clean(event, 40), _clean(actor, 60), _clean(detail, 200)
    with _lock:
        conn = get_conn()
        try:
            row = conn.execute("SELECT mac FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["mac"] if row else "genesis"
            ts = time.time()
            mac = secrets_service.audit_mac(f"{prev}|{ts!r}|{event}|{actor}|{detail}")
            with conn:
                conn.execute(
                    "INSERT INTO audit (ts, event, actor, detail, prev, mac) VALUES (?,?,?,?,?,?)",
                    (ts, event, actor, detail, prev, mac))
        finally:
            conn.close()


def recent(limit: int = 40) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, ts, event, actor, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def verify(window: int = 500) -> dict:
    """Re-compute the chain for the newest `window` rows."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (window,)).fetchall()
    finally:
        conn.close()
    rows = list(reversed(rows))
    prev_mac = None
    for r in rows:
        expected = secrets_service.audit_mac(f"{r['prev']}|{r['ts']!r}|{r['event']}|{r['actor']}|{r['detail']}")
        if expected != r["mac"] or (prev_mac is not None and r["prev"] != prev_mac):
            return {"ok": False, "bad_id": r["id"], "checked": len(rows)}
        prev_mac = r["mac"]
    return {"ok": True, "bad_id": None, "checked": len(rows)}
