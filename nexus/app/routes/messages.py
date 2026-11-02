import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.database.db import get_conn
from app.deps import caller
from app.services import ratelimit, secrets_service
from app.services.live_service import manager

router = APIRouter(prefix="/api/messages", tags=["messages"])

_version = str(time.time_ns())   # changes whenever history is cleared


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@router.post("")
async def send(body: MessageIn, who=Depends(caller)):
    text = body.text.strip()
    if not text:
        return {"sent": False}
    if not ratelimit.allow("msg", str(who["id"] or "laptop"), 30, 10):
        raise HTTPException(429, "Sending too fast")
    now = time.time()
    conn = get_conn()
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO messages (side, sender, body, created_at) VALUES (?, ?, ?, ?)",
                (who["side"], who["name"], secrets_service.encrypt(text), now))   # encrypted at rest
            new_id = cur.lastrowid
    finally:
        conn.close()
    await manager.broadcast({"type": "message", "message": {
        "id": new_id, "side": who["side"], "sender": who["name"], "body": text, "created_at": now}})
    return {"sent": True}


@router.get("")
def history(after_id: int = 0, who=Depends(caller)):
    conn = get_conn()
    try:
        if after_id == 0:
            rows = conn.execute(
                "SELECT * FROM (SELECT * FROM messages ORDER BY id DESC LIMIT 100) ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM messages WHERE id > ? ORDER BY id LIMIT 200", (after_id,)).fetchall()
    finally:
        conn.close()
    msgs = [{**dict(r), "body": secrets_service.decrypt(r["body"])} for r in rows]
    return {"me": who["side"], "version": _version, "messages": msgs}


@router.delete("")
async def clear(who=Depends(caller)):
    global _version
    conn = get_conn()
    try:
        with conn:
            conn.execute("DELETE FROM messages")
    finally:
        conn.close()
    _version = str(time.time_ns())
    await manager.broadcast({"type": "cleared", "version": _version})
    return {"cleared": True, "version": _version}
