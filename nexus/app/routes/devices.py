import time

from fastapi import APIRouter, Depends, HTTPException, Response

from app import config
from app.database.db import get_conn
from app.deps import laptop_only
from app.services import audit_service, auth_service, transfer_service
from app.services.live_service import manager

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", dependencies=[Depends(laptop_only)])
def list_devices():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, name, trusted, created_at, expires_at, last_seen, last_ip FROM devices "
            "WHERE revoked = 0 AND expires_at > ? ORDER BY created_at DESC",
            (time.time(),),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@router.post("/{device_id}/revoke", dependencies=[Depends(laptop_only)])
async def revoke(device_id: int):
    conn = get_conn()
    try:
        row = conn.execute("SELECT name FROM devices WHERE id = ?", (device_id,)).fetchone()
        with conn:
            cur = conn.execute("UPDATE devices SET revoked = 1 WHERE id = ?", (device_id,))
    finally:
        conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "Device not found")
    transfer_service.cancel_device(device_id)
    await manager.kick(device_id)                  # cut the live connection right now
    audit_service.log("device_revoked", "Laptop", row["name"] if row else str(device_id))
    return {"revoked": device_id}


@router.post("/disconnect")                        # a phone disconnecting ITSELF
async def disconnect(response: Response, device=Depends(auth_service.require_device)):
    conn = get_conn()
    try:
        with conn:
            conn.execute("UPDATE devices SET revoked = 1 WHERE id = ?", (device["id"],))
    finally:
        conn.close()
    transfer_service.cancel_device(device["id"])
    await manager.kick(device["id"])
    response.delete_cookie(config.COOKIE_NAME, path="/", secure=config.USE_TLS, httponly=True, samesite="strict")
    audit_service.log("device_disconnected", device["name"])
    return {"disconnected": True}
