import hashlib
import logging
import shutil
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from app.config import (AUTO_APPROVE_TRUSTED, MAX_UPLOAD_BYTES, MIN_FREE_BYTES, SHARE_DIR, UPLOAD_DIR)
from app.database.db import get_conn
from app.deps import caller, laptop_only
from app.services import audit_service, auth_service, file_service
from app.services import transfer_service as ts
from app.services.live_service import manager

router = APIRouter(prefix="/api/files", tags=["files"])
log = logging.getLogger("nexus")

BAD_NAME_CHARS = set('<>:"/\\|?*')
BLOCK = 4 * 1024 * 1024


def _check_space(folder, size):
    folder.mkdir(parents=True, exist_ok=True)
    if size and size + MIN_FREE_BYTES > shutil.disk_usage(folder).free:
        raise HTTPException(507, "Not enough free disk space on the laptop")


def _write_block(f, h, data: bytes):
    f.write(data)
    h.update(data)


async def _save_stream(request: Request, folder, who_name, direction, tr=None,
                       limit=MAX_UPLOAD_BYTES, check_type=True):
    if tr is not None:
        name = tr.name                          # cleaned when the request was made
    else:
        raw = request.headers.get("x-filename", "")
        if not raw:
            raise HTTPException(400, "Missing file name")
        name = file_service.clean_filename(raw)
    if check_type and file_service.is_blocked(name):
        raise HTTPException(415, "This file type is blocked for safety")

    declared = request.headers.get("content-length", "")
    declared_size = int(declared) if declared.isdigit() else 0
    if declared_size > limit:
        raise HTTPException(413, "File larger than allowed")
    _check_space(folder, declared_size)

    try:
        final, part, f = file_service.start_file(name, folder)
    except Exception:
        log.exception("Could not create the destination file")
        raise HTTPException(500, "Server could not create the file")

    if tr is not None:
        tr.state, tr.started = "uploading", time.time()
        await manager.to_side("laptop", {"type": "transfers"})

    size, error, cancelled = 0, None, False
    buf, digest = bytearray(), hashlib.sha256()
    last_push = 0.0
    try:
        async for chunk in request.stream():
            if tr is not None and tr.cancel_by:
                error, cancelled = (409, f"Cancelled by {tr.cancel_by}"), True
                break
            size += len(chunk)
            if size > limit:                    # counted, not declared
                error = (413, "File larger than approved")
                break
            buf += chunk
            if len(buf) >= BLOCK:
                await run_in_threadpool(_write_block, f, digest, bytes(buf))
                buf.clear()
            if tr is not None:
                tr.received = size
                now = time.monotonic()
                if now - last_push > 0.5:
                    last_push = now
                    await manager.to_side("laptop", {"type": "transfers"})
        if buf and error is None:
            await run_in_threadpool(_write_block, f, digest, bytes(buf))
    except ClientDisconnect:
        error, cancelled = (409, "Cancelled"), True
    except Exception:
        log.exception("Transfer failed")
        error = (500, "Transfer interrupted or disk problem")
    finally:
        f.close()

    if error is None and size == 0:
        error = (400, "Empty file")

    if error:
        file_service.abort_file(final, part)    # never keep partial files
        status = "cancelled" if cancelled else "failed"
        file_service.record_transfer(who_name, direction, name, size, status)
        audit_service.log(f"file_{status}", who_name, f"{direction} {name[:80]}")
        if tr is not None:
            tr.state, tr.message = status, error[1]
        await manager.to_side("laptop", {"type": "transfers"})
        raise HTTPException(*error)

    file_service.finish_file(final, part)
    sha = digest.hexdigest()
    file_service.record_transfer(who_name, direction, final.name, size, "completed", sha)
    audit_service.log("file_completed", who_name, f"{direction} {final.name[:80]} sha256={sha[:16]}")
    if tr is not None:
        tr.state, tr.received = "done", size
    await manager.broadcast({"type": "files", "direction": direction, "name": final.name, "size": size})
    await manager.to_side("laptop", {"type": "transfers"})
    return {"saved_as": final.name, "size": size, "sha256": sha}


# ---------- phone -> laptop (needs an APPROVED transfer) ----------
class RequestIn(BaseModel):
    name: str = Field(min_length=1, max_length=600)
    size: int = Field(gt=0)


@router.post("/request")
async def request_transfer(body: RequestIn, device=Depends(auth_service.require_device)):
    if body.size > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (limit {MAX_UPLOAD_BYTES // 2**30} GB)")
    name = file_service.clean_filename(body.name)
    if file_service.is_blocked(name):
        audit_service.log("file_type_blocked", device["name"], name[:80])
        raise HTTPException(415, "This file type is blocked for safety")
    _check_space(UPLOAD_DIR, body.size)
    if ts.pending_count(device["id"]) >= 25 or ts.pending_count() >= 100:
        raise HTTPException(429, "Too many files waiting for approval")
    auto = AUTO_APPROVE_TRUSTED and bool(device["trusted"])
    tr = ts.create(device["id"], device["name"], name, body.size, auto)
    await manager.to_side("laptop", {"type": "transfers"})
    return {"id": tr.id, "state": tr.state}


@router.post("/upload")
async def upload(request: Request, tid: str, device=Depends(auth_service.require_device)):
    tr = ts.get(tid)
    if tr is None or tr.device_id != device["id"]:
        raise HTTPException(404, "Unknown transfer")
    if tr.state != "approved":
        raise HTTPException(409, f"Transfer is {tr.state}")
    return await _save_stream(request, UPLOAD_DIR, device["name"], "upload", tr, tr.size)


@router.get("/transfers/{tid}")
def transfer_status(tid: str, device=Depends(auth_service.require_device)):
    tr = ts.get(tid)
    if tr is None or tr.device_id != device["id"]:
        raise HTTPException(404, "Unknown transfer")
    return ts.public(tr)


@router.get("/transfers", dependencies=[Depends(laptop_only)])
def transfers():
    return ts.active()


class DecideIn(BaseModel):
    approve: bool


@router.post("/transfers/{tid}/decide", dependencies=[Depends(laptop_only)])
async def decide(tid: str, body: DecideIn):
    tr = ts.get(tid)
    if tr is None or tr.state != "pending":
        raise HTTPException(409, "Nothing to decide")
    tr.state = "approved" if body.approve else "rejected"
    audit_service.log("file_approved" if body.approve else "file_rejected", tr.device_name, tr.name[:80])
    await manager.to_side("laptop", {"type": "transfers"})
    return ts.public(tr)


async def _cancel(tid, by, device_id=None):
    tr = ts.get(tid)
    if tr is None or (device_id is not None and tr.device_id != device_id):
        raise HTTPException(404, "Unknown transfer")
    if tr.state in ("pending", "approved"):
        tr.state = "cancelled"
    elif tr.state == "uploading":
        tr.cancel_by = by
    await manager.to_side("laptop", {"type": "transfers"})
    return ts.public(tr)


@router.post("/transfers/{tid}/cancel", dependencies=[Depends(laptop_only)])
async def cancel_by_laptop(tid: str):
    return await _cancel(tid, "laptop")


@router.post("/transfers/{tid}/abort")
async def abort_by_phone(tid: str, device=Depends(auth_service.require_device)):
    return await _cancel(tid, "phone", device["id"])


# ---------- laptop -> phone ----------
@router.post("/share", dependencies=[Depends(laptop_only)])
async def share(request: Request):
    return await _save_stream(request, SHARE_DIR, "Laptop", "share", check_type=False)


@router.get("/limits")
def limits(who=Depends(caller)):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    return {"max": MAX_UPLOAD_BYTES, "free": shutil.disk_usage(UPLOAD_DIR).free}


@router.get("/shared")
def shared(who=Depends(caller)):
    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in SHARE_DIR.iterdir():
        if p.is_file() and not p.is_symlink() and not p.name.startswith("."):
            st = p.stat()
            if st.st_size > 0:                       # a 0-byte file is a transfer still in progress
                items.append({"name": p.name, "size": st.st_size, "modified": st.st_mtime})
    items.sort(key=lambda x: x["modified"], reverse=True)
    out = {"files": items[:200]}
    if who["side"] == "laptop":
        out["folder"] = str(SHARE_DIR)               # the phone never sees real paths
    return out


@router.get("/download/{name}")
def download(name: str, device=Depends(auth_service.require_device)):
    if not name or name.startswith(".") or any(c in BAD_NAME_CHARS for c in name):
        raise HTTPException(404, "File not found")
    root = SHARE_DIR.resolve()
    candidate = root / name
    if candidate.is_symlink():
        raise HTTPException(404, "File not found")
    path = candidate.resolve()
    if path.parent != root or not path.is_file() or path.stat().st_size == 0:
        raise HTTPException(404, "File not found")
    return FileResponse(
        path, media_type="application/octet-stream", filename=path.name,
        content_disposition_type="attachment",
        background=BackgroundTask(
            file_service.record_transfer,
            device["name"], "download", path.name, path.stat().st_size, "completed"),
    )


@router.get("/history")
def history(who=Depends(caller)):
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM transfers ORDER BY id DESC LIMIT 50").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]
