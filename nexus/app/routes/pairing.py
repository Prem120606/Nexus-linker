import io

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app import config
from app.deps import client_ip, laptop_only
from app.services import audit_service, auth_service, ratelimit
from app.services import pairing_service as ps

router = APIRouter(prefix="/api/pairing", tags=["pairing"])


class VerifyIn(BaseModel):
    token: str = Field(min_length=10, max_length=100)
    code: str = Field(pattern=r"^\d{6}$")
    device_name: str = Field(min_length=1, max_length=40)
    trusted: bool = False


class ClaimIn(BaseModel):
    token: str = Field(min_length=10, max_length=100)
    claim_key: str = Field(min_length=10, max_length=100)


def _session_or_410(token: str):
    s = ps.find(token)
    if s is None:
        raise HTTPException(410, "Pairing session expired or invalid")
    return s


def _too_many(ip: str):
    left = ratelimit.blocked_for("pair", ip)
    if left:
        raise HTTPException(429, f"Too many failed attempts. Try again in {int(left // 60) + 1} min")


@router.post("/start", dependencies=[Depends(laptop_only)])
def start():
    s = ps.start()
    audit_service.log("pairing_started", "Laptop")
    return {"code": s.code, "expires_in": ps.PAIRING_TTL}   # the token goes only inside the QR image


@router.get("/qr.png", dependencies=[Depends(laptop_only)])
def qr():
    s = ps.current()
    if s is None or s.state != "waiting":
        raise HTTPException(404, "No active pairing session")
    # The token sits after '#', so it is never sent to the server, never logged and never in Referer
    img = qrcode.make(f"{config.base_url()}/pair#t={s.token}")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(buf.getvalue(), media_type="image/png")


@router.post("/verify")
def verify(body: VerifyIn, request: Request):
    ip = client_ip(request)
    _too_many(ip)
    s = ps.find(body.token)
    if s is None:
        ratelimit.fail("pair", ip, 10, 600, 600)
        audit_service.log("pairing_bad_token", ip)
        raise HTTPException(410, "Pairing session expired or invalid")
    name = auth_service.clean_device_name(body.device_name)
    result, key = ps.verify(s, body.code, name, body.trusted)
    if result == "ok":
        audit_service.log("pairing_code_ok", name, f"ip={ip}")
        return {"state": "pending", "claim_key": key, "message": "Waiting for approval on the laptop"}
    ratelimit.fail("pair", ip, 10, 600, 600)
    if result == "wrong":
        audit_service.log("pairing_wrong_code", ip, f"attempt {s.attempts}/{ps.MAX_ATTEMPTS}")
        raise HTTPException(401, f"Wrong code. {ps.MAX_ATTEMPTS - s.attempts} attempts left")
    if result == "locked":
        audit_service.log("pairing_locked", ip, "too many wrong codes")
        raise HTTPException(429, "Too many attempts. Start a new pairing on the laptop")
    raise HTTPException(409, "This pairing session was already used")


@router.get("/pending", dependencies=[Depends(laptop_only)])
def pending():
    s = ps.current()
    if s is None:
        return {"state": "none"}
    return {"state": s.state, "device_name": s.device_name, "trusted": s.trusted, "attempts": s.attempts}


@router.post("/approve", dependencies=[Depends(laptop_only)])
def approve():
    s = ps.current()
    if s is None or s.state != "pending":
        raise HTTPException(409, "Nothing waiting for approval")
    s.state = "approved"
    audit_service.log("pairing_approved", "Laptop", s.device_name)
    return {"state": "approved"}


@router.post("/reject", dependencies=[Depends(laptop_only)])
def reject():
    s = ps.current()
    if s is None or s.state != "pending":
        raise HTTPException(409, "Nothing waiting for approval")
    s.state = "rejected"
    audit_service.log("pairing_rejected", "Laptop", s.device_name)
    return {"state": "rejected"}


@router.post("/claim")
def claim(body: ClaimIn, request: Request, response: Response):
    ip = client_ip(request)
    _too_many(ip)
    s = _session_or_410(body.token)
    if not ps.claim_ok(s, body.claim_key):          # only the phone that typed the code may claim
        ratelimit.fail("pair", ip, 10, 600, 600)
        audit_service.log("pairing_bad_claim", ip)
        raise HTTPException(403, "Not the device that entered the code")
    if s.state in ("waiting", "pending"):
        return {"state": s.state}
    if s.state == "rejected":
        raise HTTPException(403, "Pairing was rejected on the laptop")
    if s.state != "approved":
        raise HTTPException(409, "Pairing session no longer valid")
    s.state = "used"                                 # the token can never be claimed again
    token, ttl = auth_service.create_session(s.device_name, s.trusted, ip)
    response.set_cookie(
        config.COOKIE_NAME, token, max_age=ttl, path="/",
        httponly=True, samesite="strict", secure=config.USE_TLS,
    )
    return {"state": "approved", "device": s.device_name}
