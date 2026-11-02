from fastapi import APIRouter, Depends

from app import config
from app.deps import laptop_only
from app.services import audit_service, tls_service

router = APIRouter(prefix="/api/security", tags=["security"], dependencies=[Depends(laptop_only)])


@router.get("/info")
def info():
    ip = config.get_local_ip()
    return {
        "tls": config.USE_TLS,
        "address": config.base_url(),
        "setup_url": f"{config.base_url()}/setup" if config.USE_TLS else "",
        "ca_fingerprint": tls_service.ca_fingerprint() if config.USE_TLS else "",
        "audit": audit_service.verify(),
    }


@router.get("/audit")
def audit():
    return audit_service.recent(40)
