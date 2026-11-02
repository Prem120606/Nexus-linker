import secrets
import time
from dataclasses import dataclass, field

PENDING_TTL = 120        # seconds the laptop has to answer
KEEP_FINISHED = 600
LIVE = ("pending", "approved", "uploading")


@dataclass
class Transfer:
    id: str
    device_id: int
    device_name: str
    name: str
    size: int
    state: str
    created: float = field(default_factory=time.time)
    started: float = 0.0
    received: int = 0
    cancel_by: str = ""
    message: str = ""


_items: dict[str, Transfer] = {}


def _refresh(t: Transfer):
    if t.state == "pending" and time.time() - t.created > PENDING_TTL:
        t.state = "expired"


def create(device_id, device_name, name, size, approved) -> Transfer:
    now = time.time()
    for k, t in list(_items.items()):             # forget old finished transfers
        _refresh(t)
        if t.state not in LIVE and now - t.created > KEEP_FINISHED:
            del _items[k]
    t = Transfer(secrets.token_urlsafe(12), device_id, device_name, name, size,
                 "approved" if approved else "pending")
    _items[t.id] = t
    return t


def get(tid: str):
    t = _items.get(tid)
    if t:
        _refresh(t)
    return t


def pending_count(device_id: int | None = None) -> int:
    return sum(1 for t in _items.values()
               if t.state == "pending" and (device_id is None or t.device_id == device_id))


def public(t: Transfer) -> dict:
    elapsed = time.time() - t.started if t.started else 0
    return {"id": t.id, "device": t.device_name, "name": t.name, "size": t.size,
            "state": t.state, "received": t.received, "message": t.message,
            "speed": t.received / elapsed if elapsed > 0 else 0}


def active() -> list:
    out = []
    for t in list(_items.values()):
        _refresh(t)
        if t.state in LIVE:
            out.append(public(t))
    return out


def cancel_device(device_id: int):
    for t in _items.values():
        if t.device_id == device_id and t.state in LIVE:
            if t.state == "uploading":
                t.cancel_by = "laptop"
            else:
                t.state = "cancelled"
