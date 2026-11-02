import secrets
import time
from dataclasses import dataclass

PAIRING_TTL = 180   # seconds
MAX_ATTEMPTS = 5


@dataclass
class PairingSession:
    token: str
    code: str
    expires_at: float
    attempts: int = 0
    state: str = "waiting"      # waiting -> pending -> approved -> used   (or rejected / locked)
    device_name: str = ""
    trusted: bool = False
    claim_key: str = ""         # secret handed ONLY to the phone that entered the right code


_current: PairingSession | None = None   # only ONE open pairing at a time


def start() -> PairingSession:
    global _current
    _current = PairingSession(
        token=secrets.token_urlsafe(32),
        code=f"{secrets.randbelow(1_000_000):06d}",
        expires_at=time.time() + PAIRING_TTL,
    )
    return _current


def current() -> PairingSession | None:
    if _current and time.time() > _current.expires_at:
        return None
    return _current


def find(token: str) -> PairingSession | None:
    s = current()
    if s and secrets.compare_digest(s.token.encode(), token.encode()):
        return s
    return None


def verify(s: PairingSession, code: str, device_name: str, trusted: bool) -> tuple[str, str]:
    """Returns (result, claim_key). result: ok | wrong | locked | bad_state"""
    if s.state == "locked":
        return "locked", ""
    if s.state != "waiting":
        return "bad_state", ""
    if not secrets.compare_digest(s.code.encode(), code.encode()):
        s.attempts += 1
        if s.attempts >= MAX_ATTEMPTS:
            s.state = "locked"
            return "locked", ""
        return "wrong", ""
    s.code = ""                                  # the code is dead after one success
    s.state = "pending"
    s.device_name = device_name
    s.trusted = trusted
    s.claim_key = secrets.token_urlsafe(24)
    return "ok", s.claim_key


def claim_ok(s: PairingSession, key: str) -> bool:
    return bool(s.claim_key) and secrets.compare_digest(s.claim_key.encode(), key.encode())
