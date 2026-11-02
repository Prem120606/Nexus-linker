"""Server secret + hashing + encryption helpers.

* One random 256-bit master key lives in data/secret.key (owner-only permissions).
* Session tokens are never stored: only HMAC-SHA256(key, token) is. A stolen database
  cannot be turned back into working logins.
* Message text is encrypted at rest (Fernet = AES-128-CBC + HMAC-SHA256).
"""
import base64
import hashlib
import hmac
import os
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.config import DATA_DIR

KEY_FILE = DATA_DIR / "secret.key"


def lock_down(path) -> None:
    """Make a file or folder readable by the current user only (best effort)."""
    p = Path(path)
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME", "")
            if user:
                grant = f"{user}:(OI)(CI)F" if p.is_dir() else f"{user}:F"
                subprocess.run(["icacls", str(p), "/inheritance:r", "/grant:r", grant],
                               capture_output=True, check=False)
        else:
            os.chmod(p, 0o700 if p.is_dir() else 0o600)
    except Exception:
        pass


def _load_master() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_down(DATA_DIR)
    if not KEY_FILE.exists():
        try:
            fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(base64.urlsafe_b64encode(os.urandom(32)))
            lock_down(KEY_FILE)
        except FileExistsError:
            pass
    return base64.urlsafe_b64decode(KEY_FILE.read_bytes().strip())


_MASTER = _load_master()


def _derive(label: str) -> bytes:
    return hmac.new(_MASTER, label.encode(), hashlib.sha256).digest()


_SESSION_KEY = _derive("nexus/session/v1")
_AUDIT_KEY = _derive("nexus/audit/v1")
_FERNET = Fernet(base64.urlsafe_b64encode(_derive("nexus/data/v1")))


def session_hash(token: str) -> str:
    return hmac.new(_SESSION_KEY, token.encode(), hashlib.sha256).hexdigest()


def audit_mac(text: str) -> str:
    return hmac.new(_AUDIT_KEY, text.encode(), hashlib.sha256).hexdigest()


def encrypt(text: str) -> str:
    return "v1:" + _FERNET.encrypt(text.encode()).decode()


def decrypt(value: str) -> str:
    if not value.startswith("v1:"):
        return value
    try:
        return _FERNET.decrypt(value[3:].encode()).decode()
    except InvalidToken:
        return "[unreadable]"
