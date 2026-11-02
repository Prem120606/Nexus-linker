"""Serve HTML pages with a strict Content-Security-Policy.

Inline <script> blocks are allowed only if their exact text hash is listed in the policy, so a
script injected by an attacker (XSS) would not run. External scripts must come from /static.
"""
import base64
import hashlib
import re
from pathlib import Path

from fastapi.responses import HTMLResponse

TEMPLATES = Path(__file__).parent / "templates"
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S | re.I)


def _csp(html: str) -> str:
    hashes = []
    for m in _INLINE_SCRIPT.finditer(html):
        digest = base64.b64encode(hashlib.sha256(m.group(1).encode("utf-8")).digest()).decode()
        hashes.append(f"'sha256-{digest}'")
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' " + " ".join(hashes),
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self' ws: wss:",
        "frame-src 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ])


def render(name: str) -> HTMLResponse:
    html = (TEMPLATES / name).read_text(encoding="utf-8")
    return HTMLResponse(html, headers={"Content-Security-Policy": _csp(html)})
