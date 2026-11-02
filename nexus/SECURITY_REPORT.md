# NEXUS security review

Review of every phase (pairing, messages, files, live link, dashboard) followed by fixes. Each item was checked by `app/tests/security_check.py` (32 checks) and a real-browser test of the full flow (33 checks, laptop plus phone) before packaging.

## Problems found in the earlier version, and the fix

| # | Risk | Fix | Where |
|---|------|-----|-------|
| 1 | Traffic was plain HTTP: anyone sniffing the hotspot could read messages and steal the session cookie | HTTPS (TLS 1.2+/1.3) with a private, name-constrained CA; Secure `__Host-` cookie | `tls_service.py`, `run.py`, `pairing.py` |
| 2 | Firewall rule from earlier steps allowed any remote address on port 8000 | New rule limited to the local subnet; old rule removed | `setup_firewall.ps1` |
| 3 | Anyone who saw the QR could claim the session after the owner approved (race) | `claim_key` handed only to the phone that typed the correct code | `pairing_service.py`, `pair.html` |
| 4 | Pairing token sat in the QR URL query, so it reached server logs and Referer | Token moved into the URL fragment (`#t=`), removed from the address bar | `pairing.py`, `pair.html` |
| 5 | Session lookup used a plain SHA-256 of the cookie; a stolen database could be attacked offline | Keyed HMAC-SHA-256 with a server secret; DB alone is useless | `secrets_service.py` |
| 6 | Messages stored as plain text | Encrypted at rest (Fernet, AES + HMAC) | `messages.py` |
| 7 | Laptop-only actions (approve pairing, revoke) could be triggered by a malicious web page open on the laptop (CSRF / DNS rebinding) | Origin and Sec-Fetch-Site checks, strict Host allow-list, SameSite=Strict | `security.py` |
| 8 | Server reachable from non-local addresses | Peer address must be loopback or private LAN | `security.py`, `config.py` |
| 9 | Unlimited requests, unlimited WebSockets, unbounded JSON bodies | Per-address rate limit, WS caps, 64 KB body cap, 411 for chunked JSON, uvicorn limits | `security.py`, `live.py`, `run.py` |
| 10 | Brute force of pairing tokens or codes across sessions | 5 tries per session, plus 10 failures per 10 min blocks the address for 10 min | `pairing.py`, `ratelimit.py` |
| 11 | No Content-Security-Policy: any injected script would run | Strict CSP; inline scripts allowed only by exact hash | `pages.py` |
| 12 | `/docs` and `/openapi.json` exposed the API map | Removed | `main.py` |
| 13 | Stack traces and echoed input in error responses | Generic 500 and 422 responses; details only in the log file | `main.py` |
| 14 | Half-uploaded files visible under their real name | Written to a hidden `.part` file and renamed only when complete; deleted on cancel or disconnect | `file_service.py`, `files.py` |
| 15 | Phone could upload `.exe`, `.bat`, `.ps1`, `.lnk` ... | Blocked list, checked before the laptop is even asked | `config.py`, `files.py` |
| 16 | Access log wrote every URL including query strings | Own log: only non-GET or error responses, path only, rotating files | `main.py`, `security.py` |
| 17 | No record of security events | Tamper-evident audit log (each entry chained by HMAC), shown on the Pair tab | `audit_service.py` |
| 18 | Server crash meant downtime; damaged database meant failure to start | Watchdog restarts the server; status loop cannot die; WAL mode; backups on every start (keep 5); corrupt DB set aside and replaced | `run.py`, `db.py`, `live_service.py` |
| 19 | Keys and database readable by other Windows users | Owner-only permissions (`chmod 600` / `icacls`) | `secrets_service.py` |

## Hashing, in plain words

* **Session cookie:** random 256-bit value; the database stores only `HMAC-SHA256(secret, cookie)`. A slow password hash (bcrypt) is not needed because the input is already unguessable.
* **Files:** SHA-256 computed while receiving, stored and shown in history, so you can prove a file arrived unchanged (`Get-FileHash file`).
* **Security log:** each entry's MAC covers the previous entry's MAC.
* **Certificate authority:** SHA-256 fingerprint shown for you to compare.
* There are no passwords in NEXUS, so there is nothing to crack.

## Tested here

HTTPS handshake (TLS 1.3; TLS 1.1 refused), strict certificate validation including name constraints, Host spoofing, cross-origin POST, oversized and chunked bodies, path traversal, `/static` reaching the database, token brute force with lockout, wrong code, claim without the claim key, paired phone calling laptop-only routes, revoked phone (HTTP and WebSocket), approval flow, blocked `.exe`, same-name uploads, cancel from the laptop mid-upload, phone disconnect mid-upload, byte-exact upload and download, SHA-256 correctness, encrypted messages, hashed sessions, zero CSP violations in the browser, `kill -9` recovery in about two seconds, corrupted database recovery.

## Not tested here (be aware)

Real Android certificate installation and Chrome on your phone, Windows `icacls` and firewall script, `nexus.local` on a real network, and Let's Encrypt with a real domain. These follow the documented steps but ran only in design, not on your hardware.
