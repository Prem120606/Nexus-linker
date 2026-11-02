"""NEXUS settings. Change values here, or override with environment variables."""
import ipaddress
import os
import socket
from pathlib import Path

import psutil

BASE_DIR = Path(__file__).resolve().parent.parent


def _path(env: str, default: Path) -> Path:
    return Path(os.environ.get(env) or default)


# ---------- Folders ----------
DATA_DIR = _path("NEXUS_DATA", BASE_DIR / "data")      # database, keys, certificates, logs
UPLOAD_DIR = _path("NEXUS_UPLOADS", BASE_DIR / "uploads")   # phone -> laptop files land here
SHARE_DIR = _path("NEXUS_SHARED", BASE_DIR / "shared")      # laptop -> phone files live here
LOG_DIR = DATA_DIR / "logs"
TLS_DIR = DATA_DIR / "tls"
BACKUP_DIR = DATA_DIR / "backups"

# ---------- Network ----------
USE_TLS = os.environ.get("NEXUS_TLS", "1") != "0"        # HTTPS on. Set NEXUS_TLS=0 only for debugging
HTTPS_PORT = int(os.environ.get("NEXUS_HTTPS_PORT", "8443"))
HTTP_PORT = int(os.environ.get("NEXUS_HTTP_PORT", "8000"))   # setup page + certificate download ONLY
PORT = HTTPS_PORT if USE_TLS else HTTP_PORT
SCHEME = "https" if USE_TLS else "http"
BIND_HOST = os.environ.get("NEXUS_BIND", "0.0.0.0")
# "__Host-" cookies must be Secure, so they only work with HTTPS
COOKIE_NAME = "__Host-nexus_session" if USE_TLS else "nexus_session"

HOSTNAME = socket.gethostname().lower()
ALLOWED_HOSTNAMES = {"localhost", "nexus.local", HOSTNAME, f"{HOSTNAME}.local"} | {
    h.strip().lower() for h in os.environ.get("NEXUS_HOSTNAMES", "").split(",") if h.strip()
}

# Only these networks may talk to the server (private LAN ranges + loopback by default)
_DEFAULT_NETS = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "169.254.0.0/16", "fe80::/10", "fc00::/7", "100.64.0.0/10"]
ALLOWED_NETS = [ipaddress.ip_network(n.strip(), strict=False)
                for n in (os.environ.get("NEXUS_ALLOWED_NETS") or ",".join(_DEFAULT_NETS)).split(",")
                if n.strip()]

# ---------- Limits ----------
MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024       # 10 GB per file
MIN_FREE_BYTES = 1 * 1024 * 1024 * 1024          # always keep 1 GB free on the disk
JSON_BODY_LIMIT = 64 * 1024                      # every non-file request body
MAX_DEVICES = 10                                 # paired devices at one time
RATE_LIMIT_PER_MIN = 1500                        # requests per minute per phone
MAX_WS_TOTAL = 40
MAX_WS_PER_IP = 6
AUTO_APPROVE_TRUSTED = False                     # True = trusted phones skip the approval toast

# File types a phone may NOT upload (they can run code if opened by mistake)
BLOCKED_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".pif", ".lnk", ".url", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl", ".jar", ".dll", ".sys",
    ".reg", ".inf", ".msc", ".gadget", ".application", ".appx", ".msix", ".iso", ".vhd",
}
if os.environ.get("NEXUS_ALLOW_EXT"):            # e.g. NEXUS_ALLOW_EXT=.jar,.iso
    BLOCKED_EXTENSIONS -= {e.strip().lower() for e in os.environ["NEXUS_ALLOW_EXT"].split(",")}

MDNS_ENABLED = os.environ.get("NEXUS_MDNS", "0") == "1"   # advertise nexus.local (needs: pip install zeroconf)


def ip_allowed(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in ALLOWED_NETS)


def get_local_ip() -> str:
    """The laptop's address on the current network (the one the phone should use)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))    # sends nothing; the OS just picks the interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def local_ips() -> list[str]:
    """Every private IPv4 address this laptop has (used for the HTTPS certificate)."""
    found = {"127.0.0.1", get_local_ip()}
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and ip_allowed(a.address):
                    found.add(a.address)
    except Exception:
        pass
    return sorted(found)


def base_url() -> str:
    return f"{SCHEME}://{get_local_ip()}:{PORT}"
