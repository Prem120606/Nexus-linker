import logging
import sqlite3
import time
from pathlib import Path

from app.config import BACKUP_DIR, DATA_DIR

DB_PATH = DATA_DIR / "nexus.db"
log = logging.getLogger("nexus")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row            # rows behave like dicts
    conn.execute("PRAGMA busy_timeout=5000")  # wait instead of crashing when the DB is busy
    return conn


def _integrity_ok() -> bool:
    try:
        c = sqlite3.connect(DB_PATH)
        ok = c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        c.close()
        return ok
    except sqlite3.Error:
        return False


def backup_db(keep: int = 5) -> None:
    """Copy the database (SQLite online backup) and keep the newest few copies."""
    if not DB_PATH.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    target = BACKUP_DIR / f"nexus-{time.strftime('%Y%m%d-%H%M%S')}.db"
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    old = sorted(BACKUP_DIR.glob("nexus-*.db"))[:-keep]
    for p in old:
        p.unlink(missing_ok=True)


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists() and not _integrity_ok():           # crash protection: never boot on a broken DB
        broken = DB_PATH.with_name(f"nexus.corrupt.{int(time.time())}.db")
        DB_PATH.rename(broken)
        log.error("Database was damaged; moved to %s and starting a fresh one", broken.name)
    elif DB_PATH.exists():
        try:
            backup_db()
        except Exception:
            log.exception("Backup failed")

    conn = get_conn()
    try:
        conn.execute("PRAGMA journal_mode=WAL")            # safer against power loss, faster writes
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    session_hash TEXT NOT NULL UNIQUE,
                    trusted INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    last_seen REAL,
                    last_ip TEXT
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    side TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at REAL NOT NULL
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    sha256 TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    prev TEXT NOT NULL,
                    mac TEXT NOT NULL
                )""")
    finally:
        conn.close()
