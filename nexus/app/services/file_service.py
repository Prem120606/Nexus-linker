import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import unquote

from app.config import BLOCKED_EXTENSIONS
from app.database.db import get_conn

RESERVED = {"CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10))}
BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def clean_filename(raw: str) -> str:
    """Turn untrusted input into a safe, plain file name."""
    name = unquote(raw)
    name = name.replace("\\", "/").split("/")[-1]   # drop any folder parts
    name = BAD_CHARS.sub("_", name).strip(" .")     # no odd chars, no trailing dots/spaces
    p = Path(name or "file")
    stem, ext = p.stem[:120], p.suffix[:20]
    if stem.upper() in RESERVED:
        stem = "_" + stem
    return (stem or "file") + ext


def is_blocked(name: str) -> bool:
    return Path(name).suffix.lower() in BLOCKED_EXTENSIONS


def start_file(name: str, directory: Path):
    """Reserve a brand-new file name (never overwrites) and open a hidden temp file to write into.

    Returns (final_path, temp_path, file object). The data only appears under its real name when
    finish_file() is called, so half-finished uploads can never be opened or downloaded.
    """
    directory.mkdir(parents=True, exist_ok=True)
    root = directory.resolve()
    stem, ext = Path(name).stem, Path(name).suffix
    n = 0
    while True:
        candidate = name if n == 0 else f"{stem} ({n}){ext}"
        final = (root / candidate).resolve()
        if final.parent != root:                         # defense in depth against path tricks
            raise ValueError("Unsafe path")
        try:
            fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
            os.close(fd)                                 # placeholder: the OS refuses duplicates
        except FileExistsError:
            n += 1
            continue
        part = root / f".{secrets.token_hex(8)}.part"
        return final, part, open(part, "xb")


def finish_file(final: Path, part: Path) -> None:
    os.replace(part, final)


def abort_file(final: Path, part: Path) -> None:
    part.unlink(missing_ok=True)
    final.unlink(missing_ok=True)


def record_transfer(device_name, direction, filename, size, status, sha256=""):
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                "INSERT INTO transfers (device_name, direction, filename, size, status, sha256, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (device_name, direction, filename, size, status, sha256, time.time()),
            )
    finally:
        conn.close()
