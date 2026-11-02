import asyncio
import logging
import time
from collections import Counter

import psutil
from fastapi import WebSocket

from app import config
from app.database.db import get_conn

log = logging.getLogger("nexus")
STARTED = time.time()


class Manager:
    def __init__(self):
        self.clients: dict[WebSocket, dict] = {}

    def can_add(self, ip: str) -> bool:
        if len(self.clients) >= config.MAX_WS_TOTAL:
            return False
        return Counter(w["ip"] for w in self.clients.values())[ip] < config.MAX_WS_PER_IP

    def add(self, ws: WebSocket, who: dict):
        self.clients[ws] = who

    def remove(self, ws: WebSocket):
        self.clients.pop(ws, None)

    async def broadcast(self, event: dict):
        for ws in list(self.clients):
            try:
                await ws.send_json(event)
            except Exception:
                self.clients.pop(ws, None)

    async def to_side(self, side: str, event: dict):
        """Send an event only to the laptop or only to phones."""
        for ws, who in list(self.clients.items()):
            if who["side"] == side:
                try:
                    await ws.send_json(event)
                except Exception:
                    self.clients.pop(ws, None)

    async def kick(self, device_id: int):
        """Close every socket that belongs to this device (revoked/disconnected)."""
        for ws, who in list(self.clients.items()):
            if who["device_id"] == device_id:
                self.clients.pop(ws, None)
                try:
                    await ws.close(code=4401)
                except Exception:
                    pass

    async def prune(self):
        """Authorization stays alive: drop sockets whose session ended or expired."""
        ids = {w["device_id"] for w in self.clients.values() if w["device_id"]}
        if not ids:
            return
        conn = get_conn()
        try:
            now = time.time()
            for did in ids:
                row = conn.execute("SELECT revoked, expires_at FROM devices WHERE id = ?", (did,)).fetchone()
                if row is None or row["revoked"] or row["expires_at"] <= now:
                    await self.kick(did)
        finally:
            conn.close()

    def devices_online(self) -> int:
        return len({w["device_id"] for w in self.clients.values() if w["device_id"]})


manager = Manager()


def snapshot() -> dict:
    battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    return {
        "type": "status",
        "cpu": psutil.cpu_percent(None),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage(str(config.BASE_DIR)).percent,
        "battery": None if battery is None else round(battery.percent),
        "plugged": None if battery is None else battery.power_plugged,
        "uptime": int(time.time() - STARTED),
        "devices_online": manager.devices_online(),
    }


async def status_loop():
    """Runs forever. Any error is logged and the loop keeps going (it must never die)."""
    psutil.cpu_percent(None)                    # first call is always 0, so prime it
    while True:
        await asyncio.sleep(1)
        try:
            if not manager.clients:
                continue
            await manager.prune()
            await manager.broadcast(snapshot())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("status loop error")
