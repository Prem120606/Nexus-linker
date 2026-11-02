import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app import config
from app.deps import caller, is_laptop
from app.services import auth_service
from app.services.live_service import manager, snapshot

router = APIRouter()


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ip = ws.client.host if ws.client else ""

    # 1) Block other websites from using your cookie (cross-site WebSocket hijacking)
    origin, host = ws.headers.get("origin"), ws.headers.get("host")
    if origin and urlparse(origin).netloc.lower() != (host or "").lower():
        await ws.close(code=4403)
        return

    # 2) Who is this? The laptop itself, or a paired phone. Anyone else is closed with no data.
    if is_laptop(ws):
        who = {"side": "laptop", "name": "Laptop", "device_id": None, "ip": ip}
    else:
        dev = auth_service.find_device(ws.cookies.get(config.COOKIE_NAME), ip)
        if dev is None:
            await ws.close(code=4401)
            return
        who = {"side": "phone", "name": dev["name"], "device_id": dev["id"], "ip": ip}

    # 3) Connection caps (stops socket floods)
    if not manager.can_add(ip):
        await ws.close(code=4429)
        return

    manager.add(ws, who)
    try:
        await ws.send_json({"type": "hello", "side": who["side"]})
        await ws.send_json(snapshot())
        window_start, count = time.monotonic(), 0
        while True:
            await ws.receive_text()          # clients only send a keep-alive "ping"
            count += 1
            if time.monotonic() - window_start > 5:
                window_start, count = time.monotonic(), 0
            elif count > 20:                 # more than 20 messages in 5s is not a keep-alive
                await ws.close(code=4429)
                return
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception:
        pass
    finally:
        manager.remove(ws)


@router.get("/api/status")
def status(who=Depends(caller)):
    return snapshot()
