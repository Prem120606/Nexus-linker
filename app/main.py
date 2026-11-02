import asyncio
import logging
import logging.handlers
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app import config
from app.database.db import init_db
from app.deps import laptop_only
from app.pages import render
from app.routes import devices, files, live, messages, pairing, security, setup
from app.security import SecurityMiddleware
from app.services import audit_service, live_service
from app.services.auth_service import require_device


def setup_logging() -> None:
    """Rotating log files. Cookies, tokens and query strings are never written."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    for name, fname in (("nexus", "nexus.log"), ("nexus.access", "access.log")):
        lg = logging.getLogger(name)
        if lg.handlers:
            continue
        h = logging.handlers.RotatingFileHandler(config.LOG_DIR / fname, maxBytes=1_000_000,
                                                 backupCount=5, encoding="utf-8")
        h.setFormatter(fmt)
        lg.addHandler(h)
        lg.setLevel(logging.INFO)
    logging.getLogger("nexus").addHandler(logging.StreamHandler())


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    init_db()
    audit_service.log("server_started", "System")
    task = asyncio.create_task(live_service.status_loop())    # live CPU/RAM broadcaster
    yield
    task.cancel()
    audit_service.log("server_stopped", "System")


# No /docs, /redoc or /openapi.json: strangers must not get a map of the API
app = FastAPI(title="NEXUS", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityMiddleware)

app.include_router(pairing.router)
app.include_router(devices.router)
app.include_router(messages.router)
app.include_router(files.router)
app.include_router(security.router)
app.include_router(setup.router)
app.include_router(live.router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


# ---------- Errors: never show stack traces, never echo what the client sent ----------
@app.exception_handler(RequestValidationError)
async def bad_input(request: Request, exc: RequestValidationError):
    return JSONResponse({"detail": "Invalid input"}, status_code=422)


@app.exception_handler(Exception)
async def crash_guard(request: Request, exc: Exception):
    logging.getLogger("nexus").exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal error"}, status_code=500)


# ---------- Pages ----------
@app.get("/", include_in_schema=False)
def shell():
    return render("shell.html")


@app.get("/home", include_in_schema=False)
def home():
    return render("index.html")


@app.get("/pair", include_in_schema=False)
def pair_page():
    return render("pair.html")


@app.get("/pairing", include_in_schema=False, dependencies=[Depends(laptop_only)])
def pairing_page():
    return render("pairing.html")


@app.get("/chat", include_in_schema=False)
def chat_page():
    return render("chat.html")


@app.get("/files", include_in_schema=False)
def files_page():
    return render("files.html")


# ---------- Basic API ----------
@app.get("/api/ping")
def ping():
    return {"status": "ok", "app": "NEXUS"}


@app.get("/api/me")
def me(device=Depends(require_device)):
    return {"device": device["name"], "trusted": bool(device["trusted"])}
