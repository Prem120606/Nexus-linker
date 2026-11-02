"""Start NEXUS:   python run.py

* Runs the app over HTTPS (port 8443) and a tiny HTTP setup page (port 8000: certificate download only).
* A watchdog restarts the server automatically if it ever crashes.
"""
import html
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def serve() -> None:
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
    from starlette.routing import Route

    from app import config
    from app.security import SecurityMiddleware
    from app.services import secrets_service, tls_service  # noqa: F401  (creates the secret key early)

    common = dict(host=config.BIND_HOST, access_log=False, server_header=False,
                  timeout_keep_alive=10, limit_concurrency=100, ws_max_size=4096,
                  h11_max_incomplete_event_size=16384, log_level="info")

    from app.main import app

    if not config.USE_TLS:
        print("\n  WARNING: HTTPS is OFF (NEXUS_TLS=0). Use only for debugging.\n")
        print(f"  Open on this laptop : http://127.0.0.1:{config.PORT}/")
        print(f"  Open on the phone   : {config.base_url()}/\n")
        uvicorn.Server(uvicorn.Config(app, port=config.PORT, **common)).run()
        return

    cert, key = tls_service.ensure_certs()
    ip = config.get_local_ip()

    # ---- tiny HTTP helper: setup instructions + public CA certificate. No API, no data. ----
    async def setup_page(request):
        raw = request.headers.get("host", ip)
        host = ip if raw.startswith("[") else raw.split(":")[0]
        go = f"https://{html.escape(host)}:{config.HTTPS_PORT}/"
        fp = tls_service.ca_fingerprint()
        body = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>NEXUS setup</title>
<style>body{{font-family:system-ui,sans-serif;max-width:520px;margin:24px auto;padding:0 16px;line-height:1.5}}
a.b{{display:block;padding:14px;margin:10px 0;border-radius:12px;background:#4f46e5;color:#fff;text-align:center;text-decoration:none}}
a.g{{background:#475569}}code{{word-break:break-all;font-size:12px}}</style></head><body>
<h1>NEXUS secure setup</h1>
<p>NEXUS now uses HTTPS. Do this <b>once</b> per phone so Chrome trusts your laptop:</p>
<ol><li>Tap <b>Download certificate</b> below.</li>
<li>Open <b>Settings → Security → More security → Encryption &amp; credentials → Install a certificate → CA certificate</b> and pick the downloaded file.</li>
<li>Compare this fingerprint with the one on your laptop's Pair tab:<br><code>{fp}</code></li></ol>
<a class="b" href="/ca.crt">Download certificate</a>
<a class="b g" href="{go}">Continue to NEXUS</a>
<p style="font-size:13px;color:#555">Skipping the certificate still works: Chrome shows a warning once and you can continue,
but the connection is only verified if you install the certificate.</p></body></html>"""
        return HTMLResponse(body, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"})

    async def ca_file(request):
        return FileResponse(tls_service.CA_CERT, media_type="application/x-x509-ca-cert", filename="nexus-ca.crt")

    async def other(request):
        return PlainTextResponse("Use https:// on port %d" % config.HTTPS_PORT, status_code=404)

    helper = Starlette(routes=[Route("/", setup_page), Route("/secure", setup_page),
                               Route("/ca.crt", ca_file), Route("/{path:path}", other)])
    helper.add_middleware(SecurityMiddleware)
    http_server = uvicorn.Server(uvicorn.Config(helper, port=config.HTTP_PORT, **common))
    threading.Thread(target=http_server.run, daemon=True).start()

    zc = tls_service.start_mdns(ip, config.HTTPS_PORT) if config.MDNS_ENABLED else None

    print("\n  NEXUS is running (HTTPS)")
    print(f"  Laptop control page : https://127.0.0.1:{config.HTTPS_PORT}/pairing")
    print(f"  Phone address       : https://{ip}:{config.HTTPS_PORT}/")
    print(f"  First-time phone setup (certificate): https://{ip}:{config.HTTPS_PORT}/setup")
    print(f"  Certificate fingerprint: {tls_service.ca_fingerprint()}\n")
    try:
        uvicorn.Server(uvicorn.Config(app, port=config.HTTPS_PORT, ssl_certfile=cert, ssl_keyfile=key,
                                      **common)).run()
    finally:
        http_server.should_exit = True
        if zc:
            zc.close()


def supervise() -> None:
    """Watchdog: restart the server if it dies unexpectedly."""
    crashes: list[float] = []
    while True:
        proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child"], cwd=ROOT)
        try:
            code = proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            print("\n  NEXUS stopped.")
            return
        if code == 0:
            return
        now = time.time()
        crashes = [t for t in crashes if now - t < 120] + [now]
        if len(crashes) > 5:
            print("\n  NEXUS keeps crashing. Stopped. Read data/logs/nexus.log and fix the error first.")
            return
        wait = min(2 * len(crashes), 10)
        print(f"\n  NEXUS stopped unexpectedly (exit code {code}). Restarting in {wait}s...")
        time.sleep(wait)


if __name__ == "__main__":
    if "--child" in sys.argv:
        serve()
    else:
        supervise()
