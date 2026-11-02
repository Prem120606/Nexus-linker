"""First-time phone setup, served over HTTPS as well (Chrome on Android often upgrades http:// to https://).

Only public information lives here: the certificate authority's PUBLIC certificate and its fingerprint.
"""
import html

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse

from app import config
from app.services import tls_service

router = APIRouter()

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>NEXUS setup</title>
<style>body{{font-family:system-ui,sans-serif;max-width:520px;margin:24px auto;padding:0 16px;line-height:1.5}}
a.b{{display:block;padding:14px;margin:10px 0;border-radius:12px;background:#4f46e5;color:#fff;text-align:center;text-decoration:none}}
a.g{{background:#475569}}code{{word-break:break-all;font-size:12px}}</style></head><body>
<h1>NEXUS secure setup</h1>
<p>Do this <b>once</b> per phone so Chrome trusts your laptop:</p>
<ol><li>Tap <b>Download certificate</b>.</li>
<li>Open <b>Settings, Security, More security, Encryption &amp; credentials, Install a certificate, CA certificate</b> and pick the downloaded file.</li>
<li>Check this fingerprint matches the one on your laptop's Pair tab:<br><code>{fp}</code></li></ol>
<a class="b" href="/ca.crt">Download certificate</a>
<a class="b g" href="/">Continue to NEXUS</a>
</body></html>"""


@router.get("/setup", include_in_schema=False)
def setup(request: Request):
    if not config.USE_TLS:
        return PlainTextResponse("HTTPS is off", status_code=404)
    body = PAGE.format(fp=html.escape(tls_service.ca_fingerprint()))
    return HTMLResponse(body, headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"})


@router.get("/ca.crt", include_in_schema=False)
def ca_file():
    if not config.USE_TLS or not tls_service.CA_CERT.exists():
        return PlainTextResponse("Not available", status_code=404)
    return FileResponse(tls_service.CA_CERT, media_type="application/x-x509-ca-cert", filename="nexus-ca.crt")
