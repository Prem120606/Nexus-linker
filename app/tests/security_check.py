"""Attack simulation against a RUNNING NEXUS server.

Run on the laptop (server must be started):   python -m app.tests.security_check
Uses only the Python standard library. Every line should say PASS.
"""
import http.client
import json
import ssl
import sys

HOST, PORT = "127.0.0.1", 8443
CTX = ssl._create_unverified_context()      # we are testing behaviour, not the certificate chain

results = []


def request(method, path, headers=None, body=None, host=None, chunked=False):
    conn = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=10)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host or f"{HOST}:{PORT}")
    for k, v in (headers or {}).items():
        conn.putheader(k, v)
    data = body.encode() if isinstance(body, str) else body
    if chunked:
        conn.putheader("Transfer-Encoding", "chunked")
    elif data is not None:
        conn.putheader("Content-Length", str(len(data)))
    conn.endheaders()
    if data is not None and not chunked:
        conn.send(data)
    elif chunked:
        conn.send(b"3\r\nabc\r\n0\r\n\r\n")
    r = conn.getresponse()
    text = r.read().decode(errors="replace")
    out = (r.status, {k.lower(): v for k, v in r.getheaders()}, text)
    conn.close()
    return out


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (f"   [{detail}]" if detail and not ok else ""))


def main():
    try:
        s, h, _ = request("GET", "/api/ping")
    except OSError as exc:
        print(f"Cannot reach https://{HOST}:{PORT}. Start NEXUS first. ({exc})")
        sys.exit(2)

    check("server answers over HTTPS", s == 200)
    for hdr in ("x-content-type-options", "x-frame-options", "referrer-policy",
                "content-security-policy", "cross-origin-opener-policy", "permissions-policy"):
        check(f"security header present: {hdr}", hdr in h)
    check("server version is hidden", "server" not in h, h.get("server", ""))
    check("API responses are never cached", h.get("cache-control") == "no-store")

    s, h, _ = request("GET", "/chat")
    csp = h.get("content-security-policy", "")
    check("pages carry a strict CSP (no unsafe-inline scripts)", "script-src 'self' 'sha256-" in csp and "unsafe-eval" not in csp)

    check("/docs is gone", request("GET", "/docs")[0] == 404)
    check("/openapi.json is gone", request("GET", "/openapi.json")[0] == 404)
    check("unknown path is a clean 404", request("GET", "/nothing")[0] == 404)

    s, _, _ = request("GET", "/api/ping", host="evil.example.com")
    check("DNS-rebinding: foreign Host header refused", s == 400, s)

    check("protected route without login -> 401", request("GET", "/api/me")[0] == 401)
    check("messages without login still work on the laptop (loopback)", request("GET", "/api/messages")[0] == 200)
    check("download without login is refused", request("GET", "/api/files/download/anything.txt")[0] == 401)
    check("path traversal in download is refused", request("GET", "/api/files/download/..%2Fdata%2Fnexus.db")[0] in (401, 404))
    check("database is not reachable through /static",
          request("GET", "/static/../data/nexus.db")[0] == 404 and request("GET", "/static/%2e%2e/data/nexus.db")[0] == 404)
    check("secret key is not reachable through /static", request("GET", "/static/../data/secret.key")[0] == 404)

    s, _, _ = request("POST", "/api/pairing/start", {"Origin": "https://evil.example"})
    check("CSRF: cross-origin POST refused", s == 403, s)
    s, _, _ = request("POST", "/api/pairing/start", {"Sec-Fetch-Site": "cross-site"})
    check("CSRF: Sec-Fetch-Site cross-site refused", s == 403, s)
    s, _, _ = request("POST", "/api/pairing/start", {"Origin": f"https://{HOST}:{PORT}"})
    check("same-origin POST allowed", s == 200, s)

    s, _, _ = request("POST", "/api/messages", {"Content-Type": "application/json"}, '{"text":"' + "a" * 70000 + '"}')
    check("oversized JSON body refused (413)", s == 413, s)
    s, _, _ = request("POST", "/api/messages", {"Content-Type": "application/json"}, chunked=True)
    check("chunked JSON body refused (411)", s == 411, s)
    s, _, t = request("POST", "/api/messages", {"Content-Type": "application/json"}, "{not json")
    check("bad JSON gives a plain 422, nothing echoed", s == 422 and "not json" not in t, t[:80])

    s, _, t = request("GET", "/api/security/info")
    info = json.loads(t) if s == 200 else {}
    check("HTTPS reported on", info.get("tls") is True)
    check("security log chain is intact", info.get("audit", {}).get("ok") is True)

    # file name cleaner
    sys.path.insert(0, ".")
    from app.services.file_service import clean_filename as c, is_blocked
    cases = {r"..\..\Windows\evil.txt": "evil.txt", "../../etc/passwd": "passwd",
             "%2e%2e%2fsecret.txt": "secret.txt", "CON.txt": "_CON.txt",
             "a<b>:c?.png": "a_b__c_.png", "report.pdf ": "report.pdf", "...": "file", "": "file",
             "stream.txt:hidden": "stream.txt_hidden"}
    check("filename cleaner handles 9 hostile names", all(c(k) == v for k, v in cases.items()),
          [(k, c(k)) for k, v in cases.items() if c(k) != v])
    check("executables are blocked", all(is_blocked(n) for n in ("a.exe", "b.BAT", "c.ps1", "d.lnk")))
    check("normal files are allowed", not any(is_blocked(n) for n in ("a.jpg", "b.pdf", "c.zip", "d.apk")))

    # brute force of pairing tokens (last, it locks this address for 10 minutes)
    codes = [request("POST", "/api/pairing/verify", {"Content-Type": "application/json"},
                     json.dumps({"token": "x" * 40, "code": "123456", "device_name": "t"}))[0] for _ in range(12)]
    check("pairing brute force: unknown tokens -> 410, then blocked (429)", codes[0] == 410 and codes[-1] == 429, codes)

    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
