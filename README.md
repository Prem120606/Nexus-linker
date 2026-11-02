# NEXUS (secure edition)

Free phone-to-laptop link: pairing by QR + code, chat, files in both directions, live laptop status.
Python + FastAPI + SQLite. Everything runs on your laptop; nothing goes to the internet.

## Install and run (Windows)

1. Install Python 3.11+ from python.org (tick "Add to PATH").
2. Unzip this folder, for example to `C:\Users\<you>\Desktop\nexus`.
3. **Once**, open PowerShell **as Administrator** in that folder and run:
   `powershell -ExecutionPolicy Bypass -File .\setup_firewall.ps1`
   (opens the ports for your own network only, and removes the old "NEXUS Dev" rule).
4. Double-click **start_nexus.bat** (first run installs packages). No `--reload`: it is not needed and restarts the server on every file save.
5. The window prints the addresses. On the laptop open **https://127.0.0.1:8443/** and use the **Pair** tab.

Manual start, if you prefer: `venv\Scripts\activate`, then `pip install -r requirements.txt`, then `python run.py`.

## First time on each phone (once)

NEXUS makes its own private certificate authority. Install it on the phone so Chrome trusts your laptop:

1. Phone on the laptop's hotspot. Open **`https://<laptop-ip>:8443/setup`** (printed in the window, shown on the Pair tab). Chrome warns about the certificate this one time: tap Advanced, then Continue. (The older `http://<laptop-ip>:8000/` page still exists, but Chrome often upgrades it to https and fails.)
2. Tap **Download certificate**, then Settings > Security > More security > Encryption and credentials > Install a certificate > **CA certificate**, pick the file.
3. Compare the fingerprint on the phone page with the one on the laptop's Pair tab. They must match.
4. Scan the pairing QR. It opens `https://<laptop-ip>:8443/pair`.

Skipping step 2 still works (Chrome shows a warning once and you can continue), but then the connection is encrypted without proving it is your laptop. Install the certificate.

The certificate is limited to private addresses and `.local` names, so even if `data/tls/ca.key` leaked it could not impersonate real websites. If the laptop's IP changes, the server certificate is re-issued automatically and the phone keeps trusting it.

## Domain name

* **Private network (recommended, free):** the IP address is the reliable choice. For a name, `pip install zeroconf` and start with `set NEXUS_MDNS=1`; the laptop then answers to `https://nexus.local:8443/`. Windows and many phones resolve `.local`, but Android over a hotspot does not always. Treat it as a bonus.
* **A real domain with a normal trusted certificate (no certificate install on the phone):** a free name such as `yourname.duckdns.org` can point to the laptop's *private* IP, and a free Let's Encrypt certificate can be obtained with the DNS challenge (for example with `win-acme` or `certbot`). Then start with
  `set NEXUS_CERT=C:\path\fullchain.pem` and `set NEXUS_KEY=C:\path\privkey.pem` and `set NEXUS_HOSTNAMES=yourname.duckdns.org`.
  This needs internet on the laptop to renew, and a DNS update when the private IP changes. It is optional and was not tested here.
* Never port-forward NEXUS to the internet. It is built for your local network only.

## What is protected (details in SECURITY_REPORT.md)

HTTPS everywhere, QR + one-time code + laptop approval, claim key bound to the phone that typed the code, keyed hashes for sessions, encrypted messages, SHA-256 for every transferred file, CSRF and DNS-rebinding defense, local-network-only filter, rate limits, strict CSP, tamper-evident security log, blocked executable uploads, hidden temp files, auto-restart watchdog, database backups and corruption recovery.

## Check it yourself

With NEXUS running, on the laptop: `python -m app.tests.security_check` (32 attack simulations, all should say PASS).

## Settings

Edit `app/config.py` or set environment variables before starting: `NEXUS_UPLOADS`, `NEXUS_SHARED` (folders), `NEXUS_ALLOW_EXT` (e.g. `.jar`, allow a blocked type), `NEXUS_ALLOWED_NETS` (extra networks), `NEXUS_TLS=0` (debug only, disables HTTPS).

## Honest limits

* A program already running as you on the laptop can read `data/secret.key` and act as the laptop. No local web app can prevent that; keep Windows updated and Defender on.
* The security log detects edits, but someone with the secret key could rebuild it. It is a tripwire, not a vault.
* NEXUS does not scan files for viruses. Blocked types plus Windows Defender's real-time protection are the defense; do not open unknown files from `uploads`.
* A hotspot password you share is the outer wall: use a strong one and your own phone only.
* Old data from the previous version (`nexus.db` in the project folder) is not migrated, and old phone sessions no longer work: pair again.

## Folders

`data/` (database, keys, certificates, logs, backups: never share or upload), `uploads/` (phone to laptop), `shared/` (laptop to phone).
