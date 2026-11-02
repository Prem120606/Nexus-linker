# Security policy

NEXUS is built for a private local network (laptop + your own phone). Never expose it to the internet.

## Reporting a vulnerability
Please do not open a public issue. Use GitHub's "Report a vulnerability" button (Security tab) or contact the maintainer privately.

## Never commit
`data/` (database, secret key, certificates), `uploads/`, `shared/`, any `.key`, `.pem`, `.crt`, `.env` file.
If a key is ever pushed by mistake, treat it as leaked: delete `data/` locally, restart NEXUS (it regenerates everything) and pair your devices again.
