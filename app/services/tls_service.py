"""Local HTTPS: a private certificate authority (CA) that signs the server certificate.

* The CA is restricted (NameConstraints) to private IP ranges and *.local names, so even if its
  key were stolen it could not be used to impersonate real websites on a phone that trusts it.
* Install ca.crt on the phone once. After that, every certificate this laptop issues is trusted,
  even when the laptop's IP address changes (the server certificate is re-issued automatically).
* To use a certificate from a real domain instead, set NEXUS_CERT and NEXUS_KEY.
"""
import datetime as dt
import ipaddress
import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.config import HOSTNAME, TLS_DIR, local_ips
from app.services.secrets_service import lock_down

CA_CERT = TLS_DIR / "ca.crt"
CA_KEY = TLS_DIR / "ca.key"
SRV_CERT = TLS_DIR / "server.crt"
SRV_KEY = TLS_DIR / "server.key"

_NOW = lambda: dt.datetime.now(dt.timezone.utc)  # noqa: E731

# The CA may only ever vouch for these address ranges (and *.local / localhost names)
CA_NETS = [ipaddress.ip_network(n) for n in
           ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")]


def _write_key(path, key) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    lock_down(path)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NEXUS (local)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ensure_ca():
    if CA_CERT.exists() and CA_KEY.exists():
        key = serialization.load_pem_private_key(CA_KEY.read_bytes(), None)
        cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
        if cert.not_valid_after_utc > _NOW() + dt.timedelta(days=60):
            return key, cert
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(f"NEXUS Local CA ({HOSTNAME})")
    constraints = x509.NameConstraints(
        permitted_subtrees=[
            x509.DNSName("local"), x509.DNSName("localhost"),
            *[x509.IPAddress(n) for n in CA_NETS],
        ], excluded_subtrees=None)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW() - dt.timedelta(minutes=5))
            .not_valid_after(_NOW() + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(constraints, critical=True)
            .sign(key, hashes.SHA256()))
    _write_key(CA_KEY, key)
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _wanted_sans() -> tuple[set[str], set[str]]:
    # Only addresses the CA is allowed to vouch for, or the whole certificate would be rejected
    ips = {i for i in local_ips() if any(ipaddress.ip_address(i) in n for n in CA_NETS)}
    names = {"localhost", "nexus.local", f"{HOSTNAME}.local"}
    return ips, names


def _current_sans(cert) -> tuple[set[str], set[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set(), set()
    return ({str(i) for i in san.get_values_for_type(x509.IPAddress)},
            set(san.get_values_for_type(x509.DNSName)))


def ensure_certs() -> tuple[str, str]:
    """Return (certificate file, key file) for uvicorn. Creates or renews them when needed."""
    ext_cert, ext_key = os.environ.get("NEXUS_CERT"), os.environ.get("NEXUS_KEY")
    if ext_cert and ext_key:
        return ext_cert, ext_key

    TLS_DIR.mkdir(parents=True, exist_ok=True)
    lock_down(TLS_DIR)
    ca_key, ca_cert = _ensure_ca()
    ips, names = _wanted_sans()

    if SRV_CERT.exists() and SRV_KEY.exists():
        cur = x509.load_pem_x509_certificate(SRV_CERT.read_bytes())
        have_ips, have_names = _current_sans(cur)
        same_ca = cur.issuer == ca_cert.subject
        fresh = cur.not_valid_after_utc > _NOW() + dt.timedelta(days=30)
        if same_ca and fresh and ips <= have_ips and names <= have_names:
            return str(SRV_CERT), str(SRV_KEY)

    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.DNSName(n) for n in sorted(names)] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
    cert = (x509.CertificateBuilder()
            .subject_name(_name("NEXUS server")).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW() - dt.timedelta(minutes=5))
            .not_valid_after(_NOW() + dt.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write_key(SRV_KEY, key)
    SRV_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(SRV_CERT), str(SRV_KEY)


def ca_fingerprint() -> str:
    """SHA-256 fingerprint of the CA certificate, to compare on the phone before trusting it."""
    if not CA_CERT.exists():
        return ""
    cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def start_mdns(ip: str, port: int):
    """Optional: answer to the name nexus.local on the local network (pip install zeroconf)."""
    try:
        from zeroconf import ServiceInfo, Zeroconf
        info = ServiceInfo("_https._tcp.local.", "NEXUS._https._tcp.local.",
                           addresses=[socket.inet_aton(ip)], port=port, server="nexus.local.")
        zc = Zeroconf()
        zc.register_service(info)
        return zc
    except Exception as exc:  # missing package, no multicast, etc.: never block startup
        print(f"  (nexus.local name not started: {exc})")
        return None
