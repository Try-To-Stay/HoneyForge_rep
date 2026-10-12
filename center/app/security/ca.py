"""Issue per-agent client certificates for mTLS (MASK-7).

The center holds the CA key and signs short-lived client certs. nginx verifies
them on the agent paths; agents pin the CA. Rotation = re-issuing a fresh cert
before expiry via /agent/rotate.
"""
from __future__ import annotations

import datetime
import functools
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.config import get_settings

settings = get_settings()


@functools.lru_cache
def _ca():
    certs_dir = settings.certs_dir
    with open(os.path.join(certs_dir, "ca.key"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(certs_dir, "ca.crt"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def ca_cert_pem() -> str:
    _, ca_cert = _ca()
    return ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def issue_client_cert(common_name: str, ttl_minutes: int | None = None):
    """Return (cert_pem, key_pem, not_after_iso) for a new client cert."""
    ttl = ttl_minutes or settings.client_cert_ttl_min
    ca_key, ca_cert = _ca()
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(minutes=ttl)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, not_after.isoformat()
