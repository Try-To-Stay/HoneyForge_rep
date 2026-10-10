"""Generate a self-signed TLS cert/key for the disguised collector if absent.

Runs as an init container (cert-init) writing into the shared certs volume, so
`docker compose up` is fully self-contained — no host openssl needed. For
non-Docker dev, scripts/gen-certs.sh does the same with openssl.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main(target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    crt_path = os.path.join(target_dir, "server.crt")
    key_path = os.path.join(target_dir, "server.key")
    if os.path.exists(crt_path) and os.path.exists(key_path):
        print(f"certs already present in {target_dir}")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "honeyforge.local")])
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.DNSName("honeyforge.local"),
            x509.DNSName("nginx"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"generated self-signed cert/key in {target_dir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/certs")
