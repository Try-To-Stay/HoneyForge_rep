"""Generate the PKI for the disguised collector if absent.

Produces, in the shared certs volume:
- ca.crt / ca.key   — a local CA (the center uses ca.key to issue per-agent
  client certs for mTLS; nginx uses ca.crt to verify them; agents pin ca.crt);
- server.crt/key    — the collector's TLS cert, signed by the CA (SAN: nginx,
  localhost, honeyforge.local, 127.0.0.1).

Self-contained (Python cryptography), so `docker compose up` needs no host
openssl. Used for both plain-TLS and mTLS modes (MASK-1 / MASK-7).
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


def _write_key(path: str, key) -> None:
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def _write_cert(path: str, cert) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main(target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    ca_crt = os.path.join(target_dir, "ca.crt")
    ca_key = os.path.join(target_dir, "ca.key")
    srv_crt = os.path.join(target_dir, "server.crt")
    srv_key = os.path.join(target_dir, "server.key")

    if all(os.path.exists(p) for p in (ca_crt, ca_key, srv_crt, srv_key)):
        print(f"PKI already present in {target_dir}")
        return

    now = datetime.datetime.now(datetime.timezone.utc)

    # --- CA ---
    cakey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HoneyForge-CA")])
    cacert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(cakey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(cakey, hashes.SHA256())
    )

    # --- Server cert signed by the CA ---
    srvkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("honeyforge.local"),
        x509.DNSName("nginx"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ])
    srvcert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "honeyforge.local")]))
        .issuer_name(ca_name)
        .public_key(srvkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(san, critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(cakey, hashes.SHA256())
    )

    _write_key(ca_key, cakey)
    _write_cert(ca_crt, cacert)
    _write_key(srv_key, srvkey)
    _write_cert(srv_crt, srvcert)
    print(f"generated CA + server cert in {target_dir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/certs")
