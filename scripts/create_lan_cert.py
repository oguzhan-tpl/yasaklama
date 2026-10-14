from __future__ import annotations

import argparse
import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a local self-signed HTTPS certificate for Yasaklama.")
    parser.add_argument("--ip", required=True, help="LAN IPv4 address used to open the admin panel")
    parser.add_argument("--output-dir", default="data")
    args = parser.parse_args()

    try:
        lan_ip = ipaddress.ip_address(args.ip)
        if lan_ip.version != 4 or lan_ip.is_loopback or lan_ip.is_unspecified:
            raise ValueError
    except ValueError as exc:
        raise SystemExit("--ip must be a usable LAN IPv4 address.") from exc

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cert_path = output_dir / "server-cert.pem"
    key_path = output_dir / "server-key.pem"
    if cert_path.exists() or key_path.exists():
        print("TLS certificate already exists; leaving it unchanged.")
        return

    hostname = socket.gethostname().strip() or "yasaklama-server"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yasaklama LAN"),
    ])
    now = datetime.now(timezone.utc)
    sans = [
        x509.IPAddress(lan_ip),
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=None,
            decipher_only=None,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    # Exclusive creation avoids overwriting an existing private key.
    key_fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(key_fd, "wb") as handle:
        handle.write(key_bytes)
    cert_fd = os.open(cert_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(cert_fd, "wb") as handle:
        handle.write(cert_bytes)

    print(f"Certificate: {cert_path}")
    print(f"Private key: {key_path}")
    print("This is a self-signed certificate. Browsers on other devices will warn until the")
    print("certificate is trusted by your school's managed device policy or replaced with")
    print("a certificate issued by an existing trusted school CA.")
    

if __name__ == "__main__":
    main()
