"""
NotTheNet - TLS Certificate Utility
Generates self-signed certificates for HTTPS/SMTPS/IMAPS simulation.

Security notes (OpenSSF):
- RSA 2048-bit minimum; 4096-bit used by default
- SHA-256 signature
- SAN extension included (CN-only certs are deprecated per RFC 2818)
- No MD5, no SHA-1
- Private key written with mode 0o600 (owner-read only)
"""

import ipaddress
import logging
import os
import stat
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def generate_self_signed_cert(
    cert_path: str,
    key_path: str,
    common_name: str = "notthenet.local",
    days_valid: int = 825,
    key_bits: int = 4096,
    san_ips: list = None,
    san_dns: list = None,
) -> bool:
    """
    Generate a self-signed X.509 certificate and private key.

    Args:
        cert_path:   Output path for PEM certificate.
        key_path:    Output path for PEM private key.
        common_name: Certificate CN field.
        days_valid:  Certificate validity in days (≤825 per browser policy).
        key_bits:    RSA key size in bits (minimum 2048, default 4096).
        san_ips:     List of IP SAN entries (e.g. ["127.0.0.1"]).
        san_dns:     List of DNS SAN entries (e.g. ["localhost"]).

    Returns:
        True on success, False on failure.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        logger.error(
            "cryptography package not found. Run: pip install cryptography"
        )
        return False

    if key_bits < 2048:
        logger.warning("key_bits < 2048 is insecure; forcing 2048.")
        key_bits = 2048

    san_ips = san_ips or ["127.0.0.1"]
    san_dns = san_dns or ["localhost", "notthenet.local"]

    logger.info(
        f"Generating {key_bits}-bit RSA self-signed cert for CN={common_name}"
    )

    try:
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_bits,
        )

        # Build Subject / Issuer
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        )

        # Build SAN extension
        san_list = []
        for ip in san_ips:
            try:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                logger.warning(f"Invalid SAN IP skipped: {ip}")
        for dns in san_dns:
            san_list.append(x509.DNSName(dns))

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=days_valid))
            .add_extension(
                x509.SubjectAlternativeName(san_list), critical=False
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Write certificate (world-readable is fine for a cert)
        os.makedirs(os.path.dirname(os.path.abspath(cert_path)), exist_ok=True)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Write private key — owner-read only (0o600)
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

        logger.info(f"Certificate written to {cert_path}")
        logger.info(f"Private key written to {key_path} (mode 0o600)")
        return True

    except Exception as e:
        logger.error(f"Certificate generation failed: {e}", exc_info=True)
        return False


def ensure_certs(cert_path: str, key_path: str, **kwargs) -> bool:
    """
    Generate certs only if they don't already exist.
    Returns True if certs are present (existing or freshly generated).
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        logger.debug("Existing certificates found; skipping generation.")
        return True
    return generate_self_signed_cert(cert_path, key_path, **kwargs)
