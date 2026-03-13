"""
NotTheNet - TLS Certificate Utility
Generates self-signed certificates for HTTPS/SMTPS/IMAPS simulation,
and dynamically forges per-domain certificates using an internal Root CA.

Features:
- Static self-signed cert generation (default mode)
- Root CA generation + per-domain cert forging (dynamic_certs mode)
- LRU-cached per-domain certs to avoid regeneration overhead
- SNI callback for ssl.SSLContext to serve the correct cert per hostname

Security notes (OpenSSF):
- RSA 2048-bit minimum; 4096-bit used by default
- SHA-256 signature
- SAN extension included (CN-only certs are deprecated per RFC 2818)
- No MD5, no SHA-1
- Private key written with mode 0o600 (owner-read only)
"""

from __future__ import annotations

import ipaddress
import logging
import os
import ssl
import stat
import threading
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def generate_self_signed_cert(
    cert_path: str,
    key_path: str,
    common_name: str = "www.example.com",
    days_valid: int = 825,
    key_bits: int = 4096,
    san_ips: list | None = None,
    san_dns: list | None = None,
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
    san_dns = san_dns or ["www.example.com", "example.com"]

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
        san_list: list = []
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


# ─── Root CA & Dynamic Per-Domain Certificate Generation ───────────────────


def generate_ca_cert(
    ca_cert_path: str,
    ca_key_path: str,
    common_name: str = "DigiCert Global Root CA",
    days_valid: int = 3650,
    key_bits: int = 4096,
) -> bool:
    """
    Generate a Root CA certificate + key for on-the-fly domain cert signing.

    The CA cert is self-signed with BasicConstraints(ca=True).
    Malware analysts should install this CA into the analysis VM's trust
    store if they want intercepted HTTPS to appear valid.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        logger.error("cryptography package required for CA generation.")
        return False

    if key_bits < 2048:
        key_bits = 2048

    logger.info(f"Generating Root CA: CN={common_name}, {key_bits}-bit RSA")

    try:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_bits
        )

        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigiCert Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=days_valid))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        os.makedirs(os.path.dirname(os.path.abspath(ca_cert_path)), exist_ok=True)
        with open(ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(ca_key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        os.chmod(ca_key_path, stat.S_IRUSR | stat.S_IWUSR)

        logger.info(f"Root CA cert written to {ca_cert_path}")
        logger.info(f"Root CA key  written to {ca_key_path} (mode 0o600)")
        return True
    except Exception as e:
        logger.error(f"CA certificate generation failed: {e}", exc_info=True)
        return False


def ensure_ca(ca_cert_path: str, ca_key_path: str, **kwargs) -> bool:
    """Ensure Root CA exists; generate if missing."""
    if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
        logger.debug("Existing CA certificates found; skipping generation.")
        return True
    return generate_ca_cert(ca_cert_path, ca_key_path, **kwargs)


def forge_domain_cert(
    hostname: str,
    ca_cert_path: str,
    ca_key_path: str,
    key_bits: int = 2048,
    days_valid: int = 365,
) -> tuple[bytes, bytes]:
    """
    Dynamically forge a certificate for *hostname*, signed by our Root CA.

    Returns:
        (cert_pem_bytes, key_pem_bytes)

    Raises:
        RuntimeError if CA key/cert cannot be loaded.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Validate hostname: DNS labels must not start or end with a hyphen (RFC 1123)
    for label in hostname.split("."):
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"Invalid DNS label in hostname: {label!r}")

    # Load CA
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate ephemeral key for this domain (2048-bit is enough for short-lived)
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_bits
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # Build SANs: the requested hostname + a wildcard variant
    san_list: list[x509.GeneralName] = [x509.DNSName(hostname)]
    parts = hostname.split(".")
    if len(parts) >= 2:
        wildcard = "*." + ".".join(parts[1:])
        san_list.append(x509.DNSName(wildcard))
    # If hostname looks like an IP, add IPAddress SAN
    try:
        san_list.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        pass

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName(san_list), critical=False
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()  # type: ignore[arg-type]  # always RSA; cryptography stubs return a wider union
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]  # same reason
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class DynamicCertCache:
    """
    Thread-safe LRU cache of forged per-domain TLS certificates.

    Usage:
        cache = DynamicCertCache("certs/ca.crt", "certs/ca.key")
        ssl_ctx.sni_callback = cache.sni_callback
    """

    MAX_CACHE_SIZE = 500

    def __init__(
        self,
        default_cert_path: str,
        default_key_path: str,
        ca_cert_path: str = "certs/ca.crt",
        ca_key_path: str = "certs/ca.key",
    ):
        self._default_cert = default_cert_path
        self._default_key = default_key_path
        self._ca_cert = ca_cert_path
        self._ca_key = ca_key_path
        self._cache: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

        # Ensure Root CA exists
        ensure_ca(self._ca_cert, self._ca_key)

    def _build_ctx_for_hostname(self, hostname: str) -> ssl.SSLContext:
        """Forge a cert for *hostname* and return a configured SSLContext."""
        cert_pem, key_pem = forge_domain_cert(
            hostname, self._ca_cert, self._ca_key
        )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load from in-memory PEM by writing to temp files.
        # Sanitise hostname to prevent path traversal — only allow
        # alphanumerics, hyphens, dots, and underscores.
        import re as _re
        safe_host = _re.sub(r"[^a-zA-Z0-9.\-_]", "_", hostname)[:253]
        certs_dir = os.path.dirname(os.path.abspath(self._ca_cert))
        cert_file = os.path.join(certs_dir, f"_dyn_{safe_host}.crt")
        key_file = os.path.join(certs_dir, f"_dyn_{safe_host}.key")

        with open(cert_file, "wb") as f:
            f.write(cert_pem)
        with open(key_file, "wb") as f:
            f.write(key_pem)

        try:
            os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        logger.info(f"TLS  Forged certificate for: {hostname}")
        return ctx

    def sni_callback(
        self,
        ssl_socket: ssl.SSLSocket,
        server_name: str | None,
        ssl_context: ssl.SSLContext,
    ) -> int | None:
        """
        ssl.SSLContext SNI callback.

        Called during the TLS handshake when the client sends SNI.
        Forges a certificate for the requested hostname and switches
        the SSLSocket's context to serve it.
        """
        if not server_name:
            return None  # Fall through to default cert

        hostname = server_name.lower().strip()
        if not hostname:
            return None

        with self._lock:
            if hostname in self._cache:
                # Move to end so the entry is treated as recently-used (LRU)
                self._cache[hostname] = self._cache.pop(hostname)
                ssl_socket.context = self._cache[hostname]
                return None

        try:
            ctx = self._build_ctx_for_hostname(hostname)
        except Exception as e:
            logger.warning(f"TLS  Failed to forge cert for {hostname}: {e}")
            return None  # Fall back to default cert

        with self._lock:
            # Evict oldest entries if cache is full
            if len(self._cache) >= self.MAX_CACHE_SIZE:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[hostname] = ctx

        ssl_socket.context = ctx
        return None
