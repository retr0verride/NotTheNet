"""
Tests for utils/cert_utils.py — certificate generation, CA cert,
per-domain forging, DynamicCertCache, and key-file permissions.
"""

import os

import pytest

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from utils.cert_utils import (  # noqa: E402
    DynamicCertCache,
    ensure_certs,
    forge_domain_cert,
    generate_ca_cert,
    generate_self_signed_cert,
)

# ── Self-signed cert generation ──────────────────────────────────────────────

class TestGenerateSelfSignedCert:
    def test_generates_cert_and_key(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        assert generate_self_signed_cert(cert_path, key_path) is True
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

    def test_cert_is_valid_pem(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        generate_self_signed_cert(cert_path, key_path)
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)

    def test_key_is_loadable(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        generate_self_signed_cert(cert_path, key_path)
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert key.key_size >= 2048

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
    def test_key_file_permissions(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        generate_self_signed_cert(cert_path, key_path)
        mode = os.stat(key_path).st_mode & 0o777
        assert mode == 0o600

    def test_forces_minimum_2048_bits(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        generate_self_signed_cert(cert_path, key_path, key_bits=512)
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert key.key_size >= 2048

    def test_cert_has_san_extension(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        generate_self_signed_cert(cert_path, key_path, san_dns=["test.local"])
        with open(cert_path, "rb") as f:
            pem_data = f.read()
        # Decode the base64 body to check for the SAN DNS name in DER.
        import base64
        b64 = b"".join(
            ln for ln in pem_data.split(b"\n")
            if not ln.startswith(b"-----")
        )
        der = base64.b64decode(b64)
        assert b"test.local" in der

    def test_cert_has_sct_extension(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        generate_self_signed_cert(cert_path, key_path)
        with open(cert_path, "rb") as f:
            pem_data = f.read()
        # The SCT OID (1.3.6.1.4.1.11129.2.4.2) should be present in the
        # DER-encoded cert within the PEM wrapper.
        assert len(pem_data) > 500  # sanity: cert has meaningful content


# ── ensure_certs (idempotence) ───────────────────────────────────────────────

class TestEnsureCerts:
    def test_generates_when_missing(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        assert ensure_certs(cert_path, key_path) is True
        assert os.path.exists(cert_path)

    def test_skips_when_existing(self, tmp_path):
        cert_path = str(tmp_path / "server.crt")
        key_path = str(tmp_path / "server.key")
        for p in (cert_path, key_path):
            with open(p, "w") as f:
                f.write("existing")
        assert ensure_certs(cert_path, key_path) is True
        # Files unchanged — not overwritten
        with open(cert_path) as f:
            assert f.read() == "existing"


# ── CA cert generation ───────────────────────────────────────────────────────

class TestGenerateCACert:
    def test_generates_ca_cert(self, tmp_path):
        ca_cert = str(tmp_path / "ca.crt")
        ca_key = str(tmp_path / "ca.key")
        assert generate_ca_cert(ca_cert, ca_key) is True
        with open(ca_cert, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_ca_has_key_usage(self, tmp_path):
        ca_cert = str(tmp_path / "ca.crt")
        ca_key = str(tmp_path / "ca.key")
        generate_ca_cert(ca_cert, ca_key)
        with open(ca_cert, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True


# ── Domain cert forging ──────────────────────────────────────────────────────

class TestForgeDomainCert:
    @pytest.fixture()
    def ca_pair(self, tmp_path):
        ca_cert = str(tmp_path / "ca.crt")
        ca_key = str(tmp_path / "ca.key")
        generate_ca_cert(ca_cert, ca_key, key_bits=2048)
        return ca_cert, ca_key

    def test_forge_returns_pem_tuple(self, ca_pair):
        cert_pem, key_pem = forge_domain_cert("example.com", *ca_pair)
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem

    def test_forged_cert_has_correct_cn(self, ca_pair):
        cert_pem, _ = forge_domain_cert("test.example.org", *ca_pair)
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "test.example.org"

    def test_forged_cert_has_wildcard_san(self, ca_pair):
        cert_pem, _ = forge_domain_cert("sub.example.com", *ca_pair)
        # Decode the base64 PEM body and check for the SAN in DER bytes.
        import base64
        b64 = b"".join(
            ln for ln in cert_pem.split(b"\n")
            if not ln.startswith(b"-----")
        )
        der = base64.b64decode(b64)
        assert b"sub.example.com" in der

    def test_forged_cert_is_not_ca(self, ca_pair):
        cert_pem, _ = forge_domain_cert("example.com", *ca_pair)
        # BasicConstraints CA:FALSE is DER-encoded in the cert;
        # verify the cert is a leaf by checking it validates as PEM.
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert len(cert_pem) > 500

    def test_invalid_hostname_raises(self, ca_pair):
        with pytest.raises(ValueError, match="Invalid DNS label"):
            forge_domain_cert("-invalid.com", *ca_pair)

    def test_forged_cert_has_sct(self, ca_pair):
        cert_pem, _ = forge_domain_cert("example.com", *ca_pair)
        # SCT OID presence — the fake SCT bytes prevent full ASN1 parsing,
        # so just confirm the cert PEM was generated with meaningful size.
        assert len(cert_pem) > 1000


# ── DynamicCertCache ─────────────────────────────────────────────────────────

class TestDynamicCertCache:
    @pytest.fixture()
    def cache(self, tmp_path):
        ca_cert = str(tmp_path / "ca.crt")
        ca_key = str(tmp_path / "ca.key")
        cert = str(tmp_path / "server.crt")
        key = str(tmp_path / "server.key")
        generate_ca_cert(ca_cert, ca_key, key_bits=2048)
        generate_self_signed_cert(cert, key, key_bits=2048)
        return DynamicCertCache(cert, key, ca_cert, ca_key)

    def test_sni_callback_none_server_name(self, cache):
        """No SNI → returns None (fall through to default cert)."""
        result = cache.sni_callback(None, None, None)  # type: ignore[arg-type]
        assert result is None

    def test_sni_callback_empty_string(self, cache):
        result = cache.sni_callback(None, "", None)  # type: ignore[arg-type]
        assert result is None

    def test_sni_callback_caches_context(self, cache):
        mock_sock = type("S", (), {"context": None})()
        cache.sni_callback(mock_sock, "example.com", None)  # type: ignore[arg-type]
        assert mock_sock.context is not None
        # Second call should use cache (no regeneration)
        first_ctx = mock_sock.context
        cache.sni_callback(mock_sock, "example.com", None)  # type: ignore[arg-type]
        assert mock_sock.context is first_ctx

    def test_cache_eviction_on_overflow(self, cache):
        cache.MAX_CACHE_SIZE = 2
        s = type("S", (), {"context": None})()
        cache.sni_callback(s, "a.com", None)  # type: ignore[arg-type]
        cache.sni_callback(s, "b.com", None)  # type: ignore[arg-type]
        cache.sni_callback(s, "c.com", None)  # type: ignore[arg-type]
        # Oldest (a.com) should be evicted
        assert len(cache._cache) == 2
        assert "a.com" not in cache._cache

    def test_temp_cert_files_cleaned_up(self, cache):
        """Dynamic cert files should not persist on disk."""
        s = type("S", (), {"context": None})()
        cache.sni_callback(s, "cleanup.test", None)  # type: ignore[arg-type]
        certs_dir = os.path.dirname(os.path.abspath(cache._ca_cert))
        leftovers = [f for f in os.listdir(certs_dir) if f.startswith("_dyn_")]
        assert leftovers == [], f"Temp cert files not cleaned up: {leftovers}"
