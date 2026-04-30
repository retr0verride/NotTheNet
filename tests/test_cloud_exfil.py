"""
Tests for services/cloud_exfil_routes.py

Covers: all five route handlers (S3, Azure Blob, MS Graph, Dropbox, GDrive),
body capture helpers, and host-matching regexes from http_server.py.
All tests are pure-function or use a lightweight mock handler — no live sockets.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from services.cloud_exfil_routes import (
    _read_body,
    _save_exfil_body,
    route_aws_s3,
    route_azure_blob,
    route_dropbox,
    route_gdrive_upload,
    route_graph_onedrive,
)
from services.http_server import (
    _AWS_S3_RE,
    _AZURE_BLOB_RE,
    _DROPBOX_HOSTS,
    _GRAPH_HOST,
    _HandlerConfig,
)

# ── Test helpers ──────────────────────────────────────────────────────────────

def _make_handler(
    method: str = "PUT",
    path: str = "/key.bin",
    headers: dict | None = None,
    body: bytes = b"",
    exfil_log_dir: str = "",
) -> MagicMock:
    """Return a minimal mock handler that mimics FakeHTTPHandler."""
    handler = MagicMock()
    handler.command = method
    handler.path = path
    handler.client_address = ("10.0.0.5", 54321)
    h = headers or {}
    handler.headers.get = lambda key, default="": h.get(key, default)
    handler.rfile = io.BytesIO(body)
    cfg = _HandlerConfig(exfil_log_dir=exfil_log_dir)
    handler._cfg = cfg  # noqa: SLF001

    # Capture send_response / send_header / end_headers / wfile.write calls
    handler.wfile = MagicMock()
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    return handler


def _sent_headers(handler) -> dict[str, str]:
    """Collect all send_header calls into a dict."""
    return {
        call.args[0]: call.args[1]
        for call in handler.send_header.call_args_list
        if call.args
    }


# ── _read_body ────────────────────────────────────────────────────────────────

class TestReadBody:
    def test_reads_up_to_content_length(self):
        payload = b"hello world"
        handler = _make_handler(body=payload, headers={"Content-Length": str(len(payload))})
        result = _read_body(handler, 1024)
        assert result == payload

    def test_respects_max_bytes(self):
        payload = b"A" * 100
        handler = _make_handler(body=payload, headers={"Content-Length": "100"})
        result = _read_body(handler, 50)
        assert len(result) == 50

    def test_empty_on_no_content_length(self):
        handler = _make_handler()
        assert _read_body(handler, 1024) == b""

    def test_handles_invalid_content_length(self):
        handler = _make_handler(headers={"Content-Length": "bad"})
        assert _read_body(handler, 1024) == b""


# ── _save_exfil_body ──────────────────────────────────────────────────────────

class TestSaveExfilBody:
    def test_saves_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = _save_exfil_body("10.0.0.1", "s3", b"payload", d)
            assert path is not None
            assert os.path.exists(path)
            assert open(path, "rb").read() == b"payload"

    def test_returns_none_on_empty_body(self):
        with tempfile.TemporaryDirectory() as d:
            assert _save_exfil_body("10.0.0.1", "s3", b"", d) is None

    def test_returns_none_on_empty_log_dir(self):
        assert _save_exfil_body("10.0.0.1", "s3", b"data", "") is None

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as base:
            sub = os.path.join(base, "exfil")
            _save_exfil_body("10.0.0.2", "azure_blob", b"x", sub)
            assert os.path.isdir(sub)

    def test_filename_contains_service(self):
        with tempfile.TemporaryDirectory() as d:
            path = _save_exfil_body("1.2.3.4", "dropbox", b"data", d)
            assert path is not None
            assert "dropbox" in os.path.basename(path)

    def test_ip_colon_sanitised(self):
        """IPv6 colons must not appear in filenames."""
        with tempfile.TemporaryDirectory() as d:
            path = _save_exfil_body("::1", "s3", b"data", d)
            assert path is not None
            assert ":" not in os.path.basename(path)


# ── Host-matching regexes from http_server ────────────────────────────────────

class TestHostRegexes:
    # AWS S3
    def test_s3_virtual_hosted(self):
        assert _AWS_S3_RE.search("mybucket.s3.amazonaws.com")

    def test_s3_virtual_hosted_region(self):
        assert _AWS_S3_RE.search("mybucket.s3.us-east-1.amazonaws.com")

    def test_s3_path_style(self):
        assert _AWS_S3_RE.search("s3.amazonaws.com")

    def test_s3_path_style_region(self):
        assert _AWS_S3_RE.search("s3.eu-west-1.amazonaws.com")

    def test_s3_no_match_checkip(self):
        # checkip.amazonaws.com is NOT an S3 host
        assert not _AWS_S3_RE.search("checkip.amazonaws.com")

    def test_s3_no_match_ec2(self):
        assert not _AWS_S3_RE.search("ec2.amazonaws.com")

    # Azure Blob
    def test_azure_blob_match(self):
        assert _AZURE_BLOB_RE.search("myaccount.blob.core.windows.net")

    def test_azure_blob_no_match_table(self):
        assert not _AZURE_BLOB_RE.search("myaccount.table.core.windows.net")

    # Graph + Dropbox constants
    def test_graph_host(self):
        assert _GRAPH_HOST == "graph.microsoft.com"

    def test_dropbox_hosts(self):
        assert "content.dropboxapi.com" in _DROPBOX_HOSTS
        assert "api.dropboxapi.com" in _DROPBOX_HOSTS


# ── route_aws_s3 ──────────────────────────────────────────────────────────────

class TestRouteAwsS3:
    def test_put_virtual_hosted_returns_true(self):
        handler = _make_handler("PUT", "/docs/report.pdf",
                                body=b"PAYLOAD",
                                headers={"Content-Length": "7"})
        assert route_aws_s3(handler, "exfil-bucket.s3.amazonaws.com") is True

    def test_put_returns_200(self):
        handler = _make_handler("PUT", "/k.bin", body=b"DATA",
                                headers={"Content-Length": "4"})
        route_aws_s3(handler, "bucket.s3.us-east-1.amazonaws.com")
        handler.send_response.assert_called_with(200)

    def test_delete_returns_204(self):
        handler = _make_handler("DELETE", "/k.bin")
        route_aws_s3(handler, "bucket.s3.amazonaws.com")
        handler.send_response.assert_called_with(204)

    def test_get_returns_200(self):
        handler = _make_handler("GET", "/k.bin")
        route_aws_s3(handler, "bucket.s3.amazonaws.com")
        handler.send_response.assert_called_with(200)

    def test_path_style_bucket_extraction(self):
        handler = _make_handler("PUT", "/mybucket/mykey.bin",
                                body=b"DATA", headers={"Content-Length": "4"})
        route_aws_s3(handler, "s3.amazonaws.com")
        handler.send_response.assert_called_with(200)

    def test_etag_header_present_on_put(self):
        handler = _make_handler("PUT", "/k.bin", body=b"X",
                                headers={"Content-Length": "1"})
        route_aws_s3(handler, "bucket.s3.amazonaws.com")
        headers = _sent_headers(handler)
        assert "ETag" in headers

    def test_amz_request_id_header_present(self):
        handler = _make_handler("GET", "/k.bin")
        route_aws_s3(handler, "bucket.s3.amazonaws.com")
        headers = _sent_headers(handler)
        assert "x-amz-request-id" in headers

    def test_body_saved_when_log_dir_set(self):
        with tempfile.TemporaryDirectory() as d:
            handler = _make_handler("PUT", "/k.bin", body=b"SECRET",
                                    headers={"Content-Length": "6"},
                                    exfil_log_dir=d)
            route_aws_s3(handler, "bucket.s3.amazonaws.com")
            files = os.listdir(d)
            assert any("s3" in f for f in files)

    def test_server_header_is_amazons3(self):
        handler = _make_handler("PUT", "/k.bin", body=b"X",
                                headers={"Content-Length": "1"})
        route_aws_s3(handler, "bucket.s3.amazonaws.com")
        headers = _sent_headers(handler)
        assert headers.get("Server") == "AmazonS3"


# ── route_azure_blob ──────────────────────────────────────────────────────────

class TestRouteAzureBlob:
    def test_put_returns_201(self):
        handler = _make_handler("PUT", "/container/blob.bin",
                                body=b"DATA", headers={"Content-Length": "4"})
        route_azure_blob(handler, "acct.blob.core.windows.net")
        handler.send_response.assert_called_with(201)

    def test_delete_returns_202(self):
        handler = _make_handler("DELETE", "/container/blob.bin")
        route_azure_blob(handler, "acct.blob.core.windows.net")
        handler.send_response.assert_called_with(202)

    def test_get_returns_200(self):
        handler = _make_handler("GET", "/container/blob.bin")
        route_azure_blob(handler, "acct.blob.core.windows.net")
        handler.send_response.assert_called_with(200)

    def test_etag_header_on_put(self):
        handler = _make_handler("PUT", "/c/b.bin", body=b"X",
                                headers={"Content-Length": "1"})
        route_azure_blob(handler, "acct.blob.core.windows.net")
        headers = _sent_headers(handler)
        assert "ETag" in headers
        assert headers["ETag"].startswith('"0x8')

    def test_ms_request_id_header(self):
        handler = _make_handler("GET", "/c/b.bin")
        route_azure_blob(handler, "acct.blob.core.windows.net")
        headers = _sent_headers(handler)
        assert "x-ms-request-id" in headers

    def test_body_captured(self):
        with tempfile.TemporaryDirectory() as d:
            handler = _make_handler("PUT", "/c/f.bin", body=b"EXFIL",
                                    headers={"Content-Length": "5"},
                                    exfil_log_dir=d)
            route_azure_blob(handler, "acct.blob.core.windows.net")
            files = os.listdir(d)
            assert any("azure_blob" in f for f in files)

    def test_returns_true(self):
        handler = _make_handler("PUT", "/c/b.bin", body=b"X",
                                headers={"Content-Length": "1"})
        assert route_azure_blob(handler, "acct.blob.core.windows.net") is True


# ── route_graph_onedrive ──────────────────────────────────────────────────────

class TestRouteGraphOneDrive:
    def test_content_path_returns_true(self):
        handler = _make_handler("PUT", "/v1.0/me/drive/root:/secret.docx:/content",
                                body=b"DOC", headers={"Content-Length": "3"})
        assert route_graph_onedrive(handler) is True

    def test_content_path_returns_201(self):
        handler = _make_handler("PUT", "/v1.0/me/drive/root:/secret.docx:/content",
                                body=b"DOC", headers={"Content-Length": "3"})
        route_graph_onedrive(handler)
        handler.send_response.assert_called_with(201)

    def test_upload_session_returns_200(self):
        handler = _make_handler("POST", "/v1.0/me/drive/root:/f.docx:/createUploadSession")
        route_graph_onedrive(handler)
        handler.send_response.assert_called_with(200)

    def test_upload_session_contains_upload_url(self):
        handler = _make_handler("POST", "/v1.0/me/drive/root:/f.docx:/createUploadSession")
        route_graph_onedrive(handler)
        written = handler.wfile.write.call_args[0][0]
        payload = json.loads(written)
        assert "uploadUrl" in payload

    def test_non_upload_path_returns_false(self):
        handler = _make_handler("GET", "/v1.0/me/profile")
        assert route_graph_onedrive(handler) is False

    def test_bearer_token_not_in_response(self):
        """Bearer token is logged as IOC but never echoed back."""
        handler = _make_handler(
            "PUT", "/v1.0/me/drive/root:/f.bin:/content",
            body=b"X", headers={"Content-Length": "1",
                                 "Authorization": "Bearer secret_token_123"},
        )
        route_graph_onedrive(handler)
        written = handler.wfile.write.call_args[0][0] if handler.wfile.write.called else b""
        assert b"secret_token_123" not in written

    def test_body_captured(self):
        with tempfile.TemporaryDirectory() as d:
            handler = _make_handler(
                "PUT", "/v1.0/me/drive/root:/f.bin:/content",
                body=b"DATA", headers={"Content-Length": "4"},
                exfil_log_dir=d,
            )
            route_graph_onedrive(handler)
            files = os.listdir(d)
            assert any("graph_onedrive" in f for f in files)

    def test_drive_put_without_content_keyword_matches(self):
        """PUT to /v1.0/.../drive/... without '/content' still matched."""
        handler = _make_handler("PUT", "/v1.0/me/drive/items/ABC123/children",
                                body=b"X", headers={"Content-Length": "1"})
        assert route_graph_onedrive(handler) is True


# ── route_dropbox ─────────────────────────────────────────────────────────────

class TestRouteDropbox:
    def test_upload_returns_true(self):
        handler = _make_handler("POST", "/2/files/upload",
                                body=b"FILE", headers={"Content-Length": "4"})
        assert route_dropbox(handler) is True

    def test_upload_returns_200(self):
        handler = _make_handler("POST", "/2/files/upload",
                                body=b"FILE", headers={"Content-Length": "4"})
        route_dropbox(handler)
        handler.send_response.assert_called_with(200)

    def test_upload_metadata_json(self):
        dbx_arg = json.dumps({"path": "/backup/creds.txt", "mode": "add"})
        handler = _make_handler("POST", "/2/files/upload",
                                body=b"DATA", headers={"Content-Length": "4",
                                                       "Dropbox-API-Arg": dbx_arg})
        route_dropbox(handler)
        written = json.loads(handler.wfile.write.call_args[0][0])
        assert written[".tag"] == "file"
        assert "creds.txt" in written["name"]

    def test_upload_session_start(self):
        handler = _make_handler("POST", "/2/files/upload_session/start",
                                body=b"CHUNK", headers={"Content-Length": "5"})
        route_dropbox(handler)
        handler.send_response.assert_called_with(200)
        written = json.loads(handler.wfile.write.call_args[0][0])
        assert "session_id" in written

    def test_upload_session_append_empty(self):
        handler = _make_handler("POST", "/2/files/upload_session/append_v2",
                                body=b"CHUNK", headers={"Content-Length": "5"})
        route_dropbox(handler)
        # append returns empty body (Content-Length: 0)
        headers = _sent_headers(handler)
        assert headers.get("Content-Length") == "0"

    def test_body_captured(self):
        with tempfile.TemporaryDirectory() as d:
            handler = _make_handler("POST", "/2/files/upload",
                                    body=b"SECRET", headers={"Content-Length": "6"},
                                    exfil_log_dir=d)
            route_dropbox(handler)
            assert any("dropbox" in f for f in os.listdir(d))

    def test_invalid_dbx_arg_does_not_crash(self):
        handler = _make_handler("POST", "/2/files/upload",
                                body=b"X", headers={"Content-Length": "1",
                                                    "Dropbox-API-Arg": "not json"})
        assert route_dropbox(handler) is True


# ── route_gdrive_upload ───────────────────────────────────────────────────────

class TestRouteGdriveUpload:
    def test_upload_path_returns_true(self):
        handler = _make_handler("POST", "/upload/drive/v3/files",
                                body=b"FILE", headers={"Content-Length": "4"})
        assert route_gdrive_upload(handler) is True

    def test_upload_path_returns_200(self):
        handler = _make_handler("POST", "/upload/drive/v3/files",
                                body=b"FILE", headers={"Content-Length": "4"})
        route_gdrive_upload(handler)
        handler.send_response.assert_called_with(200)

    def test_non_upload_path_returns_false(self):
        handler = _make_handler("GET", "/drive/v3/files")
        assert route_gdrive_upload(handler) is False

    def test_response_contains_file_id(self):
        handler = _make_handler("POST", "/upload/drive/v3/files",
                                body=b"DATA", headers={"Content-Length": "4"})
        route_gdrive_upload(handler)
        written = json.loads(handler.wfile.write.call_args[0][0])
        assert "id" in written
        assert written["kind"] == "drive#file"

    def test_size_in_response(self):
        payload = b"Hello Drive"
        handler = _make_handler("POST", "/upload/drive/v3/files",
                                body=payload,
                                headers={"Content-Length": str(len(payload))})
        route_gdrive_upload(handler)
        written = json.loads(handler.wfile.write.call_args[0][0])
        assert written["size"] == str(len(payload))

    def test_body_captured(self):
        with tempfile.TemporaryDirectory() as d:
            handler = _make_handler("POST", "/upload/drive/v3/files",
                                    body=b"EXFIL", headers={"Content-Length": "5"},
                                    exfil_log_dir=d)
            route_gdrive_upload(handler)
            assert any("gdrive" in f for f in os.listdir(d))

    def test_server_header_is_esf(self):
        handler = _make_handler("POST", "/upload/drive/v3/files",
                                body=b"X", headers={"Content-Length": "1"})
        route_gdrive_upload(handler)
        headers = _sent_headers(handler)
        assert headers.get("Server") == "ESF"


# ── HandlerConfig exfil_log_dir field ────────────────────────────────────────

class TestHandlerConfigExfilField:
    def test_default_value(self):
        cfg = _HandlerConfig()
        assert cfg.exfil_log_dir == "logs/exfil"

    def test_custom_value(self):
        cfg = _HandlerConfig(exfil_log_dir="logs/custom_exfil")
        assert cfg.exfil_log_dir == "logs/custom_exfil"

    def test_frozen(self):
        cfg = _HandlerConfig()
        with pytest.raises(AttributeError):
            cfg.exfil_log_dir = "/other"  # type: ignore[misc]
