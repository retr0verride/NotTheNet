"""
Cloud Exfiltration Route Handlers

Intercepts and logs upload attempts to fake cloud storage endpoints:
  - AWS S3 (virtual-hosted + path-style)
  - Azure Blob Storage
  - Microsoft Graph / OneDrive
  - Dropbox
  - Google Drive

Why this matters:
    Modern ransomware (BlackCat/ALPHV, LockBit 3, Cl0p, Akira) exfiltrates
    data to cloud storage before encrypting — the "double-extortion" pattern.
    These handlers intercept those uploads, log them, and save the raw body to
    logs/exfil/ so analysts can inspect what the malware attempted to send.

    Captured IOCs:
      - Bearer tokens (OAuth2 — often hardcoded in ransomware config blobs)
      - Bucket/container/path names
      - Payload bytes (capped at _MAX_EXFIL_BODY_BYTES per request)

Security notes (OpenSSF):
  - Request body capped at _MAX_EXFIL_BODY_BYTES to prevent disk exhaustion
  - Filenames are timestamp + sanitised IP + UUID suffix — no user input in names
  - No eval/exec of any captured data
  - Bearer tokens logged as IOCs — intentional (they're malware artefacts)
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

# Per-request body capture cap: 10 MB.
# Sufficient for credential dumps, documents, config blobs; prevents a single
# large binary from exhausting memory during read.
_MAX_EXFIL_BODY_BYTES = 10 * 1024 * 1024  # 10 MB


# ── Internal helpers ──────────────────────────────────────────────────────────

def _read_body(handler, max_bytes: int) -> bytes:
    """Read the request body up to max_bytes bytes."""
    try:
        cl = int(handler.headers.get("Content-Length", 0))
    except (ValueError, TypeError):
        cl = 0
    if cl > 0:
        return handler.rfile.read(min(cl, max_bytes))
    return b""


def _save_exfil_body(src_ip: str, service: str, body: bytes, log_dir: str) -> str | None:
    """Write raw captured body to disk.

    Returns the saved file path on success, None on error or empty body.
    Filename format: {unix_ts}_{sanitised_ip}_{service}_{8hex}.bin
    """
    if not body or not log_dir:
        return None
    try:
        os.makedirs(log_dir, exist_ok=True)
        safe_ip = src_ip.replace(":", "_").replace(".", "_")
        fname = f"{int(time.time())}_{safe_ip}_{service}_{uuid.uuid4().hex[:8]}.bin"
        fpath = os.path.join(log_dir, fname)
        with open(fpath, "wb") as fh:
            fh.write(body)
        return fpath
    except OSError as exc:
        logger.debug("cloud_exfil: failed to save body for %s: %s", service, exc)
        return None


def _send_json(handler, status: int, obj: dict, server: str) -> None:
    """Send a JSON response; swallows OSError on client disconnect."""
    body = json.dumps(obj).encode()
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Server", server)
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
    except OSError:
        pass


def _send_empty(
    handler,
    status: int,
    extra_headers: dict[str, str],
    server: str,
) -> None:
    """Send an empty body response with optional extra headers."""
    try:
        handler.send_response(status)
        for k, v in extra_headers.items():
            handler.send_header(k, v)
        handler.send_header("Content-Length", "0")
        handler.send_header("Server", server)
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
    except OSError:
        pass


# ── Route handlers ────────────────────────────────────────────────────────────

def route_aws_s3(handler, host: str, max_body_size: int = _MAX_EXFIL_BODY_BYTES) -> bool:
    """Fake AWS S3 endpoint.

    Handles both virtual-hosted style ({bucket}.s3[.region].amazonaws.com)
    and path-style (s3[.region].amazonaws.com/{bucket}/{key}).

    PUT / POST  → accept upload, capture body, return 200 + ETag.
    GET / HEAD  → return 200 (object exists, no data).
    DELETE      → return 204.
    """
    src_ip = handler.client_address[0]
    path = handler.path or "/"
    method = handler.command or ""
    auth = handler.headers.get("Authorization", "")

    # Determine bucket + key for logging
    # Path-style: host is s3[.region].amazonaws.com → first path component is bucket
    # Virtual-hosted: host is {bucket}.s3[.region].amazonaws.com
    host_parts = host.split(".")
    if host_parts[0] == "s3" or (len(host_parts) > 1 and host_parts[1] == "s3"):
        # Path-style: s3.amazonaws.com or s3.us-east-1.amazonaws.com
        parts = path.lstrip("/").split("/", 1)
        bucket = parts[0] if parts else ""
        key = parts[1] if len(parts) > 1 else ""
    else:
        # Virtual-hosted: {bucket}.s3[.region].amazonaws.com
        bucket = host_parts[0]
        key = path.lstrip("/")

    body = b""
    if method in ("PUT", "POST"):
        body = _read_body(handler, max_body_size)

    log_dir = getattr(handler._cfg, "exfil_log_dir", "")
    fpath = _save_exfil_body(src_ip, "s3", body, log_dir) if body else None

    safe_addr = sanitize_ip(src_ip)
    logger.info(
        "EXFIL S3   %s s3://%s/%s from %s (%d bytes%s)",
        method,
        sanitize_log_string(bucket, 64),
        sanitize_log_string(key, 128),
        safe_addr,
        len(body),
        f" -> {fpath}" if fpath else "",
    )

    jl = get_json_logger()
    if jl:
        jl.log(
            "cloud_exfil_s3",
            src_ip=src_ip,
            method=method,
            bucket=bucket,
            key=key,
            bytes=len(body),
            auth_header=auth[:64] if auth else "",
            saved_to=fpath or "",
        )

    etag = f'"{os.urandom(8).hex()}"'
    req_id = os.urandom(6).hex().upper()
    if method == "DELETE":
        _send_empty(handler, 204, {"x-amz-request-id": req_id}, "AmazonS3")
    elif method in ("PUT", "POST"):
        _send_empty(
            handler, 200,
            {"ETag": etag, "x-amz-request-id": req_id},
            "AmazonS3",
        )
    else:
        _send_empty(
            handler, 200,
            {
                "ETag": etag,
                "Content-Type": "application/octet-stream",
                "x-amz-request-id": req_id,
                "Last-Modified": datetime.now(timezone.utc).strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                ),
            },
            "AmazonS3",
        )
    return True


def route_azure_blob(
    handler, host: str, max_body_size: int = _MAX_EXFIL_BODY_BYTES
) -> bool:
    """Fake Azure Blob Storage endpoint ({account}.blob.core.windows.net).

    PUT     → accept block or blob upload, capture body, return 201.
    GET/HEAD → 200.
    DELETE  → 202.
    """
    src_ip = handler.client_address[0]
    path = handler.path or "/"
    method = handler.command or ""
    auth = handler.headers.get("Authorization", "")

    account = host.split(".")[0]
    path_clean = path.split("?")[0]
    parts = path_clean.lstrip("/").split("/", 1)
    container = parts[0] if parts else ""
    blob = parts[1] if len(parts) > 1 else ""

    body = b""
    if method == "PUT":
        body = _read_body(handler, max_body_size)

    log_dir = getattr(handler._cfg, "exfil_log_dir", "")
    fpath = _save_exfil_body(src_ip, "azure_blob", body, log_dir) if body else None

    safe_addr = sanitize_ip(src_ip)
    logger.info(
        "EXFIL BLOB  %s https://%s.blob.core.windows.net/%s/%s from %s (%d bytes%s)",
        method,
        sanitize_log_string(account, 32),
        sanitize_log_string(container, 64),
        sanitize_log_string(blob, 128),
        safe_addr,
        len(body),
        f" -> {fpath}" if fpath else "",
    )

    jl = get_json_logger()
    if jl:
        jl.log(
            "cloud_exfil_azure_blob",
            src_ip=src_ip,
            method=method,
            account=account,
            container=container,
            blob=blob,
            bytes=len(body),
            auth_header=auth[:64] if auth else "",
            saved_to=fpath or "",
        )

    request_id = str(uuid.uuid4())
    etag = f'"0x8{os.urandom(7).hex().upper()}"'
    common: dict[str, str] = {
        "x-ms-request-id": request_id,
        "x-ms-version": "2020-10-02",
        "x-ms-content-crc64": os.urandom(8).hex(),
    }
    server = "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0"
    if method == "DELETE":
        _send_empty(handler, 202, common, server)
    elif method == "PUT":
        _send_empty(handler, 201, {**common, "ETag": etag}, server)
    else:
        _send_empty(
            handler, 200,
            {**common, "ETag": etag, "Content-Type": "application/octet-stream"},
            server,
        )
    return True


def route_graph_onedrive(handler, max_body_size: int = _MAX_EXFIL_BODY_BYTES) -> bool:
    """Fake Microsoft Graph / OneDrive upload endpoint (graph.microsoft.com).

    PUT  /v1.0/me/drive/root:/{path}:/content  → 201 + DriveItem JSON
    POST /v1.0/.../createUploadSession          → 200 + uploadUrl
    Other non-upload paths                      → return False (fall through)

    Bearer tokens in Authorization header are logged as IOCs.
    """
    path = handler.path or "/"
    method = handler.command or ""
    low = path.lower()

    is_upload = (
        "/content" in low
        or "uploadsession" in low
        or (method in ("PUT", "POST", "PATCH") and "/drive" in low)
    )
    if not is_upload:
        return False

    src_ip = handler.client_address[0]
    auth = handler.headers.get("Authorization", "")

    body = b""
    if method in ("PUT", "POST", "PATCH"):
        body = _read_body(handler, max_body_size)

    log_dir = getattr(handler._cfg, "exfil_log_dir", "")
    fpath = _save_exfil_body(src_ip, "graph_onedrive", body, log_dir) if body else None

    safe_addr = sanitize_ip(src_ip)
    logger.info(
        "EXFIL GRAPH %s %s from %s (%d bytes%s)",
        method,
        sanitize_log_string(path, 128),
        safe_addr,
        len(body),
        f" -> {fpath}" if fpath else "",
    )

    bearer = auth[7:64] if auth.lower().startswith("bearer ") else ""
    jl = get_json_logger()
    if jl:
        jl.log(
            "cloud_exfil_graph",
            src_ip=src_ip,
            method=method,
            path=path,
            bytes=len(body),
            bearer_token=bearer,
            saved_to=fpath or "",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    item_id = os.urandom(16).hex().upper()
    server = "Microsoft-IIS/10.0"

    if "uploadsession" in low:
        _send_json(
            handler, 200,
            {
                "uploadUrl": "https://sn3302.up.1drv.com/up/fe6987415ace7X4e1eF866337",
                "expirationDateTime": "2099-01-01T00:00:00Z",
                "nextExpectedRanges": ["0-"],
            },
            server,
        )
    else:
        filename = path.split("/")[-1].split("?")[0] or "upload.bin"
        # Colon separates OneDrive path from action — strip trailing ':' / 'content'
        filename = filename.rstrip(":") or "upload.bin"
        _send_json(
            handler, 201,
            {
                "@odata.context": (
                    "https://graph.microsoft.com/v1.0/$metadata"
                    "#drives/items/$entity"
                ),
                "id": item_id,
                "name": filename,
                "size": len(body),
                "createdDateTime": now_iso,
                "lastModifiedDateTime": now_iso,
                "eTag": f'"{item_id},{1}"',
                "file": {"mimeType": "application/octet-stream"},
                "parentReference": {"driveType": "personal"},
            },
            server,
        )
    return True


def route_dropbox(handler, max_body_size: int = _MAX_EXFIL_BODY_BYTES) -> bool:
    """Fake Dropbox API endpoint (content.dropboxapi.com, api.dropboxapi.com).

    POST /2/files/upload                    → 200 + FileMetadata JSON
    POST /2/files/upload_session/start      → 200 + session_id
    POST /2/files/upload_session/append_v2  → 200
    POST /2/files/upload_session/finish     → 200 + FileMetadata JSON
    Other                                   → 200 + minimal stub
    """
    src_ip = handler.client_address[0]
    path = handler.path or "/"
    method = handler.command or ""
    auth = handler.headers.get("Authorization", "")

    # Dropbox-API-Arg header contains JSON metadata (path, mode, etc.)
    dbx_arg: dict = {}
    dbx_arg_raw = handler.headers.get("Dropbox-API-Arg", "{}")
    try:
        dbx_arg = json.loads(dbx_arg_raw)
    except Exception:
        logger.debug("cloud_exfil: Dropbox-API-Arg parse failed", exc_info=True)

    remote_path = str(dbx_arg.get("path", path))

    body = b""
    if method in ("POST", "PUT"):
        body = _read_body(handler, max_body_size)

    log_dir = getattr(handler._cfg, "exfil_log_dir", "")
    fpath = _save_exfil_body(src_ip, "dropbox", body, log_dir) if body else None

    safe_addr = sanitize_ip(src_ip)
    logger.info(
        "EXFIL DROPBOX %s %s from %s (%d bytes%s)",
        method,
        sanitize_log_string(remote_path, 128),
        safe_addr,
        len(body),
        f" -> {fpath}" if fpath else "",
    )

    bearer = auth[7:64] if auth.lower().startswith("bearer ") else ""
    jl = get_json_logger()
    if jl:
        jl.log(
            "cloud_exfil_dropbox",
            src_ip=src_ip,
            method=method,
            path=path,
            remote_path=remote_path[:128],
            bytes=len(body),
            bearer_token=bearer,
            saved_to=fpath or "",
        )

    low = path.lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    name = remote_path.split("/")[-1] or "upload.bin"

    if "upload_session/start" in low:
        _send_json(handler, 200, {"session_id": uuid.uuid4().hex}, "nginx")
    elif "upload_session/append" in low:
        _send_empty(handler, 200, {}, "nginx")
    else:
        _send_json(
            handler, 200,
            {
                ".tag": "file",
                "name": name,
                "path_lower": remote_path.lower(),
                "path_display": remote_path,
                "id": f"id:{os.urandom(16).hex()}",
                "client_modified": now_iso,
                "server_modified": now_iso,
                "rev": os.urandom(8).hex(),
                "size": len(body),
                "is_downloadable": True,
                "content_hash": os.urandom(32).hex(),
            },
            "nginx",
        )
    return True


def route_gdrive_upload(handler, max_body_size: int = _MAX_EXFIL_BODY_BYTES) -> bool:
    """Fake Google Drive upload endpoint (www.googleapis.com/upload/drive/...).

    POST /upload/drive/v3/files              → 200 + File resource JSON
    PUT  /upload/drive/v3/files/{fileId}     → 200 + File resource JSON
    Returns False if path is not an upload path (falls through to dead-drop handler).
    """
    path = handler.path or "/"
    if not path.startswith("/upload/drive/"):
        return False

    src_ip = handler.client_address[0]
    method = handler.command or ""
    auth = handler.headers.get("Authorization", "")

    body = b""
    if method in ("POST", "PUT", "PATCH"):
        body = _read_body(handler, max_body_size)

    log_dir = getattr(handler._cfg, "exfil_log_dir", "")
    fpath = _save_exfil_body(src_ip, "gdrive", body, log_dir) if body else None

    safe_addr = sanitize_ip(src_ip)
    logger.info(
        "EXFIL GDRIVE %s %s from %s (%d bytes%s)",
        method,
        sanitize_log_string(path, 128),
        safe_addr,
        len(body),
        f" -> {fpath}" if fpath else "",
    )

    bearer = auth[7:64] if auth.lower().startswith("bearer ") else ""
    jl = get_json_logger()
    if jl:
        jl.log(
            "cloud_exfil_gdrive",
            src_ip=src_ip,
            method=method,
            path=path,
            bytes=len(body),
            bearer_token=bearer,
            saved_to=fpath or "",
        )

    file_id = os.urandom(16).hex()
    now_iso = datetime.now(timezone.utc).isoformat()
    _send_json(
        handler, 200,
        {
            "kind": "drive#file",
            "id": file_id,
            "name": "upload",
            "mimeType": "application/octet-stream",
            "createdTime": now_iso,
            "modifiedTime": now_iso,
            "size": str(len(body)),
            "md5Checksum": os.urandom(16).hex(),
        },
        "ESF",
    )
    return True
