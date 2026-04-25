"""Route handlers extracted from the HTTP server.

These functions keep endpoint behavior identical while reducing the size and
complexity of services/http_server.py.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import select
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs

from services.doh_websocket import (
    DOH_CONTENT_TYPE,
    build_websocket_close_frame,
    build_websocket_handshake_response,
    handle_doh_get,
    handle_doh_post,
)
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

_TELEGRAM_PATH_RE = re.compile(r"^/bot[^/]+/([A-Za-z]+)")
_DISCORD_WEBHOOK_RE = re.compile(r"^/api(?:/v\d+)?/webhooks/(\d+)/([A-Za-z0-9_-]+)")


def route_doh(handler, max_body_size: int) -> bool:
    """Handle DNS-over-HTTPS requests."""
    safe_addr = sanitize_ip(handler.client_address[0])
    path = handler.path or "/"
    if handler.command == "GET":
        response_data = handle_doh_get(path, handler._cfg.doh_redirect_ip)
    else:
        content_length = int(handler.headers.get("Content-Length", 0))
        body = (
            handler.rfile.read(min(content_length, max_body_size))
            if content_length > 0
            else b""
        )
        response_data = handle_doh_post(body, handler._cfg.doh_redirect_ip)

    if response_data:
        if handler._cfg.log_requests:
            logger.info("DoH   request from %s -> intercepted", safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log(
                "doh_request",
                src_ip=handler.client_address[0],
                method=handler.command or "",
                path=handler.path or "/",
            )
        try:
            handler.send_response(200)
            handler.send_header("Content-Type", DOH_CONTENT_TYPE)
            handler.send_header("Content-Length", str(len(response_data)))
            handler.send_header("Cache-Control", "no-cache")
            handler.send_header("Server", handler._cfg.server_header)
            handler.end_headers()
            handler.wfile.write(response_data)
        except OSError:
            pass
        return True

    return False


def route_websocket_upgrade(handler) -> bool:
    """Complete a WebSocket handshake and send a clean close frame."""
    safe_addr = sanitize_ip(handler.client_address[0])
    ws_key = handler.headers.get("Sec-WebSocket-Key", "")
    if not ws_key:
        return False

    if handler._cfg.log_requests:
        safe_path = sanitize_log_string(handler.path or "/", 256)
        handler.log_message(
            "WS upgrade from %s path=%s -> intercepted", safe_addr, safe_path
        )
    jl = get_json_logger()
    if jl:
        jl.log("websocket_upgrade", src_ip=handler.client_address[0], path=handler.path or "/")

    try:
        handshake = build_websocket_handshake_response(ws_key)
        handler.wfile.write(handshake)
        handler.wfile.flush()

        readable, _, _ = select.select([handler.rfile], [], [], 2.0)
        if readable:
            try:
                data = (
                    handler.rfile.read1(4096)
                    if hasattr(handler.rfile, "read1")
                    else handler.rfile.read(4096)
                )
                if data and handler._cfg.log_requests:
                    preview = sanitize_log_string(data[:64].hex(), 128)
                    handler.log_message("WS frame preview: %s", preview)
            except Exception:
                logger.debug("WebSocket frame recv failed", exc_info=True)

        close_frame = build_websocket_close_frame(1000, "intercepted")
        handler.wfile.write(close_frame)
        handler.wfile.flush()
    except OSError:
        pass
    return True


def route_telegram(handler, max_body_size: int, json_content_type: str) -> bool:
    """Fake Telegram Bot API responses for stealer/RAT C2 over Telegram."""
    path = handler.path or "/"
    m = _TELEGRAM_PATH_RE.match(path)
    if not m:
        return False

    method = m.group(1).lower()
    try:
        cl = int(handler.headers.get("Content-Length", 0))
    except (ValueError, TypeError):
        cl = 0
    raw_body = handler.rfile.read(min(cl, max_body_size)) if cl > 0 else b""

    token_match = re.match(r"^/bot([^/]+)/", path)
    bot_token = token_match.group(1) if token_match else ""

    chat_id = ""
    try:
        ct = handler.headers.get("Content-Type", "")
        if "application/json" in ct:
            parsed = json.loads(raw_body)
        else:
            parsed_qs = parse_qs(raw_body.decode(errors="replace"))
            parsed = {k: v[0] for k, v in parsed_qs.items() if v}
        chat_id = str(parsed.get("chat_id", ""))
    except Exception:
        logger.debug("Telegram body parse failed", exc_info=True)

    jl = get_json_logger()
    if jl:
        jl.log(
            "telegram_c2",
            src_ip=handler.client_address[0],
            method=method,
            bot_token=bot_token,
            chat_id=chat_id,
            body=raw_body.decode(errors="replace")[:4096],
        )

    now_ts = int(time.time())
    if method == "getme":
        result: object = {
            "id": 987654321,
            "is_bot": True,
            "first_name": "NotifyBot",
            "username": "notify_alertbot",
            "can_join_groups": False,
            "can_read_all_group_messages": False,
            "supports_inline_queries": False,
        }
    elif method == "getupdates":
        result = []
    else:
        result = {
            "message_id": now_ts & 0xFFFF,
            "from": {
                "id": 987654321,
                "is_bot": True,
                "first_name": "NotifyBot",
                "username": "notify_alertbot",
            },
            "chat": {
                "id": int(chat_id) if chat_id.lstrip("-").isdigit() else -1001234567890,
                "type": "supergroup",
                "title": "Logs",
            },
            "date": now_ts,
            "text": "OK",
        }

    response_body = json.dumps({"ok": True, "result": result}).encode()
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", json_content_type)
        handler.send_header("Content-Length", str(len(response_body)))
        handler.send_header("Server", "nginx")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(response_body)
    except OSError:
        pass

    return True


def route_discord(handler, max_body_size: int, json_content_type: str) -> bool:
    """Fake Discord webhook endpoint for stealer exfil."""
    path = handler.path or "/"
    m = _DISCORD_WEBHOOK_RE.match(path)
    if not m:
        return False

    webhook_id = m.group(1)

    try:
        cl = int(handler.headers.get("Content-Length", 0))
    except (ValueError, TypeError):
        cl = 0
    raw_body = handler.rfile.read(min(cl, max_body_size)) if cl > 0 else b""

    jl = get_json_logger()
    if jl:
        jl.log(
            "discord_c2",
            src_ip=handler.client_address[0],
            webhook_id=webhook_id,
            body=raw_body.decode(errors="replace")[:4096],
        )

    discord_epoch_ms = 1420070400000
    now_ms = int(time.time() * 1000)
    snowflake = ((now_ms - discord_epoch_ms) << 22) | random.getrandbits(22)

    resp = json.dumps(
        {
            "id": str(snowflake),
            "type": 0,
            "content": "",
            "channel_id": "1100000000000000000",
            "webhook_id": webhook_id,
            "attachments": [],
            "embeds": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ).encode()
    try:
        handler.send_response(200 if handler.command == "POST" else 204)
        handler.send_header("Content-Type", json_content_type)
        handler.send_header("Content-Length", str(len(resp)))
        handler.send_header("Server", "cloudflare")
        handler.send_header("CF-Ray", f"{os.urandom(8).hex()}-IAD")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(resp)
    except OSError:
        pass
    return True


def route_simple_text(
    handler,
    event_name: str,
    body: bytes,
    content_type: str,
    server: str,
    status: int = 200,
) -> bool:
    """Generic helper for simple webhook-style responses."""
    try:
        cl = int(handler.headers.get("Content-Length", 0))
    except (ValueError, TypeError):
        cl = 0
    raw_body = handler.rfile.read(cl) if cl > 0 else b""

    jl = get_json_logger()
    if jl:
        jl.log(
            event_name,
            src_ip=handler.client_address[0],
            body=raw_body.decode(errors="replace")[:4096],
        )

    try:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Server", server)
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
    except OSError:
        pass
    return True


def route_dead_drop_ip(handler, event_name: str, host: str, server: str) -> bool:
    """Return redirect IP as plain text for dead-drop style routes."""
    jl = get_json_logger()
    if jl:
        jl.log(event_name, src_ip=handler.client_address[0], host=host, path=handler.path or "/")

    redirect_ip = handler._cfg.spoof_ip or "10.10.10.10"
    body = redirect_ip.encode() + b"\n"
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Server", server)
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
    except OSError:
        pass
    return True


def route_file_hosting(handler, host: str) -> bool:
    """Return plausible 200 response for file-hosting payload pre-checks."""
    jl = get_json_logger()
    if jl:
        jl.log(
            "file_hosting_fetch",
            src_ip=handler.client_address[0],
            host=host,
            path=handler.path or "/",
        )

    body = b"\x00" * 64
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Server", "nginx")
        handler.send_header("Accept-Ranges", "bytes")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
    except OSError:
        pass
    return True


def route_google_content(handler, host: str) -> bool:
    """Return plausible Google Docs/Drive content for dead-drop retrieval."""
    jl = get_json_logger()
    if jl:
        jl.log(
            "google_dead_drop",
            src_ip=handler.client_address[0],
            host=host,
            path=handler.path or "/",
        )

    redirect_ip = handler._cfg.spoof_ip or "10.10.10.10"
    low = (handler.path or "").lower()
    if "format=csv" in low or "tqx=out:csv" in low:
        body = redirect_ip.encode() + b"\n"
        ct = "text/csv; charset=utf-8"
    elif "export=download" in low or "uc?" in low:
        pe_stub = bytearray(512)
        pe_stub[0:2] = b"MZ"
        pe_stub[0x3C:0x40] = (0x80).to_bytes(4, "little")
        pe_stub[0x80:0x84] = b"PE\x00\x00"
        pe_stub[0x84:0x86] = (0x14C).to_bytes(2, "little")
        body = bytes(pe_stub)
        ct = "application/octet-stream"
    else:
        body = redirect_ip.encode() + b"\n"
        ct = "text/plain; charset=utf-8"

    try:
        handler.send_response(200)
        handler.send_header("Content-Type", ct)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Server", "ESF")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
    except OSError:
        pass
    return True
