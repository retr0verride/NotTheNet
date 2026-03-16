"""
NotTheNet - Dynamic HTTP Response Engine
Serves context-aware responses based on the requested file extension / path.

Why this matters:
    INetSim serves the same generic HTML to every request. Smart malware that
    requests /payload.dll and receives text/html immediately detects the sandbox.
    This module maps request paths to realistic MIME types and generates minimal
    valid file stubs (PE headers, PNG, JPEG, ZIP, PDF, etc.) so malware sees
    the content type it expects and continues executing.

Security notes (OpenSSF):
- Generated stubs are intentionally minimal and non-functional
- No user-supplied bytes are embedded in generated content
- All path matching is done against a compiled regex table (no eval/exec)
"""

from __future__ import annotations

import logging
import re
import struct
import threading

logger = logging.getLogger(__name__)

# ─── Minimal file stubs ──────────────────────────────────────────────────────
# Each stub is the smallest valid (or plausible) header for its format.
# Malware typically checks the first few bytes (magic number) and Content-Type
# header, not full structural validity.

def _pe_stub() -> bytes:
    """Minimal DOS/PE stub — valid MZ header + PE signature + minimal COFF."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"                         # e_magic
    struct.pack_into("<I", dos_header, 60, 64)       # e_lfanew → PE header at offset 64
    pe_sig = b"PE\x00\x00"
    # COFF header: machine=0x14c (i386), 0 sections, timestamps, etc.
    coff = struct.pack("<HHIIIHH",
                       0x14C,   # Machine: IMAGE_FILE_MACHINE_I386
                       1,       # NumberOfSections
                       0,       # TimeDateStamp
                       0,       # PointerToSymbolTable
                       0,       # NumberOfSymbols
                       0xF0,    # SizeOfOptionalHeader
                       0x0102)  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    # Minimal optional header (PE32)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x10B)   # Magic: PE32
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x10000) # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)   # FileAlignment
    struct.pack_into("<I", opt, 56, 0x10000) # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)   # SizeOfHeaders
    # Section header (.text)
    section = bytearray(40)
    section[0:6] = b".text\x00"
    struct.pack_into("<I", section, 8, 0x1000)   # VirtualSize
    struct.pack_into("<I", section, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", section, 16, 0x200)   # SizeOfRawData
    struct.pack_into("<I", section, 20, 0x200)   # PointerToRawData
    struct.pack_into("<I", section, 36, 0x60000020)  # Characteristics
    # Pad to FileAlignment
    body = bytes(dos_header) + pe_sig + coff + bytes(opt) + bytes(section)
    padding = b"\x00" * (0x200 - (len(body) % 0x200)) if len(body) % 0x200 else b""
    # Fake .text section content (NOP sled + RET)
    text_section = b"\x90" * 0x1F0 + b"\xC3" + b"\x00" * 0x0F
    return body + padding + text_section


def _elf_stub() -> bytes:
    """Minimal ELF 64-bit stub."""
    # ELF header (64 bytes)
    elf = bytearray(120)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2    # 64-bit
    elf[5] = 1    # little-endian
    elf[6] = 1    # ELF version
    elf[7] = 0    # OS/ABI: ELFOSABI_NONE
    struct.pack_into("<H", elf, 16, 2)     # ET_EXEC
    struct.pack_into("<H", elf, 18, 0x3E)  # EM_X86_64
    struct.pack_into("<I", elf, 20, 1)     # ELF version
    struct.pack_into("<Q", elf, 24, 0x400000)  # Entry point
    struct.pack_into("<Q", elf, 32, 64)    # Program header offset
    struct.pack_into("<H", elf, 52, 64)    # ELF header size
    struct.pack_into("<H", elf, 54, 56)    # Program header entry size
    struct.pack_into("<H", elf, 56, 1)     # Number of program headers
    # Program header (56 bytes)
    struct.pack_into("<I", elf, 64, 1)           # PT_LOAD
    struct.pack_into("<I", elf, 68, 5)           # PF_R | PF_X
    struct.pack_into("<Q", elf, 72, 0)           # Offset
    struct.pack_into("<Q", elf, 80, 0x400000)    # VAddr
    struct.pack_into("<Q", elf, 96, 120)         # Filesz
    struct.pack_into("<Q", elf, 104, 120)        # Memsz
    return bytes(elf)


def _png_stub() -> bytes:
    """Minimal valid 1×1 transparent PNG."""
    return (
        b"\x89PNG\r\n\x1a\n"
        # IHDR
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        # IDAT
        b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
        b"\r\n\xb4\x00"
        # IEND
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def _jpeg_stub() -> bytes:
    """Minimal valid 1×1 white JPEG."""
    return (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01"
        b"\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07"
        b"\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19"
        b"\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $"
        b".' \",#\x1c\x1c(7),01444\x1f'9=82<.342"
        b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
        b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01"
        b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04"
        b"\x05\x06\x07\x08\t\n\x0b"
        b"\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03"
        b"\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11"
        b"\x05\x12!1A\x06\x13Qa\x07\"q\x142\x81\x91\xa1\x08#B"
        b"\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19\x1a"
        b"%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
        b"\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96"
        b"\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa"
        b"\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5"
        b"\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
        b"\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2"
        b"\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa"
        b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00T\xdb\xe3\x8c("
        b"\xa0\x02\x80\x0f\xff\xd9"
    )


def _gif_stub() -> bytes:
    """Minimal valid 1×1 white GIF89a."""
    return (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00"
        b"\xff\xff\xff\x00\x00\x00"    # colour table (white + black)
        b"!\xf9\x04\x00\x00\x00\x00\x00"  # GCE
        b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"  # image descriptor
        b"\x02\x02D\x01\x00;"  # LZW min code size + data + trailer
    )


def _bmp_stub() -> bytes:
    """Minimal valid 1×1 white BMP."""
    # BMP header (14) + DIB header (40) + pixel data (4 bytes, padded)
    pixel = b"\xff\xff\xff\x00"  # BGR white + padding
    file_size = 14 + 40 + len(pixel)
    return (
        b"BM"
        + struct.pack("<I", file_size)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 54)       # pixel data offset
        + struct.pack("<I", 40)       # DIB header size
        + struct.pack("<i", 1)        # width
        + struct.pack("<i", 1)        # height
        + struct.pack("<HH", 1, 24)   # planes, bpp
        + b"\x00" * 24               # rest of DIB header
        + pixel
    )


def _ico_stub() -> bytes:
    """Minimal valid .ico with a 1×1 32-bit image."""
    # ICO header (6) + directory entry (16) + BMP DIB header (40) + pixel (4) + mask (4)
    dib = (
        struct.pack("<I", 40)       # DIB header size
        + struct.pack("<i", 1)      # width
        + struct.pack("<i", 2)      # height (2× for XOR+AND)
        + struct.pack("<HH", 1, 32) # planes, bpp
        + b"\x00" * 24             # rest
    )
    pixel_data = b"\xff\xff\xff\xff"  # one BGRA pixel
    mask_data = b"\x00\x00\x00\x00"   # AND mask row (padded to 4 bytes)
    image_data = dib + pixel_data + mask_data
    image_size = len(image_data)
    data_offset = 6 + 16  # ICO header + 1 directory entry
    header = struct.pack("<HHH", 0, 1, 1)  # reserved, type=ICO, count=1
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, image_size, data_offset)
    return header + entry + image_data


def _pdf_stub() -> bytes:
    """Minimal valid 1-page blank PDF."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
    )


def _zip_stub() -> bytes:
    """Minimal valid empty ZIP archive."""
    # End of central directory record
    return (
        b"PK\x05\x06"       # EOCD signature
        + b"\x00" * 16      # disk numbers, entry counts, size, offset
        + b"\x00\x00"       # comment length
    )


def _xml_stub() -> bytes:
    """Minimal valid XML document."""
    return b'<?xml version="1.0" encoding="UTF-8"?>\n<root/>\n'


def _json_stub() -> bytes:
    """Minimal valid JSON object."""
    return b"{}\n"


def _js_stub() -> bytes:
    """Minimal JavaScript file."""
    return b"/* */\n"


def _css_stub() -> bytes:
    """Minimal CSS file."""
    return b"/* */\n"


def _txt_stub() -> bytes:
    """Generic text file."""
    return b"\n"


def _swf_stub() -> bytes:
    """Minimal SWF (Flash) header — enough to pass magic-number checks."""
    # CWS (compressed) header: signature + version + file length
    return b"CWS\x09" + struct.pack("<I", 17) + b"\x78\x9c\x63\x60\x00\x00\x00\x02\x00\x01"


def _class_stub() -> bytes:
    """Minimal Java .class file header (magic + version)."""
    return b"\xca\xfe\xba\xbe\x00\x00\x003" + b"\x00" * 50


def _doc_stub() -> bytes:
    """Minimal OLE2 (DOC/XLS/PPT) Compound File header."""
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE2 magic
    struct.pack_into("<H", header, 24, 0x003E)  # minor version
    struct.pack_into("<H", header, 26, 0x0003)  # major version
    struct.pack_into("<H", header, 28, 0xFFFE)  # byte order (little-endian)
    struct.pack_into("<H", header, 30, 0x0009)  # sector size power (512)
    return bytes(header)


# ─── Extension → (MIME type, stub generator) ─────────────────────────────────

_EXTENSION_MAP: dict[str, tuple[str, bytes]] = {}
_EXT_MAP_LOCK = threading.Lock()


def _build_extension_map() -> dict[str, tuple[str, bytes]]:
    """Build the extension→(mime, body) mapping. Cached on first call."""
    if _EXTENSION_MAP:
        return _EXTENSION_MAP
    with _EXT_MAP_LOCK:
        if _EXTENSION_MAP:  # re-check after acquiring the lock
            return _EXTENSION_MAP

        pe = _pe_stub()
        elf_ = _elf_stub()
        png = _png_stub()
        jpg = _jpeg_stub()
        gif = _gif_stub()
        bmp = _bmp_stub()
        ico = _ico_stub()
        pdf = _pdf_stub()
        zip_ = _zip_stub()
        xml = _xml_stub()
        json_ = _json_stub()
        js = _js_stub()
        css = _css_stub()
        txt = _txt_stub()
        swf = _swf_stub()
        cls = _class_stub()
        doc = _doc_stub()

        entries = {
            # Windows executables / DLLs
            ".exe":  ("application/x-dosexec", pe),
            ".dll":  ("application/x-dosexec", pe),
            ".sys":  ("application/x-dosexec", pe),
            ".scr":  ("application/x-dosexec", pe),
            ".cpl":  ("application/x-dosexec", pe),
            ".ocx":  ("application/x-dosexec", pe),
            ".drv":  ("application/x-dosexec", pe),
            ".com":  ("application/x-dosexec", pe),
            # Linux executables
            ".so":   ("application/x-sharedlib", elf_),
            ".elf":  ("application/x-executable", elf_),
            # Images
            ".png":  ("image/png", png),
            ".jpg":  ("image/jpeg", jpg),
            ".jpeg": ("image/jpeg", jpg),
            ".gif":  ("image/gif", gif),
            ".bmp":  ("image/bmp", bmp),
            ".ico":  ("image/x-icon", ico),
            ".svg":  ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"/>\n'),
            ".webp": ("image/webp", b"RIFF\x00\x00\x00\x00WEBPVP8 \x00\x00\x00\x00"),
            # Documents
            ".pdf":  ("application/pdf", pdf),
            ".doc":  ("application/msword", doc),
            ".xls":  ("application/vnd.ms-excel", doc),
            ".ppt":  ("application/vnd.ms-powerpoint", doc),
            ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", zip_),
            ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", zip_),
            ".pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", zip_),
            # Archives
            ".zip":  ("application/zip", zip_),
            ".jar":  ("application/java-archive", zip_),
            ".apk":  ("application/vnd.android.package-archive", zip_),
            ".7z":   ("application/x-7z-compressed", b"7z\xbc\xaf\x27\x1c"),
            ".rar":  ("application/x-rar-compressed", b"Rar!\x1a\x07\x00"),
            ".gz":   ("application/gzip",
                      b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            ".tar":  ("application/x-tar", b"\x00" * 512),
            ".cab":  ("application/vnd.ms-cab-compressed", b"MSCF\x00\x00\x00\x00"),
            # Web
            ".html": ("text/html; charset=utf-8", b"<html><body><h1>OK</h1></body></html>\n"),
            ".htm":  ("text/html; charset=utf-8", b"<html><body><h1>OK</h1></body></html>\n"),
            ".xml":  ("application/xml", xml),
            ".json": ("application/json", json_),
            ".js":   ("application/javascript", js),
            ".mjs":  ("application/javascript", js),
            ".css":  ("text/css", css),
            ".txt":  ("text/plain", txt),
            ".csv":  ("text/csv", b"a,b,c\n"),
            ".wasm": ("application/wasm", b"\x00asm\x01\x00\x00\x00"),
            # Scripting / config
            ".ps1":  ("text/plain", b"# \n"),
            ".bat":  ("text/plain", b"@echo off\r\n"),
            ".cmd":  ("text/plain", b"@echo off\r\n"),
            ".sh":   ("text/plain", b"#!/bin/sh\n"),
            ".py":   ("text/x-python", b"# \n"),
            ".rb":   ("text/plain", b"# \n"),
            ".pl":   ("text/plain", b"#!/usr/bin/perl\n"),
            ".vbs":  ("text/plain", b"' \n"),
            ".ini":  ("text/plain", b"[default]\n"),
            ".cfg":  ("text/plain", b"[default]\n"),
            ".conf": ("text/plain", b"# \n"),
            ".yaml": ("text/yaml", b"---\n"),
            ".yml":  ("text/yaml", b"---\n"),
            ".toml": ("text/plain", b"# \n"),
            # Flash / Java
            ".swf":  ("application/x-shockwave-flash", swf),
            ".class": ("application/java-vm", cls),
            # Binary / data
            ".bin":  ("application/octet-stream", pe),
            ".dat":  ("application/octet-stream", b"\x00" * 256),
            ".raw":  ("application/octet-stream", b"\x00" * 256),
            ".iso":  ("application/x-iso9660-image", b"\x00" * 32768 + b"\x01CD001"),
            ".img":  ("application/octet-stream", b"\x00" * 512),
            # Fonts
            ".woff":  ("font/woff", b"wOFF"),
            ".woff2": ("font/woff2", b"wOF2"),
            ".ttf":   ("font/ttf", b"\x00\x01\x00\x00"),
            ".otf":   ("font/otf", b"OTTO"),
            # Media
            ".mp3":  ("audio/mpeg", b"\xff\xfb\x90\x00" + b"\x00" * 252),
            ".mp4":  ("video/mp4", b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00"),
            ".avi":  ("video/x-msvideo", b"RIFF\x00\x00\x00\x00AVI "),
            ".wav":  ("audio/wav", b"RIFF\x00\x00\x00\x00WAVEfmt "),
            ".flv":  ("video/x-flv", b"FLV\x01\x05\x00\x00\x00\x09"),
        }
        _EXTENSION_MAP.update(entries)
    return _EXTENSION_MAP


# ─── Custom rules (regex → MIME + body) ──────────────────────────────────────

class _CompiledRule:
    """A user-defined path-matching rule."""
    __slots__ = ("pattern", "mime", "body")

    def __init__(self, pattern: re.Pattern, mime: str, body: bytes):
        self.pattern = pattern
        self.mime = mime
        self.body = body


def compile_custom_rules(rules: list[dict]) -> list[_CompiledRule]:
    """
    Compile user-defined rules from config.

    Each rule dict: {"pattern": "<regex>", "mime": "...", "body": "..."}
    body is optional — if omitted the extension map stub is used.
    """
    compiled = []
    for rule in rules:
        raw = rule.get("pattern", "")
        mime = rule.get("mime", "application/octet-stream")
        body_str = rule.get("body", "")
        try:
            pat = re.compile(raw, re.IGNORECASE)
            body = body_str.encode("utf-8", errors="replace") if body_str else b""
            compiled.append(_CompiledRule(pat, mime, body))
        except re.error as exc:
            logger.warning(f"Invalid dynamic_response rule regex '{raw}': {exc}")
    return compiled


def resolve_dynamic_response(
    path: str,
    custom_rules: list[_CompiledRule] | None = None,
    fallback_body: bytes | None = None,
    fallback_mime: str = "text/html; charset=utf-8",
) -> tuple[str, bytes]:
    """
    Determine the Content-Type and response body for a given request path.

    Resolution order:
    1. Custom rules (regex match against full path)
    2. File extension lookup in the built-in map
    3. Fallback (original static response)

    Returns:
        (content_type, body_bytes)
    """
    # 1. Custom rules take priority
    if custom_rules:
        for rule in custom_rules:
            if rule.pattern.search(path):
                body = rule.body if rule.body else fallback_body or b""
                return rule.mime, body

    # 2. Extension-based lookup
    ext_map = _build_extension_map()
    # Extract extension from path (strip query string first)
    clean_path = path.split("?", 1)[0].split("#", 1)[0]
    dot_pos = clean_path.rfind(".")
    if dot_pos != -1:
        ext = clean_path[dot_pos:].lower()
        if ext in ext_map:
            mime, body = ext_map[ext]
            logger.debug(f"Dynamic response: {ext} -> {mime} ({len(body)} bytes)")
            return mime, body

    # 3. Fallback to original static response
    return fallback_mime, fallback_body or b"<html><body><h1>200 OK</h1></body></html>"
