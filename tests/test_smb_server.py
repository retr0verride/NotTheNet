"""Tests for services/smb_server.py SMB negotiate parsing helpers."""

from __future__ import annotations

import struct

from services import smb_server


class _FakeSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.timeout = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, _size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def close(self) -> None:
        return


def test_smb2_error_response_contains_status_and_message_id() -> None:
    message_id = 0x1122334455667788
    packet = smb_server._smb2_error_response(message_id)

    assert packet[0] == 0x00  # NetBIOS session message
    payload_len = struct.unpack(">I", b"\x00" + packet[1:4])[0]
    assert payload_len == len(packet) - 4

    header = packet[4:68]
    assert header[:4] == smb_server._SMB2_MAGIC
    status = struct.unpack("<I", header[8:12])[0]
    assert status == smb_server._STATUS_NOT_SUPPORTED
    parsed_message_id = struct.unpack("<Q", header[28:36])[0]
    assert parsed_message_id == message_id


def test_parse_negotiate_detects_smb1_eternalblue_probe() -> None:
    # SMB1 negotiate payload: dialect strings start at offset 33 and each entry
    # is prefixed by 0x02 and suffixed by NUL.
    data = (
        smb_server._SMB1_MAGIC
        + (b"\x00" * 29)
        + b"\x02PC NETWORK PROGRAM 1.0\x00"
        + b"\x02NT LM 0.12\x00"
    )
    session = smb_server._SMBSession(_FakeSocket([]), ("127.0.0.1", 445))

    version, dialects, eternalblue, message_id, dialect_index = session._parse_negotiate(data)

    assert version == "SMBv1"
    assert eternalblue is True
    assert any("NT LM 0.12" in d for d in dialects)
    assert message_id == 0
    # NT LM 0.12 is the second dialect (index 1) in this probe payload.
    assert dialects[dialect_index] == "NT LM 0.12"


def test_parse_negotiate_extracts_smb2_message_id() -> None:
    message_id = 42
    data = bytearray(64)
    data[:4] = smb_server._SMB2_MAGIC
    struct.pack_into("<Q", data, 28, message_id)
    session = smb_server._SMBSession(_FakeSocket([]), ("127.0.0.1", 445))

    version, dialects, eternalblue, parsed_message_id, dialect_index = (
        session._parse_negotiate(bytes(data))
    )

    assert version == "SMBv2"
    assert dialects == []
    assert eternalblue is False
    assert parsed_message_id == message_id
    assert dialect_index == 0


def test_read_smb_message_rejects_oversized_payload() -> None:
    # NetBIOS header with length > 65535 must be rejected.
    sock = _FakeSocket([b"\x00\x01\x00\x00"])
    session = smb_server._SMBSession(sock, ("127.0.0.1", 445))
    assert session._read_smb_message() is None


def test_smb_service_reads_configurable_limits() -> None:
    svc = smb_server.SMBService({"max_connections": 13, "session_timeout_sec": 6})
    assert svc.max_connections == 13
    assert svc.session_timeout == 6


def test_smb1_negotiate_response_is_well_formed() -> None:
    """The faked SMBv1 NEGOTIATE response must parse as a valid SMB1 frame so
    EternalBlue worms continue scanning the LAN instead of aborting on recv()."""
    packet = smb_server._smb1_negotiate_response(dialect_index=1)

    # NetBIOS header: 1 byte type (0x00), 3-byte big-endian length.
    assert packet[0] == 0x00
    payload_len = struct.unpack(">I", b"\x00" + packet[1:4])[0]
    assert payload_len == len(packet) - 4

    # SMB1 header magic + NEGOTIATE_PROTOCOL_RESPONSE command (0x72).
    assert packet[4:8] == smb_server._SMB1_MAGIC
    assert packet[8] == 0x72

    # Body: WordCount=17, then DialectIndex echoed back.
    body = packet[36:]
    assert body[0] == 17
    assert struct.unpack("<H", body[1:3])[0] == 1
