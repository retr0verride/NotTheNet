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
    # SMB1 NEGOTIATE request body: WordCount(1)=0 @offset 32, ByteCount(2)
    # @offset 33-34, dialect entries @offset 35+. Each entry is 0x02 + name + NUL.
    dialect_bytes = b"\x02PC NETWORK PROGRAM 1.0\x00" + b"\x02NT LM 0.12\x00"
    data = (
        smb_server._SMB1_MAGIC
        + (b"\x00" * 28)                              # rest of 32-byte header
        + b"\x00"                                     # WordCount = 0
        + struct.pack("<H", len(dialect_bytes))       # ByteCount
        + dialect_bytes
    )
    session = smb_server._SMBSession(_FakeSocket([]), ("127.0.0.1", 445))

    version, dialects, eternalblue, message_id, dialect_index, smb1_hdr = (
        session._parse_negotiate(data)
    )

    assert version == "SMBv1"
    assert eternalblue is True
    assert dialects == ["PC NETWORK PROGRAM 1.0", "NT LM 0.12"]
    assert message_id == 0
    assert dialect_index == 1
    assert dialects[dialect_index] == "NT LM 0.12"
    assert smb1_hdr == (0, 0, 0, 0)  # zero-padded request header in this fixture


def test_parse_negotiate_extracts_smb2_message_id() -> None:
    message_id = 42
    data = bytearray(64)
    data[:4] = smb_server._SMB2_MAGIC
    struct.pack_into("<Q", data, 28, message_id)
    session = smb_server._SMBSession(_FakeSocket([]), ("127.0.0.1", 445))

    version, dialects, eternalblue, parsed_message_id, dialect_index, smb1_hdr = (
        session._parse_negotiate(bytes(data))
    )

    assert version == "SMBv2"
    assert dialects == []
    assert eternalblue is False
    assert parsed_message_id == message_id
    assert dialect_index == 0
    assert smb1_hdr == (0, 0, 0, 0)


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
    packet = smb_server._smb1_negotiate_response(
        dialect_index=1, tid=0xAAAA, pid=0xBBBB, uid=0xCCCC, mid=0xDDDD,
    )

    # NetBIOS header: 1 byte type (0x00), 3-byte big-endian length.
    assert packet[0] == 0x00
    payload_len = struct.unpack(">I", b"\x00" + packet[1:4])[0]
    assert payload_len == len(packet) - 4

    # Total payload should be 32 (header) + 37 (body) = 69 bytes.
    assert payload_len == 69

    # SMB1 header magic + NEGOTIATE_PROTOCOL_RESPONSE command (0x72).
    assert packet[4:8] == smb_server._SMB1_MAGIC
    assert packet[8] == 0x72
    # Flags = REPLY|CASE_INSENSITIVE; Flags2 = UNICODE|NT_STATUS|LONG_NAMES.
    assert packet[13] == 0x88
    assert struct.unpack("<H", packet[14:16])[0] == 0xC001
    # TID/PID/UID/MID echoed from request.
    assert struct.unpack("<HHHH", packet[28:36]) == (0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD)

    # Body: WordCount=17, then DialectIndex echoed back, then trailing ByteCount=0.
    body = packet[36:]
    assert len(body) == 37
    assert body[0] == 17
    assert struct.unpack("<H", body[1:3])[0] == 1
    # ChallengeLength at offset 34, ByteCount (UInt16) at 35-36.
    assert body[34] == 0
    assert struct.unpack("<H", body[35:37])[0] == 0


def test_smb1_error_response_echoes_request_ids() -> None:
    """Drain helper must echo command + TID/PID/UID/MID and return STATUS_NOT_SUPPORTED."""
    request = bytearray(40)
    request[:4] = smb_server._SMB1_MAGIC
    request[4] = 0x73  # SESSION_SETUP_ANDX
    struct.pack_into("<HHHH", request, 24, 0x1111, 0x2222, 0x3333, 0x4444)
    packet = smb_server._smb1_error_response(bytes(request))
    assert packet[0] == 0x00
    assert packet[4:8] == smb_server._SMB1_MAGIC
    assert packet[8] == 0x73
    # NTStatus at header offset 5-8 = STATUS_NOT_SUPPORTED.
    assert struct.unpack("<I", packet[9:13])[0] == smb_server._STATUS_NOT_SUPPORTED
    assert struct.unpack("<HHHH", packet[28:36]) == (0x1111, 0x2222, 0x3333, 0x4444)
    # Body: WordCount=0, ByteCount=0.
    assert packet[36:39] == b"\x00\x00\x00"
