"""
NotTheNet - Fake LDAP Server (TCP port 389)

Why this matters:
    LDAP is the backbone of Active Directory.  Malware that targets
    enterprise environments probes LDAP to:
      - BloodHound / SharpHound â€” AD enumeration (group memberships, DACLs)
      - Mimikatz / Rubeus       â€” LDAP queries for kerberoastable SPNs
      - Cobalt Strike           â€” ldap_query BOF for trusts and admin accounts
      - RATs                    â€” credential harvesters using
                                  DirectoryServices .NET with SimpleBind

    Key intelligence with SimpleBind:
      - The Bind DN (e.g. "CN=svc_backup,OU=Service Accounts,DC=corp,DC=local")
        reveals the targeted domain and account name
      - The password arrives in PLAINTEXT inside the BindRequest â€” no hashing,
        no challenge-response.

    Protocol:
      LDAP messages are BER/DER-encoded (ASN.1). A BindRequest looks like:
        SEQUENCE {
          INTEGER  messageID
          [APPLICATION 0] BindRequest {
            INTEGER  version (3)
            OCTET STRING  name / DN
            [0 CONTEXT]   password (SimpleBind)
          }
        }

    This service parses just enough BER to extract the DN and password from
    every incoming BindRequest and returns a successful BindResponse.

Security notes (OpenSSF):
- BER parser validates tag, length, and offset before every slice
- Maximum message size capped at 65 535 bytes
- All received strings are sanitised before logging (log injection)
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import logging
import socket
import threading
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 15
_MAX_CONNECTIONS = 50


# â”€â”€ Minimal BER TLV parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _ber_read(data: bytes, pos: int) -> tuple[int, int, bytes]:
    """
    Read one BER TLV starting at *pos*.
    Returns (tag, next_pos, value) or (tag=-1, 0, b'') on error.
    """
    if pos >= len(data):
        return -1, 0, b""

    tag = data[pos]
    pos += 1

    if pos >= len(data):
        return tag, pos, b""

    first = data[pos]
    pos += 1

    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            return -1, 0, b""
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first

    if length > 65535:
        return -1, 0, b""

    end = pos + length
    if end > len(data):
        return tag, end, data[pos:]
    return tag, end, data[pos:end]


def _parse_bind_request(msg: bytes) -> tuple[int, str, str]:
    """
    Parse an LDAP LDAPMessage containing a BindRequest.
    Returns (message_id, dn, bind_credential).  On parse failure returns (1, '', '').
    """
    # Outer SEQUENCE (0x30)
    tag, pos, inner = _ber_read(msg, 0)
    if tag != 0x30:
        return 1, "", ""

    # messageID (INTEGER 0x02)
    tag, pos, mid_bytes = _ber_read(inner, 0)
    if tag != 0x02:
        return 1, "", ""
    try:
        message_id = int.from_bytes(mid_bytes, "big")
    except (ValueError, OverflowError):
        message_id = 1

    # BindRequest (APPLICATION 0 = 0x60)
    tag, _, bind_body = _ber_read(inner, pos)
    if tag != 0x60:
        return message_id, "", ""

    bpos = 0
    # version (INTEGER)
    tag, bpos, _ = _ber_read(bind_body, bpos)
    if tag != 0x02:
        return message_id, "", ""

    # name / DN (OCTET STRING 0x04)
    tag, bpos, dn_bytes = _ber_read(bind_body, bpos)
    if tag != 0x04:
        return message_id, "", ""
    dn = dn_bytes.decode("utf-8", errors="replace")

    # authentication â€” CONTEXT [0] (0x80) for SimpleBind
    if bpos >= len(bind_body):
        return message_id, dn, ""

    auth_tag, _, auth_val = _ber_read(bind_body, bpos)
    if auth_tag == 0x80:
        bind_credential = auth_val.decode("utf-8", errors="replace")
    else:
        bind_credential = "(non-simple-auth)"

    return message_id, dn, bind_credential


def _ber_length(n: int) -> bytes:
    """Encode *n* as a BER definite-form length field."""
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _bind_response(message_id: int, result_code: int = 0) -> bytes:
    """
    Build an LDAP BindResponse.
    result_code=0 â†’ success, which causes the client to continue.
    """
    mid_bytes = message_id.to_bytes(
        max(1, (message_id.bit_length() + 7) // 8), "big"
    )
    # BindResponse body: resultCode (ENUMERATED) + matchedDN + diagnostic
    result  = bytes([0x0a, 0x01, result_code])  # ENUMERATED, 1 byte
    matched = b"\x04\x00"                        # OCTET STRING ""
    diag    = b"\x04\x00"                        # OCTET STRING ""
    resp_body = result + matched + diag

    # APPLICATION 1 (BindResponse tag = 0x61)
    resp = bytes([0x61]) + _ber_length(len(resp_body)) + resp_body

    # messageID TLV
    mid_tlv = bytes([0x02, len(mid_bytes)]) + mid_bytes

    # Outer SEQUENCE
    inner = mid_tlv + resp
    return bytes([0x30]) + _ber_length(len(inner)) + inner


class _LDAPSession(threading.Thread):
    """Handles one LDAP client session."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: Optional[threading.BoundedSemaphore] = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    def _process_buffer(self, buf: bytes, safe_addr: str) -> bytes:
        """Parse complete BER messages from buf, send responses. Return remaining bytes."""
        jl = get_json_logger()
        while len(buf) >= 2:
            if buf[0] != 0x30:
                break
            if buf[1] & 0x80:
                n = buf[1] & 0x7F
                if len(buf) < 2 + n:
                    break
                content_len = int.from_bytes(buf[2:2 + n], "big")
                total_len = 2 + n + content_len
            else:
                content_len = buf[1]
                total_len = 2 + content_len
            if len(buf) < total_len:
                break
            msg_bytes = buf[:total_len]
            buf = buf[total_len:]
            message_id, dn, bind_credential = _parse_bind_request(msg_bytes)
            logger.info(
                "LDAP bind from %s: dn=%s pass=%s",
                safe_addr,
                sanitize_log_string(dn),
                sanitize_log_string(bind_credential),
            )
            if jl:
                jl.log(
                    "ldap_bind",
                    src_ip=self.addr[0],
                    dn=dn,
                    credential=bind_credential,
                )
            self.conn.sendall(_bind_response(message_id))
        return buf

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        try:
            self.conn.settimeout(SESSION_TIMEOUT)
            buf = b""
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65535:
                    break
                buf = self._process_buffer(buf, safe_addr)
        except OSError:
            logger.debug("LDAP session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()


class LDAPService:
    """Fake LDAP server on TCP port 389."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 389))
        self.bind_ip = bind_ip
        self._sem = threading.BoundedSemaphore(int(config.get("max_connections", _MAX_CONNECTIONS)))
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="ldap-server"
            )
            self._thread.start()
            logger.info("LDAP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("LDAP failed to bind on port %s: %s", self.port, e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("LDAP at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _LDAPSession(conn, addr, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("LDAP service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
