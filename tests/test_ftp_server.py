"""Tests for services/ftp_server.py upload and disk-usage behavior."""

from __future__ import annotations

from pathlib import Path

from services import ftp_server


class _FakeControlConn:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


class _FakeDataConn:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        return

    def recv(self, _size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def close(self) -> None:
        self.closed = True


def _session(upload_dir: str | None = None) -> ftp_server._FTPSession:
    return ftp_server._FTPSession(
        conn=_FakeControlConn(),
        addr=("127.0.0.1", 12345),
        banner="220 test",
        upload_dir=upload_dir,
    )


def test_get_disk_usage_sums_files(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"1234")
    (tmp_path / "b.bin").write_bytes(b"12")
    (tmp_path / "sub").mkdir()
    assert ftp_server._get_disk_usage(str(tmp_path)) == 6


def test_recv_file_discards_when_uploads_disabled(monkeypatch) -> None:
    sess = _session(upload_dir=None)
    data_conn = _FakeDataConn([b"abc", b"def", b""])
    monkeypatch.setattr(sess, "_accept_data", lambda: data_conn)

    sess._recv_file("sample.bin", "127.0.0.1")

    sent_text = b"".join(sess.conn.sent).decode("utf-8", errors="replace")
    assert "150 Ok to send data" in sent_text
    assert "226 Transfer complete (discarded)" in sent_text
    assert data_conn.closed


def test_write_upload_enforces_size_cap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ftp_server, "MAX_UPLOAD_SIZE_BYTES", 10)
    sess = _session(upload_dir=str(tmp_path))
    data_conn = _FakeDataConn([b"12345", b"67890", b""])
    save_path = tmp_path / "saved.bin"

    received = sess._write_upload(
        data_conn=data_conn,
        save_path=str(save_path),
        safe_addr="127.0.0.1",
        safe_fname="saved.bin",
        remote_name="remote.dat",
    )

    # Counter includes bytes read from the wire, but file write truncates at cap.
    assert received == 10
    assert save_path.read_bytes() == b"1234567890"
