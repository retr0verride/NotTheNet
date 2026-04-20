"""Tests for services/mail_server.py SMTP parsing and save behavior."""

from __future__ import annotations

from pathlib import Path

from services import mail_server


class _FakeConn:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


def _smtp(save_dir: str | None = None) -> mail_server._SMTPClientThread:
    return mail_server._SMTPClientThread(
        conn=_FakeConn(),
        addr=("127.0.0.1", 2525),
        hostname="mail.example.com",
        banner="220 test",
        save_dir=save_dir,
    )


def test_auth_login_state_machine() -> None:
    smtp = _smtp()

    smtp._handle_line("ignored", "127.0.0.1")
    # No auth state by default; unrecognized command path.
    assert b"500 Unrecognized command" in b"".join(smtp.conn.sent)

    smtp.conn.sent.clear()
    smtp._auth_state = "login_user"
    smtp._handle_line("dXNlcg==", "127.0.0.1")
    assert smtp._auth_state == "login_pass"
    assert b"334 UGFzc3dvcmQ6" in b"".join(smtp.conn.sent)

    smtp.conn.sent.clear()
    smtp._handle_line("cGFzcw==", "127.0.0.1")
    assert smtp._auth_state is None
    assert b"235 2.7.0 Authentication successful" in b"".join(smtp.conn.sent)


def test_data_mode_enforces_message_size(monkeypatch) -> None:
    smtp = _smtp()
    smtp.data_mode = True
    monkeypatch.setattr(mail_server, "MAX_EMAIL_SIZE_BYTES", 10)

    smtp._handle_line("12345", "127.0.0.1")
    smtp._handle_line("67890", "127.0.0.1")
    smtp._handle_line("EXTRA", "127.0.0.1")

    assert smtp.current_size == 10
    assert smtp.mail_data == ["12345", "67890"]


def test_save_email_writes_eml_file(tmp_path: Path) -> None:
    smtp = _smtp(save_dir=str(tmp_path))
    smtp.mail_data = ["Subject: test", "", "body"]

    smtp._save_email()

    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 1
    assert "Subject: test" in files[0].read_text(encoding="utf-8")


def test_save_email_skips_when_disk_cap_exceeded(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "existing.eml").write_bytes(b"12345")
    monkeypatch.setattr(mail_server, "MAX_DISK_USAGE_BYTES", 4)
    smtp = _smtp(save_dir=str(tmp_path))
    smtp.mail_data = ["new message"]

    smtp._save_email()

    files = list(tmp_path.glob("*.eml"))
    # Only the pre-existing file should remain.
    assert len(files) == 1
    assert files[0].name == "existing.eml"
