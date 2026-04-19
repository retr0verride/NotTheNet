"""
Tests for JsonEventLogger periodic-flush behaviour.

Before the fix, every log() call did self._file.flush() — under high-frequency
traffic (malware hitting every service) this produced hundreds of kernel
syscalls per second and held the write lock while doing so, contributing to
GUI-thread starvation.

After the fix, flush() is called at most once per _FLUSH_INTERVAL second.
These tests verify that:
  1. Many rapid writes do NOT flush on every write.
  2. A flush is eventually issued (within _FLUSH_INTERVAL).
  3. close() always does a final flush so no data is lost on shutdown.
  4. Events written under a size cap are actually persisted.
"""

import os
import tempfile
import threading
import time
import unittest

import pytest

from utils.json_logger import _FLUSH_INTERVAL, JsonEventLogger


@pytest.mark.limit_memory("10 MB")
class TestPeriodicFlush(unittest.TestCase):

    def _make_logger(self, tmp_path: str) -> JsonEventLogger:
        return JsonEventLogger(tmp_path, max_bytes=10 * 1024 * 1024)

    # ------------------------------------------------------------------
    # Core: flush is NOT called on every write
    # ------------------------------------------------------------------

    def test_flush_not_called_on_every_write(self):
        """Rapid consecutive writes must not flush after each one."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            logger = JsonEventLogger(path)
            flush_calls = []

            _orig_flush = logger._file.flush

            def _counting_flush():
                flush_calls.append(time.monotonic())
                _orig_flush()

            logger._file.flush = _counting_flush

            # Fire 50 writes in rapid succession (well within _FLUSH_INTERVAL).
            for i in range(50):
                logger.log("test_event", idx=i)

            logger.close()

            # We expect at most 2 flushes: one triggered by the interval
            # and one by close().  Certainly not 50.
            self.assertLess(
                len(flush_calls), 10,
                f"Expected far fewer than 50 flushes; got {len(flush_calls)}",
            )
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # Core: flush is eventually issued
    # ------------------------------------------------------------------

    def test_flush_issued_within_interval(self):
        """A flush must occur within _FLUSH_INTERVAL + small margin."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            logger = JsonEventLogger(path)
            flushed = threading.Event()

            _orig_flush = logger._file.flush

            def _notify_flush():
                flushed.set()
                _orig_flush()

            logger._file.flush = _notify_flush

            # Write one event, then poll until flush fires or we time out.
            logger.log("first_event", data="x")

            # Wait for the first flush (triggered by the interval).
            # We allow _FLUSH_INTERVAL + 0.5s margin to avoid flakiness.
            limit = _FLUSH_INTERVAL + 0.5
            # Keep writing so the interval check fires on a subsequent write.
            deadline = time.monotonic() + limit
            while not flushed.is_set() and time.monotonic() < deadline:
                logger.log("keep_alive", ts=time.monotonic())
                time.sleep(0.05)

            logger.close()

            self.assertTrue(
                flushed.is_set(),
                f"Expected a flush within {limit:.1f}s but none occurred",
            )
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # close() must flush so no data is lost
    # ------------------------------------------------------------------

    def test_close_flushes_pending_data(self):
        """Events written but not yet flushed must appear in the file after close()."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            # Force _last_flush into the future so the periodic flush never
            # fires during the test — only close() should flush.
            logger = JsonEventLogger(path)
            logger._last_flush = time.monotonic() + 9999

            logger.log("sentinel_event", marker="close_flush_test")
            logger.close()

            with open(path, encoding="utf-8") as fh:
                content = fh.read()

            self.assertIn("sentinel_event", content)
            self.assertIn("close_flush_test", content)
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # Size cap
    # ------------------------------------------------------------------

    def test_events_dropped_when_cap_reached(self):
        """Writes beyond max_bytes must be silently dropped, not crash."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            logger = JsonEventLogger(path, max_bytes=200)

            for i in range(100):
                logger.log("overflow", idx=i)
            logger.close()

            size = os.path.getsize(path)
            self.assertLessEqual(size, 400,  # some leeway for the last line
                                 "File should respect the size cap")
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # Thread safety: concurrent writers must not corrupt the file
    # ------------------------------------------------------------------

    def test_concurrent_writes_are_safe(self):
        """Multiple threads writing simultaneously must not raise or corrupt."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            logger = JsonEventLogger(path, max_bytes=50 * 1024 * 1024)
            errors = []

            def _writer(thread_id: int):
                try:
                    for i in range(200):
                        logger.log("concurrent", thread=thread_id, idx=i)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=_writer, args=(n,)) for n in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10.0)

            logger.close()

            self.assertEqual(errors, [], f"Writer threads raised: {errors}")

            # Every line must be valid JSON.
            import json
            with open(path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if line:
                        try:
                            json.loads(line)
                        except json.JSONDecodeError as e:
                            self.fail(f"Line {lineno} is not valid JSON: {e}\n{line!r}")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
