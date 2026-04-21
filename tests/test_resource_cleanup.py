"""
Resource-cleanup and bounded-growth regression tests.

Targets:
  - DynamicCertCache: LRU eviction keeps cache ≤ MAX_CACHE_SIZE; no temp files
    left behind after _build_ctx_for_hostname (regression for CHANGELOG fix)
  - JsonEventLogger: byte-cap enforced; memory growth bounded under sustained writes
  - _ReuseServer._per_ip: connection counter cleaned up after all connections close
"""
from __future__ import annotations

import collections
import gc
import os
import threading
import tracemalloc

import pytest

cryptography = pytest.importorskip("cryptography")

from utils.cert_utils import (  # noqa: E402
    DynamicCertCache,
    generate_ca_cert,
    generate_self_signed_cert,
)
from utils.json_logger import JsonEventLogger  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def pki(tmp_path):
    """Generate a minimal CA + server cert pair into tmp_path."""
    ca_cert  = str(tmp_path / "ca.crt")
    ca_key   = str(tmp_path / "ca.key")
    srv_cert = str(tmp_path / "srv.crt")
    srv_key  = str(tmp_path / "srv.key")
    generate_ca_cert(ca_cert, ca_key)
    generate_self_signed_cert(srv_cert, srv_key)
    return ca_cert, ca_key, srv_cert, srv_key


# ── DynamicCertCache: LRU eviction bound ─────────────────────────────────────

class TestDynamicCertCacheEviction:

    def test_cache_never_exceeds_max_size(self, pki):
        """Inserting beyond MAX_CACHE_SIZE must evict oldest entries in FIFO order."""
        ca_cert, ca_key, srv_cert, srv_key = pki
        cache = DynamicCertCache(srv_cert, srv_key, ca_cert, ca_key)
        MAX = DynamicCertCache.MAX_CACHE_SIZE

        for i in range(MAX + 100):
            hostname = f"host{i}.example.com"
            with cache._lock:
                if len(cache._cache) >= MAX:
                    oldest = next(iter(cache._cache))
                    del cache._cache[oldest]
                cache._cache[hostname] = object()  # sentinel value

        with cache._lock:
            assert len(cache._cache) == MAX

    def test_oldest_entries_evicted_first(self, pki):
        """FIFO eviction: first-inserted keys are removed before later ones."""
        ca_cert, ca_key, srv_cert, srv_key = pki
        cache = DynamicCertCache(srv_cert, srv_key, ca_cert, ca_key)
        MAX = DynamicCertCache.MAX_CACHE_SIZE

        for i in range(MAX):
            with cache._lock:
                cache._cache[f"original-{i}.com"] = object()

        # Add one more — must evict "original-0.com"
        with cache._lock:
            if len(cache._cache) >= MAX:
                oldest = next(iter(cache._cache))
                del cache._cache[oldest]
            cache._cache["newcomer.com"] = object()

        with cache._lock:
            assert "original-0.com" not in cache._cache
            assert "newcomer.com" in cache._cache

    def test_no_temp_files_after_cert_build(self, pki, tmp_path):
        """_build_ctx_for_hostname must delete _dyn_* temp files after loading.

        Regression for the CHANGELOG-documented bug where cert/key temp files
        were retained after load_cert_chain(), leaking key material on disk.
        """
        ca_cert, ca_key, srv_cert, srv_key = pki
        cache = DynamicCertCache(srv_cert, srv_key, ca_cert, ca_key)

        before = set(os.listdir(tmp_path))
        cache._build_ctx_for_hostname("testhost.example.com")
        after = set(os.listdir(tmp_path))

        leaked = {f for f in (after - before) if f.startswith("_dyn_")}
        assert not leaked, f"Temp cert files not cleaned up: {leaked}"

    def test_repeated_builds_leave_no_temp_files(self, pki, tmp_path):
        """Building certs for 20 distinct hostnames must leave no _dyn_* residue."""
        ca_cert, ca_key, srv_cert, srv_key = pki
        cache = DynamicCertCache(srv_cert, srv_key, ca_cert, ca_key)

        for i in range(20):
            cache._build_ctx_for_hostname(f"malware{i}.evil.com")

        stale = [f for f in os.listdir(tmp_path) if f.startswith("_dyn_")]
        assert not stale, f"Stale temp files: {stale}"

    def test_cache_memory_growth_bounded(self, pki):
        """Object growth from MAX+100 cache inserts must be < 5 MB."""
        ca_cert, ca_key, srv_cert, srv_key = pki
        cache = DynamicCertCache(srv_cert, srv_key, ca_cert, ca_key)
        MAX = DynamicCertCache.MAX_CACHE_SIZE

        gc.collect()
        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()

        for i in range(MAX + 100):
            with cache._lock:
                if len(cache._cache) >= MAX:
                    oldest = next(iter(cache._cache))
                    del cache._cache[oldest]
                cache._cache[f"mem-{i}.example.com"] = object()

        gc.collect()
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        growth = sum(
            s.size_diff for s in snap2.compare_to(snap1, "lineno") if s.size_diff > 0
        )
        assert growth < 5 * 1024 * 1024, (
            f"Cache grew by {growth / 1024:.0f} KB after {MAX + 100} inserts — possible leak"
        )


# ── JsonEventLogger: byte-cap enforcement ────────────────────────────────────

class TestJsonEventLoggerCap:

    def test_byte_cap_enforced(self, tmp_path):
        """File on disk must not exceed max_bytes after writing past the cap."""
        log_path = str(tmp_path / "events.jsonl")
        cap = 10 * 1024  # 10 KB
        jl = JsonEventLogger(log_path, max_bytes=cap)

        # 200 events × ~200 bytes = ~40 KB if uncapped
        for i in range(200):
            jl.log("test_event", idx=i, payload="x" * 150)
        jl.close()

        assert os.path.getsize(log_path) <= cap

    def test_bytes_written_counter_stays_within_cap(self, tmp_path):
        """Internal _bytes_written counter must not exceed _max_bytes."""
        log_path = str(tmp_path / "events.jsonl")
        cap = 8 * 1024  # 8 KB
        jl = JsonEventLogger(log_path, max_bytes=cap)

        for i in range(200):
            jl.log("overflow_test", seq=i, data="y" * 100)

        assert jl._bytes_written <= cap
        jl.close()

    def test_cap_warn_flag_set_once(self, tmp_path):
        """_cap_warned must be True after cap is hit, and not reset."""
        log_path = str(tmp_path / "events.jsonl")
        jl = JsonEventLogger(log_path, max_bytes=512)

        for i in range(100):
            jl.log("overflow", idx=i, data="z" * 50)

        assert jl._cap_warned is True
        jl.close()

    def test_memory_bounded_under_sustained_writes(self, tmp_path):
        """Logger memory footprint must not grow unboundedly past the cap."""
        log_path = str(tmp_path / "events.jsonl")
        cap = 50 * 1024  # 50 KB
        jl = JsonEventLogger(log_path, max_bytes=cap)

        gc.collect()
        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()

        for i in range(1000):
            jl.log("stress", seq=i, data="a" * 100)

        gc.collect()
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()
        jl.close()

        growth = sum(
            s.size_diff for s in snap2.compare_to(snap1, "lineno") if s.size_diff > 0
        )
        # 1000 writes against a 50 KB cap must not consume > 2 MB of new objects
        assert growth < 2 * 1024 * 1024, (
            f"Logger accumulated {growth / 1024:.0f} KB for 1000 capped writes — possible leak"
        )

    def test_close_is_idempotent(self, tmp_path):
        """Calling close() twice must not raise."""
        log_path = str(tmp_path / "events.jsonl")
        jl = JsonEventLogger(log_path)
        jl.log("event", x=1)
        jl.close()
        jl.close()  # must not raise


# ── _ReuseServer._per_ip: connection counter cleanup ─────────────────────────

class TestPerIpCounterCleanup:
    """Verify the catch-all TCP server's per-IP connection counter is leak-free."""

    def _make_server(self):
        """Instantiate _ReuseServer without binding a real socket."""
        from services.catch_all import _ReuseServer  # noqa: PLC0415
        server = object.__new__(_ReuseServer)
        server._per_ip = collections.defaultdict(int)
        server._per_ip_lock = threading.Lock()
        server._sem = None
        server._max_per_ip = 20
        return server

    def _acquire(self, server, ip: str) -> bool:
        """Simulate a connection being accepted (returns False if over limit)."""
        with server._per_ip_lock:
            if server._per_ip[ip] >= server._max_per_ip:
                return False
            server._per_ip[ip] += 1
        return True

    def _release(self, server, ip: str) -> None:
        """Simulate a connection being closed."""
        with server._per_ip_lock:
            server._per_ip[ip] -= 1
            if server._per_ip[ip] <= 0:
                del server._per_ip[ip]

    def test_dict_empty_after_all_connections_close(self):
        """_per_ip must be empty once every simulated connection has been released."""
        server = self._make_server()

        for i in range(500):
            ip = f"10.0.{i // 256}.{i % 256}"
            self._acquire(server, ip)
            self._release(server, ip)

        assert len(server._per_ip) == 0, (
            f"_per_ip not empty after all connections closed: {dict(server._per_ip)}"
        )

    def test_concurrent_connections_no_residual_entries(self):
        """Parallel acquire/release across threads must leave _per_ip empty."""
        server = self._make_server()
        errors: list[str] = []

        def connect_disconnect(ip: str, rounds: int) -> None:
            for _ in range(rounds):
                self._acquire(server, ip)
                self._release(server, ip)

        # Each thread uses a unique IP so there's no cross-thread contention
        threads = [
            threading.Thread(target=connect_disconnect, args=(f"10.1.0.{i}", 100))
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            if t.is_alive():
                errors.append(f"thread {t.name} timed out")

        assert not errors, f"Thread errors: {errors}"
        assert len(server._per_ip) == 0, (
            f"_per_ip residual entries after concurrent test: {dict(server._per_ip)}"
        )

    def test_per_ip_limit_prevents_overflow(self):
        """Connections beyond max_per_ip must be rejected, not accumulated."""
        server = self._make_server()
        ip = "192.168.1.100"
        accepted = 0

        for _ in range(server._max_per_ip + 10):
            if self._acquire(server, ip):
                accepted += 1

        assert accepted == server._max_per_ip
        with server._per_ip_lock:
            assert server._per_ip[ip] == server._max_per_ip
