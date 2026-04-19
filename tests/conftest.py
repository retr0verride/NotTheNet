"""
pytest conftest — cross-platform limit_memory marker.

When pytest-memray is installed (Linux/CI) it owns the marker natively.
When it is NOT installed (Windows dev) this plugin provides an equivalent
implementation backed by stdlib tracemalloc so the same @pytest.mark.limit_memory
markers are enforced on every platform.
"""

import tracemalloc

import pytest


def _parse_bytes(value: str) -> int:
    """Convert a human-readable size string to bytes.

    Accepts formats: "50 MB", "10MB", "512KB", "1 GB".
    """
    value = value.strip()
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    for suffix, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
        if value.upper().endswith(suffix):
            return int(float(value[: -len(suffix)].strip()) * multiplier)
    return int(value)  # bare number → bytes


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "limit_memory: per-test peak allocation ceiling (e.g. '50 MB'). "
        "Enforced by pytest-memray when available, otherwise by tracemalloc.",
    )


def _memray_active() -> bool:
    """Return True if pytest-memray is installed and will handle the marker."""
    try:
        import pytest_memray  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.fixture(autouse=True)
def _tracemalloc_limit(request: pytest.FixtureRequest) -> object:
    """Enforce limit_memory markers via tracemalloc on platforms without memray."""
    if _memray_active():
        yield  # let pytest-memray do its job
        return

    marker = request.node.get_closest_marker("limit_memory")
    if marker is None:
        yield
        return

    limit_bytes = _parse_bytes(marker.args[0])

    tracemalloc.start()
    try:
        yield
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    if peak > limit_bytes:
        limit_mb = limit_bytes / 1024**2
        peak_mb = peak / 1024**2
        pytest.fail(
            f"Memory limit exceeded: peak {peak_mb:.1f} MB > limit {limit_mb:.1f} MB"
        )
