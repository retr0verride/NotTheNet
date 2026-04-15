"""OpenTelemetry integration hooks.

Provides a tracer, meter, and a ``record_span`` context manager that work in
two modes:

1. **Full mode** — when the ``opentelemetry-sdk`` package is installed AND the
   ``NTN_OTEL_ENDPOINT`` environment variable points to an OTLP collector,
   real spans / metrics are exported via OTLP/gRPC.

2. **No-op mode** — when ``opentelemetry-sdk`` is NOT installed (the default
   air-gapped deployment), all calls are silent no-ops so the rest of the
   codebase never needs to check ``if otel_enabled:``.

Install the optional packages to enable full mode:

    pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc

Environment variables (12-factor config):
    NTN_OTEL_ENDPOINT   — OTLP/gRPC endpoint  (e.g. http://collector:4317)
    NTN_OTEL_ENABLED    — set to "1" to opt-in (default: off)
    OTEL_SERVICE_NAME   — overrides the default service name "notthenet"
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

# ── Attempt to import optional OTel packages ─────────────────────────────────

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    try:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        _OTLP_AVAILABLE = True
    except ImportError:
        _OTLP_AVAILABLE = False

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    _OTLP_AVAILABLE = False


# ── Module-level provider references ─────────────────────────────────────────

_tracer_provider: Any = None
_meter_provider: Any = None
_initialised = False


def _is_enabled() -> bool:
    return os.environ.get("NTN_OTEL_ENABLED", "0").strip().lower() in ("1", "true", "yes")


def initialise(service_name: str = "notthenet", endpoint: str | None = None) -> bool:
    """Initialise OTel providers.  Call once at startup after loading config.

    Returns True if instrumentation is active, False for no-op mode.
    """
    global _tracer_provider, _meter_provider, _initialised

    if _initialised:
        return _tracer_provider is not None

    _initialised = True

    if not _is_enabled() or not _OTEL_AVAILABLE:
        logger.debug("OpenTelemetry: no-op mode (OTEL_ENABLED=%s, sdk=%s)",
                     _is_enabled(), _OTEL_AVAILABLE)
        return False

    endpoint = endpoint or os.environ.get("NTN_OTEL_ENDPOINT", "http://localhost:4317")
    svc_name = os.environ.get("OTEL_SERVICE_NAME", service_name)
    resource = Resource(attributes={SERVICE_NAME: svc_name})

    # ── Tracer ────────────────────────────────────────────────────────────────
    try:
        tp = TracerProvider(resource=resource)
        if _OTLP_AVAILABLE:
            tp.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
            )
        trace.set_tracer_provider(tp)
        _tracer_provider = tp
    except Exception as exc:  # pragma: no cover
        logger.warning("OTel tracer init failed: %s", exc)

    # ── Meter ─────────────────────────────────────────────────────────────────
    try:
        readers = []
        if _OTLP_AVAILABLE:
            readers.append(
                PeriodicExportingMetricReader(
                    OTLPMetricExporter(endpoint=endpoint, insecure=True),
                    export_interval_millis=30_000,
                )
            )
        mp = MeterProvider(resource=resource, metric_readers=readers)
        otel_metrics.set_meter_provider(mp)
        _meter_provider = mp
    except Exception as exc:  # pragma: no cover
        logger.warning("OTel meter init failed: %s", exc)

    logger.info("OpenTelemetry active: endpoint=%s service=%s", endpoint, svc_name)
    return _tracer_provider is not None


def get_tracer(name: str = "notthenet") -> Any:
    """Return an OTel tracer, or a no-op stub if OTel is not active."""
    if _OTEL_AVAILABLE and _tracer_provider is not None:
        return _tracer_provider.get_tracer(name)
    return _NoOpTracer()


def get_meter(name: str = "notthenet") -> Any:
    """Return an OTel meter, or a no-op stub if OTel is not active."""
    if _OTEL_AVAILABLE and _meter_provider is not None:
        return _meter_provider.get_meter(name)
    return _NoOpMeter()


@contextmanager
def record_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """Context manager that wraps a block of code in an OTel span.

    In no-op mode this is a transparent pass-through with zero overhead.

    Example::

        with record_span("dns.resolve", attributes={"qname": qname}):
            result = resolve(qname)
    """
    if _OTEL_AVAILABLE and _tracer_provider is not None:
        tracer = _tracer_provider.get_tracer("notthenet")
        with tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            yield span
    else:
        yield None


# ── No-op stubs ───────────────────────────────────────────────────────────────

class _NoOpTracer:
    @contextlib.contextmanager
    def start_as_current_span(self, name: str, **_kw: Any) -> Generator[Any, None, None]:
        yield None

    def start_span(self, name: str, **_kw: Any) -> _NoOpSpan:
        return _NoOpSpan()


class _NoOpSpan:
    def set_attribute(self, *_a: Any, **_kw: Any) -> None: pass
    def record_exception(self, *_a: Any, **_kw: Any) -> None: pass
    def set_status(self, *_a: Any, **_kw: Any) -> None: pass
    def __enter__(self) -> _NoOpSpan: return self
    def __exit__(self, *_a: Any) -> None: pass


class _NoOpMeter:
    def create_counter(self, *_a: Any, **_kw: Any) -> _NoOpInstrument:
        return _NoOpInstrument()

    def create_histogram(self, *_a: Any, **_kw: Any) -> _NoOpInstrument:
        return _NoOpInstrument()

    def create_up_down_counter(self, *_a: Any, **_kw: Any) -> _NoOpInstrument:
        return _NoOpInstrument()

    def create_observable_gauge(self, *_a: Any, **_kw: Any) -> _NoOpInstrument:
        return _NoOpInstrument()


class _NoOpInstrument:
    def add(self, *_a: Any, **_kw: Any) -> None: pass
    def record(self, *_a: Any, **_kw: Any) -> None: pass
