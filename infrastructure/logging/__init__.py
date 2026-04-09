# infrastructure/logging/__init__.py
from infrastructure.logging.setup import configure_logging
from infrastructure.logging.otel import get_tracer, get_meter, record_span

__all__ = ["configure_logging", "get_tracer", "get_meter", "record_span"]
