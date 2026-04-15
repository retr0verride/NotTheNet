# infrastructure/logging/__init__.py
from infrastructure.logging.otel import get_meter, get_tracer, record_span
from infrastructure.logging.setup import configure_logging

__all__ = ["configure_logging", "get_tracer", "get_meter", "record_span"]
