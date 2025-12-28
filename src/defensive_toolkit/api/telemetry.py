"""
OpenTelemetry Integration for Defensive Toolkit API

Provides distributed tracing with automatic instrumentation for:
- FastAPI HTTP requests
- HTTPX outbound calls
- Redis operations (when enabled)

Author: Defensive Toolkit
Date: 2025-12-28
"""

import logging
from typing import Optional

from fastapi import FastAPI

logger = logging.getLogger(__name__)

# Track initialization state
_tracer_provider: Optional[object] = None
_is_initialized: bool = False


def setup_telemetry(app: FastAPI, settings: object) -> bool:
    """
    Initialize OpenTelemetry instrumentation for the FastAPI application.

    This function sets up distributed tracing with OTLP export when OTEL is enabled.
    It instruments FastAPI for automatic span creation on incoming requests and
    optionally instruments HTTPX and Redis for outbound call tracing.

    Args:
        app: FastAPI application instance
        settings: Application settings with OTEL configuration

    Returns:
        bool: True if OTEL was successfully initialized, False otherwise

    Configuration (via settings):
        - otel_enabled: Enable/disable OTEL (default: False)
        - otel_service_name: Service name in traces (default: "defensive-toolkit")
        - otel_exporter_endpoint: OTLP endpoint (default: "http://localhost:4317")
        - otel_trace_sample_rate: Sampling rate 0.0-1.0 (default: 1.0)
    """
    global _tracer_provider, _is_initialized

    if not getattr(settings, "otel_enabled", False):
        logger.info("[i] OpenTelemetry disabled via configuration")
        return False

    if _is_initialized:
        logger.debug("[i] OpenTelemetry already initialized")
        return True

    try:
        # Import OTEL packages (optional dependencies)
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

    except ImportError as e:
        logger.warning(
            f"[-] OpenTelemetry packages not installed. "
            f"Install with: pip install defensive-toolkit[otel]. Error: {e}"
        )
        return False

    try:
        # Get configuration from settings
        service_name = getattr(settings, "otel_service_name", "defensive-toolkit")
        endpoint = getattr(settings, "otel_exporter_endpoint", "http://localhost:4317")
        sample_rate = getattr(settings, "otel_trace_sample_rate", 1.0)

        # Create resource identifying this service
        resource = Resource(attributes={
            SERVICE_NAME: service_name,
            "service.version": getattr(settings, "app_version", "unknown"),
            "deployment.environment": "production" if not getattr(settings, "debug", False) else "development",
        })

        # Create sampler based on configured rate
        sampler = TraceIdRatioBased(sample_rate)

        # Create TracerProvider with resource and sampler
        _tracer_provider = TracerProvider(
            resource=resource,
            sampler=sampler,
        )

        # Configure OTLP exporter
        otlp_exporter = OTLPSpanExporter(
            endpoint=endpoint,
            insecure=endpoint.startswith("http://"),  # Use insecure for http, secure for https
        )

        # Add batch processor for efficient span export
        span_processor = BatchSpanProcessor(otlp_exporter)
        _tracer_provider.add_span_processor(span_processor)

        # Set as global tracer provider
        trace.set_tracer_provider(_tracer_provider)

        # Instrument FastAPI
        FastAPIInstrumentor.instrument_app(
            app,
            tracer_provider=_tracer_provider,
            excluded_urls="health,health/.*,metrics",  # Skip health checks and metrics
        )

        # Instrument HTTPX for outbound calls
        _instrument_httpx()

        # Instrument Redis if enabled
        if getattr(settings, "redis_enabled", False):
            _instrument_redis()

        _is_initialized = True
        logger.info(
            f"[+] OpenTelemetry initialized: service={service_name}, "
            f"endpoint={endpoint}, sample_rate={sample_rate}"
        )
        return True

    except Exception as e:
        logger.error(f"[-] Failed to initialize OpenTelemetry: {e}")
        return False


def _instrument_httpx() -> bool:
    """Instrument HTTPX for outbound HTTP call tracing."""
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
        logger.debug("[+] HTTPX instrumentation enabled")
        return True
    except ImportError:
        logger.debug("[i] HTTPX instrumentation not available")
        return False
    except Exception as e:
        logger.warning(f"[-] Failed to instrument HTTPX: {e}")
        return False


def _instrument_redis() -> bool:
    """Instrument Redis for cache operation tracing."""
    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        RedisInstrumentor().instrument()
        logger.debug("[+] Redis instrumentation enabled")
        return True
    except ImportError:
        logger.debug("[i] Redis instrumentation not available")
        return False
    except Exception as e:
        logger.warning(f"[-] Failed to instrument Redis: {e}")
        return False


def get_tracer(name: str = "defensive-toolkit"):
    """
    Get a tracer instance for creating custom spans.

    Use this to add manual instrumentation for business operations
    that aren't automatically traced.

    Args:
        name: Tracer name (typically module name)

    Returns:
        Tracer instance or NoOpTracer if OTEL not initialized

    Example:
        tracer = get_tracer(__name__)
        with tracer.start_as_current_span("process_ioc") as span:
            span.set_attribute("ioc.type", "ip")
            span.set_attribute("ioc.value", "1.2.3.4")
            # ... do work ...
    """
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        # Return a no-op tracer if OTEL not installed
        return _NoOpTracer()


class _NoOpTracer:
    """No-operation tracer for when OTEL is not available."""

    def start_as_current_span(self, name: str, **kwargs):
        """Return a no-op context manager."""
        return _NoOpSpan()

    def start_span(self, name: str, **kwargs):
        """Return a no-op span."""
        return _NoOpSpan()


class _NoOpSpan:
    """No-operation span context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key: str, value) -> None:
        """No-op attribute setting."""
        pass

    def add_event(self, name: str, **kwargs) -> None:
        """No-op event adding."""
        pass

    def set_status(self, status) -> None:
        """No-op status setting."""
        pass

    def record_exception(self, exception, **kwargs) -> None:
        """No-op exception recording."""
        pass

    def end(self) -> None:
        """No-op span end."""
        pass


def shutdown_telemetry() -> None:
    """
    Gracefully shutdown OpenTelemetry.

    Call this during application shutdown to flush any pending spans
    and release resources.
    """
    global _tracer_provider, _is_initialized

    if not _is_initialized or _tracer_provider is None:
        return

    try:
        _tracer_provider.shutdown()
        logger.info("[+] OpenTelemetry shutdown complete")
    except Exception as e:
        logger.warning(f"[-] Error during OpenTelemetry shutdown: {e}")
    finally:
        _is_initialized = False
        _tracer_provider = None


def is_telemetry_enabled() -> bool:
    """Check if OpenTelemetry is currently enabled and initialized."""
    return _is_initialized


def get_telemetry_status() -> dict:
    """
    Get current telemetry status for health checks.

    Returns:
        dict: Status information including enabled state and provider info
    """
    return {
        "enabled": _is_initialized,
        "provider": type(_tracer_provider).__name__ if _tracer_provider else None,
    }
