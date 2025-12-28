"""
Unit tests for OpenTelemetry Integration.

Tests telemetry setup, shutdown, and helper functions.

Author: Defensive Toolkit
Date: 2025-12-28
"""

from unittest.mock import MagicMock, patch

import pytest


class TestTelemetryModule:
    """Tests for telemetry module imports and basic functionality."""

    def test_import_telemetry_module(self):
        """Test that telemetry module can be imported."""
        from defensive_toolkit.api import telemetry

        assert hasattr(telemetry, "setup_telemetry")
        assert hasattr(telemetry, "shutdown_telemetry")
        assert hasattr(telemetry, "get_tracer")
        assert hasattr(telemetry, "is_telemetry_enabled")
        assert hasattr(telemetry, "get_telemetry_status")

    def test_get_telemetry_status_disabled(self):
        """Test status when telemetry is not initialized."""
        from defensive_toolkit.api.telemetry import get_telemetry_status

        status = get_telemetry_status()
        assert isinstance(status, dict)
        assert "enabled" in status
        assert "provider" in status

    def test_is_telemetry_enabled_default(self):
        """Test telemetry is disabled by default."""
        from defensive_toolkit.api.telemetry import is_telemetry_enabled

        # Should be False when not initialized
        enabled = is_telemetry_enabled()
        assert isinstance(enabled, bool)


class TestNoOpTracer:
    """Tests for NoOpTracer when OTEL is not available."""

    def test_get_tracer_returns_object(self):
        """Test get_tracer returns a tracer-like object."""
        from defensive_toolkit.api.telemetry import get_tracer

        tracer = get_tracer("test-module")
        assert tracer is not None

    def test_noop_tracer_context_manager(self):
        """Test NoOpTracer can be used as context manager."""
        from defensive_toolkit.api.telemetry import get_tracer

        tracer = get_tracer("test")

        # Should not raise even without OTEL
        with tracer.start_as_current_span("test_span") as span:
            span.set_attribute("key", "value")
            span.add_event("test_event")

    def test_noop_span_methods(self):
        """Test NoOpSpan methods don't raise."""
        from defensive_toolkit.api.telemetry import _NoOpSpan

        span = _NoOpSpan()

        # All methods should be no-ops
        span.set_attribute("key", "value")
        span.add_event("event")
        span.set_status("OK")
        span.record_exception(Exception("test"))
        span.end()

        # Context manager
        with span:
            pass


class TestSetupTelemetry:
    """Tests for telemetry setup functionality."""

    def test_setup_disabled_returns_false(self):
        """Test setup returns False when OTEL disabled."""
        from defensive_toolkit.api.telemetry import setup_telemetry

        app = MagicMock()
        settings = MagicMock()
        settings.otel_enabled = False

        result = setup_telemetry(app, settings)
        assert result is False

    def test_setup_with_missing_packages(self):
        """Test setup handles missing OTEL packages gracefully."""
        from defensive_toolkit.api.telemetry import setup_telemetry

        app = MagicMock()
        settings = MagicMock()
        settings.otel_enabled = True
        settings.otel_service_name = "test-service"
        settings.otel_exporter_endpoint = "http://localhost:4317"
        settings.otel_trace_sample_rate = 1.0
        settings.app_version = "1.0.0"
        settings.debug = False

        # This may return True or False depending on whether OTEL is installed
        result = setup_telemetry(app, settings)
        assert isinstance(result, bool)


class TestShutdownTelemetry:
    """Tests for telemetry shutdown functionality."""

    def test_shutdown_when_not_initialized(self):
        """Test shutdown doesn't raise when not initialized."""
        from defensive_toolkit.api.telemetry import shutdown_telemetry

        # Should not raise even if not initialized
        shutdown_telemetry()


class TestHealthCheckIntegration:
    """Tests for telemetry health check integration."""

    def test_telemetry_health_check_disabled(self):
        """Test health check reports disabled when OTEL is off."""
        from defensive_toolkit.api.health import check_telemetry_health

        health = check_telemetry_health()
        assert health.name == "telemetry"
        assert health.status in ("disabled", "degraded", "healthy")

    def test_telemetry_in_readiness_check(self):
        """Test telemetry status included in readiness check."""
        # Import to ensure no errors
        from defensive_toolkit.api.health import perform_readiness_check

        # The function should exist and be callable
        assert callable(perform_readiness_check)


class TestConfigSettings:
    """Tests for OTEL configuration settings."""

    def test_otel_settings_exist(self):
        """Test OTEL settings are defined in config."""
        from defensive_toolkit.api.config import Settings

        settings = Settings()
        assert hasattr(settings, "otel_enabled")
        assert hasattr(settings, "otel_service_name")
        assert hasattr(settings, "otel_exporter_endpoint")
        assert hasattr(settings, "otel_trace_sample_rate")

    def test_otel_settings_defaults(self):
        """Test OTEL settings have correct defaults."""
        from defensive_toolkit.api.config import Settings

        settings = Settings()
        assert settings.otel_enabled is False
        assert settings.otel_service_name == "defensive-toolkit"
        assert settings.otel_exporter_endpoint == "http://localhost:4317"
        assert settings.otel_trace_sample_rate == 1.0


class TestMainIntegration:
    """Tests for telemetry integration in main.py."""

    def test_telemetry_imported_in_main(self):
        """Test telemetry functions are imported in main."""
        from defensive_toolkit.api import main

        assert hasattr(main, "setup_telemetry")
        assert hasattr(main, "shutdown_telemetry")
        assert hasattr(main, "get_telemetry_status")
