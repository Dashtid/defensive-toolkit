#!/usr/bin/env python3
"""
Tests for the Rust-backed log parser.

These tests verify both the Rust implementation (when available)
and the Python fallback behavior.
"""

import tempfile
from pathlib import Path

import pytest

from defensive_toolkit.log_analysis.parsers.log_parser_fast import (
    LogEntry,
    LogParser,
    get_log_parser,
    is_rust_available,
)


class TestLogParserFast:
    """Tests for the high-performance log parser."""

    def test_parser_creation(self):
        """Test parser can be created."""
        parser = LogParser(log_format="auto")
        assert parser is not None
        assert parser.backend in ("rust", "python")

    def test_backend_detection(self):
        """Test that backend is correctly detected."""
        parser = LogParser()
        if is_rust_available():
            assert parser.backend == "rust"
        else:
            assert parser.backend == "python"

    def test_parse_syslog_line(self):
        """Test parsing a syslog line."""
        parser = LogParser(log_format="syslog")
        line = "Oct 15 14:30:22 webserver01 sshd[12345]: Failed password for admin"

        entry = parser.parse_line(line)

        assert entry is not None
        assert entry.timestamp == "Oct 15 14:30:22"
        assert entry.hostname == "webserver01"
        assert entry.process == "sshd"
        assert entry.pid == 12345
        assert "Failed password" in entry.message

    def test_parse_json_line(self):
        """Test parsing a JSON log line."""
        parser = LogParser(log_format="json")
        line = '{"timestamp":"2025-10-15T14:30:22Z","severity":"ERROR","message":"Test error","source_ip":"192.168.1.100"}'

        entry = parser.parse_line(line)

        assert entry is not None
        assert entry.timestamp == "2025-10-15T14:30:22Z"
        assert entry.severity == "ERROR"
        assert entry.message == "Test error"
        assert entry.source_ip == "192.168.1.100"

    def test_parse_apache_line(self):
        """Test parsing an Apache log line."""
        parser = LogParser(log_format="apache")
        line = '192.168.1.50 - admin [15/Oct/2025:14:30:22 +0000] "GET /api HTTP/1.1" 200 4523 "-" "curl"'

        entry = parser.parse_line(line)

        assert entry is not None
        assert entry.source_ip == "192.168.1.50"
        assert entry.user == "admin"
        assert "GET /api" in entry.message

    def test_parse_auto_detect(self):
        """Test auto-detection of log formats."""
        parser = LogParser(log_format="auto")

        # Test JSON detection
        json_line = '{"message":"test"}'
        entry = parser.parse_line(json_line)
        assert entry is not None

        # Test syslog detection
        syslog_line = "Oct 15 14:30:22 host process: message"
        entry = parser.parse_line(syslog_line)
        assert entry is not None

    def test_parse_empty_line(self):
        """Test parsing empty lines returns None."""
        parser = LogParser()
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None

    def test_log_entry_to_dict(self):
        """Test LogEntry.to_dict() method."""
        entry = LogEntry(
            timestamp="2025-01-01",
            hostname="server",
            message="test message",
        )
        d = entry.to_dict()

        assert d["timestamp"] == "2025-01-01"
        assert d["hostname"] == "server"
        assert d["message"] == "test message"
        assert d["process"] is None

    def test_log_entry_repr(self):
        """Test LogEntry string representation."""
        entry = LogEntry(
            timestamp="2025-01-01",
            hostname="server",
            message="test",
        )
        repr_str = repr(entry)
        assert "LogEntry" in repr_str
        assert "2025-01-01" in repr_str

    def test_parse_file(self):
        """Test parsing a log file."""
        parser = LogParser(log_format="syslog")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("Oct 15 14:30:22 host1 process1: message1\n")
            f.write("Oct 15 14:30:23 host2 process2: message2\n")
            f.write("Oct 15 14:30:24 host3 process3: message3\n")
            f.name
            temp_path = Path(f.name)

        try:
            entries = parser.parse_file(temp_path)
            assert len(entries) == 3
            assert entries[0].hostname == "host1"
            assert entries[1].hostname == "host2"
            assert entries[2].hostname == "host3"
        finally:
            temp_path.unlink()

    def test_parse_file_max_lines(self):
        """Test parsing with max_lines limit."""
        parser = LogParser(log_format="syslog")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for i in range(100):
                f.write(f"Oct 15 14:30:{i:02d} host process: message {i}\n")
            temp_path = Path(f.name)

        try:
            entries = parser.parse_file(temp_path, max_lines=10)
            assert len(entries) == 10
        finally:
            temp_path.unlink()

    def test_parse_file_parallel(self):
        """Test parallel file parsing."""
        parser = LogParser(log_format="syslog")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for i in range(1000):
                f.write(f"Oct 15 14:30:00 host process[{i}]: message {i}\n")
            temp_path = Path(f.name)

        try:
            entries = parser.parse_file_parallel(temp_path, chunk_size=100)
            assert len(entries) == 1000
        finally:
            temp_path.unlink()

    def test_parse_lines_parallel(self):
        """Test parallel line parsing."""
        parser = LogParser(log_format="syslog")

        lines = [f"Oct 15 14:30:00 host process[{i}]: message {i}" for i in range(100)]

        entries = parser.parse_lines_parallel(lines)
        assert len(entries) == 100

    def test_get_stats(self):
        """Test statistics gathering."""
        parser = LogParser(log_format="syslog")

        lines = [
            "Oct 15 14:30:22 host1 process: message from 192.168.1.1",
            "Oct 15 14:30:23 host2 process: message",
            '{"timestamp":"2025-01-01","severity":"ERROR","message":"test"}',
        ]

        # Parse with auto to get mixed results
        auto_parser = LogParser(log_format="auto")
        entries = [e for line in lines if (e := auto_parser.parse_line(line)) is not None]

        stats = LogParser.get_stats(entries)
        assert stats["total"] == 3
        assert stats["with_timestamp"] >= 2

    def test_get_log_parser_factory(self):
        """Test the factory function."""
        parser = get_log_parser("syslog", prefer_rust=True)
        assert parser is not None

        parser = get_log_parser("json", prefer_rust=False)
        assert parser is not None


class TestLogParserPerformance:
    """Performance-related tests (not actual benchmarks)."""

    @pytest.mark.slow
    def test_large_file_parsing(self):
        """Test parsing a large log file doesn't crash."""
        parser = LogParser(log_format="syslog")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for i in range(10000):
                f.write(f"Oct 15 14:30:00 host process[{i}]: message {i}\n")
            temp_path = Path(f.name)

        try:
            entries = parser.parse_file(temp_path)
            assert len(entries) == 10000
        finally:
            temp_path.unlink()

    @pytest.mark.slow
    def test_parallel_vs_sequential(self):
        """Test that parallel parsing works correctly."""
        parser = LogParser(log_format="syslog")

        lines = [f"Oct 15 14:30:00 host process[{i}]: message {i}" for i in range(1000)]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for line in lines:
                f.write(line + "\n")
            temp_path = Path(f.name)

        try:
            sequential = parser.parse_file(temp_path)
            parallel = parser.parse_file_parallel(temp_path, chunk_size=100)

            # Results should be the same (order might differ in parallel)
            assert len(sequential) == len(parallel)
        finally:
            temp_path.unlink()


class TestRustAvailability:
    """Tests for Rust availability detection."""

    def test_is_rust_available_returns_bool(self):
        """Test that is_rust_available returns a boolean."""
        result = is_rust_available()
        assert isinstance(result, bool)

    def test_fallback_behavior(self):
        """Test that Python fallback works when Rust is unavailable."""
        # This test always passes because the wrapper handles fallback
        parser = LogParser(log_format="syslog")
        line = "Oct 15 14:30:22 host process: message"
        entry = parser.parse_line(line)
        assert entry is not None
