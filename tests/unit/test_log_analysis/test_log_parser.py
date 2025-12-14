#!/usr/bin/env python3
"""
Unit tests for log-analysis/parsers/log-parser.py
"""

import json
import sys
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.log_analysis.parsers.log_parser import LogEntry, LogParser


class TestLogEntry:
    """Test LogEntry dataclass"""

    def test_log_entry_creation(self):
        """Test creating LogEntry"""
        entry = LogEntry(
            timestamp="2025-10-15T14:30:22Z",
            hostname="webserver01",
            message="Test message",
            severity="INFO",
        )

        assert entry.timestamp == "2025-10-15T14:30:22Z"
        assert entry.hostname == "webserver01"
        assert entry.message == "Test message"
        assert entry.severity == "INFO"

    def test_log_entry_defaults(self):
        """Test LogEntry with default values"""
        entry = LogEntry(message="Test")

        assert entry.timestamp is None
        assert entry.hostname is None
        assert entry.message == "Test"

    def test_log_entry_to_dict(self):
        """Test converting LogEntry to dictionary"""
        entry = LogEntry(timestamp="2025-10-15T14:30:22Z", hostname="server01", message="Test")

        result = entry.to_dict()

        assert isinstance(result, dict)
        assert result["timestamp"] == "2025-10-15T14:30:22Z"
        assert result["hostname"] == "server01"
        assert result["message"] == "Test"


class TestLogParser:
    """Test LogParser class"""

    def test_init_default(self):
        """Test parser initialization with default format"""
        parser = LogParser()
        assert parser.log_format == "auto"

    def test_init_specific_format(self):
        """Test parser initialization with specific format"""
        parser = LogParser(log_format="syslog")
        assert parser.log_format == "syslog"

    def test_init_format_lowercase(self):
        """Test format is converted to lowercase"""
        parser = LogParser(log_format="SYSLOG")
        assert parser.log_format == "syslog"

    def test_parse_line_empty(self):
        """Test parsing empty line"""
        parser = LogParser()
        result = parser.parse_line("")

        assert result is None

    def test_parse_line_whitespace_only(self):
        """Test parsing whitespace-only line"""
        parser = LogParser()
        result = parser.parse_line("   \n\t   ")

        assert result is None

    def test_parse_syslog_basic(self, sample_syslog_line):
        """Test parsing basic syslog line"""
        parser = LogParser(log_format="syslog")
        result = parser.parse_line(sample_syslog_line)

        assert result is not None
        assert isinstance(result, LogEntry)
        assert result.hostname == "webserver01"
        assert result.process == "sshd"
        assert result.pid == 12345
        assert "Failed password" in result.message

    def test_parse_syslog_with_priority(self):
        """Test parsing syslog with priority"""
        parser = LogParser(log_format="syslog")
        log_line = "<134>Oct 15 14:30:22 host01 sshd[123]: Test message"

        result = parser.parse_line(log_line)

        assert result is not None
        assert result.hostname == "host01"
        assert result.process == "sshd"

    def test_parse_apache_log(self, sample_apache_log_line):
        """Test parsing Apache access log"""
        parser = LogParser(log_format="apache")
        result = parser.parse_line(sample_apache_log_line)

        assert result is not None
        assert result.source_ip == "192.168.1.50"
        assert "GET /admin/login" in result.message
        assert result.user == "-"  # Anonymous user

    def test_parse_json_log(self, sample_json_log_line):
        """Test parsing JSON log"""
        parser = LogParser(log_format="json")
        result = parser.parse_line(sample_json_log_line)

        assert result is not None
        assert result.severity == "ERROR"
        assert result.message == "Authentication failed"
        assert result.user == "admin"
        assert result.source_ip == "192.168.1.100"

    def test_parse_json_invalid(self):
        """Test parsing invalid JSON"""
        parser = LogParser(log_format="json")
        result = parser.parse_line("{ invalid json }")

        # Should handle gracefully
        assert result is None or isinstance(result, LogEntry)

    def test_auto_detect_syslog(self, sample_syslog_line):
        """Test auto-detection of syslog format"""
        parser = LogParser(log_format="auto")
        result = parser.parse_line(sample_syslog_line)

        assert result is not None
        assert result.hostname == "webserver01"

    def test_auto_detect_apache(self, sample_apache_log_line):
        """Test auto-detection of Apache format"""
        parser = LogParser(log_format="auto")
        result = parser.parse_line(sample_apache_log_line)

        assert result is not None
        assert result.source_ip == "192.168.1.50"

    def test_auto_detect_json(self, sample_json_log_line):
        """Test auto-detection of JSON format"""
        parser = LogParser(log_format="auto")
        result = parser.parse_line(sample_json_log_line)

        assert result is not None
        assert result.severity == "ERROR"

    def test_extract_ips_from_message(self):
        """Test IP address extraction from message"""
        parser = LogParser()
        message = "Connection from 192.168.1.100 to 10.0.0.5 blocked"

        # Assuming parser has IP extraction logic
        ips = parser.IP_PATTERN.findall(message)

        assert "192.168.1.100" in ips
        assert "10.0.0.5" in ips

    def test_parse_multiple_lines(self, sample_syslog_line, sample_apache_log_line):
        """Test parsing multiple log lines"""
        parser = LogParser(log_format="auto")

        result1 = parser.parse_line(sample_syslog_line)
        result2 = parser.parse_line(sample_apache_log_line)

        assert result1 is not None
        assert result2 is not None
        assert result1.hostname == "webserver01"
        assert result2.source_ip == "192.168.1.50"


class TestLogParserEdgeCases:
    """Test edge cases and error handling"""

    def test_parse_malformed_syslog(self):
        """Test parsing malformed syslog"""
        parser = LogParser(log_format="syslog")
        malformed = "This is not a valid syslog line"

        result = parser.parse_line(malformed)

        # Should return None or LogEntry with raw message
        assert result is None or result.message == malformed

    def test_parse_syslog_missing_pid(self):
        """Test parsing syslog without PID"""
        parser = LogParser(log_format="syslog")
        log_line = "Oct 15 14:30:22 host01 sshd: Test message"

        result = parser.parse_line(log_line)

        assert result is not None
        assert result.process == "sshd"
        assert result.pid is None

    def test_parse_apache_partial_match(self):
        """Test parsing partial Apache log"""
        parser = LogParser(log_format="apache")
        partial = "192.168.1.50 - - [15/Oct/2025:14:30:22 +0000]"

        result = parser.parse_line(partial)

        # May not match full pattern
        assert result is None or result.source_ip == "192.168.1.50"

    def test_parse_json_nested_structure(self):
        """Test parsing JSON with nested structure"""
        parser = LogParser(log_format="json")
        nested_json = json.dumps(
            {
                "timestamp": "2025-10-15T14:30:22Z",
                "severity": "WARNING",
                "message": "Test",
                "metadata": {"user": "admin", "session_id": "abc123"},
            }
        )

        result = parser.parse_line(nested_json)

        assert result is not None
        assert result.severity == "WARNING"
        assert result.message == "Test"

    def test_parse_unicode_characters(self):
        """Test parsing logs with unicode characters"""
        parser = LogParser(log_format="syslog")
        log_line = "Oct 15 14:30:22 host01 app[123]: User 用户 logged in"

        result = parser.parse_line(log_line)

        assert result is not None
        assert "用户" in result.message

    def test_parse_very_long_line(self):
        """Test parsing very long log line"""
        parser = LogParser(log_format="syslog")
        long_message = "A" * 10000
        log_line = f"Oct 15 14:30:22 host01 app[123]: {long_message}"

        result = parser.parse_line(log_line)

        assert result is not None
        assert len(result.message) > 0


class TestLogParserWindowsEventLog:
    """Test Windows Event Log parsing"""

    def test_parse_windows_event_log_json(self, sample_windows_event_log):
        """Test parsing Windows Event Log in JSON format"""
        parser = LogParser(log_format="json")
        log_line = json.dumps(sample_windows_event_log)

        result = parser.parse_line(log_line)

        assert result is not None
        # Check if EventID is captured
        assert result.event_id == "4625" or "4625" in str(result.raw)


class TestLogParserIntegration:
    """Integration tests for LogParser"""

    def test_parse_log_file(
        self, create_sample_log_file, sample_syslog_line, sample_apache_log_line
    ):
        """Test parsing entire log file"""
        parser = LogParser(log_format="auto")
        log_file = create_sample_log_file("test.log", [sample_syslog_line, sample_apache_log_line])

        entries = []
        with open(log_file, "r") as f:
            for line in f:
                entry = parser.parse_line(line)
                if entry:
                    entries.append(entry)

        assert len(entries) == 2
        assert entries[0].hostname == "webserver01"
        assert entries[1].source_ip == "192.168.1.50"

    def test_parse_mixed_format_log_file(
        self, create_sample_log_file, sample_syslog_line, sample_json_log_line
    ):
        """Test parsing log file with mixed formats"""
        parser = LogParser(log_format="auto")
        log_file = create_sample_log_file("mixed.log", [sample_syslog_line, sample_json_log_line])

        entries = []
        with open(log_file, "r") as f:
            for line in f:
                entry = parser.parse_line(line)
                if entry:
                    entries.append(entry)

        assert len(entries) == 2


# [+] Parametrized Tests
@pytest.mark.parametrize("log_format", ["syslog", "apache", "nginx", "json", "auto"])
def test_parser_formats(log_format):
    """Test parser initialization with different formats"""
    parser = LogParser(log_format=log_format)
    assert parser.log_format == log_format.lower()


@pytest.mark.parametrize("empty_input", ["", "   ", "\n", "\t\t", "     \n  "])
def test_parse_empty_inputs(empty_input):
    """Test parsing various empty inputs"""
    parser = LogParser()
    result = parser.parse_line(empty_input)
    assert result is None


# [+] Mark integration tests
@pytest.mark.integration
def test_large_log_file_parsing(tmp_path):
    """Test parsing large log file"""
    parser = LogParser(log_format="auto")
    large_log = tmp_path / "large.log"

    # Create large log file
    with open(large_log, "w") as f:
        for i in range(10000):
            f.write(f"Oct 15 14:30:22 host01 app[{i}]: Message {i}\n")

    entries = []
    with open(large_log, "r") as f:
        for line in f:
            entry = parser.parse_line(line)
            if entry:
                entries.append(entry)

    assert len(entries) == 10000


# [+] Performance tests
@pytest.mark.slow
def test_parser_performance(sample_syslog_line):
    """Test parser performance"""
    parser = LogParser(log_format="syslog")

    import time

    start = time.time()

    for _ in range(10000):
        parser.parse_line(sample_syslog_line)

    duration = time.time() - start

    # Should parse 10k lines in reasonable time (< 5 seconds)
    assert duration < 5.0
