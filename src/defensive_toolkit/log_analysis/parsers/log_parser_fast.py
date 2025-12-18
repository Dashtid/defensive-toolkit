#!/usr/bin/env python3
"""
High-Performance Log Parser (Rust-backed)

This module provides a drop-in replacement for the pure Python log_parser
using a Rust backend for 10-100x performance improvement.

Usage:
    # Use Rust implementation (fast)
    from defensive_toolkit.log_analysis.parsers.log_parser_fast import LogParser, LogEntry

    # Or use with automatic fallback to Python if Rust not available
    from defensive_toolkit.log_analysis.parsers import get_log_parser
    LogParser = get_log_parser()  # Returns Rust or Python implementation

The Rust module must be built separately:
    cd rust/log_parser
    maturin develop --release
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import Rust implementation
_RUST_AVAILABLE = False
_RustLogParser = None

try:
    # Import from top-level module (installed separately via maturin)
    from _log_parser_rs import LogParser as _RustLogParser

    _RUST_AVAILABLE = True
    logger.debug("[+] Rust log parser loaded successfully")
except ImportError as e:
    logger.debug(f"[-] Rust log parser not available: {e}")
    logger.debug("[i] Falling back to pure Python implementation")


def is_rust_available() -> bool:
    """Check if the Rust implementation is available."""
    return _RUST_AVAILABLE


class LogEntry:
    """
    Standardized log entry structure.

    This class wraps the Rust LogEntry when available, or provides
    a compatible pure-Python implementation.
    """

    __slots__ = (
        "timestamp",
        "hostname",
        "process",
        "pid",
        "severity",
        "message",
        "source_ip",
        "dest_ip",
        "user",
        "event_id",
        "raw",
        "_rust_entry",
    )

    def __init__(
        self,
        timestamp: Optional[str] = None,
        hostname: Optional[str] = None,
        process: Optional[str] = None,
        pid: Optional[int] = None,
        severity: Optional[str] = None,
        message: str = "",
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        user: Optional[str] = None,
        event_id: Optional[str] = None,
        raw: str = "",
        _rust_entry=None,
    ):
        if _rust_entry is not None:
            # Wrap a Rust LogEntry
            self._rust_entry = _rust_entry
            self.timestamp = _rust_entry.timestamp
            self.hostname = _rust_entry.hostname
            self.process = _rust_entry.process
            self.pid = _rust_entry.pid
            self.severity = _rust_entry.severity
            self.message = _rust_entry.message
            self.source_ip = _rust_entry.source_ip
            self.dest_ip = _rust_entry.dest_ip
            self.user = _rust_entry.user
            self.event_id = _rust_entry.event_id
            self.raw = _rust_entry.raw
        else:
            # Pure Python entry
            self._rust_entry = None
            self.timestamp = timestamp
            self.hostname = hostname
            self.process = process
            self.pid = pid
            self.severity = severity
            self.message = message
            self.source_ip = source_ip
            self.dest_ip = dest_ip
            self.user = user
            self.event_id = event_id
            self.raw = raw

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "process": self.process,
            "pid": self.pid,
            "severity": self.severity,
            "message": self.message,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "user": self.user,
            "event_id": self.event_id,
            "raw": self.raw,
        }

    def __repr__(self) -> str:
        msg_preview = self.message[:50] + "..." if len(self.message) > 50 else self.message
        return f"LogEntry(timestamp={self.timestamp!r}, hostname={self.hostname!r}, message={msg_preview!r})"

    @classmethod
    def from_rust(cls, rust_entry) -> "LogEntry":
        """Create a LogEntry from a Rust LogEntry."""
        return cls(_rust_entry=rust_entry)


class LogParser:
    """
    High-performance log parser with Rust backend.

    Provides the same interface as the pure Python LogParser but uses
    Rust for parsing when available, providing 10-100x speedup.
    """

    def __init__(self, log_format: str = "auto"):
        """
        Initialize parser.

        Args:
            log_format: Log format (auto, syslog, json, apache, nginx)
        """
        self.log_format = log_format.lower()

        if _RUST_AVAILABLE:
            self._rust_parser = _RustLogParser(log_format)
            self._use_rust = True
        else:
            self._rust_parser = None
            self._use_rust = False
            # Import Python fallback
            from defensive_toolkit.log_analysis.parsers.log_parser import (
                LogParser as PythonLogParser,
            )

            self._python_parser = PythonLogParser(log_format)

    @property
    def backend(self) -> str:
        """Return which backend is being used."""
        return "rust" if self._use_rust else "python"

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line."""
        if self._use_rust:
            result = self._rust_parser.parse_line(line)
            if result is not None:
                return LogEntry.from_rust(result)
            return None
        else:
            result = self._python_parser.parse_line(line)
            if result is not None:
                # Convert Python LogEntry to our LogEntry
                return LogEntry(
                    timestamp=result.timestamp,
                    hostname=result.hostname,
                    process=result.process,
                    pid=result.pid,
                    severity=result.severity,
                    message=result.message,
                    source_ip=result.source_ip,
                    dest_ip=result.dest_ip,
                    user=result.user,
                    event_id=result.event_id,
                    raw=result.raw,
                )
            return None

    def parse_file(self, file_path: Path, max_lines: Optional[int] = None) -> List[LogEntry]:
        """
        Parse entire log file.

        Args:
            file_path: Path to the log file
            max_lines: Maximum lines to parse (None for all)

        Returns:
            List of LogEntry objects
        """
        file_path = Path(file_path)

        if self._use_rust:
            results = self._rust_parser.parse_file(str(file_path), max_lines)
            return [LogEntry.from_rust(r) for r in results]
        else:
            results = self._python_parser.parse_file(file_path, max_lines)
            return [
                LogEntry(
                    timestamp=r.timestamp,
                    hostname=r.hostname,
                    process=r.process,
                    pid=r.pid,
                    severity=r.severity,
                    message=r.message,
                    source_ip=r.source_ip,
                    dest_ip=r.dest_ip,
                    user=r.user,
                    event_id=r.event_id,
                    raw=r.raw,
                )
                for r in results
            ]

    def parse_file_parallel(
        self,
        file_path: Path,
        max_lines: Optional[int] = None,
        chunk_size: int = 10000,
    ) -> List[LogEntry]:
        """
        Parse entire log file in parallel (Rust only).

        Falls back to sequential parsing if Rust is not available.

        Args:
            file_path: Path to the log file
            max_lines: Maximum lines to parse (None for all)
            chunk_size: Lines per parallel chunk (default: 10000)

        Returns:
            List of LogEntry objects
        """
        file_path = Path(file_path)

        if self._use_rust:
            results = self._rust_parser.parse_file_parallel(str(file_path), max_lines, chunk_size)
            return [LogEntry.from_rust(r) for r in results]
        else:
            # Fallback to sequential parsing
            logger.warning("[!] Parallel parsing requires Rust backend. Using sequential parsing.")
            return self.parse_file(file_path, max_lines)

    def parse_lines_parallel(self, lines: List[str]) -> List[LogEntry]:
        """
        Parse multiple lines in parallel (Rust only).

        Args:
            lines: List of log lines to parse

        Returns:
            List of LogEntry objects
        """
        if self._use_rust:
            results = self._rust_parser.parse_lines_parallel(lines)
            return [LogEntry.from_rust(r) for r in results]
        else:
            # Fallback to sequential
            return [entry for line in lines if (entry := self.parse_line(line)) is not None]

    @staticmethod
    def get_stats(entries: List[LogEntry]) -> Dict[str, int]:
        """
        Get statistics about parsed entries.

        Args:
            entries: List of LogEntry objects

        Returns:
            Dictionary with statistics
        """
        return {
            "total": len(entries),
            "with_timestamp": sum(1 for e in entries if e.timestamp),
            "with_hostname": sum(1 for e in entries if e.hostname),
            "with_source_ip": sum(1 for e in entries if e.source_ip),
            "with_severity": sum(1 for e in entries if e.severity),
        }


def get_log_parser(log_format: str = "auto", prefer_rust: bool = True) -> LogParser:
    """
    Get a log parser instance.

    Args:
        log_format: Log format (auto, syslog, json, apache, nginx)
        prefer_rust: If True, use Rust when available (default: True)

    Returns:
        LogParser instance (Rust-backed if available and preferred)
    """
    if prefer_rust and _RUST_AVAILABLE:
        return LogParser(log_format)

    # Return Python-only parser
    from defensive_toolkit.log_analysis.parsers.log_parser import LogParser as PythonLogParser

    return PythonLogParser(log_format)


# Convenience exports
__all__ = [
    "LogParser",
    "LogEntry",
    "is_rust_available",
    "get_log_parser",
]
