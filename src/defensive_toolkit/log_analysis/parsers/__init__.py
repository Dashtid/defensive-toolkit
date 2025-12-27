"""
Log Parsing Module

High-performance log parsing with optional Rust backend.
Supports syslog, JSON, Apache, Nginx, and Windows Event Log formats.
"""

from defensive_toolkit.log_analysis.parsers.log_parser_fast import (
    LogEntry,
    LogParser,
    get_log_parser,
    is_rust_available,
)

__all__ = [
    "LogEntry",
    "LogParser",
    "get_log_parser",
    "is_rust_available",
]
