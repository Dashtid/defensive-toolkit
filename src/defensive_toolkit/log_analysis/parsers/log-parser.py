#!/usr/bin/env python3
"""
Universal Log Parser
Parses common log formats: Syslog, JSON, Apache/Nginx, Windows Event Log
Extracts structured data from unstructured logs
"""

import re
import json
import argparse
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Standardized log entry structure"""
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    severity: Optional[str] = None
    message: str = ""
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    event_id: Optional[str] = None
    raw: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


class LogParser:
    """Universal log parser for multiple formats"""

    # Regex patterns
    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)'
    )

    RFC3164_PATTERN = re.compile(
        r'<(?P<pri>\d+)>'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<tag>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)'
    )

    APACHE_COMBINED_PATTERN = re.compile(
        r'(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )

    NGINX_PATTERN = re.compile(
        r'(?P<ip>\S+)\s+-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )

    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def __init__(self, log_format: str = 'auto'):
        """
        Initialize parser

        Args:
            log_format: Log format (auto, syslog, json, apache, nginx, windows)
        """
        self.log_format = log_format.lower()

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        line = line.strip()
        if not line:
            return None

        if self.log_format == 'auto':
            return self._auto_detect_and_parse(line)
        elif self.log_format == 'syslog':
            return self._parse_syslog(line)
        elif self.log_format == 'json':
            return self._parse_json(line)
        elif self.log_format == 'apache':
            return self._parse_apache(line)
        elif self.log_format == 'nginx':
            return self._parse_nginx(line)
        else:
            return self._parse_generic(line)

    def parse_file(self, file_path: Path, max_lines: int = None) -> List[LogEntry]:
        """Parse entire log file"""
        logger.info(f"Parsing log file: {file_path}")
        entries = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_lines and i >= max_lines:
                        break

                    entry = self.parse_line(line)
                    if entry:
                        entries.append(entry)

            logger.info(f"Parsed {len(entries)} log entries")
            return entries

        except Exception as e:
            logger.error(f"Error parsing file: {e}")
            return []

    def _auto_detect_and_parse(self, line: str) -> Optional[LogEntry]:
        """Auto-detect log format and parse"""
        # Try JSON first
        if line.startswith('{'):
            entry = self._parse_json(line)
            if entry:
                return entry

        # Try Apache/Nginx (starts with IP)
        if self.IP_PATTERN.match(line.split()[0] if line.split() else ''):
            entry = self._parse_apache(line)
            if entry:
                return entry

        # Try syslog (RFC3164 with priority)
        if line.startswith('<'):
            entry = self._parse_syslog(line)
            if entry:
                return entry

        # Try standard syslog
        entry = self._parse_syslog(line)
        if entry:
            return entry

        # Fallback to generic
        return self._parse_generic(line)

    def _parse_syslog(self, line: str) -> Optional[LogEntry]:
        """Parse syslog format"""
        # Try RFC3164 with priority
        match = self.RFC3164_PATTERN.match(line)
        if match:
            groups = match.groupdict()
            return LogEntry(
                timestamp=groups.get('timestamp'),
                hostname=groups.get('hostname'),
                process=groups.get('tag'),
                pid=int(groups['pid']) if groups.get('pid') else None,
                message=groups.get('message', ''),
                raw=line
            )

        # Try standard syslog
        match = self.SYSLOG_PATTERN.match(line)
        if match:
            groups = match.groupdict()
            return LogEntry(
                timestamp=groups.get('timestamp'),
                hostname=groups.get('hostname'),
                process=groups.get('process'),
                pid=int(groups['pid']) if groups.get('pid') else None,
                message=groups.get('message', ''),
                raw=line
            )

        return None

    def _parse_json(self, line: str) -> Optional[LogEntry]:
        """Parse JSON log format"""
        try:
            data = json.loads(line)

            # Extract common fields (flexible mapping)
            return LogEntry(
                timestamp=data.get('timestamp') or data.get('time') or data.get('@timestamp'),
                hostname=data.get('hostname') or data.get('host'),
                process=data.get('process') or data.get('app'),
                pid=data.get('pid'),
                severity=data.get('level') or data.get('severity'),
                message=data.get('message') or data.get('msg') or str(data),
                source_ip=data.get('source_ip') or data.get('src_ip'),
                dest_ip=data.get('dest_ip') or data.get('dst_ip'),
                user=data.get('user') or data.get('username'),
                event_id=data.get('event_id') or data.get('id'),
                raw=line
            )

        except json.JSONDecodeError:
            return None

    def _parse_apache(self, line: str) -> Optional[LogEntry]:
        """Parse Apache Combined Log Format"""
        match = self.APACHE_COMBINED_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Extract IPs from request if present
        request = groups.get('request', '')
        dest_ip = None
        if request:
            ips = self.IP_PATTERN.findall(request)
            dest_ip = ips[0] if ips else None

        return LogEntry(
            timestamp=groups.get('timestamp'),
            source_ip=groups.get('ip'),
            dest_ip=dest_ip,
            user=groups.get('user') if groups.get('user') != '-' else None,
            message=f"{groups.get('request')} {groups.get('status')}",
            raw=line
        )

    def _parse_nginx(self, line: str) -> Optional[LogEntry]:
        """Parse Nginx log format"""
        match = self.NGINX_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        return LogEntry(
            timestamp=groups.get('timestamp'),
            source_ip=groups.get('ip'),
            message=f"{groups.get('request')} {groups.get('status')}",
            raw=line
        )

    def _parse_generic(self, line: str) -> LogEntry:
        """Generic parser for unknown formats"""
        # Extract IPs
        ips = self.IP_PATTERN.findall(line)
        source_ip = ips[0] if ips else None
        dest_ip = ips[1] if len(ips) > 1 else None

        # Try to extract timestamp (various formats)
        timestamp = None
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO 8601
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # Standard datetime
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',  # Syslog timestamp
        ]

        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group()
                break

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            message=line,
            raw=line
        )


def main():
    parser = argparse.ArgumentParser(
        description='Universal Log Parser',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect format and parse
  python log-parser.py --file /var/log/syslog --format auto

  # Parse specific format
  python log-parser.py --file access.log --format apache --output parsed.json

  # Parse syslog
  python log-parser.py --file /var/log/messages --format syslog

  # Parse JSON logs
  python log-parser.py --file app.log --format json
        """
    )

    parser.add_argument('--file', '-f', type=Path, required=True,
                       help='Log file to parse')
    parser.add_argument('--format', choices=['auto', 'syslog', 'json', 'apache', 'nginx'],
                       default='auto', help='Log format (default: auto)')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output JSON file')
    parser.add_argument('--max-lines', type=int,
                       help='Maximum lines to parse')
    parser.add_argument('--filter', type=str,
                       help='Filter messages containing string')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create parser
    log_parser = LogParser(log_format=args.format)

    # Parse file
    entries = log_parser.parse_file(args.file, max_lines=args.max_lines)

    # Apply filter if specified
    if args.filter:
        entries = [e for e in entries if args.filter.lower() in e.message.lower()]
        logger.info(f"Filtered to {len(entries)} entries")

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([e.to_dict() for e in entries], f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        # Print sample entries
        print(f"\n{'='*80}")
        print(f"Parsed {len(entries)} log entries")
        print(f"{'='*80}\n")

        for i, entry in enumerate(entries[:10]):  # Show first 10
            print(f"Entry {i+1}:")
            print(f"  Timestamp: {entry.timestamp}")
            print(f"  Hostname: {entry.hostname}")
            print(f"  Process: {entry.process}")
            print(f"  Message: {entry.message[:100]}...")
            print()

        if len(entries) > 10:
            print(f"... and {len(entries) - 10} more entries")


if __name__ == '__main__':
    main()
