"""
Log Analysis API Router.

Provides endpoints for parsing logs and detecting anomalies.
Wires to log_analysis.parsers.log_parser and log_analysis.analysis.anomaly_detector.
"""

import logging
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from defensive_toolkit.api.dependencies import (
    get_current_active_user,
    require_write_scope,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/log-analysis", tags=["Log Analysis"])


# =============================================================================
# Request/Response Models
# =============================================================================


class ParsedLogEntry(BaseModel):
    """Parsed log entry."""

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


class ParseLogsRequest(BaseModel):
    """Request to parse log lines."""

    log_lines: List[str] = Field(..., description="Log lines to parse")
    log_format: str = Field(
        default="auto",
        description="Log format: auto, syslog, json, apache, nginx",
    )


class ParseLogsResponse(BaseModel):
    """Response from parsing logs."""

    entries_parsed: int
    entries_failed: int
    log_format: str
    backend: str
    entries: List[ParsedLogEntry]


class ParserInfoResponse(BaseModel):
    """Parser backend information."""

    rust_available: bool
    active_backend: str
    supported_formats: List[str]


class DetectAnomaliesRequest(BaseModel):
    """Request to detect anomalies in logs."""

    log_entries: List[Dict[str, Any]] = Field(
        ..., description="Parsed log entries (as dicts)"
    )
    baseline_id: Optional[str] = Field(
        default=None, description="ID of baseline to compare against"
    )
    threshold_stddev: float = Field(
        default=2.0, description="Standard deviations for anomaly threshold"
    )


class Anomaly(BaseModel):
    """Detected anomaly."""

    type: str
    severity: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class DetectAnomaliesResponse(BaseModel):
    """Response from anomaly detection."""

    analysis_id: str
    entries_analyzed: int
    anomalies_detected: int
    anomalies: List[Anomaly]
    statistics: Dict[str, Any]


class CreateBaselineRequest(BaseModel):
    """Request to create baseline statistics."""

    log_entries: List[Dict[str, Any]] = Field(
        ..., description="Parsed log entries for baseline"
    )
    name: Optional[str] = Field(
        default=None, description="Name for the baseline"
    )


class BaselineResponse(BaseModel):
    """Response from baseline creation."""

    baseline_id: str
    name: Optional[str]
    entry_count: int
    created_at: str
    statistics_summary: Dict[str, Any]


class LogStatsRequest(BaseModel):
    """Request to get log statistics."""

    log_entries: List[Dict[str, Any]] = Field(
        ..., description="Parsed log entries"
    )


class LogStatsResponse(BaseModel):
    """Log statistics response."""

    total_entries: int
    with_timestamp: int
    with_hostname: int
    with_source_ip: int
    with_severity: int
    unique_hostnames: int
    unique_source_ips: int
    unique_processes: int
    top_processes: Dict[str, int]
    top_source_ips: Dict[str, int]
    severity_distribution: Dict[str, int]


class FilterLogsRequest(BaseModel):
    """Request to filter parsed logs."""

    log_entries: List[Dict[str, Any]] = Field(
        ..., description="Parsed log entries to filter"
    )
    hostname: Optional[str] = Field(default=None, description="Filter by hostname")
    source_ip: Optional[str] = Field(default=None, description="Filter by source IP")
    process: Optional[str] = Field(default=None, description="Filter by process name")
    severity: Optional[str] = Field(default=None, description="Filter by severity")
    message_contains: Optional[str] = Field(
        default=None, description="Filter by message content"
    )
    limit: int = Field(default=1000, description="Maximum entries to return")


class FilterLogsResponse(BaseModel):
    """Filtered logs response."""

    total_input: int
    total_matched: int
    filters_applied: Dict[str, str]
    entries: List[Dict[str, Any]]


# =============================================================================
# In-memory baseline storage (would be database in production)
# =============================================================================

_baselines: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Helper Functions
# =============================================================================


def get_log_parser(log_format: str = "auto"):
    """Get log parser instance."""
    try:
        from defensive_toolkit.log_analysis.parsers.log_parser_fast import (
            LogParser,
            is_rust_available,
        )

        return LogParser(log_format), "rust" if is_rust_available() else "python"
    except ImportError:
        try:
            from defensive_toolkit.log_analysis.parsers.log_parser import LogParser

            return LogParser(log_format), "python"
        except ImportError as e:
            logger.error(f"Failed to import LogParser: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Log parser module not available",
            )


def get_anomaly_detector(baseline_id: Optional[str] = None, threshold: float = 2.0):
    """Get anomaly detector instance."""
    try:
        from defensive_toolkit.log_analysis.analysis.anomaly_detector import (
            AnomalyDetector,
        )

        # Load baseline if specified
        baseline_file = None
        if baseline_id and baseline_id in _baselines:
            # Create temp file with baseline for detector
            baseline_data = _baselines[baseline_id]
            baseline_file = Path(tempfile.gettempdir()) / f"baseline_{baseline_id}.json"
            import json

            with open(baseline_file, "w") as f:
                json.dump(baseline_data, f)

        return AnomalyDetector(baseline_file=baseline_file, threshold_stddev=threshold)
    except ImportError as e:
        logger.error(f"Failed to import AnomalyDetector: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anomaly detector module not available",
        )


# =============================================================================
# Endpoints
# =============================================================================


@router.post("/parse", response_model=ParseLogsResponse)
async def parse_logs(
    request: ParseLogsRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Parse log lines.

    Parses raw log lines into structured entries.
    Supports auto-detection of log format or explicit format specification.
    """
    parser, backend = get_log_parser(request.log_format)

    entries = []
    failed = 0

    for line in request.log_lines:
        try:
            entry = parser.parse_line(line)
            if entry:
                entries.append(
                    ParsedLogEntry(
                        timestamp=entry.timestamp,
                        hostname=entry.hostname,
                        process=entry.process,
                        pid=entry.pid,
                        severity=entry.severity,
                        message=entry.message,
                        source_ip=entry.source_ip,
                        dest_ip=entry.dest_ip,
                        user=entry.user,
                        event_id=entry.event_id,
                        raw=entry.raw,
                    )
                )
            else:
                failed += 1
        except Exception as e:
            logger.warning(f"Failed to parse line: {e}")
            failed += 1

    return ParseLogsResponse(
        entries_parsed=len(entries),
        entries_failed=failed,
        log_format=request.log_format,
        backend=backend,
        entries=entries,
    )


@router.post("/parse-file", response_model=ParseLogsResponse)
async def parse_log_file(
    file: UploadFile = File(...),
    log_format: str = Query(default="auto", description="Log format"),
    max_lines: Optional[int] = Query(default=None, description="Max lines to parse"),
    current_user: str = Depends(get_current_active_user),
):
    """
    Parse uploaded log file.

    Accepts a log file upload and parses it into structured entries.
    """
    parser, backend = get_log_parser(log_format)

    # Save uploaded file temporarily
    temp_path = Path(tempfile.gettempdir()) / f"upload_{uuid.uuid4()}.log"

    try:
        content = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content)

        # Parse file
        raw_entries = parser.parse_file(temp_path, max_lines=max_lines)

        entries = [
            ParsedLogEntry(
                timestamp=e.timestamp,
                hostname=e.hostname,
                process=e.process,
                pid=e.pid,
                severity=e.severity,
                message=e.message,
                source_ip=e.source_ip,
                dest_ip=e.dest_ip,
                user=e.user,
                event_id=e.event_id,
                raw=e.raw,
            )
            for e in raw_entries
        ]

        return ParseLogsResponse(
            entries_parsed=len(entries),
            entries_failed=0,
            log_format=log_format,
            backend=backend,
            entries=entries,
        )

    finally:
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()


@router.get("/parser-info", response_model=ParserInfoResponse)
async def get_parser_info(
    current_user: str = Depends(get_current_active_user),
):
    """
    Get parser backend information.

    Returns whether Rust backend is available and supported formats.
    """
    try:
        from defensive_toolkit.log_analysis.parsers.log_parser_fast import (
            is_rust_available,
        )

        rust_available = is_rust_available()
    except ImportError:
        rust_available = False

    return ParserInfoResponse(
        rust_available=rust_available,
        active_backend="rust" if rust_available else "python",
        supported_formats=["auto", "syslog", "json", "apache", "nginx"],
    )


@router.post("/anomalies/detect", response_model=DetectAnomaliesResponse)
async def detect_anomalies(
    request: DetectAnomaliesRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Detect anomalies in log entries.

    Analyzes parsed log entries for statistical anomalies including:
    - Frequency anomalies (unusually frequent events)
    - Pattern anomalies (failure bursts)
    - Rate anomalies (unusual hourly distribution)
    - Statistical deviations from baseline (if provided)
    """
    detector = get_anomaly_detector(
        baseline_id=request.baseline_id,
        threshold=request.threshold_stddev,
    )

    raw_anomalies = detector.detect_anomalies(request.log_entries)

    anomalies = [
        Anomaly(
            type=a["type"],
            severity=a["severity"],
            description=a["description"],
            details=a.get("details", {}),
        )
        for a in raw_anomalies
    ]

    # Get current stats
    stats = detector.current_stats.copy()
    # Convert Counter objects to dicts for JSON serialization
    for key in ["processes", "hostnames", "severities", "users", "source_ips", "error_keywords"]:
        if key in stats:
            stats[key] = dict(stats[key])
    if "hourly_distribution" in stats:
        stats["hourly_distribution"] = dict(stats["hourly_distribution"])

    return DetectAnomaliesResponse(
        analysis_id=str(uuid.uuid4()),
        entries_analyzed=len(request.log_entries),
        anomalies_detected=len(anomalies),
        anomalies=anomalies,
        statistics=stats,
    )


@router.post(
    "/anomalies/create-baseline",
    response_model=BaselineResponse,
    dependencies=[Depends(require_write_scope)],
)
async def create_baseline(
    request: CreateBaselineRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Create baseline statistics from log entries.

    Creates a statistical baseline that can be used for
    comparative anomaly detection in future analyses.
    """
    detector = get_anomaly_detector()

    # Compute statistics
    stats = detector._compute_statistics(request.log_entries)

    baseline_id = str(uuid.uuid4())
    from datetime import datetime

    baseline = {
        "baseline_id": baseline_id,
        "name": request.name,
        "timestamp": datetime.now().isoformat(),
        "entry_count": len(request.log_entries),
        "statistics": stats,
    }

    # Store baseline
    _baselines[baseline_id] = baseline

    # Prepare summary (convert Counter to dict for serialization)
    summary = {
        "total_entries": stats.get("total_entries", 0),
        "unique_processes": len(stats.get("processes", {})),
        "unique_hostnames": len(stats.get("hostnames", {})),
        "unique_source_ips": len(stats.get("source_ips", {})),
        "error_keywords_tracked": len(stats.get("error_keywords", {})),
    }

    return BaselineResponse(
        baseline_id=baseline_id,
        name=request.name,
        entry_count=len(request.log_entries),
        created_at=baseline["timestamp"],
        statistics_summary=summary,
    )


@router.get("/anomalies/baselines")
async def list_baselines(
    current_user: str = Depends(get_current_active_user),
):
    """
    List available baselines.

    Returns all stored baseline IDs and their metadata.
    """
    return {
        "baselines": [
            {
                "baseline_id": bid,
                "name": b.get("name"),
                "entry_count": b.get("entry_count"),
                "created_at": b.get("timestamp"),
            }
            for bid, b in _baselines.items()
        ]
    }


@router.get("/anomalies/baseline/{baseline_id}")
async def get_baseline(
    baseline_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get baseline details.

    Returns the full baseline statistics for a given baseline ID.
    """
    if baseline_id not in _baselines:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline not found: {baseline_id}",
        )

    baseline = _baselines[baseline_id]

    # Convert Counter objects to dicts
    stats = baseline.get("statistics", {}).copy()
    for key in ["processes", "hostnames", "severities", "users", "source_ips", "error_keywords"]:
        if key in stats:
            stats[key] = dict(stats[key])
    if "hourly_distribution" in stats:
        stats["hourly_distribution"] = dict(stats["hourly_distribution"])

    return {
        "baseline_id": baseline_id,
        "name": baseline.get("name"),
        "entry_count": baseline.get("entry_count"),
        "created_at": baseline.get("timestamp"),
        "statistics": stats,
    }


@router.delete(
    "/anomalies/baseline/{baseline_id}",
    dependencies=[Depends(require_write_scope)],
)
async def delete_baseline(
    baseline_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Delete a baseline.

    Removes a stored baseline by ID.
    """
    if baseline_id not in _baselines:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline not found: {baseline_id}",
        )

    del _baselines[baseline_id]

    return {"status": "deleted", "baseline_id": baseline_id}


@router.post("/stats", response_model=LogStatsResponse)
async def get_log_stats(
    request: LogStatsRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get statistics for parsed log entries.

    Provides aggregate statistics including counts, unique values,
    and distributions across various log fields.
    """
    from collections import Counter

    entries = request.log_entries

    processes = Counter()
    hostnames = Counter()
    source_ips = Counter()
    severities = Counter()

    with_timestamp = 0
    with_hostname = 0
    with_source_ip = 0
    with_severity = 0

    for entry in entries:
        if entry.get("timestamp"):
            with_timestamp += 1
        if entry.get("hostname"):
            with_hostname += 1
            hostnames[entry["hostname"]] += 1
        if entry.get("source_ip"):
            with_source_ip += 1
            source_ips[entry["source_ip"]] += 1
        if entry.get("severity"):
            with_severity += 1
            severities[entry["severity"]] += 1
        if entry.get("process"):
            processes[entry["process"]] += 1

    return LogStatsResponse(
        total_entries=len(entries),
        with_timestamp=with_timestamp,
        with_hostname=with_hostname,
        with_source_ip=with_source_ip,
        with_severity=with_severity,
        unique_hostnames=len(hostnames),
        unique_source_ips=len(source_ips),
        unique_processes=len(processes),
        top_processes=dict(processes.most_common(10)),
        top_source_ips=dict(source_ips.most_common(10)),
        severity_distribution=dict(severities),
    )


@router.post("/filter", response_model=FilterLogsResponse)
async def filter_logs(
    request: FilterLogsRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Filter parsed log entries.

    Applies filters to log entries based on hostname, source IP,
    process name, severity, or message content.
    """
    entries = request.log_entries
    filters_applied = {}

    if request.hostname:
        entries = [e for e in entries if e.get("hostname") == request.hostname]
        filters_applied["hostname"] = request.hostname

    if request.source_ip:
        entries = [e for e in entries if e.get("source_ip") == request.source_ip]
        filters_applied["source_ip"] = request.source_ip

    if request.process:
        entries = [
            e for e in entries if request.process.lower() in (e.get("process") or "").lower()
        ]
        filters_applied["process"] = request.process

    if request.severity:
        entries = [
            e
            for e in entries
            if (e.get("severity") or "").lower() == request.severity.lower()
        ]
        filters_applied["severity"] = request.severity

    if request.message_contains:
        entries = [
            e
            for e in entries
            if request.message_contains.lower() in (e.get("message") or "").lower()
        ]
        filters_applied["message_contains"] = request.message_contains

    # Apply limit
    limited_entries = entries[: request.limit]

    return FilterLogsResponse(
        total_input=len(request.log_entries),
        total_matched=len(entries),
        filters_applied=filters_applied,
        entries=limited_entries,
    )


@router.get("/sources")
async def list_log_sources(
    current_user: str = Depends(get_current_active_user),
):
    """
    List supported log sources.

    Returns the list of log formats that can be parsed.
    """
    return {
        "formats": [
            {"name": "auto", "description": "Auto-detect format"},
            {"name": "syslog", "description": "Standard syslog format (RFC 3164/5424)"},
            {"name": "json", "description": "JSON-formatted logs"},
            {"name": "apache", "description": "Apache Combined Log Format"},
            {"name": "nginx", "description": "Nginx access log format"},
        ],
        "total": 5,
    }
