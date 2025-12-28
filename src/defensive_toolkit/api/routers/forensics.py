"""
Forensics API Router.

Provides endpoints for digital forensics operations including:
- Memory analysis (Volatility 3)
- Malware hunting in memory
- Disk forensics (MFT parsing, file carving)
- Browser artifact extraction
- Timeline generation and analysis

Wires to forensics.memory, forensics.disk, forensics.artifacts, forensics.timeline modules.
"""

import logging
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field

from defensive_toolkit.api.dependencies import (
    get_current_active_user,
    require_write_scope,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/forensics", tags=["Forensics"])


# =============================================================================
# Request/Response Models
# =============================================================================


class MemoryAnalysisRequest(BaseModel):
    """Request for memory analysis."""

    memory_dump_path: str = Field(..., description="Path to memory dump file")
    analysis_type: str = Field(
        default="quick",
        description="Analysis type: quick, full, or malware_hunt",
    )


class MemoryAnalysisResponse(BaseModel):
    """Response from memory analysis."""

    analysis_id: str
    memory_dump: str
    analysis_type: str
    status: str
    plugins_run: List[Dict[str, Any]] = Field(default_factory=list)
    suspicious_findings: List[Dict[str, Any]] = Field(default_factory=list)
    statistics: Dict[str, Any] = Field(default_factory=dict)


class MalwareHuntRequest(BaseModel):
    """Request for malware hunting."""

    memory_dump_path: str = Field(..., description="Path to memory dump file")
    ioc_file_path: Optional[str] = Field(
        default=None, description="Path to IOC file (optional)"
    )


class MalwareHuntResponse(BaseModel):
    """Response from malware hunting."""

    hunt_id: str
    memory_dump: str
    total_findings: int
    severity_counts: Dict[str, int]
    findings: List[Dict[str, Any]]


class MFTParseRequest(BaseModel):
    """Request to parse MFT file."""

    mft_file_path: str = Field(..., description="Path to $MFT file")
    analyze_suspicious: bool = Field(
        default=True, description="Analyze for suspicious files"
    )


class MFTParseResponse(BaseModel):
    """Response from MFT parsing."""

    parse_id: str
    mft_file: str
    entries_parsed: int
    suspicious_files: List[Dict[str, Any]]
    severity_counts: Dict[str, int]


class FileCarveRequest(BaseModel):
    """Request to carve files from disk image."""

    image_path: str = Field(..., description="Path to disk image")
    tool: str = Field(
        default="both",
        description="Carving tool: bulk_extractor, foremost, or both",
    )
    file_types: Optional[List[str]] = Field(
        default=None,
        description="File types to carve (foremost only)",
    )


class FileCarveResponse(BaseModel):
    """Response from file carving."""

    carve_id: str
    image_file: str
    tools_run: List[Dict[str, Any]]
    files_carved: Dict[str, int]
    statistics: Dict[str, Any]


class BrowserExtractRequest(BaseModel):
    """Request to extract browser artifacts."""

    user_profile_path: str = Field(
        ..., description="Path to user profile directory"
    )
    browsers: List[str] = Field(
        default=["chrome", "edge", "firefox"],
        description="Browsers to extract from",
    )


class BrowserExtractResponse(BaseModel):
    """Response from browser extraction."""

    extract_id: str
    user_profile: str
    browsers_analyzed: List[str]
    artifacts_extracted: Dict[str, int]


class TimelineGenerateRequest(BaseModel):
    """Request to generate timeline."""

    source_files: List[str] = Field(
        ..., description="Paths to timeline source files (JSON or CSV)"
    )
    analyze: bool = Field(
        default=True, description="Analyze timeline after generation"
    )


class TimelineEntry(BaseModel):
    """Timeline entry."""

    timestamp: str
    event_type: str
    source: str
    description: str


class TimelineGenerateResponse(BaseModel):
    """Response from timeline generation."""

    timeline_id: str
    total_entries: int
    sources: List[str]
    entries: List[TimelineEntry]
    analysis: Optional[Dict[str, Any]] = None


class TimelineAnalysisResponse(BaseModel):
    """Timeline analysis results."""

    timeline_id: str
    total_entries: int
    event_types: Dict[str, int]
    sources: Dict[str, int]
    daily_distribution: Dict[str, int]
    busiest_days: List[Dict[str, Any]]


class VolatilityPlugin(BaseModel):
    """Volatility plugin information."""

    name: str
    description: str
    category: str


# =============================================================================
# In-memory storage for async results (would be database in production)
# =============================================================================

_analysis_results: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Helper Functions
# =============================================================================


def get_volatility_analyzer(memory_dump: Path, output_dir: Path):
    """Get Volatility analyzer instance."""
    try:
        from defensive_toolkit.forensics.memory.volatility_auto_analyze import (
            VolatilityAnalyzer,
        )

        return VolatilityAnalyzer(memory_dump, output_dir)
    except ImportError as e:
        logger.error(f"Failed to import VolatilityAnalyzer: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Volatility analyzer module not available",
        )


def get_malware_hunter(memory_dump: Path, ioc_file: Optional[Path] = None):
    """Get MalwareHunter instance."""
    try:
        from defensive_toolkit.forensics.memory.hunt_malware import MalwareHunter

        return MalwareHunter(memory_dump, ioc_file)
    except ImportError as e:
        logger.error(f"Failed to import MalwareHunter: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Malware hunter module not available",
        )


def get_mft_analyzer(mft_file: Path, output_dir: Path):
    """Get MFT analyzer instance."""
    try:
        from defensive_toolkit.forensics.disk.extract_mft import MFTAnalyzer

        return MFTAnalyzer(mft_file, output_dir)
    except ImportError as e:
        logger.error(f"Failed to import MFTAnalyzer: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFT analyzer module not available",
        )


def get_file_carver(image_file: Path, output_dir: Path):
    """Get FileCarver instance."""
    try:
        from defensive_toolkit.forensics.disk.carve_files import FileCarver

        return FileCarver(image_file, output_dir)
    except ImportError as e:
        logger.error(f"Failed to import FileCarver: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="File carver module not available",
        )


def get_browser_forensics(user_profile: Path, output_dir: Path):
    """Get BrowserForensics instance."""
    try:
        from defensive_toolkit.forensics.artifacts.browser.extract_browser_history import (
            BrowserForensics,
        )

        return BrowserForensics(user_profile, output_dir)
    except ImportError as e:
        logger.error(f"Failed to import BrowserForensics: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Browser forensics module not available",
        )


def get_timeline_generator(output_file: Path):
    """Get TimelineGenerator instance."""
    try:
        from defensive_toolkit.forensics.timeline.generate_timeline import (
            TimelineGenerator,
        )

        return TimelineGenerator(output_file)
    except ImportError as e:
        logger.error(f"Failed to import TimelineGenerator: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Timeline generator module not available",
        )


# =============================================================================
# Memory Analysis Endpoints
# =============================================================================


@router.post("/memory/analyze", response_model=MemoryAnalysisResponse)
async def analyze_memory(
    request: MemoryAnalysisRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Analyze memory dump using Volatility 3.

    Supports three analysis modes:
    - quick: Essential plugins for fast triage
    - full: Comprehensive analysis with all plugins
    - malware_hunt: Focus on malware detection indicators
    """
    memory_dump = Path(request.memory_dump_path)

    if not memory_dump.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Memory dump not found: {memory_dump}",
        )

    # Create output directory
    output_dir = Path(tempfile.gettempdir()) / f"volatility_{uuid.uuid4()}"

    analyzer = get_volatility_analyzer(memory_dump, output_dir)
    analysis_id = str(uuid.uuid4())

    try:
        # Run analysis based on type
        if request.analysis_type == "quick":
            analyzer.quick_analysis()
        elif request.analysis_type == "full":
            analyzer.full_analysis()
        elif request.analysis_type == "malware_hunt":
            analyzer.malware_hunt()
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid analysis type: {request.analysis_type}",
            )

        # Generate report
        analyzer.generate_report()

        return MemoryAnalysisResponse(
            analysis_id=analysis_id,
            memory_dump=str(memory_dump),
            analysis_type=request.analysis_type,
            status="completed",
            plugins_run=analyzer.results.get("plugins_run", []),
            suspicious_findings=analyzer.results.get("suspicious_findings", []),
            statistics=analyzer.results.get("statistics", {}),
        )

    except Exception as e:
        logger.error(f"Memory analysis failed: {e}")
        return MemoryAnalysisResponse(
            analysis_id=analysis_id,
            memory_dump=str(memory_dump),
            analysis_type=request.analysis_type,
            status="failed",
            statistics={"error": str(e)},
        )


@router.post("/memory/hunt", response_model=MalwareHuntResponse)
async def hunt_malware_in_memory(
    request: MalwareHuntRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Hunt for malware indicators in memory dump.

    Checks for:
    - Suspicious processes
    - Code injection (malfind)
    - Suspicious network connections
    - Hidden/unlinked processes
    - Suspicious DLLs
    - Persistence mechanisms
    """
    memory_dump = Path(request.memory_dump_path)

    if not memory_dump.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Memory dump not found: {memory_dump}",
        )

    ioc_file = Path(request.ioc_file_path) if request.ioc_file_path else None
    if ioc_file and not ioc_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC file not found: {ioc_file}",
        )

    hunter = get_malware_hunter(memory_dump, ioc_file)
    hunt_id = str(uuid.uuid4())

    try:
        hunter.hunt()

        # Count by severity
        findings = hunter.findings
        severity_counts = {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
        }

        return MalwareHuntResponse(
            hunt_id=hunt_id,
            memory_dump=str(memory_dump),
            total_findings=len(findings),
            severity_counts=severity_counts,
            findings=findings,
        )

    except Exception as e:
        logger.error(f"Malware hunt failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Malware hunt failed: {str(e)}",
        )


@router.get("/memory/plugins")
async def list_volatility_plugins(
    current_user: str = Depends(get_current_active_user),
):
    """
    List available Volatility 3 plugins.

    Returns categorized list of plugins for memory analysis.
    """
    plugins = [
        # System information
        VolatilityPlugin(
            name="windows.info.Info",
            description="System information",
            category="system",
        ),
        # Process analysis
        VolatilityPlugin(
            name="windows.pslist.PsList",
            description="List running processes",
            category="process",
        ),
        VolatilityPlugin(
            name="windows.pstree.PsTree",
            description="Process tree",
            category="process",
        ),
        VolatilityPlugin(
            name="windows.psscan.PsScan",
            description="Scan for hidden processes",
            category="process",
        ),
        VolatilityPlugin(
            name="windows.cmdline.CmdLine",
            description="Process command lines",
            category="process",
        ),
        # Network
        VolatilityPlugin(
            name="windows.netscan.NetScan",
            description="Network connections",
            category="network",
        ),
        VolatilityPlugin(
            name="windows.netstat.NetStat",
            description="Network statistics",
            category="network",
        ),
        # DLLs and drivers
        VolatilityPlugin(
            name="windows.dlllist.DllList",
            description="Loaded DLLs",
            category="modules",
        ),
        VolatilityPlugin(
            name="windows.modules.Modules",
            description="Kernel modules",
            category="modules",
        ),
        VolatilityPlugin(
            name="windows.driverscan.DriverScan",
            description="Driver scan",
            category="modules",
        ),
        # Malware detection
        VolatilityPlugin(
            name="windows.malfind.Malfind",
            description="Find injected code",
            category="malware",
        ),
        VolatilityPlugin(
            name="windows.ldrmodules.LdrModules",
            description="Unlinked DLLs",
            category="malware",
        ),
        # Registry
        VolatilityPlugin(
            name="windows.registry.hivelist.HiveList",
            description="Registry hives",
            category="registry",
        ),
        # Files
        VolatilityPlugin(
            name="windows.filescan.FileScan",
            description="Scan for files",
            category="filesystem",
        ),
        VolatilityPlugin(
            name="windows.handles.Handles",
            description="File handles",
            category="filesystem",
        ),
        # Timeline
        VolatilityPlugin(
            name="timeliner.Timeliner",
            description="Timeline generation",
            category="timeline",
        ),
    ]

    return {
        "plugins": [p.model_dump() for p in plugins],
        "total": len(plugins),
        "categories": list(set(p.category for p in plugins)),
    }


# =============================================================================
# Disk Forensics Endpoints
# =============================================================================


@router.post("/disk/parse-mft", response_model=MFTParseResponse)
async def parse_mft(
    request: MFTParseRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Parse Windows NTFS Master File Table ($MFT).

    Extracts file metadata and optionally analyzes for suspicious files
    including executables in temp directories, hidden files, etc.
    """
    mft_file = Path(request.mft_file_path)

    if not mft_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MFT file not found: {mft_file}",
        )

    output_dir = Path(tempfile.gettempdir()) / f"mft_{uuid.uuid4()}"

    analyzer = get_mft_analyzer(mft_file, output_dir)
    parse_id = str(uuid.uuid4())

    try:
        # Parse MFT
        parsed_csv = analyzer.parse_mft()

        if not parsed_csv:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFT parsing failed - analyzeMFT may not be installed",
            )

        entries_parsed = 0
        suspicious_files = []

        if parsed_csv and parsed_csv.exists():
            # Count entries
            with open(parsed_csv, "r", encoding="utf-8", errors="ignore") as f:
                entries_parsed = sum(1 for _ in f) - 1  # Subtract header

            # Analyze for suspicious files if requested
            if request.analyze_suspicious:
                analyzer.analyze_suspicious_files(parsed_csv)
                suspicious_files = analyzer.suspicious_findings

        # Count by severity
        severity_counts = {
            "critical": len([f for f in suspicious_files if f.get("severity") == "critical"]),
            "high": len([f for f in suspicious_files if f.get("severity") == "high"]),
            "medium": len([f for f in suspicious_files if f.get("severity") == "medium"]),
            "low": len([f for f in suspicious_files if f.get("severity") == "low"]),
        }

        return MFTParseResponse(
            parse_id=parse_id,
            mft_file=str(mft_file),
            entries_parsed=entries_parsed,
            suspicious_files=suspicious_files[:100],  # Limit to 100
            severity_counts=severity_counts,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFT parsing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MFT parsing failed: {str(e)}",
        )


@router.post(
    "/disk/carve",
    response_model=FileCarveResponse,
    dependencies=[Depends(require_write_scope)],
)
async def carve_files(
    request: FileCarveRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Carve files from disk image.

    Uses bulk_extractor and/or foremost to recover files
    from disk images including deleted files.
    """
    image_path = Path(request.image_path)

    if not image_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Disk image not found: {image_path}",
        )

    output_dir = Path(tempfile.gettempdir()) / f"carve_{uuid.uuid4()}"

    carver = get_file_carver(image_path, output_dir)
    carve_id = str(uuid.uuid4())

    try:
        # Run carving tools
        if request.tool in ["bulk_extractor", "both"]:
            carver.run_bulk_extractor()

        if request.tool in ["foremost", "both"]:
            carver.run_foremost(request.file_types)

        # Analyze results
        carver.analyze_carved_files()

        return FileCarveResponse(
            carve_id=carve_id,
            image_file=str(image_path),
            tools_run=carver.results.get("tools_run", []),
            files_carved=carver.results.get("files_carved", {}),
            statistics=carver.results.get("statistics", {}),
        )

    except Exception as e:
        logger.error(f"File carving failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File carving failed: {str(e)}",
        )


# =============================================================================
# Browser Forensics Endpoints
# =============================================================================


@router.post("/artifacts/browser", response_model=BrowserExtractResponse)
async def extract_browser_artifacts(
    request: BrowserExtractRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Extract browser artifacts from user profile.

    Extracts browsing history, downloads, cookies from:
    - Chrome
    - Edge
    - Firefox
    """
    user_profile = Path(request.user_profile_path)

    if not user_profile.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User profile not found: {user_profile}",
        )

    output_dir = Path(tempfile.gettempdir()) / f"browser_{uuid.uuid4()}"

    forensics = get_browser_forensics(user_profile, output_dir)
    extract_id = str(uuid.uuid4())

    try:
        # Extract from specified browsers
        if "chrome" in request.browsers:
            forensics.extract_chrome_history()
            forensics.extract_chrome_cookies()

        if "edge" in request.browsers:
            forensics.extract_edge_history()

        if "firefox" in request.browsers:
            forensics.extract_firefox_history()

        return BrowserExtractResponse(
            extract_id=extract_id,
            user_profile=str(user_profile),
            browsers_analyzed=forensics.results.get("browsers_analyzed", []),
            artifacts_extracted=forensics.results.get("artifacts_extracted", {}),
        )

    except Exception as e:
        logger.error(f"Browser extraction failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Browser extraction failed: {str(e)}",
        )


# =============================================================================
# Timeline Endpoints
# =============================================================================


@router.post("/timeline/generate", response_model=TimelineGenerateResponse)
async def generate_timeline(
    request: TimelineGenerateRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Generate forensic timeline from multiple sources.

    Merges timeline entries from JSON and CSV files,
    sorts by timestamp, and optionally analyzes patterns.
    """
    # Validate source files exist
    source_paths = []
    for source in request.source_files:
        path = Path(source)
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Source file not found: {source}",
            )
        source_paths.append(path)

    output_file = Path(tempfile.gettempdir()) / f"timeline_{uuid.uuid4()}.csv"

    generator = get_timeline_generator(output_file)
    timeline_id = str(uuid.uuid4())

    try:
        # Merge timelines
        generator.merge_timelines(source_paths)
        generator.sort_timeline()

        # Analyze if requested
        analysis = None
        if request.analyze and generator.timeline_entries:
            analysis = generator.analyze_timeline()

        # Convert entries
        entries = [
            TimelineEntry(
                timestamp=e.get("timestamp", ""),
                event_type=e.get("event_type", "unknown"),
                source=e.get("source", ""),
                description=e.get("description", ""),
            )
            for e in generator.timeline_entries[:1000]  # Limit entries
        ]

        return TimelineGenerateResponse(
            timeline_id=timeline_id,
            total_entries=len(generator.timeline_entries),
            sources=[str(p) for p in source_paths],
            entries=entries,
            analysis=analysis,
        )

    except Exception as e:
        logger.error(f"Timeline generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Timeline generation failed: {str(e)}",
        )


@router.post("/timeline/analyze", response_model=TimelineAnalysisResponse)
async def analyze_timeline(
    entries: List[Dict[str, Any]],
    current_user: str = Depends(get_current_active_user),
):
    """
    Analyze timeline entries for patterns.

    Provides statistics on event types, sources, and temporal distribution.
    """
    timeline_id = str(uuid.uuid4())

    # Count event types
    event_types: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    daily_distribution: Dict[str, int] = {}

    for entry in entries:
        # Event types
        etype = entry.get("event_type", "unknown")
        event_types[etype] = event_types.get(etype, 0) + 1

        # Sources
        source = entry.get("source", "unknown")
        sources[source] = sources.get(source, 0) + 1

        # Daily distribution
        timestamp = entry.get("timestamp", "")
        if timestamp:
            day = timestamp[:10]  # Extract date portion
            daily_distribution[day] = daily_distribution.get(day, 0) + 1

    # Find busiest days
    busiest = sorted(daily_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
    busiest_days = [{"date": d[0], "count": d[1]} for d in busiest]

    return TimelineAnalysisResponse(
        timeline_id=timeline_id,
        total_entries=len(entries),
        event_types=event_types,
        sources=sources,
        daily_distribution=daily_distribution,
        busiest_days=busiest_days,
    )


@router.post("/timeline/merge")
async def merge_timelines(
    timeline_files: List[str],
    current_user: str = Depends(get_current_active_user),
):
    """
    Merge multiple timeline files.

    Combines entries from multiple JSON or CSV timeline files
    and returns a sorted, unified timeline.
    """
    # Validate files
    paths = []
    for f in timeline_files:
        path = Path(f)
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Timeline file not found: {f}",
            )
        paths.append(path)

    output_file = Path(tempfile.gettempdir()) / f"merged_{uuid.uuid4()}.csv"

    generator = get_timeline_generator(output_file)

    try:
        generator.merge_timelines(paths)
        generator.sort_timeline()
        generator.write_timeline()

        return {
            "status": "merged",
            "total_entries": len(generator.timeline_entries),
            "sources": [str(p) for p in paths],
            "output_file": str(output_file),
        }

    except Exception as e:
        logger.error(f"Timeline merge failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Timeline merge failed: {str(e)}",
        )


# =============================================================================
# Async Results Endpoints
# =============================================================================


@router.get("/results/{task_id}")
async def get_analysis_results(
    task_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get analysis results by task ID.

    Returns cached results for long-running analysis tasks.
    """
    if task_id not in _analysis_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis results not found: {task_id}",
        )

    return _analysis_results[task_id]


# =============================================================================
# Legacy/Compatibility Endpoints
# =============================================================================


@router.get("/artifacts/types")
async def list_artifact_types(
    current_user: str = Depends(get_current_active_user),
):
    """
    List supported artifact types for forensic analysis.
    """
    return {
        "artifact_types": [
            {
                "type": "memory",
                "description": "Memory dump analysis (Volatility 3)",
                "supported_formats": ["raw", "dmp", "lime", "vmem"],
            },
            {
                "type": "disk",
                "description": "Disk image forensics",
                "supported_formats": ["raw", "dd", "e01", "aff"],
            },
            {
                "type": "mft",
                "description": "NTFS Master File Table",
                "supported_formats": ["$MFT"],
            },
            {
                "type": "browser",
                "description": "Browser artifacts",
                "supported_browsers": ["chrome", "edge", "firefox"],
            },
            {
                "type": "timeline",
                "description": "Timeline generation",
                "supported_formats": ["csv", "json", "plaso"],
            },
            {
                "type": "file_carving",
                "description": "File recovery from disk images",
                "tools": ["bulk_extractor", "foremost"],
            },
        ],
        "total": 6,
    }


@router.post("/analyze")
async def analyze_artifact_legacy(
    artifact_type: str = Query(..., description="Type of artifact"),
    artifact_path: str = Query(..., description="Path to artifact"),
    current_user: str = Depends(get_current_active_user),
):
    """
    Legacy endpoint for artifact analysis.

    Redirects to specific analysis endpoints based on artifact type.
    """
    if artifact_type == "memory":
        return await analyze_memory(
            MemoryAnalysisRequest(memory_dump_path=artifact_path, analysis_type="quick"),
            current_user,
        )
    elif artifact_type == "mft":
        return await parse_mft(
            MFTParseRequest(mft_file_path=artifact_path),
            current_user,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Use specific endpoint for artifact type: {artifact_type}",
        )
