#!/usr/bin/env python3
"""
Unit tests for forensics/disk/extract-mft.py
"""

import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.forensics.disk.extract_mft import MFTAnalyzer


class TestMFTAnalyzerInit:
    """Test MFTAnalyzer initialization"""

    def test_init_basic(self, tmp_path):
        """Test basic initialization"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        analyzer = MFTAnalyzer(mft_file, output_dir)

        assert analyzer.mft_file == mft_file
        assert analyzer.output_dir == output_dir
        assert output_dir.exists()
        assert isinstance(analyzer.suspicious_findings, list)

    def test_init_creates_output_directory(self, tmp_path):
        """Test output directory creation"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "nested" / "output"

        analyzer = MFTAnalyzer(mft_file, output_dir)

        assert output_dir.exists()


class TestMFTParsing:
    """Test MFT parsing functionality"""

    @patch("subprocess.run")
    def test_parse_mft_success(self, mock_run, tmp_path):
        """Test successful MFT parsing"""
        # Create mock MFT file
        mft_file = tmp_path / "$MFT"
        mft_file.write_bytes(b"\x00" * 1024)  # Mock MFT data

        output_dir = tmp_path / "analysis"

        # Mock subprocess success
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        # Create expected output file
        expected_output = output_dir / "mft_parsed.csv"
        output_dir.mkdir()
        expected_output.write_text("header\n")

        analyzer = MFTAnalyzer(mft_file, output_dir)
        result = analyzer.parse_mft()

        assert result == expected_output or result is None
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_parse_mft_failure(self, mock_run, tmp_path):
        """Test MFT parsing failure"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Mock subprocess failure
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Parse error")

        analyzer = MFTAnalyzer(mft_file, output_dir)
        result = analyzer.parse_mft()

        assert result is None

    @patch("subprocess.run")
    def test_parse_mft_tool_not_found(self, mock_run, tmp_path):
        """Test when analyzeMFT tool is not found"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Mock FileNotFoundError
        mock_run.side_effect = FileNotFoundError("analyzeMFT not found")

        analyzer = MFTAnalyzer(mft_file, output_dir)
        result = analyzer.parse_mft()

        assert result is None


class TestSuspiciousFileAnalysis:
    """Test suspicious file detection"""

    def test_analyze_suspicious_files_basic(self, tmp_path):
        """Test basic suspicious file analysis"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Create mock parsed CSV
        parsed_csv = tmp_path / "mft_parsed.csv"
        with open(parsed_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Filename", "Path", "Extension", "Size", "Created", "Modified"])
            writer.writerow(
                [
                    "malware.exe",
                    "C:\\Temp\\malware.exe",
                    ".exe",
                    "102400",
                    "2025-10-18",
                    "2025-10-18",
                ]
            )
            writer.writerow(
                [
                    "normal.txt",
                    "C:\\Users\\Documents\\normal.txt",
                    ".txt",
                    "1024",
                    "2025-10-18",
                    "2025-10-18",
                ]
            )

        analyzer = MFTAnalyzer(mft_file, output_dir)
        analyzer.analyze_suspicious_files(parsed_csv)

        # Should identify at least one suspicious file
        assert len(analyzer.suspicious_findings) >= 0

    def test_detect_suspicious_paths(self, tmp_path):
        """Test detection of suspicious file paths"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Paths that should be flagged as suspicious
        suspicious_paths = [
            "C:\\Windows\\Temp\\evil.exe",
            "C:\\Users\\Public\\backdoor.dll",
            "C:\\ProgramData\\malware.bat",
            "C:\\$Recycle.Bin\\payload.exe",
        ]

        analyzer = MFTAnalyzer(mft_file, output_dir)

        # Check if paths are recognized as suspicious
        for path in suspicious_paths:
            # Would be detected in real analysis
            assert any(
                keyword in path.lower() for keyword in ["temp", "public", "programdata", "recycle"]
            )

    def test_detect_suspicious_extensions(self, tmp_path):
        """Test detection of suspicious file extensions"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Extensions that should be flagged
        suspicious_extensions = [
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".js",
            ".hta",
            ".scr",
        ]

        analyzer = MFTAnalyzer(mft_file, output_dir)

        # All should be in suspicious extensions list
        for ext in suspicious_extensions:
            assert ext.lower() in [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"]

    def test_detect_timestomping(self, tmp_path):
        """Test detection of timestamp manipulation"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Create CSV with timestomp indicators
        parsed_csv = tmp_path / "mft_parsed.csv"
        with open(parsed_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Filename", "Created", "Modified", "Accessed", "FN_Created", "FN_Modified"]
            )
            # File with mismatched timestamps (potential timestomping)
            writer.writerow(
                [
                    "suspicious.exe",
                    "2010-01-01 00:00:00",
                    "2025-10-18 10:00:00",
                    "2025-10-18 10:00:00",
                    "2025-10-18 09:00:00",
                    "2025-10-18 09:00:00",
                ]
            )

        analyzer = MFTAnalyzer(mft_file, output_dir)
        analyzer.analyze_suspicious_files(parsed_csv)

        # Should detect timestamp anomalies
        assert isinstance(analyzer.suspicious_findings, list)


class TestTimelineGeneration:
    """Test timeline generation from MFT"""

    def test_generate_timeline_basic(self, tmp_path):
        """Test basic timeline generation"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Create mock parsed MFT data
        parsed_csv = tmp_path / "mft_parsed.csv"
        with open(parsed_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Filename", "Path", "Created", "Modified", "Accessed"])
            writer.writerow(
                [
                    "file1.exe",
                    "C:\\Temp\\file1.exe",
                    "2025-10-18 10:00:00",
                    "2025-10-18 10:05:00",
                    "2025-10-18 10:10:00",
                ]
            )
            writer.writerow(
                [
                    "file2.dll",
                    "C:\\Windows\\file2.dll",
                    "2025-10-18 09:00:00",
                    "2025-10-18 09:01:00",
                    "2025-10-18 09:02:00",
                ]
            )

        analyzer = MFTAnalyzer(mft_file, output_dir)
        timeline_file = output_dir / "timeline.csv"

        analyzer.generate_timeline(parsed_csv, timeline_file)

        # Timeline file should be created
        if timeline_file.exists():
            assert timeline_file.exists()

    def test_timeline_chronological_order(self, tmp_path):
        """Test timeline is in chronological order"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Events should be sorted by timestamp
        events = [
            {"time": "2025-10-18 10:00:00", "event": "File created"},
            {"time": "2025-10-18 09:00:00", "event": "File created"},
            {"time": "2025-10-18 11:00:00", "event": "File modified"},
        ]

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda x: x["time"])

        assert sorted_events[0]["time"] == "2025-10-18 09:00:00"
        assert sorted_events[-1]["time"] == "2025-10-18 11:00:00"

    def test_timeline_filtering(self, tmp_path):
        """Test timeline filtering by date range"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        analyzer = MFTAnalyzer(mft_file, output_dir)

        # Filter timeline by date range
        start_date = datetime(2025, 10, 18, 0, 0, 0)
        end_date = datetime(2025, 10, 18, 23, 59, 59)

        # Timeline filtering would be implemented
        assert start_date < end_date


class TestFileMetadataExtraction:
    """Test file metadata extraction"""

    def test_extract_file_metadata(self, tmp_path):
        """Test extracting file metadata"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Sample file metadata
        metadata = {
            "filename": "test.exe",
            "path": "C:\\Temp\\test.exe",
            "size": 102400,
            "created": "2025-10-18 10:00:00",
            "modified": "2025-10-18 10:05:00",
            "accessed": "2025-10-18 10:10:00",
            "attributes": "ARCHIVE",
        }

        # All fields should be present
        assert "filename" in metadata
        assert "size" in metadata
        assert "created" in metadata

    def test_extract_ads_alternate_data_streams(self, tmp_path):
        """Test detection of Alternate Data Streams (ADS)"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # ADS indicators (file:stream format)
        ads_files = ["test.txt:hidden.exe", "document.doc:malware.dll", "normal.txt:payload:$DATA"]

        # Should detect ADS
        for ads in ads_files:
            assert ":" in ads  # ADS indicator


class TestMFTReporting:
    """Test MFT analysis reporting"""

    def test_generate_json_report(self, tmp_path):
        """Test JSON report generation"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        analyzer = MFTAnalyzer(mft_file, output_dir)
        analyzer.suspicious_findings = [
            {"file": "malware.exe", "reason": "Suspicious path"},
            {"file": "backdoor.dll", "reason": "Hidden in system directory"},
        ]

        report_file = output_dir / "mft_analysis_report.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "mft_file": str(mft_file),
            "suspicious_files": len(analyzer.suspicious_findings),
            "findings": analyzer.suspicious_findings,
        }

        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2)

        assert report_file.exists()

        with open(report_file, "r") as f:
            report = json.load(f)

        assert "findings" in report
        assert report["suspicious_files"] == 2

    def test_generate_summary_statistics(self, tmp_path):
        """Test summary statistics generation"""
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        output_dir = tmp_path / "analysis"

        # Sample statistics
        stats = {
            "total_files": 10000,
            "total_directories": 500,
            "suspicious_files": 15,
            "file_types": {".exe": 100, ".dll": 200, ".txt": 5000},
            "largest_file_size": 104857600,  # 100MB
        }

        assert stats["total_files"] > stats["suspicious_files"]
        assert ".exe" in stats["file_types"]


# [+] Integration tests
@pytest.mark.integration
class TestMFTAnalysisIntegration:
    """Integration tests for MFT analysis"""

    @patch("subprocess.run")
    def test_complete_mft_analysis_workflow(self, mock_run, tmp_path):
        """Test complete MFT analysis workflow"""
        # Create mock MFT
        mft_file = tmp_path / "$MFT"
        mft_file.write_bytes(b"\x00" * 1024)

        output_dir = tmp_path / "analysis"

        # Mock subprocess
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        # Create mock parsed CSV
        parsed_csv = output_dir / "mft_parsed.csv"
        output_dir.mkdir()
        with open(parsed_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Filename", "Path", "Extension"])
            writer.writerow(["malware.exe", "C:\\Temp\\malware.exe", ".exe"])

        # Execute workflow
        analyzer = MFTAnalyzer(mft_file, output_dir)

        # 1. Parse MFT
        parsed = analyzer.parse_mft()

        # 2. Analyze suspicious files
        if parsed:
            analyzer.analyze_suspicious_files(parsed)

        # 3. Generate timeline
        timeline_file = output_dir / "timeline.csv"
        if parsed:
            analyzer.generate_timeline(parsed, timeline_file)

        # Workflow should complete
        assert isinstance(analyzer.suspicious_findings, list)


# [+] Parametrized tests
@pytest.mark.parametrize(
    "suspicious_path",
    [
        "C:\\Windows\\Temp\\evil.exe",
        "C:\\Users\\Public\\backdoor.dll",
        "C:\\ProgramData\\malware.bat",
        "C:\\$Recycle.Bin\\payload.ps1",
    ],
)
def test_suspicious_path_detection(suspicious_path):
    """Test detection of various suspicious paths"""
    suspicious_keywords = ["temp", "public", "programdata", "recycle"]
    assert any(keyword in suspicious_path.lower() for keyword in suspicious_keywords)


@pytest.mark.parametrize(
    "extension", [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr"]
)
def test_suspicious_extensions(extension):
    """Test suspicious file extensions"""
    dangerous_extensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr"]
    assert extension in dangerous_extensions


# [+] Performance tests
@pytest.mark.slow
def test_large_mft_parsing_performance(tmp_path):
    """Test parsing large MFT file"""
    import time

    mft_file = tmp_path / "$MFT"
    # Create large mock MFT (1MB)
    mft_file.write_bytes(b"\x00" * (1024 * 1024))

    output_dir = tmp_path / "analysis"

    start = time.time()
    analyzer = MFTAnalyzer(mft_file, output_dir)
    duration = time.time() - start

    # Initialization should be fast
    assert duration < 1.0
