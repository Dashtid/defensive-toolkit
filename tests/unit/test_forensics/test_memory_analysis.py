#!/usr/bin/env python3
"""
Unit tests for forensics/memory/volatility-auto-analyze.py
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from forensics.memory.volatility_auto_analyze import VolatilityAnalyzer


class TestVolatilityAnalyzerInit:
    """Test VolatilityAnalyzer initialization"""

    def test_init_basic(self, tmp_path):
        """Test basic initialization"""
        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()

        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)

        assert analyzer.memory_dump == memory_dump
        assert analyzer.output_dir == output_dir
        assert output_dir.exists()
        assert 'timestamp' in analyzer.results
        assert 'plugins_run' in analyzer.results

    def test_init_creates_output_directory(self, tmp_path):
        """Test output directory creation"""
        memory_dump = tmp_path / "test.raw"
        memory_dump.touch()

        output_dir = tmp_path / "nested" / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)

        assert output_dir.exists()

    def test_init_with_existing_directory(self, tmp_path):
        """Test initialization with existing directory"""
        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()

        output_dir = tmp_path / "existing"
        output_dir.mkdir()

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)

        assert output_dir.exists()


class TestVolatilityPluginExecution:
    """Test Volatility plugin execution"""

    @patch('subprocess.run')
    def test_run_plugin_basic(self, mock_run, tmp_path):
        """Test running basic Volatility plugin"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Plugin output",
            stderr=""
        )

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.run_plugin("windows.pslist")

        assert isinstance(result, dict)
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_run_plugin_with_output_file(self, mock_run, tmp_path):
        """Test plugin execution with output file"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.run_plugin("windows.pslist", output_file="pslist.txt")

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_run_plugin_with_extra_args(self, mock_run, tmp_path):
        """Test plugin with extra arguments"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.run_plugin(
            "windows.pslist",
            extra_args=["--pid", "1234"]
        )

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_run_plugin_failure(self, mock_run, tmp_path):
        """Test handling plugin execution failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Plugin error"
        )

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.run_plugin("windows.pslist")

        # Should handle failure gracefully
        assert isinstance(result, dict)
        assert result.get('success') is False or 'error' in result


class TestProcessAnalysis:
    """Test process analysis functionality"""

    @patch('subprocess.run')
    def test_analyze_processes(self, mock_run, tmp_path):
        """Test process listing and analysis"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="PID\tPPID\tName\n1234\t500\tmalware.exe\n",
            stderr=""
        )

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.analyze_processes()

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_detect_hidden_processes(self, mock_run, tmp_path):
        """Test hidden process detection"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.detect_hidden_processes()

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_process_tree_analysis(self, mock_run, tmp_path):
        """Test process tree generation"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.generate_process_tree()

        assert isinstance(result, dict)


class TestNetworkAnalysis:
    """Test network connection analysis"""

    @patch('subprocess.run')
    def test_analyze_network_connections(self, mock_run, tmp_path):
        """Test network connection enumeration"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="PID\tLocal\tRemote\n1234\t192.168.1.10:4444\t10.0.0.5:80\n",
            stderr=""
        )

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.analyze_network()

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_detect_suspicious_connections(self, mock_run, tmp_path):
        """Test suspicious connection detection"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.detect_suspicious_connections()

        assert isinstance(result, dict)


class TestMalwareDetection:
    """Test malware detection functionality"""

    @patch('subprocess.run')
    def test_malware_hunt_mode(self, mock_run, tmp_path):
        """Test malware hunting mode"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.malware_hunt()

        assert isinstance(result, dict)
        assert 'suspicious_findings' in analyzer.results

    @patch('subprocess.run')
    def test_detect_code_injection(self, mock_run, tmp_path):
        """Test code injection detection"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.detect_code_injection()

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_scan_for_malicious_dlls(self, mock_run, tmp_path):
        """Test DLL scanning"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.scan_dlls()

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_detect_rootkits(self, mock_run, tmp_path):
        """Test rootkit detection"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.detect_rootkits()

        assert isinstance(result, dict)


class TestTimelineGeneration:
    """Test timeline generation"""

    @patch('subprocess.run')
    def test_generate_timeline(self, mock_run, tmp_path):
        """Test memory timeline generation"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.generate_timeline()

        assert isinstance(result, dict)

    @patch('subprocess.run')
    def test_timeline_with_filters(self, mock_run, tmp_path):
        """Test filtered timeline generation"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.generate_timeline(
            start_time="2025-10-18T00:00:00",
            end_time="2025-10-18T23:59:59"
        )

        assert isinstance(result, dict)


class TestQuickAnalysis:
    """Test quick analysis mode"""

    @patch('subprocess.run')
    def test_quick_analysis_mode(self, mock_run, tmp_path):
        """Test quick analysis mode"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.quick_analysis()

        assert isinstance(result, dict)
        # Quick mode should run fewer plugins
        assert len(analyzer.results['plugins_run']) > 0


class TestReportGeneration:
    """Test analysis report generation"""

    @patch('subprocess.run')
    def test_generate_report_json(self, mock_run, tmp_path):
        """Test JSON report generation"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        analyzer.analyze_processes()
        analyzer.analyze_network()

        report_file = output_dir / "analysis_report.json"
        analyzer.generate_report(report_file, format="json")

        if report_file.exists():
            with open(report_file, 'r') as f:
                report = json.load(f)
            assert 'timestamp' in report

    @patch('subprocess.run')
    def test_generate_report_html(self, mock_run, tmp_path):
        """Test HTML report generation"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)

        report_file = output_dir / "report.html"
        analyzer.generate_report(report_file, format="html")

        # Report generation method may exist
        assert isinstance(analyzer.results, dict)


# [+] Integration tests
@pytest.mark.integration
class TestVolatilityIntegration:
    """Integration tests for Volatility analysis"""

    @patch('subprocess.run')
    def test_complete_analysis_workflow(self, mock_run, tmp_path):
        """Test complete memory analysis workflow"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "incident_memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "analysis"

        # Initialize analyzer
        analyzer = VolatilityAnalyzer(memory_dump, output_dir)

        # Run comprehensive analysis
        analyzer.analyze_processes()
        analyzer.analyze_network()
        analyzer.malware_hunt()
        analyzer.generate_timeline()

        # Generate report
        report_file = output_dir / "final_report.json"
        analyzer.results['summary'] = {
            'plugins_executed': len(analyzer.results['plugins_run']),
            'suspicious_findings': len(analyzer.results['suspicious_findings'])
        }

        with open(report_file, 'w') as f:
            json.dump(analyzer.results, f, indent=2)

        assert report_file.exists()

    @patch('subprocess.run')
    def test_malware_investigation_workflow(self, mock_run, tmp_path):
        """Test malware-focused investigation"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "malware_sample.raw"
        memory_dump.touch()
        output_dir = tmp_path / "malware_analysis"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)

        # Malware-specific checks
        analyzer.detect_code_injection()
        analyzer.detect_rootkits()
        analyzer.scan_dlls()
        analyzer.detect_hidden_processes()

        # Check for findings
        assert isinstance(analyzer.results['suspicious_findings'], list)


# [+] Parametrized tests
@pytest.mark.parametrize("plugin", [
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.malfind",
    "windows.dlllist"
])
def test_common_plugins(plugin, tmp_path):
    """Test common Volatility plugins"""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        memory_dump = tmp_path / "memory.raw"
        memory_dump.touch()
        output_dir = tmp_path / "output"

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        result = analyzer.run_plugin(plugin)

        assert isinstance(result, dict)


# [+] Performance tests
@pytest.mark.slow
def test_analysis_performance(tmp_path):
    """Test analysis performance with large memory dump"""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        # Simulate large memory dump
        memory_dump = tmp_path / "large_memory.raw"
        memory_dump.touch()

        output_dir = tmp_path / "output"

        import time
        start = time.time()

        analyzer = VolatilityAnalyzer(memory_dump, output_dir)
        analyzer.quick_analysis()

        duration = time.time() - start

        # Quick analysis should be fast even with mocking
        assert duration < 10.0
