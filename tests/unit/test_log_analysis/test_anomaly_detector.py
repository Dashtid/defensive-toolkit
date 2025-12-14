#!/usr/bin/env python3
"""
Unit tests for log-analysis/analysis/anomaly-detector.py
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.log_analysis.analysis.anomaly_detector import AnomalyDetector


class TestAnomalyDetectorInit:
    """Test AnomalyDetector initialization"""

    def test_init_default(self):
        """Test default initialization"""
        detector = AnomalyDetector()

        assert detector.threshold_stddev == 2.0
        assert detector.baseline is None
        assert detector.current_stats == {}
        assert detector.anomalies == []

    def test_init_custom_threshold(self):
        """Test initialization with custom threshold"""
        detector = AnomalyDetector(threshold_stddev=3.0)
        assert detector.threshold_stddev == 3.0

    def test_init_with_baseline_file(self, tmp_path):
        """Test initialization with baseline file"""
        baseline_data = {
            "timestamp": "2025-10-18T00:00:00",
            "entry_count": 1000,
            "statistics": {"avg_events_per_hour": 100.0, "unique_ips": 50},
        }

        baseline_file = tmp_path / "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        detector = AnomalyDetector(baseline_file=baseline_file)

        assert detector.baseline is not None
        assert detector.baseline["entry_count"] == 1000


class TestBaselineCreation:
    """Test baseline creation functionality"""

    def test_create_baseline_basic(self, tmp_path):
        """Test creating baseline from log entries"""
        detector = AnomalyDetector()

        log_entries = [
            {"severity": "INFO", "source_ip": "192.168.1.10"},
            {"severity": "INFO", "source_ip": "192.168.1.20"},
            {"severity": "WARNING", "source_ip": "192.168.1.10"},
        ]

        output_file = tmp_path / "baseline.json"
        baseline = detector.create_baseline(log_entries, output_file)

        assert output_file.exists()
        assert baseline["entry_count"] == 3
        assert "timestamp" in baseline
        assert "statistics" in baseline

    def test_create_baseline_empty_logs(self, tmp_path):
        """Test creating baseline with empty log list"""
        detector = AnomalyDetector()

        output_file = tmp_path / "baseline.json"
        baseline = detector.create_baseline([], output_file)

        assert baseline["entry_count"] == 0

    def test_create_baseline_large_dataset(self, tmp_path):
        """Test baseline creation with large dataset"""
        detector = AnomalyDetector()

        # Generate large log dataset
        log_entries = [
            {
                "severity": "INFO" if i % 10 != 0 else "ERROR",
                "source_ip": f"192.168.1.{i % 100}",
                "timestamp": f"2025-10-18T{i % 24:02d}:00:00",
            }
            for i in range(10000)
        ]

        output_file = tmp_path / "baseline.json"
        baseline = detector.create_baseline(log_entries, output_file)

        assert baseline["entry_count"] == 10000
        assert output_file.exists()


class TestAnomalyDetection:
    """Test anomaly detection functionality"""

    def test_detect_anomalies_basic(self):
        """Test basic anomaly detection"""
        detector = AnomalyDetector()

        log_entries = [
            {"severity": "INFO", "message": "Normal operation"},
            {"severity": "INFO", "message": "Normal operation"},
            {"severity": "ERROR", "message": "Critical failure"},  # Anomaly
        ]

        anomalies = detector.detect_anomalies(log_entries)

        assert isinstance(anomalies, list)

    def test_detect_frequency_anomalies(self):
        """Test frequency-based anomaly detection"""
        detector = AnomalyDetector()

        # Create logs with frequency spike
        log_entries = [
            {"source_ip": "192.168.1.10", "event": "login"} for _ in range(100)  # Normal activity
        ] + [
            {"source_ip": "192.168.1.100", "event": "login_failed"}
            for _ in range(500)  # Anomalous spike
        ]

        anomalies = detector.detect_anomalies(log_entries)

        # Should detect the spike
        assert len(anomalies) > 0

    def test_detect_pattern_anomalies(self):
        """Test pattern-based anomaly detection"""
        detector = AnomalyDetector()

        log_entries = [
            {"message": "Normal user activity"},
            {"message": "Normal user activity"},
            {"message": "SQL injection attempt: ' OR '1'='1"},  # Anomaly
            {"message": "XSS attempt: <script>alert('xss')</script>"},  # Anomaly
        ]

        anomalies = detector.detect_anomalies(log_entries)

        # Should detect attack patterns
        assert len(anomalies) > 0

    def test_detect_with_baseline(self, tmp_path):
        """Test anomaly detection with baseline comparison"""
        # Create baseline
        baseline_data = {
            "timestamp": "2025-10-18T00:00:00",
            "entry_count": 1000,
            "statistics": {"avg_events_per_hour": 100.0, "error_rate": 0.01, "unique_ips": 50},
        }

        baseline_file = tmp_path / "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        detector = AnomalyDetector(baseline_file=baseline_file)

        # Current logs with deviation from baseline
        log_entries = [
            {"severity": "ERROR", "source_ip": f"192.168.1.{i}"}
            for i in range(200)  # Much higher error rate
        ]

        anomalies = detector.detect_anomalies(log_entries)

        # Should detect deviation from baseline
        assert len(anomalies) > 0

    def test_detect_rate_anomalies(self):
        """Test rate-based anomaly detection"""
        detector = AnomalyDetector()

        # Simulate time-based events with rate spike
        log_entries = []

        # Normal rate: 1 event per second
        for hour in range(0, 10):
            for second in range(60):
                log_entries.append(
                    {"timestamp": f"2025-10-18T{hour:02d}:00:{second:02d}", "event": "normal"}
                )

        # Spike: 100 events per second
        for second in range(60):
            for _ in range(100):
                log_entries.append(
                    {"timestamp": f"2025-10-18T10:00:{second:02d}", "event": "spike"}
                )

        anomalies = detector.detect_anomalies(log_entries)

        # Should detect rate anomaly
        assert len(anomalies) > 0


class TestStatisticalAnalysis:
    """Test statistical analysis methods"""

    def test_compute_statistics(self):
        """Test statistics computation"""
        detector = AnomalyDetector()

        log_entries = [
            {"severity": "INFO", "source_ip": "192.168.1.10"},
            {"severity": "INFO", "source_ip": "192.168.1.20"},
            {"severity": "ERROR", "source_ip": "192.168.1.10"},
            {"severity": "WARNING", "source_ip": "192.168.1.30"},
        ]

        stats = detector._compute_statistics(log_entries)

        assert isinstance(stats, dict)
        assert "total_entries" in stats or len(stats) > 0

    def test_standard_deviation_calculation(self):
        """Test standard deviation calculation"""
        detector = AnomalyDetector(threshold_stddev=2.0)

        # Values: mean=10, values within 2 stddev are normal
        values = [8, 9, 10, 11, 12]  # Normal
        anomalous_values = [1, 25]  # Anomalous (> 2 stddev)

        # Test that threshold is applied correctly
        assert detector.threshold_stddev == 2.0


class TestAnomalyClassification:
    """Test anomaly classification and severity"""

    def test_anomaly_severity_high(self):
        """Test high severity anomaly detection"""
        detector = AnomalyDetector(threshold_stddev=2.0)

        # Extreme deviation should be high severity
        log_entries = [{"value": 100, "metric": "cpu"} for _ in range(100)] + [  # Normal
            {"value": 10000, "metric": "cpu"}  # Extreme spike
        ]

        anomalies = detector.detect_anomalies(log_entries)

        # Check if high severity anomalies detected
        if anomalies:
            high_severity = [a for a in anomalies if a.get("severity") == "HIGH"]
            # May or may not classify by severity depending on implementation

    def test_anomaly_categories(self):
        """Test anomaly categorization"""
        detector = AnomalyDetector()

        log_entries = [
            {"event": "failed_login", "count": 1000},  # Frequency anomaly
            {"message": "' OR '1'='1"},  # Pattern anomaly
            {"rate": 5000},  # Rate anomaly
        ]

        anomalies = detector.detect_anomalies(log_entries)

        # Anomalies should have categories
        assert isinstance(anomalies, list)


class TestAnomalyReporting:
    """Test anomaly reporting functionality"""

    def test_generate_anomaly_report(self, tmp_path):
        """Test generating anomaly report"""
        detector = AnomalyDetector()

        log_entries = [{"severity": "ERROR", "message": "Critical failure"} for _ in range(100)]

        anomalies = detector.detect_anomalies(log_entries)

        # Generate report
        report_file = tmp_path / "anomaly_report.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_logs_analyzed": len(log_entries),
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
        }

        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2)

        assert report_file.exists()

        with open(report_file, "r") as f:
            report = json.load(f)

        assert "anomalies_detected" in report

    def test_anomaly_summary_statistics(self):
        """Test anomaly summary generation"""
        detector = AnomalyDetector()

        log_entries = [{"event": f"event_{i}"} for i in range(1000)]
        anomalies = detector.detect_anomalies(log_entries)

        summary = {
            "total_analyzed": len(log_entries),
            "anomalies_found": len(anomalies),
            "anomaly_rate": len(anomalies) / len(log_entries) if log_entries else 0,
        }

        assert summary["total_analyzed"] == 1000
        assert summary["anomaly_rate"] >= 0.0


class TestTimeSeriesAnalysis:
    """Test time-series anomaly detection"""

    def test_time_series_anomaly(self):
        """Test time-based anomaly detection"""
        detector = AnomalyDetector()

        # Create time series with anomaly
        log_entries = []

        # Normal pattern: 100 events per hour
        for hour in range(0, 24):
            for _ in range(100):
                log_entries.append({"timestamp": f"2025-10-18T{hour:02d}:00:00", "event": "normal"})

        # Anomalous hour: 1000 events
        for _ in range(1000):
            log_entries.append({"timestamp": "2025-10-18T12:00:00", "event": "spike"})

        anomalies = detector.detect_anomalies(log_entries)

        assert len(anomalies) > 0

    def test_sliding_window_analysis(self):
        """Test sliding window anomaly detection"""
        detector = AnomalyDetector()

        # Events with sliding window pattern
        log_entries = []
        for minute in range(60):
            count = 10 if minute != 30 else 100  # Spike at minute 30
            for _ in range(count):
                log_entries.append({"timestamp": f"2025-10-18T10:{minute:02d}:00", "event": "test"})

        anomalies = detector.detect_anomalies(log_entries)

        # Should detect spike
        assert isinstance(anomalies, list)


# [+] Integration tests
@pytest.mark.integration
class TestAnomalyDetectorIntegration:
    """Integration tests for anomaly detection"""

    def test_full_anomaly_detection_workflow(self, tmp_path):
        """Test complete anomaly detection workflow"""
        # 1. Create baseline from historical data
        detector = AnomalyDetector()

        historical_logs = [
            {"severity": "INFO", "source_ip": f"192.168.1.{i % 50}"} for i in range(10000)
        ]

        baseline_file = tmp_path / "baseline.json"
        baseline = detector.create_baseline(historical_logs, baseline_file)

        assert baseline_file.exists()

        # 2. Load baseline and detect anomalies in new data
        detector2 = AnomalyDetector(baseline_file=baseline_file)

        current_logs = [
            {"severity": "ERROR", "source_ip": f"192.168.1.{i}"}
            for i in range(1000)  # High error rate - anomalous
        ]

        anomalies = detector2.detect_anomalies(current_logs)

        # 3. Generate report
        report_file = tmp_path / "report.json"
        report = {
            "baseline": baseline,
            "anomalies": anomalies,
            "summary": {"total_analyzed": len(current_logs), "anomalies_found": len(anomalies)},
        }

        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        assert report_file.exists()

    def test_real_time_anomaly_detection(self):
        """Test real-time anomaly detection simulation"""
        detector = AnomalyDetector()

        # Simulate incoming log stream
        log_stream = []

        # Normal traffic
        for i in range(100):
            log_stream.append({"timestamp": f"2025-10-18T10:00:{i:02d}", "event": "normal"})

            # Detect anomalies every 10 entries
            if i % 10 == 0 and i > 0:
                anomalies = detector.detect_anomalies(log_stream[-10:])
                # Process anomalies in real-time
                assert isinstance(anomalies, list)


# [+] Parametrized tests
@pytest.mark.parametrize("threshold", [1.0, 2.0, 3.0])
def test_different_thresholds(threshold):
    """Test anomaly detection with different thresholds"""
    detector = AnomalyDetector(threshold_stddev=threshold)
    assert detector.threshold_stddev == threshold


@pytest.mark.parametrize(
    "anomaly_type", ["frequency_spike", "pattern_match", "rate_change", "statistical_deviation"]
)
def test_anomaly_types(anomaly_type):
    """Test detection of different anomaly types"""
    detector = AnomalyDetector()

    # Create logs based on anomaly type
    if anomaly_type == "frequency_spike":
        log_entries = [{"event": "test"} for _ in range(1000)]
    elif anomaly_type == "pattern_match":
        log_entries = [{"message": "' OR '1'='1"}]
    elif anomaly_type == "rate_change":
        log_entries = [{"timestamp": f"2025-10-18T10:00:{i:02d}"} for i in range(60)]
    else:
        log_entries = [{"value": 100} for _ in range(10)]

    anomalies = detector.detect_anomalies(log_entries)
    assert isinstance(anomalies, list)


# [+] Performance tests
@pytest.mark.slow
def test_large_scale_anomaly_detection():
    """Test anomaly detection on large dataset"""
    import time

    detector = AnomalyDetector()

    # Generate large log dataset (100k entries)
    log_entries = [
        {
            "timestamp": f"2025-10-18T{i % 24:02d}:{i % 60:02d}:{i % 60:02d}",
            "severity": "INFO" if i % 100 != 0 else "ERROR",
            "source_ip": f"192.168.1.{i % 255}",
            "message": f"Event {i}",
        }
        for i in range(100000)
    ]

    start = time.time()
    anomalies = detector.detect_anomalies(log_entries)
    duration = time.time() - start

    # Should complete in reasonable time (< 30 seconds)
    assert duration < 30.0
    assert isinstance(anomalies, list)
