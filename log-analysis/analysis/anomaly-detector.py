#!/usr/bin/env python3
"""
Log Anomaly Detector
Statistical anomaly detection in log files
Detects unusual patterns, frequency spikes, and baseline deviations
"""

import sys
import json
import argparse
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict
import statistics
import re

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Statistical anomaly detection for logs"""

    def __init__(self, baseline_file: Optional[Path] = None, threshold_stddev: float = 2.0):
        """
        Initialize anomaly detector

        Args:
            baseline_file: Pre-computed baseline statistics
            threshold_stddev: Standard deviations for anomaly threshold
        """
        self.threshold_stddev = threshold_stddev
        self.baseline = self._load_baseline(baseline_file) if baseline_file else None
        self.current_stats = {}
        self.anomalies = []

    def _load_baseline(self, baseline_file: Path) -> Dict:
        """Load baseline statistics from file"""
        try:
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)
            logger.info(f"Loaded baseline from {baseline_file}")
            return baseline
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return {}

    def create_baseline(self, log_entries: List[Dict], output_file: Path):
        """
        Create baseline statistics from log data

        Args:
            log_entries: List of parsed log entries
            output_file: Where to save baseline
        """
        logger.info("Creating baseline statistics")

        stats = self._compute_statistics(log_entries)

        baseline = {
            'timestamp': datetime.now().isoformat(),
            'entry_count': len(log_entries),
            'statistics': stats
        }

        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        logger.info(f"Baseline saved to {output_file}")
        return baseline

    def detect_anomalies(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Detect anomalies in log entries

        Args:
            log_entries: List of parsed log entries

        Returns:
            List of detected anomalies
        """
        logger.info(f"Analyzing {len(log_entries)} log entries for anomalies")

        self.current_stats = self._compute_statistics(log_entries)
        self.anomalies = []

        # Frequency-based anomalies
        self._detect_frequency_anomalies(log_entries)

        # Pattern-based anomalies
        self._detect_pattern_anomalies(log_entries)

        # Statistical anomalies (if baseline exists)
        if self.baseline:
            self._detect_statistical_anomalies()

        # Rate-based anomalies
        self._detect_rate_anomalies(log_entries)

        logger.info(f"Detected {len(self.anomalies)} anomalies")
        return self.anomalies

    def _compute_statistics(self, log_entries: List[Dict]) -> Dict:
        """Compute statistical features from log entries"""
        stats = {
            'total_entries': len(log_entries),
            'processes': Counter(),
            'hostnames': Counter(),
            'severities': Counter(),
            'users': Counter(),
            'source_ips': Counter(),
            'error_keywords': Counter(),
            'hourly_distribution': defaultdict(int),
            'message_lengths': []
        }

        # Error keywords to track
        error_keywords = [
            'error', 'fail', 'denied', 'unauthorized', 'refused',
            'timeout', 'exception', 'critical', 'alert', 'warning'
        ]

        for entry in log_entries:
            # Count by fields
            if entry.get('process'):
                stats['processes'][entry['process']] += 1
            if entry.get('hostname'):
                stats['hostnames'][entry['hostname']] += 1
            if entry.get('severity'):
                stats['severities'][entry['severity']] += 1
            if entry.get('user'):
                stats['users'][entry['user']] += 1
            if entry.get('source_ip'):
                stats['source_ips'][entry['source_ip']] += 1

            # Track message characteristics
            message = entry.get('message', '').lower()
            stats['message_lengths'].append(len(message))

            # Count error keywords
            for keyword in error_keywords:
                if keyword in message:
                    stats['error_keywords'][keyword] += 1

            # Hourly distribution
            timestamp = entry.get('timestamp', '')
            if timestamp:
                try:
                    # Extract hour from various timestamp formats
                    hour_match = re.search(r'(\d{2}):(\d{2}):(\d{2})', timestamp)
                    if hour_match:
                        hour = int(hour_match.group(1))
                        stats['hourly_distribution'][hour] += 1
                except:
                    pass

        # Compute statistics for message lengths
        if stats['message_lengths']:
            stats['message_length_mean'] = statistics.mean(stats['message_lengths'])
            stats['message_length_stddev'] = statistics.stdev(stats['message_lengths']) \
                if len(stats['message_lengths']) > 1 else 0

        return stats

    def _detect_frequency_anomalies(self, log_entries: List[Dict]):
        """Detect anomalously frequent events"""
        # Check for unusually frequent processes
        processes = self.current_stats['processes']
        if processes:
            total = sum(processes.values())
            for process, count in processes.most_common(10):
                frequency = count / total
                if frequency > 0.3:  # More than 30% of logs from one process
                    self.anomalies.append({
                        'type': 'high_frequency',
                        'severity': 'medium',
                        'description': f'Process "{process}" appears in {frequency*100:.1f}% of logs',
                        'details': {
                            'process': process,
                            'count': count,
                            'frequency': frequency
                        }
                    })

        # Check for unusually frequent source IPs
        source_ips = self.current_stats['source_ips']
        if source_ips:
            total = sum(source_ips.values())
            for ip, count in source_ips.most_common(5):
                frequency = count / total
                if frequency > 0.2 and count > 100:  # More than 20% and >100 entries
                    self.anomalies.append({
                        'type': 'high_frequency_ip',
                        'severity': 'high',
                        'description': f'Source IP "{ip}" appears {count} times ({frequency*100:.1f}%)',
                        'details': {
                            'ip': ip,
                            'count': count,
                            'frequency': frequency
                        }
                    })

    def _detect_pattern_anomalies(self, log_entries: List[Dict]):
        """Detect anomalous patterns in log messages"""
        # Detect repeated failure patterns
        failure_patterns = defaultdict(list)
        failure_keywords = ['failed', 'error', 'denied', 'refused', 'timeout']

        for i, entry in enumerate(log_entries):
            message = entry.get('message', '').lower()
            for keyword in failure_keywords:
                if keyword in message:
                    failure_patterns[keyword].append(i)

        # Check for failure bursts
        for keyword, indices in failure_patterns.items():
            if len(indices) > 20:  # More than 20 occurrences
                # Check for temporal clustering
                if len(indices) > 2:
                    gaps = [indices[i+1] - indices[i] for i in range(len(indices)-1)]
                    avg_gap = statistics.mean(gaps) if gaps else 0
                    if avg_gap < 10:  # Failures occurring close together
                        self.anomalies.append({
                            'type': 'failure_burst',
                            'severity': 'high',
                            'description': f'Burst of "{keyword}" events detected',
                            'details': {
                                'keyword': keyword,
                                'count': len(indices),
                                'avg_gap': avg_gap
                            }
                        })

    def _detect_statistical_anomalies(self):
        """Detect statistical deviations from baseline"""
        if not self.baseline:
            return

        baseline_stats = self.baseline.get('statistics', {})

        # Compare error keyword frequencies
        baseline_errors = baseline_stats.get('error_keywords', {})
        current_errors = self.current_stats.get('error_keywords', {})

        for keyword, current_count in current_errors.items():
            baseline_count = baseline_errors.get(keyword, 0)
            if baseline_count > 0:
                ratio = current_count / baseline_count
                if ratio > 2.0:  # More than 2x baseline
                    self.anomalies.append({
                        'type': 'statistical_deviation',
                        'severity': 'high',
                        'description': f'Error keyword "{keyword}" is {ratio:.1f}x above baseline',
                        'details': {
                            'keyword': keyword,
                            'baseline': baseline_count,
                            'current': current_count,
                            'ratio': ratio
                        }
                    })

        # Compare process distributions
        baseline_procs = dict(baseline_stats.get('processes', {}))
        current_procs = dict(self.current_stats.get('processes', {}))

        for process, current_count in current_procs.items():
            baseline_count = baseline_procs.get(process, 0)
            if baseline_count > 0:
                ratio = current_count / baseline_count
                if ratio > 3.0:  # More than 3x baseline
                    self.anomalies.append({
                        'type': 'process_spike',
                        'severity': 'medium',
                        'description': f'Process "{process}" activity is {ratio:.1f}x above baseline',
                        'details': {
                            'process': process,
                            'baseline': baseline_count,
                            'current': current_count,
                            'ratio': ratio
                        }
                    })

    def _detect_rate_anomalies(self, log_entries: List[Dict]):
        """Detect anomalous event rates"""
        hourly_dist = self.current_stats.get('hourly_distribution', {})

        if len(hourly_dist) > 1:
            counts = list(hourly_dist.values())
            mean_rate = statistics.mean(counts)
            stddev_rate = statistics.stdev(counts) if len(counts) > 1 else 0

            for hour, count in hourly_dist.items():
                if stddev_rate > 0:
                    z_score = (count - mean_rate) / stddev_rate
                    if abs(z_score) > self.threshold_stddev:
                        self.anomalies.append({
                            'type': 'rate_anomaly',
                            'severity': 'medium' if z_score > 0 else 'low',
                            'description': f'Unusual activity at hour {hour:02d}:00',
                            'details': {
                                'hour': hour,
                                'count': count,
                                'mean': mean_rate,
                                'z_score': z_score
                            }
                        })

    def generate_report(self, output_format: str = 'json', output_file: Optional[Path] = None) -> str:
        """Generate anomaly detection report"""
        if output_format == 'json':
            return self._generate_json_report(output_file)
        else:
            return self._generate_text_report(output_file)

    def _generate_json_report(self, output_file: Optional[Path] = None) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'anomalies_detected': len(self.anomalies),
            'anomalies': self.anomalies,
            'statistics': self.current_stats
        }

        json_output = json.dumps(report, indent=2, default=str)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            logger.info(f"JSON report saved to {output_file}")

        return json_output

    def _generate_text_report(self, output_file: Optional[Path] = None) -> str:
        """Generate text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("Log Anomaly Detection Report")
        lines.append("=" * 80)
        lines.append(f"Timestamp: {datetime.now().isoformat()}")
        lines.append(f"Anomalies Detected: {len(self.anomalies)}")
        lines.append("")

        if self.anomalies:
            # Group by severity
            by_severity = defaultdict(list)
            for anomaly in self.anomalies:
                by_severity[anomaly['severity']].append(anomaly)

            for severity in ['high', 'medium', 'low']:
                if severity in by_severity:
                    lines.append(f"\n{severity.upper()} SEVERITY ANOMALIES")
                    lines.append("-" * 80)
                    for anomaly in by_severity[severity]:
                        lines.append(f"\n[!] {anomaly['type'].replace('_', ' ').title()}")
                        lines.append(f"    {anomaly['description']}")
                        if 'details' in anomaly:
                            for key, value in anomaly['details'].items():
                                if isinstance(value, float):
                                    lines.append(f"    {key}: {value:.2f}")
                                else:
                                    lines.append(f"    {key}: {value}")
        else:
            lines.append("NO ANOMALIES DETECTED")

        lines.append("\n" + "=" * 80)

        report = "\n".join(lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Text report saved to {output_file}")

        return report


def main():
    parser = argparse.ArgumentParser(
        description='Log Anomaly Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline from parsed logs
  python anomaly-detector.py --create-baseline --input parsed-logs.json --output baseline.json

  # Detect anomalies against baseline
  python anomaly-detector.py --detect --input current-logs.json --baseline baseline.json

  # Detect anomalies without baseline (pattern-based)
  python anomaly-detector.py --detect --input logs.json --output anomalies.txt
        """
    )

    parser.add_argument('--create-baseline', action='store_true',
                       help='Create baseline statistics')
    parser.add_argument('--detect', action='store_true',
                       help='Detect anomalies')
    parser.add_argument('--input', '-i', type=Path, required=True,
                       help='Input file (parsed JSON logs)')
    parser.add_argument('--baseline', '-b', type=Path,
                       help='Baseline statistics file')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output file')
    parser.add_argument('--output-format', choices=['json', 'text'],
                       default='text', help='Output format')
    parser.add_argument('--threshold', type=float, default=2.0,
                       help='Anomaly threshold (std devs, default: 2.0)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Load input logs
    try:
        with open(args.input, 'r') as f:
            log_entries = json.load(f)
        logger.info(f"Loaded {len(log_entries)} log entries")
    except Exception as e:
        logger.error(f"Failed to load input: {e}")
        sys.exit(1)

    detector = AnomalyDetector(
        baseline_file=args.baseline,
        threshold_stddev=args.threshold
    )

    if args.create_baseline:
        if not args.output:
            parser.error("--create-baseline requires --output")
        detector.create_baseline(log_entries, args.output)

    elif args.detect:
        anomalies = detector.detect_anomalies(log_entries)
        report = detector.generate_report(
            output_format=args.output_format,
            output_file=args.output
        )

        if not args.output:
            print(report)

        sys.exit(1 if len(anomalies) > 0 else 0)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
