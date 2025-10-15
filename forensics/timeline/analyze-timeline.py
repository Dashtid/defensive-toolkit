#!/usr/bin/env python3
"""
Timeline Analysis and Pattern Detection
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Analyzes forensic timelines to identify:
    - Suspicious temporal patterns
    - Activity spikes and anomalies
    - Event correlations
    - Attack progression indicators
    - Timeline gaps (anti-forensics)

Requirements:
    - pandas (pip install pandas)
    - Python 3.8+

Usage:
    python analyze-timeline.py --timeline timeline.csv --output analysis/
    python analyze-timeline.py --timeline timeline.csv --detect-anomalies
    python analyze-timeline.py --timeline timeline.csv --correlation-window 300
"""

import argparse
import csv
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logging.warning("pandas not available - some features will be limited")

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class TimelineAnalyzer:
    """Analyze forensic timelines for patterns and anomalies"""

    def __init__(self, timeline_file: Path, output_dir: Path):
        self.timeline_file = timeline_file
        self.output_dir = output_dir
        self.events = []
        self.findings = []

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def load_timeline(self) -> bool:
        """
        Load timeline from CSV file

        Returns:
            bool: True if successful
        """
        logger.info(f"[+] Loading timeline: {self.timeline_file}")

        try:
            with open(self.timeline_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp
                    timestamp_str = row.get('timestamp', row.get('time', ''))

                    if timestamp_str:
                        try:
                            timestamp = self._parse_timestamp(timestamp_str)
                            self.events.append({
                                'timestamp': timestamp,
                                'timestamp_str': timestamp_str,
                                'event_type': row.get('event_type', row.get('type', 'unknown')),
                                'source': row.get('source', ''),
                                'description': row.get('description', row.get('message', '')),
                                'raw': row
                            })
                        except:
                            pass

            # Sort by timestamp
            self.events.sort(key=lambda x: x['timestamp'])

            logger.info(f"[OK] Loaded {len(self.events)} events")
            return len(self.events) > 0

        except Exception as e:
            logger.error(f"[X] Error loading timeline: {e}")
            return False

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f'
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str[:19], fmt[:19])
            except ValueError:
                continue

        raise ValueError(f"Cannot parse timestamp: {timestamp_str}")

    def detect_activity_spikes(self, window_minutes: int = 60) -> None:
        """
        Detect unusual activity spikes

        Args:
            window_minutes: Time window for spike detection (minutes)
        """
        logger.info(f"[+] Detecting activity spikes (window: {window_minutes} minutes)...")

        if not self.events:
            return

        # Count events per window
        window_counts = defaultdict(int)

        for event in self.events:
            # Round timestamp to window
            window_start = event['timestamp'].replace(
                minute=(event['timestamp'].minute // window_minutes) * window_minutes,
                second=0,
                microsecond=0
            )
            window_counts[window_start] += 1

        # Calculate statistics
        counts = list(window_counts.values())
        if not counts:
            return

        mean_count = sum(counts) / len(counts)
        std_dev = (sum((x - mean_count) ** 2 for x in counts) / len(counts)) ** 0.5
        threshold = mean_count + (2 * std_dev)  # 2 standard deviations

        # Find spikes
        spikes = [(window, count) for window, count in window_counts.items()
                 if count > threshold]

        if spikes:
            for window, count in sorted(spikes, key=lambda x: x[1], reverse=True)[:10]:
                self.findings.append({
                    'type': 'Activity Spike',
                    'severity': 'medium',
                    'timestamp': window.isoformat(),
                    'description': f'Unusual activity spike detected',
                    'details': {
                        'event_count': count,
                        'mean': round(mean_count, 2),
                        'threshold': round(threshold, 2),
                        'window_minutes': window_minutes
                    }
                })

            logger.info(f"[!] Found {len(spikes)} activity spikes")

    def detect_timeline_gaps(self, gap_threshold_minutes: int = 120) -> None:
        """
        Detect suspicious gaps in timeline (potential anti-forensics)

        Args:
            gap_threshold_minutes: Minimum gap to report (minutes)
        """
        logger.info(f"[+] Detecting timeline gaps (threshold: {gap_threshold_minutes} minutes)...")

        gaps = []

        for i in range(len(self.events) - 1):
            current_event = self.events[i]
            next_event = self.events[i + 1]

            time_diff = next_event['timestamp'] - current_event['timestamp']
            gap_minutes = time_diff.total_seconds() / 60

            if gap_minutes >= gap_threshold_minutes:
                gaps.append({
                    'start': current_event['timestamp'],
                    'end': next_event['timestamp'],
                    'duration_minutes': gap_minutes
                })

        if gaps:
            for gap in gaps:
                self.findings.append({
                    'type': 'Timeline Gap',
                    'severity': 'high',
                    'timestamp': gap['start'].isoformat(),
                    'description': 'Suspicious gap in timeline (possible log deletion/tampering)',
                    'details': {
                        'gap_start': gap['start'].isoformat(),
                        'gap_end': gap['end'].isoformat(),
                        'duration_minutes': round(gap['duration_minutes'], 2)
                    }
                })

            logger.info(f"[!] Found {len(gaps)} timeline gaps")

    def correlate_events(self, window_seconds: int = 300) -> None:
        """
        Find correlated events within time window

        Args:
            window_seconds: Correlation window (seconds)
        """
        logger.info(f"[+] Correlating events (window: {window_seconds} seconds)...")

        suspicious_patterns = [
            ['powershell', 'network'],
            ['download', 'execution'],
            ['credential', 'network'],
            ['file_creation', 'process_creation'],
            ['registry_modification', 'persistence']
        ]

        correlations = []

        for i, event1 in enumerate(self.events):
            # Check events within window
            for event2 in self.events[i+1:]:
                time_diff = (event2['timestamp'] - event1['timestamp']).total_seconds()

                if time_diff > window_seconds:
                    break

                # Check for suspicious patterns
                desc1 = (event1['event_type'] + ' ' + event1['description']).lower()
                desc2 = (event2['event_type'] + ' ' + event2['description']).lower()

                for pattern in suspicious_patterns:
                    if any(keyword in desc1 for keyword in pattern) and \
                       any(keyword in desc2 for keyword in pattern):
                        correlations.append({
                            'pattern': ' + '.join(pattern),
                            'event1': event1,
                            'event2': event2,
                            'time_diff': time_diff
                        })

        if correlations:
            logger.info(f"[!] Found {len(correlations)} correlated events")

            for corr in correlations[:20]:  # Limit to top 20
                self.findings.append({
                    'type': 'Event Correlation',
                    'severity': 'high',
                    'timestamp': corr['event1']['timestamp'].isoformat(),
                    'description': f'Suspicious event correlation: {corr["pattern"]}',
                    'details': {
                        'pattern': corr['pattern'],
                        'event1_type': corr['event1']['event_type'],
                        'event1_desc': corr['event1']['description'],
                        'event2_type': corr['event2']['event_type'],
                        'event2_desc': corr['event2']['description'],
                        'time_difference_seconds': round(corr['time_diff'], 2)
                    }
                })

    def detect_off_hours_activity(self, work_start_hour: int = 8, work_end_hour: int = 18) -> None:
        """
        Detect activity outside normal work hours

        Args:
            work_start_hour: Work day start hour (0-23)
            work_end_hour: Work day end hour (0-23)
        """
        logger.info(f"[+] Detecting off-hours activity (work hours: {work_start_hour}-{work_end_hour})...")

        off_hours_events = []

        for event in self.events:
            hour = event['timestamp'].hour
            is_weekend = event['timestamp'].weekday() >= 5  # Saturday or Sunday

            if is_weekend or hour < work_start_hour or hour >= work_end_hour:
                off_hours_events.append(event)

        if off_hours_events:
            logger.info(f"[!] Found {len(off_hours_events)} off-hours events")

            # Group by type
            off_hours_by_type = defaultdict(int)
            for event in off_hours_events:
                off_hours_by_type[event['event_type']] += 1

            self.findings.append({
                'type': 'Off-Hours Activity',
                'severity': 'medium',
                'timestamp': off_hours_events[0]['timestamp'].isoformat(),
                'description': f'{len(off_hours_events)} events outside normal work hours',
                'details': {
                    'total_events': len(off_hours_events),
                    'percentage': round(len(off_hours_events) / len(self.events) * 100, 2),
                    'event_types': dict(off_hours_by_type)
                }
            })

    def analyze_temporal_patterns(self) -> None:
        """Analyze temporal patterns in timeline"""
        logger.info("[+] Analyzing temporal patterns...")

        if not self.events:
            return

        # Hourly distribution
        hourly_dist = defaultdict(int)
        daily_dist = defaultdict(int)
        weekday_dist = defaultdict(int)

        for event in self.events:
            hourly_dist[event['timestamp'].hour] += 1
            daily_dist[event['timestamp'].date().isoformat()] += 1
            weekday_dist[event['timestamp'].strftime('%A')] += 1

        # Find patterns
        patterns = {
            'busiest_hour': max(hourly_dist.items(), key=lambda x: x[1]),
            'busiest_day': max(daily_dist.items(), key=lambda x: x[1]),
            'busiest_weekday': max(weekday_dist.items(), key=lambda x: x[1]),
            'hourly_distribution': dict(hourly_dist),
            'daily_distribution': dict(daily_dist),
            'weekday_distribution': dict(weekday_dist)
        }

        # Save patterns
        patterns_file = self.output_dir / 'temporal_patterns.json'
        with open(patterns_file, 'w') as f:
            json.dump(patterns, f, indent=2)

        logger.info(f"[OK] Temporal patterns saved: {patterns_file}")

    def generate_report(self) -> None:
        """Generate analysis report"""
        logger.info("\n" + "="*70)
        logger.info("Timeline Analysis Report")
        logger.info("="*70)

        logger.info(f"\nTimeline: {self.timeline_file}")
        logger.info(f"Total Events: {len(self.events)}")

        if self.events:
            logger.info(f"Time Range: {self.events[0]['timestamp_str']} to {self.events[-1]['timestamp_str']}")

        # Group findings by severity
        critical = [f for f in self.findings if f['severity'] == 'critical']
        high = [f for f in self.findings if f['severity'] == 'high']
        medium = [f for f in self.findings if f['severity'] == 'medium']

        logger.info(f"\n[+] Findings Summary:")
        logger.info(f"  Critical: {len(critical)}")
        logger.info(f"  High: {len(high)}")
        logger.info(f"  Medium: {len(medium)}")
        logger.info(f"  Total: {len(self.findings)}")

        if self.findings:
            logger.info(f"\n[!] Top 15 Findings:\n")
            for i, finding in enumerate(self.findings[:15], 1):
                logger.info(f"{i}. [{finding['severity'].upper()}] {finding['type']}")
                logger.info(f"   {finding['description']}")
                logger.info(f"   Time: {finding['timestamp']}\n")

        # Save findings to JSON
        findings_file = self.output_dir / 'analysis_findings.json'
        with open(findings_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'timeline_file': str(self.timeline_file),
                'total_events': len(self.events),
                'total_findings': len(self.findings),
                'severity_counts': {
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium)
                },
                'findings': self.findings
            }, f, indent=2)

        logger.info(f"[OK] Report saved to: {findings_file}")
        logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(description='Timeline analysis and pattern detection')
    parser.add_argument('--timeline', type=Path, required=True, help='Timeline CSV file')
    parser.add_argument('--output', type=Path, default=Path('timeline_analysis'),
                        help='Output directory')
    parser.add_argument('--detect-anomalies', action='store_true',
                        help='Detect activity anomalies')
    parser.add_argument('--correlation-window', type=int, default=300,
                        help='Event correlation window (seconds)')
    parser.add_argument('--spike-window', type=int, default=60,
                        help='Activity spike detection window (minutes)')
    parser.add_argument('--gap-threshold', type=int, default=120,
                        help='Timeline gap threshold (minutes)')

    args = parser.parse_args()

    if not args.timeline.exists():
        logger.error(f"[X] Timeline file not found: {args.timeline}")
        return 1

    analyzer = TimelineAnalyzer(args.timeline, args.output)

    # Load timeline
    if not analyzer.load_timeline():
        return 1

    # Run analyses
    analyzer.detect_activity_spikes(args.spike_window)
    analyzer.detect_timeline_gaps(args.gap_threshold)
    analyzer.correlate_events(args.correlation_window)
    analyzer.detect_off_hours_activity()
    analyzer.analyze_temporal_patterns()

    # Generate report
    analyzer.generate_report()

    return 0


if __name__ == '__main__':
    exit(main())
