#!/usr/bin/env python3
"""
Timeline Generation and Analysis
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Generates forensic timelines from multiple sources and formats:
    - Windows Event Logs (EVTX)
    - MFT records
    - Registry artifacts
    - Browser history
    - File system metadata
    Uses log2timeline/plaso format when available

Requirements:
    - plaso/log2timeline (optional, for comprehensive timeline generation)
    - Python 3.8+

Usage:
    python generate-timeline.py --source /evidence --output timeline.csv
    python generate-timeline.py --plaso-dump evidence.plaso --output timeline.csv
    python generate-timeline.py --merge file1.csv file2.csv --output merged.csv
"""

import argparse
import csv
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class TimelineGenerator:
    """Generate forensic timelines from multiple sources"""

    def __init__(self, output_file: Path):
        self.output_file = output_file
        self.timeline_entries = []

    def check_plaso(self) -> bool:
        """Check if plaso/log2timeline is available"""
        try:
            result = subprocess.run(
                ['log2timeline.py', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def generate_with_plaso(self, source_path: Path, plaso_file: Path) -> bool:
        """
        Generate timeline using log2timeline

        Args:
            source_path: Evidence source directory/file
            plaso_file: Output plaso database file

        Returns:
            bool: True if successful
        """
        logger.info("[+] Generating timeline with log2timeline...")
        logger.info(f"    Source: {source_path}")
        logger.info(f"    Plaso file: {plaso_file}")

        if not self.check_plaso():
            logger.error("[X] log2timeline not found. Install: pip install plaso")
            return False

        try:
            # Run log2timeline
            cmd = [
                'log2timeline.py',
                '--status_view', 'linear',
                '--storage-file', str(plaso_file),
                str(source_path)
            ]

            logger.info(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )

            if result.returncode == 0:
                logger.info("[OK] Timeline generation complete")
                return True
            else:
                logger.error(f"[X] log2timeline failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("[X] log2timeline timed out (1 hour)")
            return False
        except Exception as e:
            logger.error(f"[X] Error running log2timeline: {e}")
            return False

    def export_plaso_timeline(self, plaso_file: Path) -> bool:
        """
        Export plaso database to CSV timeline

        Args:
            plaso_file: Plaso database file

        Returns:
            bool: True if successful
        """
        logger.info("[+] Exporting plaso timeline to CSV...")

        try:
            cmd = [
                'psort.py',
                '-o', 'l2tcsv',
                '-w', str(self.output_file),
                str(plaso_file)
            ]

            logger.info(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )

            if result.returncode == 0:
                logger.info(f"[OK] Timeline exported: {self.output_file}")
                return True
            else:
                logger.error(f"[X] psort failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("[X] psort timed out (30 minutes)")
            return False
        except Exception as e:
            logger.error(f"[X] Error exporting timeline: {e}")
            return False

    def parse_json_timeline(self, json_file: Path) -> None:
        """
        Parse JSON timeline entries

        Args:
            json_file: JSON file with timeline entries
        """
        logger.info(f"[+] Parsing JSON timeline: {json_file}")

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

                # Handle different JSON formats
                if isinstance(data, list):
                    entries = data
                elif isinstance(data, dict):
                    # Try common keys
                    entries = data.get('timeline', data.get('events', data.get('entries', [])))
                else:
                    logger.error("[X] Unsupported JSON format")
                    return

                for entry in entries:
                    self.timeline_entries.append({
                        'timestamp': entry.get('timestamp', entry.get('time', '')),
                        'event_type': entry.get('event_type', entry.get('type', 'unknown')),
                        'source': entry.get('source', json_file.name),
                        'description': entry.get('description', entry.get('message', '')),
                        'details': entry.get('details', {})
                    })

                logger.info(f"[OK] Parsed {len(entries)} entries")

        except Exception as e:
            logger.error(f"[X] Error parsing JSON: {e}")

    def parse_csv_timeline(self, csv_file: Path) -> None:
        """
        Parse CSV timeline entries

        Args:
            csv_file: CSV file with timeline entries
        """
        logger.info(f"[+] Parsing CSV timeline: {csv_file}")

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Try to identify timestamp column
                    timestamp = row.get('timestamp', row.get('time', row.get('date', '')))

                    self.timeline_entries.append({
                        'timestamp': timestamp,
                        'event_type': row.get('event_type', row.get('type', 'unknown')),
                        'source': row.get('source', csv_file.name),
                        'description': row.get('description', row.get('message', '')),
                        'details': row
                    })

                logger.info(f"[OK] Parsed {reader.line_num - 1} entries")

        except Exception as e:
            logger.error(f"[X] Error parsing CSV: {e}")

    def merge_timelines(self, timeline_files: List[Path]) -> None:
        """
        Merge multiple timeline files

        Args:
            timeline_files: List of timeline files to merge
        """
        logger.info(f"[+] Merging {len(timeline_files)} timeline files...")

        for file_path in timeline_files:
            if not file_path.exists():
                logger.warning(f"[!] File not found: {file_path}")
                continue

            # Detect file format
            if file_path.suffix.lower() == '.json':
                self.parse_json_timeline(file_path)
            elif file_path.suffix.lower() == '.csv':
                self.parse_csv_timeline(file_path)
            else:
                logger.warning(f"[!] Unsupported format: {file_path}")

        logger.info(f"[OK] Total entries: {len(self.timeline_entries)}")

    def sort_timeline(self) -> None:
        """Sort timeline entries by timestamp"""
        logger.info("[+] Sorting timeline...")

        try:
            self.timeline_entries.sort(key=lambda x: self._parse_timestamp(x['timestamp']))
            logger.info("[OK] Timeline sorted")
        except Exception as e:
            logger.error(f"[X] Error sorting timeline: {e}")

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse timestamp string to datetime object

        Args:
            timestamp_str: Timestamp string in various formats

        Returns:
            datetime object
        """
        # Try common formats
        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%m/%d/%Y %H:%M:%S'
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        # If all parsing fails, return epoch
        return datetime(1970, 1, 1)

    def write_timeline(self) -> None:
        """Write timeline to output file"""
        logger.info(f"[+] Writing timeline to: {self.output_file}")

        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['timestamp', 'event_type', 'source', 'description']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')

                writer.writeheader()
                writer.writerows(self.timeline_entries)

            logger.info(f"[OK] Timeline written ({len(self.timeline_entries)} entries)")

        except Exception as e:
            logger.error(f"[X] Error writing timeline: {e}")

    def analyze_timeline(self) -> Dict:
        """
        Analyze timeline for patterns

        Returns:
            dict: Analysis results
        """
        logger.info("[+] Analyzing timeline...")

        analysis = {
            'total_entries': len(self.timeline_entries),
            'event_types': {},
            'sources': {},
            'hourly_distribution': {},
            'daily_distribution': {}
        }

        for entry in self.timeline_entries:
            # Count event types
            event_type = entry['event_type']
            analysis['event_types'][event_type] = analysis['event_types'].get(event_type, 0) + 1

            # Count sources
            source = entry['source']
            analysis['sources'][source] = analysis['sources'].get(source, 0) + 1

            # Temporal distribution
            try:
                dt = self._parse_timestamp(entry['timestamp'])
                hour_key = dt.strftime('%Y-%m-%d %H:00')
                day_key = dt.strftime('%Y-%m-%d')

                analysis['hourly_distribution'][hour_key] = \
                    analysis['hourly_distribution'].get(hour_key, 0) + 1

                analysis['daily_distribution'][day_key] = \
                    analysis['daily_distribution'].get(day_key, 0) + 1
            except:
                pass

        return analysis

    def generate_report(self, analysis: Dict) -> None:
        """
        Generate timeline analysis report

        Args:
            analysis: Analysis results
        """
        logger.info("\n" + "="*70)
        logger.info("Timeline Analysis Report")
        logger.info("="*70)

        logger.info(f"\nTotal Entries: {analysis['total_entries']}")

        logger.info("\n[+] Event Types (Top 10):")
        for event_type, count in sorted(analysis['event_types'].items(),
                                       key=lambda x: x[1], reverse=True)[:10]:
            logger.info(f"  {event_type}: {count}")

        logger.info("\n[+] Sources:")
        for source, count in sorted(analysis['sources'].items(),
                                    key=lambda x: x[1], reverse=True):
            logger.info(f"  {source}: {count}")

        logger.info("\n[+] Busiest Days (Top 5):")
        for day, count in sorted(analysis['daily_distribution'].items(),
                                key=lambda x: x[1], reverse=True)[:5]:
            logger.info(f"  {day}: {count} events")

        # Save analysis to JSON
        analysis_file = self.output_file.parent / f"{self.output_file.stem}_analysis.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2)

        logger.info(f"\n[OK] Analysis saved to: {analysis_file}")
        logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(description='Timeline generation and analysis')
    parser.add_argument('--source', type=Path, help='Evidence source directory')
    parser.add_argument('--plaso-file', type=Path, help='Plaso database file')
    parser.add_argument('--plaso-dump', type=Path, help='Dump existing plaso file to CSV')
    parser.add_argument('--merge', type=Path, nargs='+', help='Merge timeline files')
    parser.add_argument('--output', type=Path, required=True, help='Output timeline file (CSV)')
    parser.add_argument('--analyze', action='store_true', help='Analyze timeline')

    args = parser.parse_args()

    generator = TimelineGenerator(args.output)

    # Generate timeline with plaso
    if args.source:
        plaso_file = args.plaso_file or Path('timeline.plaso')

        if generator.generate_with_plaso(args.source, plaso_file):
            generator.export_plaso_timeline(plaso_file)
        else:
            logger.error("[X] Timeline generation failed")
            return 1

    # Export existing plaso file
    elif args.plaso_dump:
        if not args.plaso_dump.exists():
            logger.error(f"[X] Plaso file not found: {args.plaso_dump}")
            return 1

        generator.export_plaso_timeline(args.plaso_dump)

    # Merge timeline files
    elif args.merge:
        generator.merge_timelines(args.merge)
        generator.sort_timeline()
        generator.write_timeline()

    else:
        logger.error("[X] No input specified. Use --source, --plaso-dump, or --merge")
        parser.print_help()
        return 1

    # Analyze if requested
    if args.analyze and generator.timeline_entries:
        analysis = generator.analyze_timeline()
        generator.generate_report(analysis)

    return 0


if __name__ == '__main__':
    exit(main())
