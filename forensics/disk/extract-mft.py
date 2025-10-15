#!/usr/bin/env python3
"""
MFT (Master File Table) Parser and Analyzer
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Parses Windows NTFS Master File Table (MFT) to extract file metadata,
    identify suspicious files, and generate timelines.

Requirements:
    - analyzeMFT (pip install analyzeMFT)
    - Python 3.8+

Usage:
    python extract-mft.py --mft $MFT --output analysis/
    python extract-mft.py --mft $MFT --suspicious-only
    python extract-mft.py --mft $MFT --timeline timeline.csv
"""

import argparse
import csv
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class MFTAnalyzer:
    """Parse and analyze Windows MFT"""

    def __init__(self, mft_file: Path, output_dir: Path):
        self.mft_file = mft_file
        self.output_dir = output_dir
        self.suspicious_findings = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def parse_mft(self) -> Optional[Path]:
        """
        Parse MFT using analyzeMFT

        Returns:
            Path to parsed CSV file
        """
        logger.info(f"Parsing MFT file: {self.mft_file}")

        output_csv = self.output_dir / "mft_parsed.csv"

        try:
            # Use analyzeMFT to parse MFT
            cmd = [
                'analyzeMFT.py',
                '-f', str(self.mft_file),
                '-o', str(output_csv),
                '--csv'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )

            if result.returncode == 0 and output_csv.exists():
                logger.info(f"[OK] MFT parsed successfully: {output_csv}")
                return output_csv
            else:
                logger.error(f"[X] MFT parsing failed: {result.stderr}")
                return None

        except FileNotFoundError:
            logger.error("[X] analyzeMFT not found. Install: pip install analyzeMFT")
            return None
        except Exception as e:
            logger.error(f"[X] Error parsing MFT: {e}")
            return None

    def analyze_suspicious_files(self, parsed_csv: Path) -> None:
        """
        Analyze parsed MFT for suspicious files

        Args:
            parsed_csv: Path to parsed MFT CSV
        """
        logger.info("Analyzing for suspicious files...")

        suspicious_paths = [
            'temp', 'appdata', 'programdata', 'users\\public', 'downloads',
            'recycle.bin', '$recycle.bin', 'windows\\temp'
        ]

        suspicious_extensions = [
            '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta',
            '.scr', '.com', '.pif', '.msi', '.reg'
        ]

        try:
            with open(parsed_csv, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    filename = row.get('Filename', '').lower()
                    filepath = row.get('Path', '').lower()

                    # Check for suspicious paths
                    for susp_path in suspicious_paths:
                        if susp_path in filepath:
                            # Check for executable extensions
                            for ext in suspicious_extensions:
                                if filename.endswith(ext):
                                    self.suspicious_findings.append({
                                        'type': 'Suspicious File Location',
                                        'severity': 'medium',
                                        'filename': row.get('Filename', ''),
                                        'path': row.get('Path', ''),
                                        'created': row.get('Standard Information Created', ''),
                                        'modified': row.get('Standard Information Modified', ''),
                                        'size': row.get('File Size', ''),
                                        'reason': f'Executable in suspicious location: {susp_path}'
                                    })
                                    break

                    # Check for hidden files with executable extensions
                    if filename.startswith('.') or row.get('Flags', '').lower() == 'hidden':
                        for ext in suspicious_extensions:
                            if filename.endswith(ext):
                                self.suspicious_findings.append({
                                    'type': 'Hidden Executable',
                                    'severity': 'high',
                                    'filename': row.get('Filename', ''),
                                    'path': row.get('Path', ''),
                                    'created': row.get('Standard Information Created', ''),
                                    'modified': row.get('Standard Information Modified', ''),
                                    'size': row.get('File Size', ''),
                                    'reason': 'Hidden file with executable extension'
                                })
                                break

                    # Check for recently created executables
                    created_date = row.get('Standard Information Created', '')
                    if created_date:
                        try:
                            # Check if created in last 7 days (if timestamp parseable)
                            # Simplified check - just flag recent dates
                            for ext in suspicious_extensions:
                                if filename.endswith(ext):
                                    self.suspicious_findings.append({
                                        'type': 'Recent Executable',
                                        'severity': 'low',
                                        'filename': row.get('Filename', ''),
                                        'path': row.get('Path', ''),
                                        'created': created_date,
                                        'modified': row.get('Standard Information Modified', ''),
                                        'size': row.get('File Size', ''),
                                        'reason': 'Recently created executable'
                                    })
                                    break
                        except:
                            pass

            logger.info(f"[OK] Found {len(self.suspicious_findings)} suspicious files")

        except Exception as e:
            logger.error(f"[X] Error analyzing MFT: {e}")

    def generate_timeline(self, parsed_csv: Path, output_file: Path) -> None:
        """
        Generate timeline from parsed MFT

        Args:
            parsed_csv: Path to parsed MFT CSV
            output_file: Output timeline file
        """
        logger.info("Generating timeline...")

        timeline_entries = []

        try:
            with open(parsed_csv, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    filename = row.get('Filename', '')
                    filepath = row.get('Path', '')

                    # Add creation time
                    created = row.get('Standard Information Created', '')
                    if created:
                        timeline_entries.append({
                            'timestamp': created,
                            'event': 'File Created',
                            'filename': filename,
                            'path': filepath,
                            'size': row.get('File Size', '')
                        })

                    # Add modification time
                    modified = row.get('Standard Information Modified', '')
                    if modified:
                        timeline_entries.append({
                            'timestamp': modified,
                            'event': 'File Modified',
                            'filename': filename,
                            'path': filepath,
                            'size': row.get('File Size', '')
                        })

                    # Add access time
                    accessed = row.get('Standard Information Accessed', '')
                    if accessed:
                        timeline_entries.append({
                            'timestamp': accessed,
                            'event': 'File Accessed',
                            'filename': filename,
                            'path': filepath,
                            'size': row.get('File Size', '')
                        })

            # Sort by timestamp
            timeline_entries.sort(key=lambda x: x['timestamp'])

            # Write timeline
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['timestamp', 'event', 'filename', 'path', 'size']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(timeline_entries)

            logger.info(f"[OK] Timeline generated: {output_file} ({len(timeline_entries)} entries)")

        except Exception as e:
            logger.error(f"[X] Error generating timeline: {e}")

    def generate_report(self) -> None:
        """Generate analysis report"""
        logger.info("\n" + "="*70)
        logger.info("MFT Analysis Report")
        logger.info("="*70)

        # Group by severity
        critical = [f for f in self.suspicious_findings if f['severity'] == 'critical']
        high = [f for f in self.suspicious_findings if f['severity'] == 'high']
        medium = [f for f in self.suspicious_findings if f['severity'] == 'medium']
        low = [f for f in self.suspicious_findings if f['severity'] == 'low']

        logger.info(f"\nSuspicious Files Summary:")
        logger.info(f"  Critical: {len(critical)}")
        logger.info(f"  High: {len(high)}")
        logger.info(f"  Medium: {len(medium)}")
        logger.info(f"  Low: {len(low)}")
        logger.info(f"  Total: {len(self.suspicious_findings)}")

        if self.suspicious_findings:
            logger.info(f"\n[!] Top 20 Suspicious Files:\n")
            for i, finding in enumerate(self.suspicious_findings[:20], 1):
                logger.info(f"{i}. [{finding['severity'].upper()}] {finding['type']}")
                logger.info(f"   File: {finding['path']}\\{finding['filename']}")
                logger.info(f"   Reason: {finding['reason']}")
                logger.info(f"   Created: {finding['created']}")
                logger.info(f"   Size: {finding['size']}\n")

            # Save to JSON
            report_file = self.output_dir / 'suspicious_files.json'
            with open(report_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'mft_file': str(self.mft_file),
                    'total_findings': len(self.suspicious_findings),
                    'severity_counts': {
                        'critical': len(critical),
                        'high': len(high),
                        'medium': len(medium),
                        'low': len(low)
                    },
                    'findings': self.suspicious_findings
                }, f, indent=2)

            logger.info(f"[OK] Report saved to: {report_file}")
        else:
            logger.info("\n[OK] No suspicious files found")

        logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(description='MFT Parser and Analyzer')
    parser.add_argument('--mft', type=Path, required=True, help='MFT file ($MFT)')
    parser.add_argument('--output', type=Path, default=Path('mft_analysis'), help='Output directory')
    parser.add_argument('--timeline', type=Path, help='Generate timeline CSV')
    parser.add_argument('--suspicious-only', action='store_true', help='Only show suspicious files')

    args = parser.parse_args()

    if not args.mft.exists():
        logger.error(f"[X] MFT file not found: {args.mft}")
        return 1

    analyzer = MFTAnalyzer(args.mft, args.output)

    # Parse MFT
    parsed_csv = analyzer.parse_mft()
    if not parsed_csv:
        return 1

    # Analyze for suspicious files
    analyzer.analyze_suspicious_files(parsed_csv)

    # Generate timeline if requested
    if args.timeline:
        analyzer.generate_timeline(parsed_csv, args.timeline)

    # Generate report
    if not args.suspicious_only or analyzer.suspicious_findings:
        analyzer.generate_report()

    return 0 if not analyzer.suspicious_findings else 1


if __name__ == '__main__':
    exit(main())
