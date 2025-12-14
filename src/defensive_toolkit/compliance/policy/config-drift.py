#!/usr/bin/env python3
"""
Configuration Drift Detector
Detects changes from baseline system configuration
Monitors configuration files, services, users, and system settings
"""

import argparse
import difflib
import hashlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class DriftDetector:
    """Configuration drift detection engine"""

    def __init__(self, baseline_file: Path):
        self.baseline_file = baseline_file
        self.baseline = self._load_baseline()
        self.current_state = {}
        self.drift_results = {
            'timestamp': datetime.now().isoformat(),
            'baseline_file': str(baseline_file),
            'baseline_timestamp': self.baseline.get('timestamp', 'unknown'),
            'drift_detected': [],
            'summary': {
                'total_checks': 0,
                'drifted': 0,
                'unchanged': 0
            }
        }

    def _load_baseline(self) -> Dict:
        """Load baseline configuration"""
        try:
            with open(self.baseline_file, 'r') as f:
                baseline = json.load(f)
            logger.info(f"Loaded baseline from {self.baseline_file}")
            return baseline
        except FileNotFoundError:
            logger.error(f"Baseline file not found: {self.baseline_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid baseline JSON: {e}")
            sys.exit(1)

    def create_baseline(self, config_files: List[Path], output_file: Path):
        """Create new baseline configuration snapshot"""
        logger.info("Creating baseline configuration snapshot")

        baseline = {
            'timestamp': datetime.now().isoformat(),
            'files': {}
        }

        for file_path in config_files:
            if file_path.exists():
                baseline['files'][str(file_path)] = {
                    'hash': self._compute_file_hash(file_path),
                    'size': file_path.stat().st_size,
                    'mtime': file_path.stat().st_mtime
                }
                logger.info(f"Added to baseline: {file_path}")
            else:
                logger.warning(f"File not found: {file_path}")

        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        logger.info(f"Baseline saved to {output_file}")

    def detect_drift(self) -> Dict:
        """Detect configuration drift from baseline"""
        logger.info("Detecting configuration drift")

        baseline_files = self.baseline.get('files', {})

        for file_path_str, baseline_info in baseline_files.items():
            file_path = Path(file_path_str)
            self.drift_results['summary']['total_checks'] += 1

            drift_entry = {
                'file': file_path_str,
                'drift_type': None,
                'details': {}
            }

            # Check if file still exists
            if not file_path.exists():
                drift_entry['drift_type'] = 'deleted'
                drift_entry['details'] = {
                    'baseline_hash': baseline_info['hash'],
                    'baseline_size': baseline_info['size']
                }
                self.drift_results['drift_detected'].append(drift_entry)
                self.drift_results['summary']['drifted'] += 1
                logger.warning(f"DRIFT: File deleted - {file_path}")
                continue

            # Check file hash
            current_hash = self._compute_file_hash(file_path)
            current_size = file_path.stat().st_size
            current_mtime = file_path.stat().st_mtime

            if current_hash != baseline_info['hash']:
                drift_entry['drift_type'] = 'modified'
                drift_entry['details'] = {
                    'baseline_hash': baseline_info['hash'],
                    'current_hash': current_hash,
                    'baseline_size': baseline_info['size'],
                    'current_size': current_size,
                    'mtime_changed': current_mtime != baseline_info.get('mtime', 0)
                }
                self.drift_results['drift_detected'].append(drift_entry)
                self.drift_results['summary']['drifted'] += 1
                logger.warning(f"DRIFT: File modified - {file_path}")
            else:
                self.drift_results['summary']['unchanged'] += 1
                logger.debug(f"No drift: {file_path}")

        return self.drift_results

    def generate_diff(self, file_path: Path, baseline_content: str = None) -> str:
        """Generate diff between baseline and current file"""
        if not file_path.exists():
            return "File has been deleted"

        try:
            with open(file_path, 'r') as f:
                current_content = f.read()

            if baseline_content is None:
                return "No baseline content available for diff"

            diff = difflib.unified_diff(
                baseline_content.splitlines(keepends=True),
                current_content.splitlines(keepends=True),
                fromfile=f'baseline/{file_path.name}',
                tofile=f'current/{file_path.name}'
            )

            return ''.join(diff)

        except Exception as e:
            return f"Error generating diff: {e}"

    def generate_report(self, output_format: str = 'json', output_file: Optional[Path] = None) -> str:
        """Generate drift detection report"""
        if output_format == 'json':
            return self._generate_json_report(output_file)
        else:
            return self._generate_text_report(output_file)

    def _generate_json_report(self, output_file: Optional[Path] = None) -> str:
        """Generate JSON report"""
        json_output = json.dumps(self.drift_results, indent=2)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            logger.info(f"JSON report saved to {output_file}")

        return json_output

    def _generate_text_report(self, output_file: Optional[Path] = None) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("Configuration Drift Detection Report")
        lines.append("=" * 80)
        lines.append(f"Scan Timestamp: {self.drift_results['timestamp']}")
        lines.append(f"Baseline Timestamp: {self.drift_results['baseline_timestamp']}")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 80)
        summary = self.drift_results['summary']
        lines.append(f"Total Files Checked: {summary['total_checks']}")
        lines.append(f"Files with Drift: {summary['drifted']}")
        lines.append(f"Unchanged Files: {summary['unchanged']}")
        lines.append("")

        if self.drift_results['drift_detected']:
            lines.append("DRIFT DETECTED")
            lines.append("-" * 80)
            for drift in self.drift_results['drift_detected']:
                lines.append(f"\n[!] {drift['file']}")
                lines.append(f"    Drift Type: {drift['drift_type'].upper()}")

                if drift['drift_type'] == 'modified':
                    details = drift['details']
                    lines.append(f"    Baseline Hash: {details['baseline_hash'][:16]}...")
                    lines.append(f"    Current Hash:  {details['current_hash'][:16]}...")
                    lines.append(f"    Size Change: {details['baseline_size']} -> {details['current_size']} bytes")
                elif drift['drift_type'] == 'deleted':
                    lines.append("    File has been deleted from system")
        else:
            lines.append("NO DRIFT DETECTED")
            lines.append("-" * 80)
            lines.append("All monitored files match baseline configuration")

        lines.append("\n" + "=" * 80)

        report = "\n".join(lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Text report saved to {output_file}")

        return report

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file"""
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error computing hash for {file_path}: {e}")
            return ""


def main():
    parser = argparse.ArgumentParser(
        description='Configuration Drift Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline from config files
  python config-drift.py --create-baseline --files /etc/ssh/sshd_config /etc/pam.d/* --output baseline.json

  # Detect drift from baseline
  python config-drift.py --detect --baseline baseline.json --output-format text

  # Generate JSON drift report
  python config-drift.py --detect --baseline baseline.json --output-format json --output drift-report.json
        """
    )

    parser.add_argument('--create-baseline', action='store_true',
                       help='Create new baseline configuration snapshot')
    parser.add_argument('--detect', action='store_true',
                       help='Detect drift from baseline')
    parser.add_argument('--baseline', '-b', type=Path,
                       help='Baseline configuration file')
    parser.add_argument('--files', nargs='+', type=Path,
                       help='Configuration files to monitor (for baseline creation)')
    parser.add_argument('--output-format', choices=['json', 'text'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.create_baseline:
        if not args.files or not args.output:
            parser.error("--create-baseline requires --files and --output")

        detector = DriftDetector.__new__(DriftDetector)
        detector.create_baseline(config_files=args.files, output_file=args.output)

    elif args.detect:
        if not args.baseline:
            parser.error("--detect requires --baseline")

        detector = DriftDetector(baseline_file=args.baseline)
        results = detector.detect_drift()
        report = detector.generate_report(output_format=args.output_format, output_file=args.output)

        if not args.output:
            print(report)

        # Exit with error if drift detected
        if results['summary']['drifted'] > 0:
            logger.warning(f"Configuration drift detected: {results['summary']['drifted']} files changed")
            sys.exit(1)
        else:
            logger.info("No configuration drift detected")
            sys.exit(0)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
