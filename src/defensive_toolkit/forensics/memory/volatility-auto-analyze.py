#!/usr/bin/env python3
"""
Volatility 3 Automated Memory Analysis
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automates common Volatility 3 memory analysis tasks including:
    - Process listing and analysis
    - Network connections
    - DLL/driver analysis
    - Malware detection indicators
    - Timeline generation

Requirements:
    - Volatility 3 (pip install volatility3)
    - Python 3.8+

Usage:
    python volatility-auto-analyze.py memory.dmp --output report/
    python volatility-auto-analyze.py memory.dmp --quick
    python volatility-auto-analyze.py memory.dmp --malware-hunt
"""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class VolatilityAnalyzer:
    """Automated Volatility 3 memory analysis"""

    def __init__(self, memory_dump: Path, output_dir: Path):
        """
        Initialize analyzer

        Args:
            memory_dump: Path to memory dump file
            output_dir: Directory for analysis results
        """
        self.memory_dump = memory_dump
        self.output_dir = output_dir
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'memory_dump': str(memory_dump),
            'plugins_run': [],
            'suspicious_findings': [],
            'statistics': {}
        }

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_plugin(self, plugin: str, output_file: Optional[str] = None,
                   extra_args: List[str] = None) -> Dict:
        """
        Run Volatility 3 plugin

        Args:
            plugin: Plugin name
            output_file: Optional output filename
            extra_args: Additional arguments for plugin

        Returns:
            dict: Plugin execution results
        """
        logger.info(f"Running plugin: {plugin}")

        # Build command
        cmd = ['vol', '-f', str(self.memory_dump), plugin]

        if extra_args:
            cmd.extend(extra_args)

        # Prepare output file
        if output_file:
            output_path = self.output_dir / output_file
        else:
            output_path = self.output_dir / f"{plugin.replace('.', '_')}.txt"

        result = {
            'plugin': plugin,
            'output_file': str(output_path),
            'status': 'unknown',
            'error': None
        }

        try:
            # Run plugin and capture output
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if process.returncode == 0:
                # Save output to file
                with open(output_path, 'w') as f:
                    f.write(process.stdout)

                result['status'] = 'success'
                result['lines'] = len(process.stdout.splitlines())
                logger.info(f"[OK] {plugin} completed ({result['lines']} lines)")
            else:
                result['status'] = 'failed'
                result['error'] = process.stderr
                logger.error(f"[X] {plugin} failed: {process.stderr}")

        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['error'] = 'Plugin execution timed out (5 minutes)'
            logger.error(f"[X] {plugin} timed out")

        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"[X] {plugin} error: {e}")

        self.results['plugins_run'].append(result)
        return result

    def quick_analysis(self) -> None:
        """Run quick triage analysis"""
        logger.info("Starting quick triage analysis...")

        # Essential plugins for quick analysis
        plugins = [
            ('windows.info.Info', 'system_info.txt'),
            ('windows.pslist.PsList', 'processes.txt'),
            ('windows.pstree.PsTree', 'process_tree.txt'),
            ('windows.netscan.NetScan', 'network_connections.txt'),
            ('windows.cmdline.CmdLine', 'command_lines.txt'),
        ]

        for plugin, output_file in plugins:
            self.run_plugin(plugin, output_file)

    def full_analysis(self) -> None:
        """Run comprehensive analysis"""
        logger.info("Starting comprehensive analysis...")

        # All analysis plugins
        plugins = [
            # System information
            ('windows.info.Info', 'system_info.txt'),

            # Process analysis
            ('windows.pslist.PsList', 'processes.txt'),
            ('windows.pstree.PsTree', 'process_tree.txt'),
            ('windows.psscan.PsScan', 'process_scan.txt'),
            ('windows.cmdline.CmdLine', 'command_lines.txt'),
            ('windows.envars.Envars', 'environment_variables.txt'),

            # Network analysis
            ('windows.netscan.NetScan', 'network_connections.txt'),
            ('windows.netstat.NetStat', 'network_stats.txt'),

            # DLL and driver analysis
            ('windows.dlllist.DllList', 'loaded_dlls.txt'),
            ('windows.modules.Modules', 'kernel_modules.txt'),
            ('windows.driverscan.DriverScan', 'drivers.txt'),

            # Registry
            ('windows.registry.hivelist.HiveList', 'registry_hives.txt'),
            ('windows.registry.printkey.PrintKey', 'registry_run_keys.txt',
             ['--key', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run']),

            # File analysis
            ('windows.filescan.FileScan', 'file_scan.txt'),
            ('windows.handles.Handles', 'file_handles.txt'),

            # Malware detection
            ('windows.malfind.Malfind', 'malfind.txt'),
            ('windows.ldrmodules.LdrModules', 'unlinked_dlls.txt'),

            # Timeline
            ('timeliner.Timeliner', 'timeline.txt'),
        ]

        for item in plugins:
            if len(item) == 2:
                plugin, output_file = item
                self.run_plugin(plugin, output_file)
            else:
                plugin, output_file, extra_args = item
                self.run_plugin(plugin, output_file, extra_args)

    def malware_hunt(self) -> None:
        """Focus on malware-specific analysis"""
        logger.info("Starting malware hunting analysis...")

        # Malware-focused plugins
        plugins = [
            ('windows.malfind.Malfind', 'malfind.txt'),
            ('windows.ldrmodules.LdrModules', 'unlinked_dlls.txt'),
            ('windows.pslist.PsList', 'processes.txt'),
            ('windows.psscan.PsScan', 'hidden_processes.txt'),
            ('windows.dlllist.DllList', 'loaded_dlls.txt'),
            ('windows.netscan.NetScan', 'network_connections.txt'),
            ('windows.cmdline.CmdLine', 'command_lines.txt'),
            ('windows.svcscan.SvcScan', 'services.txt'),
        ]

        for plugin, output_file in plugins:
            self.run_plugin(plugin, output_file)

        # Analyze results for suspicious indicators
        self._analyze_for_malware()

    def _analyze_for_malware(self) -> None:
        """Analyze results for malware indicators"""
        logger.info("Analyzing for malware indicators...")

        suspicious_findings = []

        # Check malfind results
        malfind_file = self.output_dir / 'malfind.txt'
        if malfind_file.exists():
            with open(malfind_file, 'r') as f:
                content = f.read()
                if 'MZ' in content or 'This program cannot be run' in content:
                    suspicious_findings.append({
                        'indicator': 'Injected code detected',
                        'source': 'malfind.txt',
                        'severity': 'high'
                    })

        # Check for hidden processes
        pslist_file = self.output_dir / 'processes.txt'
        psscan_file = self.output_dir / 'hidden_processes.txt'
        if pslist_file.exists() and psscan_file.exists():
            with open(pslist_file, 'r') as f:
                pslist_pids = set([line.split()[1] for line in f if line.strip()])
            with open(psscan_file, 'r') as f:
                psscan_pids = set([line.split()[1] for line in f if line.strip()])

            hidden = psscan_pids - pslist_pids
            if hidden:
                suspicious_findings.append({
                    'indicator': f'Hidden processes detected: {len(hidden)}',
                    'source': 'process comparison',
                    'severity': 'critical'
                })

        # Check for suspicious network connections
        netscan_file = self.output_dir / 'network_connections.txt'
        if netscan_file.exists():
            suspicious_ports = ['4444', '8080', '1337', '31337']
            with open(netscan_file, 'r') as f:
                for line in f:
                    if any(port in line for port in suspicious_ports):
                        suspicious_findings.append({
                            'indicator': 'Suspicious port detected',
                            'details': line.strip(),
                            'source': 'network_connections.txt',
                            'severity': 'medium'
                        })

        self.results['suspicious_findings'] = suspicious_findings

        if suspicious_findings:
            logger.warning(f"[!] Found {len(suspicious_findings)} suspicious indicators")
            for finding in suspicious_findings:
                logger.warning(f"  - {finding['indicator']} (severity: {finding['severity']})")
        else:
            logger.info("[OK] No obvious malware indicators found")

    def generate_report(self) -> None:
        """Generate analysis summary report"""
        logger.info("Generating analysis report...")

        report_path = self.output_dir / 'analysis_report.json'

        # Calculate statistics
        successful = len([p for p in self.results['plugins_run'] if p['status'] == 'success'])
        failed = len([p for p in self.results['plugins_run'] if p['status'] != 'success'])

        self.results['statistics'] = {
            'total_plugins': len(self.results['plugins_run']),
            'successful': successful,
            'failed': failed,
            'suspicious_findings': len(self.results['suspicious_findings'])
        }

        # Save JSON report
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"[OK] Report saved to: {report_path}")

        # Generate text summary
        summary_path = self.output_dir / 'ANALYSIS_SUMMARY.txt'
        with open(summary_path, 'w') as f:
            f.write("="*70 + "\n")
            f.write("Volatility 3 Memory Analysis Summary\n")
            f.write("="*70 + "\n\n")
            f.write(f"Timestamp: {self.results['timestamp']}\n")
            f.write(f"Memory Dump: {self.memory_dump}\n")
            f.write(f"Output Directory: {self.output_dir}\n\n")

            f.write("Statistics:\n")
            f.write(f"  Plugins Run: {self.results['statistics']['total_plugins']}\n")
            f.write(f"  Successful: {self.results['statistics']['successful']}\n")
            f.write(f"  Failed: {self.results['statistics']['failed']}\n")
            f.write(f"  Suspicious Findings: {self.results['statistics']['suspicious_findings']}\n\n")

            if self.results['suspicious_findings']:
                f.write("Suspicious Findings:\n")
                for i, finding in enumerate(self.results['suspicious_findings'], 1):
                    f.write(f"\n  {i}. {finding['indicator']}\n")
                    f.write(f"     Severity: {finding['severity']}\n")
                    f.write(f"     Source: {finding['source']}\n")
                    if 'details' in finding:
                        f.write(f"     Details: {finding['details']}\n")

            f.write("\n" + "="*70 + "\n")
            f.write("Analysis complete. Review individual plugin outputs for details.\n")
            f.write("="*70 + "\n")

        logger.info(f"[OK] Summary saved to: {summary_path}")


def check_volatility() -> bool:
    """Check if Volatility 3 is installed"""
    try:
        result = subprocess.run(['vol', '--help'], capture_output=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Automated Volatility 3 memory analysis'
    )
    parser.add_argument(
        'memory_dump',
        type=Path,
        help='Path to memory dump file'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('volatility_analysis'),
        help='Output directory (default: volatility_analysis)'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick triage analysis (faster)'
    )
    parser.add_argument(
        '--malware-hunt',
        action='store_true',
        help='Focus on malware detection'
    )

    args = parser.parse_args()

    # Check if memory dump exists
    if not args.memory_dump.exists():
        logger.error(f"[X] Memory dump not found: {args.memory_dump}")
        sys.exit(1)

    # Check if Volatility 3 is installed
    if not check_volatility():
        logger.error("[X] Volatility 3 not found. Install: pip install volatility3")
        sys.exit(1)

    logger.info("="*70)
    logger.info("Volatility 3 Automated Memory Analysis")
    logger.info("="*70)
    logger.info(f"Memory Dump: {args.memory_dump}")
    logger.info(f"Output Directory: {args.output}")

    # Initialize analyzer
    analyzer = VolatilityAnalyzer(args.memory_dump, args.output)

    # Run analysis based on mode
    if args.quick:
        logger.info("Mode: Quick Triage")
        analyzer.quick_analysis()
    elif args.malware_hunt:
        logger.info("Mode: Malware Hunting")
        analyzer.malware_hunt()
    else:
        logger.info("Mode: Full Analysis")
        analyzer.full_analysis()

    # Generate report
    analyzer.generate_report()

    # Summary
    stats = analyzer.results['statistics']
    logger.info("\n" + "="*70)
    logger.info("Analysis Complete")
    logger.info("="*70)
    logger.info(f"Plugins Run: {stats['total_plugins']}")
    logger.info(f"Successful: {stats['successful']}")
    logger.info(f"Failed: {stats['failed']}")
    logger.info(f"Suspicious Findings: {stats['suspicious_findings']}")
    logger.info(f"\nResults saved to: {args.output}")
    logger.info("="*70)


if __name__ == '__main__':
    main()
