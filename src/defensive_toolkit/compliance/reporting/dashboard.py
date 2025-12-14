#!/usr/bin/env python3
"""
Compliance Dashboard Generator
Creates real-time compliance status dashboard
Combines CIS, NIST, and policy check results
"""

import json
import argparse
import logging
from typing import Dict, List
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def generate_html_dashboard(compliance_data: Dict, output_file: Path):
    """Generate HTML compliance dashboard"""

    html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .score {{ font-size: 36px; font-weight: bold; }}
        .score.good {{ color: #27ae60; }}
        .score.warning {{ color: #f39c12; }}
        .score.bad {{ color: #e74c3c; }}
        .framework {{ margin: 20px 0; background-color: white; padding: 20px; border-radius: 5px; }}
        .framework h2 {{ border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .status-bar {{ height: 30px; background-color: #ecf0f1; border-radius: 5px; overflow: hidden; margin: 10px 0; }}
        .status-segment {{ height: 100%; float: left; }}
        .status-pass {{ background-color: #27ae60; }}
        .status-fail {{ background-color: #e74c3c; }}
        .status-skip {{ background-color: #95a5a6; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        .badge {{ padding: 5px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge.pass {{ background-color: #27ae60; color: white; }}
        .badge.fail {{ background-color: #e74c3c; color: white; }}
        .badge.warn {{ background-color: #f39c12; color: white; }}
        .badge.skip {{ background-color: #95a5a6; color: white; }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Compliance Dashboard</h1>
            <p class="timestamp">Generated: {timestamp}</p>
        </div>

        <div class="summary">
            <div class="card">
                <h3>Overall Compliance</h3>
                <div class="score {overall_class}">{overall_score}%</div>
                <p>{total_checks} total checks</p>
            </div>
            <div class="card">
                <h3>Passed Checks</h3>
                <div class="score good">{passed}</div>
                <p>{passed_pct}% of total</p>
            </div>
            <div class="card">
                <h3>Failed Checks</h3>
                <div class="score bad">{failed}</div>
                <p>{failed_pct}% of total</p>
            </div>
            <div class="card">
                <h3>Skipped/Manual</h3>
                <div class="score">{skipped}</div>
                <p>{skipped_pct}% of total</p>
            </div>
        </div>

        {frameworks_html}

    </div>
</body>
</html>
"""

    # Calculate overall statistics
    total_checks = compliance_data.get('total_checks', 0)
    passed = compliance_data.get('passed', 0)
    failed = compliance_data.get('failed', 0)
    skipped = compliance_data.get('skipped', 0)

    overall_score = round((passed / total_checks * 100) if total_checks > 0 else 0, 1)
    passed_pct = round((passed / total_checks * 100) if total_checks > 0 else 0, 1)
    failed_pct = round((failed / total_checks * 100) if total_checks > 0 else 0, 1)
    skipped_pct = round((skipped / total_checks * 100) if total_checks > 0 else 0, 1)

    overall_class = 'good' if overall_score >= 80 else 'warning' if overall_score >= 60 else 'bad'

    # Generate framework sections
    frameworks_html = ""
    for framework in compliance_data.get('frameworks', []):
        f_passed = framework.get('passed', 0)
        f_failed = framework.get('failed', 0)
        f_skipped = framework.get('skipped', 0)
        f_total = f_passed + f_failed + f_skipped

        f_score = round((f_passed / f_total * 100) if f_total > 0 else 0, 1)

        # Status bar percentages
        pass_width = (f_passed / f_total * 100) if f_total > 0 else 0
        fail_width = (f_failed / f_total * 100) if f_total > 0 else 0
        skip_width = (f_skipped / f_total * 100) if f_total > 0 else 0

        frameworks_html += f"""
        <div class="framework">
            <h2>{framework.get('name', 'Unknown Framework')}</h2>
            <p>{framework.get('description', '')}</p>
            <div class="status-bar">
                <div class="status-segment status-pass" style="width: {pass_width}%"></div>
                <div class="status-segment status-fail" style="width: {fail_width}%"></div>
                <div class="status-segment status-skip" style="width: {skip_width}%"></div>
            </div>
            <p><strong>Compliance Score: {f_score}%</strong> (Passed: {f_passed}, Failed: {f_failed}, Skipped: {f_skipped})</p>
        </div>
"""

    # Generate HTML
    html_output = html_template.format(
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        overall_score=overall_score,
        overall_class=overall_class,
        total_checks=total_checks,
        passed=passed,
        failed=failed,
        skipped=skipped,
        passed_pct=passed_pct,
        failed_pct=failed_pct,
        skipped_pct=skipped_pct,
        frameworks_html=frameworks_html
    )

    with open(output_file, 'w') as f:
        f.write(html_output)

    logger.info(f"HTML dashboard generated: {output_file}")


def load_compliance_results(result_files: List[Path]) -> Dict:
    """Load and aggregate compliance results from multiple sources"""
    compliance_data = {
        'total_checks': 0,
        'passed': 0,
        'failed': 0,
        'skipped': 0,
        'frameworks': []
    }

    for result_file in result_files:
        if not result_file.exists():
            logger.warning(f"Result file not found: {result_file}")
            continue

        try:
            with open(result_file, 'r') as f:
                result = json.load(f)

            # Detect framework type
            if 'cis_version' in result:
                framework_name = f"CIS Controls {result['cis_version']}"
            elif 'framework' in result and 'NIST' in result['framework']:
                framework_name = result['framework']
            elif 'policy_file' in result:
                framework_name = "Security Policy"
            else:
                framework_name = result_file.stem

            summary = result.get('compliance_summary', result.get('summary', {}))

            framework_data = {
                'name': framework_name,
                'description': result.get('description', ''),
                'passed': summary.get('passed', 0),
                'failed': summary.get('failed', 0),
                'skipped': summary.get('not_applicable', summary.get('skipped', 0)),
                'total': summary.get('total', 0)
            }

            compliance_data['frameworks'].append(framework_data)

            # Aggregate totals
            compliance_data['total_checks'] += framework_data['total']
            compliance_data['passed'] += framework_data['passed']
            compliance_data['failed'] += framework_data['failed']
            compliance_data['skipped'] += framework_data['skipped']

            logger.info(f"Loaded results from {result_file.name}")

        except Exception as e:
            logger.error(f"Error loading {result_file}: {e}")

    return compliance_data


def main():
    parser = argparse.ArgumentParser(
        description='Compliance Dashboard Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate dashboard from multiple compliance results
  python dashboard.py --results cis-results.json nist-results.json policy-results.json --output dashboard.html

  # Single framework dashboard
  python dashboard.py --results cis-results.json --output cis-dashboard.html
        """
    )

    parser.add_argument('--results', nargs='+', type=Path, required=True,
                       help='Compliance result files (JSON)')
    parser.add_argument('--output', '-o', type=Path, default=Path('compliance-dashboard.html'),
                       help='Output HTML file (default: compliance-dashboard.html)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Load compliance results
    compliance_data = load_compliance_results(args.results)

    if compliance_data['total_checks'] == 0:
        logger.error("No compliance data loaded")
        return 1

    # Generate dashboard
    generate_html_dashboard(compliance_data, args.output)

    logger.info(f"Compliance dashboard ready: {args.output}")
    return 0


if __name__ == '__main__':
    exit(main())
