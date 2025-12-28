#!/usr/bin/env python3
"""
Splunk Sigma Rule Deployment Script
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automatically converts Sigma detection rules to Splunk SPL format
    and deploys them as saved searches/alerts in Splunk.

Requirements:
    - sigma-cli (pip install sigma-cli)
    - splunk-sdk (pip install splunk-sdk)
    - Python 3.8+

Usage:
    python deploy_sigma_rules.py --config config.yml --rules-dir ../../rules/sigma
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, Optional

try:
    import splunklib.client as client
    import splunklib.results as results
except ImportError:
    print("[X] Error: splunk-sdk not installed. Run: pip install splunk-sdk")
    sys.exit(1)

try:
    from sigma.cli import SigmaCLI
except ImportError:
    print("[X] Error: sigma-cli not installed. Run: pip install sigma-cli")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class SplunkSigmaDeployer:
    """Deploy Sigma rules to Splunk as saved searches"""

    def __init__(self, host: str, port: int, username: str, password: str):
        """
        Initialize Splunk connection

        Args:
            host: Splunk server hostname/IP
            port: Splunk management port (default 8089)
            username: Splunk admin username
            password: Splunk admin password
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.service = None

    def connect(self) -> bool:
        """
        Connect to Splunk instance

        Returns:
            bool: True if connection successful
        """
        try:
            logger.info(f"Connecting to Splunk at {self.host}:{self.port}")
            self.service = client.connect(
                host=self.host, port=self.port, username=self.username, password=self.password
            )
            logger.info(f"[OK] Connected to Splunk (version {self.service.info['version']})")
            return True
        except Exception as e:
            logger.error(f"[X] Failed to connect to Splunk: {e}")
            return False

    def convert_sigma_to_spl(self, sigma_file: Path) -> Optional[Dict]:
        """
        Convert Sigma rule to Splunk SPL format

        Args:
            sigma_file: Path to Sigma YAML file

        Returns:
            dict: Converted rule metadata and SPL query
        """
        try:
            # Use sigma-cli to convert
            import subprocess

            result = subprocess.run(
                ["sigma", "convert", "-t", "splunk", str(sigma_file)],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                logger.error(f"[X] Failed to convert {sigma_file.name}: {result.stderr}")
                return None

            spl_query = result.stdout.strip()

            # Parse Sigma file for metadata
            import yaml

            with open(sigma_file, "r") as f:
                sigma_rule = yaml.safe_load(f)

            return {
                "title": sigma_rule.get("title", sigma_file.stem),
                "id": sigma_rule.get("id", ""),
                "description": sigma_rule.get("description", ""),
                "level": sigma_rule.get("level", "medium"),
                "query": spl_query,
                "tags": sigma_rule.get("tags", []),
                "falsepositives": sigma_rule.get("falsepositives", []),
            }

        except Exception as e:
            logger.error(f"[X] Error converting {sigma_file.name}: {e}")
            return None

    def create_saved_search(self, rule: Dict, app: str = "search") -> bool:
        """
        Create saved search in Splunk from converted rule

        Args:
            rule: Converted rule dictionary
            app: Splunk app to deploy to (default: search)

        Returns:
            bool: True if creation successful
        """
        try:
            search_name = f"Sigma - {rule['title']}"

            # Check if search already exists
            if search_name in self.service.saved_searches:
                logger.warning(f"[!] Saved search '{search_name}' already exists, updating...")
                saved_search = self.service.saved_searches[search_name]
                saved_search.update(search=rule["query"])
            else:
                # Determine alert severity
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "informational": "info",
                }
                severity = severity_map.get(rule["level"], "medium")

                # Create saved search
                saved_search = self.service.saved_searches.create(
                    search_name,
                    search=rule["query"],
                    **{
                        "description": rule["description"],
                        "is_scheduled": True,
                        "cron_schedule": "*/15 * * * *",  # Every 15 minutes
                        "dispatch.earliest_time": "-15m",
                        "dispatch.latest_time": "now",
                        "alert_type": "always",
                        "alert_severity": severity,
                        "alert.track": True,
                        "alert.digest_mode": True,
                        "actions": "email",
                        "action.email.to": "security@example.com",  # Update this
                        "action.email.subject": f'Sigma Alert: {rule["title"]}',
                    },
                )
                logger.info(f"[+] Created saved search: {search_name}")

            return True

        except Exception as e:
            logger.error(f"[X] Failed to create saved search: {e}")
            return False

    def deploy_rules(self, rules_dir: Path, app: str = "search") -> Dict:
        """
        Deploy all Sigma rules from directory to Splunk

        Args:
            rules_dir: Directory containing Sigma rules
            app: Splunk app to deploy to

        Returns:
            dict: Deployment statistics
        """
        stats = {"total": 0, "converted": 0, "deployed": 0, "failed": 0}

        # Find all Sigma rule files
        sigma_files = list(rules_dir.rglob("*.yml"))
        stats["total"] = len(sigma_files)

        logger.info(f"Found {stats['total']} Sigma rule files")

        for sigma_file in sigma_files:
            logger.info(f"Processing: {sigma_file.name}")

            # Convert rule
            rule = self.convert_sigma_to_spl(sigma_file)
            if not rule:
                stats["failed"] += 1
                continue

            stats["converted"] += 1

            # Deploy to Splunk
            if self.create_saved_search(rule, app):
                stats["deployed"] += 1
            else:
                stats["failed"] += 1

        return stats


def load_config(config_file: Path) -> Dict:
    """Load configuration from YAML file"""
    import yaml

    try:
        with open(config_file, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"[X] Failed to load config: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Deploy Sigma rules to Splunk as saved searches")
    parser.add_argument(
        "--config", type=Path, default="splunk_config.yml", help="Path to Splunk configuration file"
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default="../../../rules/sigma",
        help="Directory containing Sigma rules",
    )
    parser.add_argument("--app", default="search", help="Splunk app to deploy to (default: search)")
    parser.add_argument(
        "--dry-run", action="store_true", help="Convert rules but do not deploy to Splunk"
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    splunk_config = config.get("splunk", {})

    if not args.dry_run:
        # Initialize deployer
        deployer = SplunkSigmaDeployer(
            host=splunk_config.get("host", "localhost"),
            port=splunk_config.get("port", 8089),
            username=splunk_config.get("username", "admin"),
            password=splunk_config.get("password", ""),
        )

        # Connect to Splunk
        if not deployer.connect():
            logger.error("[X] Failed to connect to Splunk. Exiting.")
            sys.exit(1)

        # Deploy rules
        logger.info("Starting rule deployment...")
        stats = deployer.deploy_rules(args.rules_dir, args.app)

        # Print summary
        logger.info("\n" + "=" * 50)
        logger.info("Deployment Summary:")
        logger.info(f"  Total rules: {stats['total']}")
        logger.info(f"  Converted: {stats['converted']}")
        logger.info(f"  Deployed: {stats['deployed']}")
        logger.info(f"  Failed: {stats['failed']}")
        logger.info("=" * 50)

        if stats["deployed"] > 0:
            logger.info(f"\n[OK] Successfully deployed {stats['deployed']} rules to Splunk")
            logger.info("[i] View in Splunk: Settings > Searches, reports, and alerts")

    else:
        # Dry-run mode: convert rules and display results without deployment
        logger.info("[i] Dry run mode - rules will be converted but not deployed")
        dry_run_convert(args.rules_dir)


def dry_run_convert(rules_dir: Path) -> Dict:
    """
    Convert all Sigma rules to SPL format without deploying.

    Args:
        rules_dir: Directory containing Sigma rules

    Returns:
        dict: Conversion statistics and results
    """
    import subprocess

    import yaml

    stats = {"total": 0, "converted": 0, "failed": 0, "rules": []}

    sigma_files = list(rules_dir.rglob("*.yml"))
    stats["total"] = len(sigma_files)

    logger.info(f"Found {stats['total']} Sigma rule files for dry-run conversion")
    logger.info("=" * 60)

    for sigma_file in sigma_files:
        try:
            # Parse Sigma file for metadata
            with open(sigma_file, "r", encoding="utf-8") as f:
                sigma_rule = yaml.safe_load(f)

            title = sigma_rule.get("title", sigma_file.stem)
            rule_id = sigma_rule.get("id", "N/A")
            level = sigma_rule.get("level", "medium")

            # Convert to SPL using sigma-cli
            result = subprocess.run(
                ["sigma", "convert", "-t", "splunk", str(sigma_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                spl_query = result.stdout.strip()
                stats["converted"] += 1

                rule_info = {
                    "file": sigma_file.name,
                    "title": title,
                    "id": rule_id,
                    "level": level,
                    "spl": spl_query,
                    "status": "OK",
                }
                stats["rules"].append(rule_info)

                # Display converted rule
                logger.info(f"\n[+] {title}")
                logger.info(f"    File: {sigma_file.name}")
                logger.info(f"    ID: {rule_id}")
                logger.info(f"    Level: {level}")
                logger.info(f"    SPL Query:")
                # Truncate long queries for display
                display_query = spl_query[:200] + "..." if len(spl_query) > 200 else spl_query
                logger.info(f"    {display_query}")

            else:
                stats["failed"] += 1
                error_msg = result.stderr.strip() or "Unknown conversion error"
                stats["rules"].append(
                    {
                        "file": sigma_file.name,
                        "title": title,
                        "status": "FAILED",
                        "error": error_msg,
                    }
                )
                logger.error(f"\n[X] Failed: {title}")
                logger.error(f"    Error: {error_msg}")

        except subprocess.TimeoutExpired:
            stats["failed"] += 1
            logger.error(f"\n[X] Timeout converting: {sigma_file.name}")
        except Exception as e:
            stats["failed"] += 1
            logger.error(f"\n[X] Error processing {sigma_file.name}: {e}")

    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("Dry Run Conversion Summary:")
    logger.info(f"  Total rules:     {stats['total']}")
    logger.info(f"  Converted:       {stats['converted']}")
    logger.info(f"  Failed:          {stats['failed']}")
    logger.info(f"  Success rate:    {stats['converted']/max(stats['total'], 1)*100:.1f}%")
    logger.info("=" * 60)

    if stats["converted"] > 0:
        logger.info("\n[i] To deploy these rules, run without --dry-run flag")
        logger.info("[i] Example: python deploy_sigma_rules.py --config config.yml")

    return stats


if __name__ == "__main__":
    main()
