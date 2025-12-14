#!/usr/bin/env python3
"""
Azure Sentinel Sigma Rule Deployment Script
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Converts Sigma detection rules to KQL format and deploys them as
    Scheduled Analytics Rules in Azure Sentinel.

Requirements:
    - sigma-cli (pip install sigma-cli)
    - azure-mgmt-securityinsight (pip install azure-mgmt-securityinsight)
    - azure-identity (pip install azure-identity)
    - Python 3.8+

Usage:
    python deploy_sigma_rules.py --config sentinel_config.yml --rules-dir ../../rules/sigma
"""

import argparse
import logging
import sys
import uuid
from pathlib import Path
from typing import Dict, Optional

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.securityinsight import SecurityInsights
    from azure.mgmt.securityinsight.models import ScheduledAlertRule
except ImportError:
    print(
        "[X] Error: Azure SDK not installed. Run: pip install azure-mgmt-securityinsight azure-identity"
    )
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class SentinelSigmaDeployer:
    """Deploy Sigma rules to Azure Sentinel as analytics rules"""

    def __init__(self, subscription_id: str, resource_group: str, workspace_name: str):
        """
        Initialize Azure Sentinel connection

        Args:
            subscription_id: Azure subscription ID
            resource_group: Resource group name
            workspace_name: Log Analytics workspace name
        """
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.client = None

    def connect(self) -> bool:
        """
        Connect to Azure Sentinel

        Returns:
            bool: True if connection successful
        """
        try:
            logger.info(f"Connecting to Azure Sentinel workspace: {self.workspace_name}")
            credential = DefaultAzureCredential()
            self.client = SecurityInsights(credential, self.subscription_id)
            logger.info("[OK] Connected to Azure Sentinel")
            return True
        except Exception as e:
            logger.error(f"[X] Failed to connect to Azure Sentinel: {e}")
            return False

    def convert_sigma_to_kql(self, sigma_file: Path) -> Optional[Dict]:
        """
        Convert Sigma rule to KQL format

        Args:
            sigma_file: Path to Sigma YAML file

        Returns:
            dict: Converted rule metadata and KQL query
        """
        try:
            # Use sigma-cli to convert
            import subprocess

            result = subprocess.run(
                ["sigma", "convert", "-t", "azure-sentinel", str(sigma_file)],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                logger.error(f"[X] Failed to convert {sigma_file.name}: {result.stderr}")
                return None

            kql_query = result.stdout.strip()

            # Parse Sigma file for metadata
            import yaml

            with open(sigma_file, "r") as f:
                sigma_rule = yaml.safe_load(f)

            # Map Sigma level to Sentinel severity
            severity_map = {
                "critical": "High",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Informational",
            }

            # Extract MITRE ATT&CK tactics
            tactics = []
            for tag in sigma_rule.get("tags", []):
                if tag.startswith("attack."):
                    tactic = tag.replace("attack.", "").replace("_", " ").title()
                    tactics.append(tactic)

            return {
                "title": sigma_rule.get("title", sigma_file.stem),
                "id": sigma_rule.get("id", str(uuid.uuid4())),
                "description": sigma_rule.get("description", ""),
                "severity": severity_map.get(sigma_rule.get("level", "medium"), "Medium"),
                "query": kql_query,
                "tactics": list(set(tactics)),
                "tags": sigma_rule.get("tags", []),
                "references": sigma_rule.get("references", []),
            }

        except Exception as e:
            logger.error(f"[X] Error converting {sigma_file.name}: {e}")
            return None

    def create_analytics_rule(self, rule: Dict) -> bool:
        """
        Create Scheduled Analytics Rule in Azure Sentinel

        Args:
            rule: Converted rule dictionary

        Returns:
            bool: True if creation successful
        """
        try:
            rule_name = f"Sigma - {rule['title']}"
            rule_id = str(uuid.uuid4())

            # Check if rule exists
            try:
                existing_rule = self.client.alert_rules.get(
                    self.resource_group, self.workspace_name, rule_id
                )
                logger.warning(f"[!] Rule '{rule_name}' already exists, skipping...")
                return True
            except:
                pass  # Rule doesn't exist, create it

            # Create rule properties
            rule_properties = {
                "displayName": rule_name,
                "description": rule["description"],
                "severity": rule["severity"],
                "enabled": True,
                "query": rule["query"],
                "queryFrequency": "PT15M",  # Run every 15 minutes
                "queryPeriod": "PT15M",  # Look back 15 minutes
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT1H",
                "suppressionEnabled": False,
                "tactics": rule["tactics"],
                "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
                "incidentConfiguration": {
                    "createIncident": True,
                    "groupingConfiguration": {
                        "enabled": False,
                        "reopenClosedIncident": False,
                        "lookbackDuration": "PT5H",
                        "matchingMethod": "AllEntities",
                    },
                },
            }

            # Create the rule
            alert_rule = ScheduledAlertRule(kind="Scheduled", **rule_properties)

            self.client.alert_rules.create_or_update(
                self.resource_group, self.workspace_name, rule_id, alert_rule
            )

            logger.info(f"[+] Created analytics rule: {rule_name}")
            return True

        except Exception as e:
            logger.error(f"[X] Failed to create analytics rule: {e}")
            return False

    def deploy_rules(self, rules_dir: Path) -> Dict:
        """
        Deploy all Sigma rules from directory to Sentinel

        Args:
            rules_dir: Directory containing Sigma rules

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
            rule = self.convert_sigma_to_kql(sigma_file)
            if not rule:
                stats["failed"] += 1
                continue

            stats["converted"] += 1

            # Deploy to Sentinel
            if self.create_analytics_rule(rule):
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
    parser = argparse.ArgumentParser(
        description="Deploy Sigma rules to Azure Sentinel as analytics rules"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default="sentinel_config.yml",
        help="Path to Sentinel configuration file",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default="../../../rules/sigma",
        help="Directory containing Sigma rules",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Convert rules but do not deploy to Sentinel"
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    sentinel_config = config.get("sentinel", {})

    if not args.dry_run:
        # Initialize deployer
        deployer = SentinelSigmaDeployer(
            subscription_id=sentinel_config.get("subscription_id", ""),
            resource_group=sentinel_config.get("resource_group", ""),
            workspace_name=sentinel_config.get("workspace_name", ""),
        )

        # Connect to Sentinel
        if not deployer.connect():
            logger.error("[X] Failed to connect to Azure Sentinel. Exiting.")
            sys.exit(1)

        # Deploy rules
        logger.info("Starting rule deployment...")
        stats = deployer.deploy_rules(args.rules_dir)

        # Print summary
        logger.info("\n" + "=" * 50)
        logger.info("Deployment Summary:")
        logger.info(f"  Total rules: {stats['total']}")
        logger.info(f"  Converted: {stats['converted']}")
        logger.info(f"  Deployed: {stats['deployed']}")
        logger.info(f"  Failed: {stats['failed']}")
        logger.info("=" * 50)

        if stats["deployed"] > 0:
            logger.info(f"\n[OK] Successfully deployed {stats['deployed']} rules to Azure Sentinel")
            logger.info("[i] View in Azure Portal: Sentinel > Analytics > Active rules")

    else:
        logger.info("[i] Dry run mode - rules will be converted but not deployed")


if __name__ == "__main__":
    main()
