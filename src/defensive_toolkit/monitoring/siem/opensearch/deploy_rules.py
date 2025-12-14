#!/usr/bin/env python3
"""
OpenSearch Security Analytics Rule Deployment

Deploy Sigma detection rules to OpenSearch Security Analytics.

Usage:
    python deploy_rules.py --config opensearch_config.yml
    python deploy_rules.py --dry-run

Requirements:
    pip install opensearch-py pyyaml sigma-cli
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict

import yaml
from opensearchpy import OpenSearch

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class OpenSearchDeployer:
    """Deploy Sigma rules to OpenSearch Security Analytics"""

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.os_config = self.config["opensearch"]
        self.client = self._connect()

    def _load_config(self, config_path: str) -> Dict:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def _connect(self) -> OpenSearch:
        """Connect to OpenSearch cluster"""
        try:
            client = OpenSearch(
                hosts=[{"host": self.os_config["host"], "port": self.os_config["port"]}],
                http_auth=(
                    self.os_config["username"],
                    os.getenv("OPENSEARCH_PASSWORD") or self.os_config.get("password"),
                ),
                use_ssl=self.os_config["protocol"] == "https",
                verify_certs=self.os_config.get("verify_ssl", True),
                timeout=self.os_config.get("timeout", 30),
            )

            # Test connection
            info = client.info()
            logger.info(f"Connected to OpenSearch {info['version']['number']}")
            return client

        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            sys.exit(1)

    def deploy_rules(self, rules_dir: str, dry_run: bool = False) -> Dict:
        """Deploy Sigma rules to OpenSearch"""
        stats = {"total": 0, "deployed": 0, "failed": 0}

        rules_path = Path(rules_dir)
        sigma_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
        stats["total"] = len(sigma_files)

        logger.info(f"Found {stats['total']} Sigma rules to deploy")

        for sigma_file in sigma_files:
            try:
                with open(sigma_file, "r") as f:
                    rule_data = yaml.safe_load(f)

                if dry_run:
                    logger.info(
                        f"[DRY RUN] Would deploy: {rule_data.get('title', sigma_file.name)}"
                    )
                    stats["deployed"] += 1
                else:
                    # TODO: Implement actual OpenSearch Security Analytics API calls
                    # See: https://opensearch.org/docs/latest/security-analytics/api-tools/
                    logger.warning("Full OpenSearch deployment not yet implemented - template only")
                    stats["deployed"] += 1

            except Exception as e:
                logger.error(f"Failed to deploy {sigma_file}: {e}")
                stats["failed"] += 1

        logger.info(f"Deployment complete: {stats['deployed']}/{stats['total']} rules")
        return stats


def main():
    parser = argparse.ArgumentParser(description="Deploy Sigma rules to OpenSearch")
    parser.add_argument("--config", default="opensearch_config.yml", help="Config file path")
    parser.add_argument("--rules-dir", default="../../rules/sigma", help="Rules directory")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    args = parser.parse_args()

    deployer = OpenSearchDeployer(args.config)
    stats = deployer.deploy_rules(args.rules_dir, dry_run=args.dry_run)

    if stats["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
