#!/usr/bin/env python3
"""
OpenSearch Security Analytics Rule Deployment

Deploy Sigma detection rules to OpenSearch Security Analytics.

This module provides functionality to:
- Convert Sigma rules to OpenSearch Security Analytics format
- Deploy rules via the Security Analytics Rule API
- Create detectors for deployed rules
- Support dry-run mode for validation

Usage:
    python deploy_rules.py --config opensearch_config.yml
    python deploy_rules.py --dry-run
    python deploy_rules.py --rules-dir ../../rules/sigma --category windows

Requirements:
    pip install opensearch-py pyyaml sigma-cli

API Reference:
    https://docs.opensearch.org/latest/security-analytics/api-tools/rule-api/
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from opensearchpy import OpenSearch
from opensearchpy.exceptions import RequestError

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Mapping from Sigma logsource to OpenSearch Security Analytics categories
LOGSOURCE_TO_CATEGORY = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "aws": "cloudtrail",
    "azure": "azure",
    "gcp": "gcp",
    "kubernetes": "kubernetes",
    "network": "network",
    "apache": "apache_access",
    "dns": "dns",
    "webserver": "apache_access",
    "firewall": "network",
    "proxy": "network",
    "antivirus": "windows",
}


class OpenSearchDeployer:
    """Deploy Sigma rules to OpenSearch Security Analytics"""

    SECURITY_ANALYTICS_BASE = "/_plugins/_security_analytics"

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

    def _determine_category(self, rule_data: Dict) -> str:
        """
        Determine OpenSearch Security Analytics category from Sigma rule logsource.

        Args:
            rule_data: Parsed Sigma rule YAML

        Returns:
            str: OpenSearch category (windows, linux, cloudtrail, etc.)
        """
        logsource = rule_data.get("logsource", {})
        product = logsource.get("product", "").lower()
        category = logsource.get("category", "").lower()
        service = logsource.get("service", "").lower()

        # Check product first
        if product in LOGSOURCE_TO_CATEGORY:
            return LOGSOURCE_TO_CATEGORY[product]

        # Check category
        if category in LOGSOURCE_TO_CATEGORY:
            return LOGSOURCE_TO_CATEGORY[category]

        # Check service
        if service in LOGSOURCE_TO_CATEGORY:
            return LOGSOURCE_TO_CATEGORY[service]

        # Check tags for cloud platforms
        tags = rule_data.get("tags", [])
        for tag in tags:
            if "cloud.aws" in tag:
                return "cloudtrail"
            if "cloud.azure" in tag:
                return "azure"
            if "cloud.gcp" in tag:
                return "gcp"
            if "cloud.kubernetes" in tag:
                return "kubernetes"

        # Default to windows if process_creation or similar
        if "process" in category or "sysmon" in category:
            return "windows"

        return "others"

    def _format_sigma_for_opensearch(self, rule_data: Dict, file_path: Path) -> Dict:
        """
        Format Sigma rule for OpenSearch Security Analytics API.

        Args:
            rule_data: Parsed Sigma rule YAML
            file_path: Path to rule file (for reading raw content)

        Returns:
            dict: Formatted rule for API
        """
        # Read raw YAML content
        with open(file_path, "r", encoding="utf-8") as f:
            rule_content = f.read()

        return {
            "rule": rule_content,
            "custom": True,  # Mark as custom rule (not prepackaged)
        }

    def _get_existing_rule(self, rule_id: str, category: str) -> Optional[Dict]:
        """
        Check if a rule already exists in OpenSearch.

        Args:
            rule_id: Sigma rule ID (UUID)
            category: Rule category

        Returns:
            dict: Existing rule data or None
        """
        try:
            # Search for rule by ID
            search_body = {"query": {"match": {"_id": rule_id}}}

            response = self.client.transport.perform_request(
                "POST",
                f"{self.SECURITY_ANALYTICS_BASE}/rules/_search?pre_packaged=false",
                body=search_body,
            )

            hits = response.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]
            return None

        except Exception:
            return None

    def create_rule(self, rule_data: Dict, file_path: Path, category: str) -> Dict[str, Any]:
        """
        Create a detection rule in OpenSearch Security Analytics.

        API: POST /_plugins/_security_analytics/rules?category=<category>

        Args:
            rule_data: Parsed Sigma rule
            file_path: Path to rule file
            category: Rule category

        Returns:
            dict: API response with rule ID
        """
        formatted_rule = self._format_sigma_for_opensearch(rule_data, file_path)

        try:
            response = self.client.transport.perform_request(
                "POST",
                f"{self.SECURITY_ANALYTICS_BASE}/rules?category={category}",
                body=formatted_rule,
            )

            rule_id = response.get("_id", "unknown")
            logger.info(f"[+] Created rule: {rule_data.get('title')} (ID: {rule_id})")
            return {"success": True, "rule_id": rule_id, "action": "created"}

        except RequestError as e:
            error_msg = str(e)
            if "already exists" in error_msg.lower():
                return self.update_rule(rule_data, file_path, category)
            logger.error(f"[X] Failed to create rule: {error_msg}")
            return {"success": False, "error": error_msg}

        except Exception as e:
            logger.error(f"[X] Failed to create rule: {e}")
            return {"success": False, "error": str(e)}

    def update_rule(self, rule_data: Dict, file_path: Path, category: str) -> Dict[str, Any]:
        """
        Update an existing detection rule in OpenSearch Security Analytics.

        API: PUT /_plugins/_security_analytics/rules/<rule_id>?category=<category>&forced=true

        Args:
            rule_data: Parsed Sigma rule
            file_path: Path to rule file
            category: Rule category

        Returns:
            dict: API response
        """
        rule_id = rule_data.get("id")
        if not rule_id:
            return {"success": False, "error": "Rule has no ID for update"}

        formatted_rule = self._format_sigma_for_opensearch(rule_data, file_path)

        try:
            response = self.client.transport.perform_request(
                "PUT",
                f"{self.SECURITY_ANALYTICS_BASE}/rules/{rule_id}?category={category}&forced=true",
                body=formatted_rule,
            )

            logger.info(f"[~] Updated rule: {rule_data.get('title')} (ID: {rule_id})")
            return {"success": True, "rule_id": rule_id, "action": "updated"}

        except Exception as e:
            logger.error(f"[X] Failed to update rule {rule_id}: {e}")
            return {"success": False, "error": str(e)}

    def list_rules(self, category: str = None, prepackaged: bool = False) -> List[Dict]:
        """
        List existing rules in OpenSearch Security Analytics.

        API: GET /_plugins/_security_analytics/rules/_search

        Args:
            category: Filter by category (optional)
            prepackaged: Include prepackaged rules (default False)

        Returns:
            list: List of rules
        """
        try:
            search_body = {"query": {"match_all": {}}, "size": 1000}

            pre_packaged_param = "true" if prepackaged else "false"
            endpoint = f"{self.SECURITY_ANALYTICS_BASE}/rules/_search?pre_packaged={pre_packaged_param}"

            response = self.client.transport.perform_request("POST", endpoint, body=search_body)

            hits = response.get("hits", {}).get("hits", [])
            rules = [hit.get("_source", {}) for hit in hits]

            if category:
                rules = [r for r in rules if r.get("category") == category]

            return rules

        except Exception as e:
            logger.error(f"Failed to list rules: {e}")
            return []

    def deploy_rules(
        self, rules_dir: str, dry_run: bool = False, category_override: str = None
    ) -> Dict:
        """
        Deploy Sigma rules to OpenSearch Security Analytics.

        Args:
            rules_dir: Directory containing Sigma rules
            dry_run: If True, validate without deploying
            category_override: Force all rules to this category

        Returns:
            dict: Deployment statistics
        """
        stats = {
            "total": 0,
            "deployed": 0,
            "updated": 0,
            "failed": 0,
            "skipped": 0,
            "rules": [],
        }

        rules_path = Path(rules_dir)
        sigma_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
        stats["total"] = len(sigma_files)

        logger.info(f"Found {stats['total']} Sigma rules to deploy")
        logger.info("=" * 60)

        for sigma_file in sigma_files:
            try:
                with open(sigma_file, "r", encoding="utf-8") as f:
                    rule_data = yaml.safe_load(f)

                title = rule_data.get("title", sigma_file.name)
                rule_id = rule_data.get("id", "N/A")

                # Determine category
                category = category_override or self._determine_category(rule_data)

                if dry_run:
                    logger.info(f"[DRY RUN] Would deploy: {title}")
                    logger.info(f"          Category: {category}")
                    logger.info(f"          ID: {rule_id}")
                    stats["deployed"] += 1
                    stats["rules"].append(
                        {
                            "file": sigma_file.name,
                            "title": title,
                            "category": category,
                            "status": "dry_run",
                        }
                    )
                else:
                    # Deploy to OpenSearch
                    result = self.create_rule(rule_data, sigma_file, category)

                    if result.get("success"):
                        if result.get("action") == "updated":
                            stats["updated"] += 1
                        else:
                            stats["deployed"] += 1
                        stats["rules"].append(
                            {
                                "file": sigma_file.name,
                                "title": title,
                                "category": category,
                                "rule_id": result.get("rule_id"),
                                "status": result.get("action"),
                            }
                        )
                    else:
                        stats["failed"] += 1
                        stats["rules"].append(
                            {
                                "file": sigma_file.name,
                                "title": title,
                                "status": "failed",
                                "error": result.get("error"),
                            }
                        )

            except Exception as e:
                logger.error(f"[X] Failed to process {sigma_file}: {e}")
                stats["failed"] += 1
                stats["rules"].append(
                    {"file": sigma_file.name, "status": "failed", "error": str(e)}
                )

        # Print summary
        logger.info("\n" + "=" * 60)
        logger.info("Deployment Summary:")
        logger.info(f"  Total rules:    {stats['total']}")
        logger.info(f"  Created:        {stats['deployed']}")
        logger.info(f"  Updated:        {stats['updated']}")
        logger.info(f"  Failed:         {stats['failed']}")
        logger.info(f"  Skipped:        {stats['skipped']}")
        logger.info("=" * 60)

        return stats


def main():
    parser = argparse.ArgumentParser(
        description="Deploy Sigma rules to OpenSearch Security Analytics"
    )
    parser.add_argument("--config", default="opensearch_config.yml", help="Config file path")
    parser.add_argument("--rules-dir", default="../../rules/sigma", help="Rules directory")
    parser.add_argument("--dry-run", action="store_true", help="Validate without deploying")
    parser.add_argument(
        "--category",
        help="Override category for all rules (windows, linux, cloudtrail, etc.)",
    )
    parser.add_argument("--list", action="store_true", help="List existing custom rules")
    args = parser.parse_args()

    deployer = OpenSearchDeployer(args.config)

    if args.list:
        rules = deployer.list_rules()
        logger.info(f"Found {len(rules)} custom rules:")
        for rule in rules:
            logger.info(f"  - {rule.get('title', 'Unknown')} ({rule.get('category', 'N/A')})")
        return

    stats = deployer.deploy_rules(
        args.rules_dir, dry_run=args.dry_run, category_override=args.category
    )

    if stats["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
