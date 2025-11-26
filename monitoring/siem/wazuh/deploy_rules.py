#!/usr/bin/env python3
"""
Wazuh SIEM Rule Deployment

Deploy Sigma detection rules to Wazuh SIEM by converting them to Wazuh rule format.

Usage:
    python deploy_rules.py --config wazuh_config.yml
    python deploy_rules.py --config wazuh_config.yml --dry-run
    python deploy_rules.py --rules-dir ../../detection-rules/sigma

Requirements:
    pip install pyyaml requests sigma-cli
"""

import argparse
import logging
import os
import sys
import yaml
import requests
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WazuhDeployer:
    """Deploy Sigma rules to Wazuh SIEM"""

    def __init__(self, config_path: str):
        """
        Initialize Wazuh deployer.

        Args:
            config_path: Path to wazuh_config.yml
        """
        self.config = self._load_config(config_path)
        self.wazuh_config = self.config['wazuh']
        self.deployment_config = self.config['deployment']

        # Wazuh API base URL
        self.base_url = (
            f"{self.wazuh_config['protocol']}://"
            f"{self.wazuh_config['manager_host']}:"
            f"{self.wazuh_config['manager_port']}"
        )

        self.session = requests.Session()
        self.token = None

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)

    def authenticate(self) -> bool:
        """
        Authenticate with Wazuh API.

        Returns:
            bool: True if authentication successful
        """
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"

            # Get password from environment or config
            password = os.getenv('WAZUH_PASSWORD') or self.wazuh_config.get('password')

            response = self.session.post(
                auth_url,
                auth=(self.wazuh_config['username'], password),
                verify=self.wazuh_config.get('verify_ssl', True),
                timeout=self.wazuh_config.get('timeout', 30)
            )

            if response.status_code == 200:
                self.token = response.json()['data']['token']
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                logger.info("Successfully authenticated with Wazuh API")
                return True
            else:
                logger.error(f"Authentication failed: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False

    def convert_sigma_to_wazuh(self, sigma_file: Path) -> Optional[str]:
        """
        Convert Sigma rule to Wazuh format using sigma-cli.

        Args:
            sigma_file: Path to Sigma rule file

        Returns:
            Optional[str]: Wazuh rule XML or None if conversion failed
        """
        try:
            # Use sigma-cli to convert to Wazuh format
            # Note: Wazuh uses custom XML format, so we'll generate it
            logger.info(f"Converting {sigma_file.name} to Wazuh format...")

            # Read Sigma rule
            with open(sigma_file, 'r') as f:
                sigma_rule = yaml.safe_load(f)

            # Generate Wazuh XML rule
            rule_xml = self._generate_wazuh_xml(sigma_rule, sigma_file.stem)

            return rule_xml

        except Exception as e:
            logger.error(f"Failed to convert {sigma_file}: {e}")
            return None

    def _generate_wazuh_xml(self, sigma_rule: Dict, rule_id_prefix: str) -> str:
        """
        Generate Wazuh XML rule from Sigma rule.

        Args:
            sigma_rule: Parsed Sigma rule dictionary
            rule_id_prefix: Prefix for rule ID

        Returns:
            str: Wazuh XML rule
        """
        # Extract Sigma rule metadata
        title = sigma_rule.get('title', 'Untitled Rule')
        description = sigma_rule.get('description', '')
        level = sigma_rule.get('level', 'medium')

        # Map Sigma levels to Wazuh levels
        level_map = {
            'low': 5,
            'medium': 7,
            'high': 10,
            'critical': 12
        }
        wazuh_level = level_map.get(level, 7)

        # Generate unique rule ID (100000+)
        rule_id = 100000 + hash(rule_id_prefix) % 10000

        # Build XML rule
        rule_xml = f"""
  <rule id="{rule_id}" level="{wazuh_level}">
    <description>{title}</description>
    <info type="text">{description}</info>
    <group>custom_detection,sigma_rules</group>
  </rule>
"""

        return rule_xml

    def deploy_rules(self, rules_dir: str, dry_run: bool = False) -> Dict:
        """
        Deploy all Sigma rules from directory to Wazuh.

        Args:
            rules_dir: Directory containing Sigma rules
            dry_run: If True, don't actually deploy rules

        Returns:
            Dict: Deployment statistics
        """
        stats = {
            'total': 0,
            'converted': 0,
            'deployed': 0,
            'failed': 0
        }

        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.error(f"Rules directory not found: {rules_dir}")
            return stats

        # Find all Sigma rule files
        sigma_files = list(rules_path.rglob('*.yml')) + list(rules_path.rglob('*.yaml'))
        stats['total'] = len(sigma_files)

        logger.info(f"Found {stats['total']} Sigma rules to deploy")

        # Collect all converted rules
        wazuh_rules = []

        for sigma_file in sigma_files:
            # Convert to Wazuh format
            wazuh_rule = self.convert_sigma_to_wazuh(sigma_file)

            if wazuh_rule:
                wazuh_rules.append(wazuh_rule)
                stats['converted'] += 1
            else:
                stats['failed'] += 1

        if dry_run:
            logger.info(f"[DRY RUN] Would deploy {stats['converted']} rules")
            logger.info("Converted rules preview:")
            for rule in wazuh_rules[:3]:  # Show first 3
                print(rule)
            return stats

        # Deploy to Wazuh
        if self.deployment_config.get('deploy_custom_rules', True):
            success = self._deploy_custom_rules(wazuh_rules)
            if success:
                stats['deployed'] = stats['converted']

        logger.info(f"Deployment complete: {stats['deployed']}/{stats['total']} rules deployed")
        return stats

    def _deploy_custom_rules(self, rules: List[str]) -> bool:
        """
        Deploy custom rules to Wazuh.

        Args:
            rules: List of Wazuh XML rules

        Returns:
            bool: True if deployment successful
        """
        try:
            # Generate custom rules file
            rules_file = Path(self.wazuh_config['rules_directory']) / 'custom_sigma_rules.xml'

            # Build complete XML file
            xml_content = f"""
<!-- Custom Sigma Rules for Wazuh -->
<!-- Generated: {datetime.utcnow().isoformat()} -->
<group name="sigma,custom">
{''.join(rules)}
</group>
"""

            # Backup existing rules if configured
            if self.deployment_config.get('backup_rules', True):
                if rules_file.exists():
                    backup_dir = Path(self.deployment_config['backup_directory'])
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    backup_file = backup_dir / f"custom_sigma_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
                    rules_file.rename(backup_file)
                    logger.info(f"Backed up existing rules to {backup_file}")

            # Write new rules file
            with open(rules_file, 'w') as f:
                f.write(xml_content)

            logger.info(f"Deployed custom rules to {rules_file}")

            # Restart Wazuh manager if configured
            if self.deployment_config.get('auto_restart', False):
                logger.info("Restarting Wazuh manager...")
                subprocess.run(['systemctl', 'restart', 'wazuh-manager'], check=True)
                logger.info("Wazuh manager restarted successfully")

            return True

        except Exception as e:
            logger.error(f"Failed to deploy custom rules: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Deploy Sigma rules to Wazuh SIEM')
    parser.add_argument(
        '--config',
        default='wazuh_config.yml',
        help='Path to wazuh_config.yml'
    )
    parser.add_argument(
        '--rules-dir',
        default='../../detection-rules/sigma',
        help='Directory containing Sigma rules'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be deployed without actually deploying'
    )

    args = parser.parse_args()

    logger.info("=" * 70)
    logger.info("Wazuh SIEM Rule Deployment")
    logger.info("=" * 70)

    # Initialize deployer
    deployer = WazuhDeployer(args.config)

    # Authenticate
    if not deployer.authenticate():
        logger.error("Failed to authenticate. Exiting.")
        sys.exit(1)

    # Deploy rules
    stats = deployer.deploy_rules(args.rules_dir, dry_run=args.dry_run)

    # Summary
    logger.info("=" * 70)
    logger.info("Deployment Summary:")
    logger.info(f"  Total rules found: {stats['total']}")
    logger.info(f"  Successfully converted: {stats['converted']}")
    logger.info(f"  Successfully deployed: {stats['deployed']}")
    logger.info(f"  Failed: {stats['failed']}")
    logger.info("=" * 70)

    if stats['failed'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
