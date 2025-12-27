"""Wazuh integration."""

from defensive_toolkit.monitoring.siem.wazuh.deploy_rules import (
    deploy_rules_to_wazuh,
)

__all__ = ["deploy_rules_to_wazuh"]
