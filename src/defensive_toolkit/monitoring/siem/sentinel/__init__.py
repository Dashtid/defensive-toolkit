"""Azure Sentinel integration."""

from defensive_toolkit.monitoring.siem.sentinel.deploy_sigma_rules import (
    deploy_sigma_rules_to_sentinel,
)

__all__ = ["deploy_sigma_rules_to_sentinel"]
