"""Splunk integration."""

from defensive_toolkit.monitoring.siem.splunk.deploy_sigma_rules import (
    deploy_sigma_rules_to_splunk,
)

__all__ = ["deploy_sigma_rules_to_splunk"]
