"""
Linux Security Hardening Scripts

Automated security hardening for Ubuntu/Debian and RHEL/CentOS systems
based on CIS Benchmarks.
"""

__version__ = "1.0.0"

from defensive_toolkit.hardening.linux.cis_benchmarks import (
    HardeningCheck,
    HardeningScanResult,
    LinuxHardeningScanner,
)

__all__ = ["LinuxHardeningScanner", "HardeningCheck", "HardeningScanResult"]
