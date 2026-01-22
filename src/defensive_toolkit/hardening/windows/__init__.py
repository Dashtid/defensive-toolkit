"""Windows Security Hardening Scanner.

Provides CIS Benchmark and Microsoft Security Baseline compliance checking
for Windows systems.
"""

from defensive_toolkit.hardening.linux.cis_benchmarks import (
    HardeningCheck,
    HardeningScanResult,
)
from defensive_toolkit.hardening.windows.cis_benchmarks import WindowsHardeningScanner

__all__ = ["WindowsHardeningScanner", "HardeningCheck", "HardeningScanResult"]
