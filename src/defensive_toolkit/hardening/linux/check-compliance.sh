#!/bin/bash
#
# CIS Compliance Checker
# Automated compliance checking against CIS Benchmarks
#

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "Must run as root"; exit 1; }

echo "======================================================================"
echo "  CIS Compliance Checker"
echo "======================================================================"
echo ""

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "[*] OS: $PRETTY_NAME"
fi

# Check if Lynis is installed (recommended for comprehensive auditing)
if command -v lynis &>/dev/null; then
    echo "[*] Running Lynis security audit..."
    lynis audit system --quick --quiet
else
    echo "[!] Lynis not installed. Install for comprehensive auditing:"
    echo "    Ubuntu/Debian: apt-get install lynis"
    echo "    RHEL/CentOS: yum install lynis"
    echo ""
    echo "[*] Running basic compliance checks..."

    # Run basic audit script
    ./audit-security-posture.sh
fi

echo ""
echo "======================================================================"
echo "[*] For SCAP-compliant scanning, use OpenSCAP:"
echo "    Ubuntu: oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis ..."
echo "    RHEL: oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis ..."
echo "======================================================================"
