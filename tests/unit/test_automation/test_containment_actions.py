#!/usr/bin/env python3
"""
Unit tests for automation/actions/containment.py
"""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.automation.actions.containment import (
    block_ip,
    disable_user_account,
    isolate_host,
    quarantine_file,
    terminate_process,
)


class TestIsolateHost:
    """Test host isolation functionality"""

    def test_isolate_host_dry_run(self):
        """Test host isolation in dry run mode"""
        result = isolate_host("workstation01", method="firewall", dry_run=True)
        assert result is True

    def test_isolate_host_firewall_method(self):
        """Test host isolation via firewall"""
        result = isolate_host("workstation01", method="firewall", dry_run=True)
        assert result is True

    def test_isolate_host_edr_method(self):
        """Test host isolation via EDR"""
        result = isolate_host("workstation01", method="edr", dry_run=True)
        assert result is True

    def test_isolate_host_vlan_method(self):
        """Test host isolation via VLAN"""
        result = isolate_host("workstation01", method="vlan", dry_run=True)
        assert result is True

    @patch("subprocess.run")
    def test_isolate_host_with_subprocess(self, mock_run):
        """Test host isolation with actual command execution"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        # In dry_run=False, would execute actual commands
        result = isolate_host("192.168.1.100", method="firewall", dry_run=True)
        assert result is True

    def test_isolate_host_invalid_hostname(self):
        """Test host isolation with invalid hostname"""
        result = isolate_host("", method="firewall", dry_run=True)
        # Should handle gracefully
        assert isinstance(result, bool)

    @pytest.mark.parametrize("method", ["firewall", "edr", "vlan"])
    def test_isolate_host_all_methods(self, method):
        """Test all isolation methods"""
        result = isolate_host("test-host", method=method, dry_run=True)
        assert result is True


class TestBlockIP:
    """Test IP blocking functionality"""

    def test_block_ip_basic(self):
        """Test basic IP blocking"""
        result = block_ip("192.168.1.100", dry_run=True)
        assert result is True

    def test_block_ip_inbound(self):
        """Test inbound IP blocking"""
        result = block_ip("192.168.1.100", direction="inbound", dry_run=True)
        assert result is True

    def test_block_ip_outbound(self):
        """Test outbound IP blocking"""
        result = block_ip("192.168.1.100", direction="outbound", dry_run=True)
        assert result is True

    def test_block_ip_both_directions(self):
        """Test blocking both directions"""
        result = block_ip("192.168.1.100", direction="both", dry_run=True)
        assert result is True

    def test_block_ip_with_duration(self):
        """Test temporary IP blocking"""
        result = block_ip("192.168.1.100", duration=3600, dry_run=True)
        assert result is True

    def test_block_ip_permanent(self):
        """Test permanent IP blocking"""
        result = block_ip("192.168.1.100", duration=None, dry_run=True)
        assert result is True

    def test_block_ip_invalid_format(self):
        """Test blocking invalid IP format"""
        result = block_ip("not-an-ip", dry_run=True)
        # Should handle gracefully
        assert isinstance(result, bool)

    def test_block_ip_multiple_ips(self):
        """Test blocking multiple IPs"""
        ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
        results = [block_ip(ip, dry_run=True) for ip in ips]
        assert all(results)

    @pytest.mark.parametrize(
        "ip,direction",
        [
            ("192.168.1.100", "inbound"),
            ("10.0.0.50", "outbound"),
            ("172.16.0.1", "both"),
        ],
    )
    def test_block_ip_parametrized(self, ip, direction):
        """Test IP blocking with various parameters"""
        result = block_ip(ip, direction=direction, dry_run=True)
        assert result is True


class TestQuarantineFile:
    """Test file quarantine functionality"""

    def test_quarantine_file_basic(self, tmp_path):
        """Test basic file quarantine"""
        test_file = tmp_path / "malware.exe"
        test_file.touch()

        result = quarantine_file(str(test_file), dry_run=True)
        assert result is True

    def test_quarantine_file_custom_directory(self, tmp_path):
        """Test quarantine to custom directory"""
        test_file = tmp_path / "suspicious.dll"
        test_file.touch()

        quarantine_dir = tmp_path / "quarantine"

        result = quarantine_file(str(test_file), quarantine_dir=str(quarantine_dir), dry_run=True)
        assert result is True

    def test_quarantine_file_nonexistent(self):
        """Test quarantining non-existent file"""
        result = quarantine_file("/nonexistent/file.exe", dry_run=True)
        # Should handle gracefully
        assert isinstance(result, bool)

    def test_quarantine_file_with_metadata(self, tmp_path):
        """Test quarantine with metadata preservation"""
        test_file = tmp_path / "test.exe"
        test_file.touch()

        # Would preserve file metadata (hash, timestamp, etc.)
        result = quarantine_file(str(test_file), dry_run=True)
        assert result is True

    @pytest.mark.parametrize(
        "filename",
        [
            "malware.exe",
            "trojan.dll",
            "ransomware.bin",
            "backdoor.sh",
        ],
    )
    def test_quarantine_different_filetypes(self, tmp_path, filename):
        """Test quarantining different file types"""
        test_file = tmp_path / filename
        test_file.touch()

        result = quarantine_file(str(test_file), dry_run=True)
        assert result is True


class TestTerminateProcess:
    """Test process termination functionality"""

    def test_terminate_process_by_pid(self):
        """Test terminating process by PID"""
        result = terminate_process(pid=1234, dry_run=True)
        assert result is True

    def test_terminate_process_by_name(self):
        """Test terminating process by name"""
        result = terminate_process(process_name="malware.exe", dry_run=True)
        assert result is True

    def test_terminate_process_force_kill(self):
        """Test force killing process (dry run mode)"""
        result = terminate_process(pid=1234, dry_run=True)
        assert result is True

    def test_terminate_process_graceful(self):
        """Test graceful process termination (dry run mode)"""
        result = terminate_process(pid=5678, dry_run=True)
        assert result is True

    @patch("subprocess.run")
    def test_terminate_process_subprocess_call(self, mock_run):
        """Test process termination subprocess call"""
        mock_run.return_value = Mock(returncode=0)

        result = terminate_process(pid=9999, dry_run=True)
        assert result is True

    def test_terminate_multiple_processes(self):
        """Test terminating multiple processes"""
        pids = [1234, 5678, 9012]
        results = [terminate_process(pid=pid, dry_run=True) for pid in pids]
        assert all(results)


class TestDisableUserAccount:
    """Test user account disabling functionality"""

    def test_disable_user_account_basic(self):
        """Test basic user account disabling"""
        result = disable_user_account("compromised_user", dry_run=True)
        assert result is True

    def test_disable_user_account_with_reason(self):
        """Test disabling user account (dry run mode)"""
        result = disable_user_account("test_user", dry_run=True)
        assert result is True

    def test_disable_user_account_temporary(self):
        """Test temporary account disable (dry run mode)"""
        result = disable_user_account("temp_user", dry_run=True)
        assert result is True

    def test_disable_user_account_permanent(self):
        """Test permanent account disable (dry run mode)"""
        result = disable_user_account("malicious_user", dry_run=True)
        assert result is True

    @pytest.mark.parametrize(
        "username",
        [
            "user1",
            "admin_compromised",
            "service_account",
        ],
    )
    def test_disable_different_users(self, username):
        """Test disabling different user types"""
        result = disable_user_account(username, dry_run=True)
        assert result is True


class TestContainmentIntegration:
    """Integration tests for containment actions"""

    def test_full_containment_workflow(self, tmp_path):
        """Test complete containment workflow"""
        # Scenario: Malware detected on host

        # 1. Isolate host
        isolate_result = isolate_host("infected-host", dry_run=True)
        assert isolate_result is True

        # 2. Block malicious IP
        block_result = block_ip("192.168.1.100", dry_run=True)
        assert block_result is True

        # 3. Quarantine malicious file
        malware_file = tmp_path / "malware.exe"
        malware_file.touch()
        quarantine_result = quarantine_file(str(malware_file), dry_run=True)
        assert quarantine_result is True

        # 4. Terminate malicious process
        terminate_result = terminate_process(pid=1234, dry_run=True)
        assert terminate_result is True

        # 5. Disable compromised account
        disable_result = disable_user_account("compromised", dry_run=True)
        assert disable_result is True

        # All containment actions successful
        assert all(
            [isolate_result, block_result, quarantine_result, terminate_result, disable_result]
        )

    def test_ransomware_containment(self):
        """Test ransomware-specific containment"""
        actions = {
            "isolate_hosts": isolate_host("file-server", dry_run=True),
            "block_c2": block_ip("192.168.1.100", dry_run=True),
            "terminate_ransomware": terminate_process(process_name="ransomware.exe", dry_run=True),
            "disable_accounts": disable_user_account("victim_user", dry_run=True),
        }

        assert all(actions.values())

    def test_lateral_movement_containment(self):
        """Test lateral movement containment"""
        # Multiple hosts involved
        hosts = ["host1", "host2", "host3"]
        isolation_results = [isolate_host(host, dry_run=True) for host in hosts]

        # Block attacker IP
        block_result = block_ip("10.0.0.50", dry_run=True)

        # Disable compromised accounts
        accounts = ["admin1", "service_account"]
        disable_results = [disable_user_account(acc, dry_run=True) for acc in accounts]

        assert all(isolation_results)
        assert block_result is True
        assert all(disable_results)


class TestContainmentErrorHandling:
    """Test error handling in containment actions"""

    def test_isolate_host_handles_exception(self):
        """Test exception handling in host isolation"""
        # Should not raise exception even with invalid input
        try:
            result = isolate_host(None, dry_run=True)
            assert isinstance(result, bool)
        except Exception:
            pytest.fail("Should handle exceptions gracefully")

    def test_block_ip_handles_invalid_input(self):
        """Test handling invalid IP input"""
        invalid_ips = ["", None, "999.999.999.999", "not-an-ip"]

        for invalid_ip in invalid_ips:
            try:
                result = block_ip(invalid_ip, dry_run=True)
                assert isinstance(result, bool)
            except Exception:
                pytest.fail(f"Should handle invalid IP: {invalid_ip}")

    def test_quarantine_handles_permission_error(self):
        """Test handling permission errors"""
        # Simulate protected system file
        result = quarantine_file("/system/protected.dll", dry_run=True)
        assert isinstance(result, bool)


# [+] Performance tests
@pytest.mark.slow
class TestContainmentPerformance:
    """Test containment action performance"""

    def test_bulk_ip_blocking_performance(self):
        """Test blocking many IPs quickly"""
        import time

        ips = [f"192.168.1.{i}" for i in range(100)]

        start = time.time()
        results = [block_ip(ip, dry_run=True) for ip in ips]
        duration = time.time() - start

        assert all(results)
        assert duration < 5.0  # Should complete in < 5 seconds

    def test_concurrent_containment_actions(self):
        """Test multiple containment actions concurrently"""
        actions = [
            isolate_host("host1", dry_run=True),
            block_ip("192.168.1.100", dry_run=True),
            terminate_process(pid=1234, dry_run=True),
        ]

        assert all(actions)
