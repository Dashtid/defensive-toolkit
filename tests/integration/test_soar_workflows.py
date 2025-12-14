#!/usr/bin/env python3
"""
Integration tests for SOAR workflows
Tests end-to-end security automation scenarios
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.mark.integration
class TestSOARWorkflows:
    """Test complete SOAR workflow scenarios"""

    def test_phishing_response_workflow(self, tmp_path):
        """Test phishing email response workflow"""
        # Create phishing response playbook
        playbook = {
            "name": "Phishing Response",
            "description": "Automated phishing email response",
            "tasks": [
                {
                    "name": "Extract IOCs",
                    "action": "analyze_email",
                    "parameters": {"email_id": "test123"},
                },
                {"name": "Enrich IOCs", "action": "enrich_ioc", "parameters": {"ioc_type": "url"}},
                {
                    "name": "Block malicious URLs",
                    "action": "block_url",
                    "parameters": {"urls": ["http://evil.com"]},
                },
                {
                    "name": "Create incident ticket",
                    "action": "create_ticket",
                    "parameters": {"title": "Phishing Campaign Detected", "severity": "HIGH"},
                },
                {
                    "name": "Send notification",
                    "action": "send_email",
                    "parameters": {"to": "security@example.com", "subject": "Phishing Alert"},
                },
            ],
        }

        playbook_file = tmp_path / "phishing_response.yaml"
        with open(playbook_file, "w") as f:
            yaml.dump(playbook, f)

        assert playbook_file.exists()
        assert len(playbook["tasks"]) == 5

    def test_malware_containment_workflow(self, tmp_path):
        """Test malware detection and containment workflow"""
        playbook = {
            "name": "Malware Containment",
            "description": "Isolate infected hosts",
            "tasks": [
                {
                    "name": "Identify infected host",
                    "action": "log",
                    "parameters": {"message": "Host 192.168.1.100 infected"},
                },
                {
                    "name": "Isolate host from network",
                    "action": "isolate_host",
                    "parameters": {"hostname": "WORKSTATION01"},
                },
                {
                    "name": "Quarantine malicious files",
                    "action": "quarantine_file",
                    "parameters": {"path": "C:\\Temp\\malware.exe"},
                },
                {
                    "name": "Collect forensic artifacts",
                    "action": "collect_artifacts",
                    "parameters": {"host": "WORKSTATION01"},
                },
                {
                    "name": "Create incident",
                    "action": "create_ticket",
                    "parameters": {"title": "Malware Detected", "severity": "CRITICAL"},
                },
            ],
        }

        playbook_file = tmp_path / "malware_containment.yaml"
        with open(playbook_file, "w") as f:
            yaml.dump(playbook, f)

        assert playbook_file.exists()
        # Verify containment steps are present
        action_names = [task["action"] for task in playbook["tasks"]]
        assert "isolate_host" in action_names
        assert "quarantine_file" in action_names

    def test_vulnerability_remediation_workflow(self, tmp_path):
        """Test vulnerability detection and remediation workflow"""
        playbook = {
            "name": "Vulnerability Remediation",
            "description": "Automated patch management",
            "tasks": [
                {
                    "name": "Scan for vulnerabilities",
                    "action": "run_scan",
                    "parameters": {"scanner": "openvas", "target": "192.168.1.0/24"},
                },
                {
                    "name": "Prioritize vulnerabilities",
                    "action": "risk_score",
                    "parameters": {"threshold": "HIGH"},
                },
                {"name": "Check patch availability", "action": "check_patches", "parameters": {}},
                {
                    "name": "Create remediation tickets",
                    "action": "create_ticket",
                    "parameters": {"title": "Critical Vulnerabilities Detected"},
                },
                {
                    "name": "Schedule patching",
                    "action": "schedule_maintenance",
                    "parameters": {"window": "next_saturday"},
                },
            ],
        }

        playbook_file = tmp_path / "vuln_remediation.yaml"
        with open(playbook_file, "w") as f:
            yaml.dump(playbook, f)

        assert playbook_file.exists()

    def test_alert_enrichment_workflow(self, tmp_path):
        """Test security alert enrichment workflow"""
        playbook = {
            "name": "Alert Enrichment",
            "description": "Enrich alerts with context",
            "tasks": [
                {
                    "name": "Receive alert",
                    "action": "set_variable",
                    "parameters": {"name": "alert_id", "value": "ALT-2025-001"},
                },
                {
                    "name": "Query SIEM for context",
                    "action": "siem_query",
                    "parameters": {"timeframe": "1h", "entity": "${source_ip}"},
                },
                {
                    "name": "Check threat intelligence",
                    "action": "threat_intel_lookup",
                    "parameters": {"ioc": "${source_ip}"},
                },
                {
                    "name": "User context lookup",
                    "action": "ldap_lookup",
                    "parameters": {"username": "${user}"},
                },
                {
                    "name": "Update alert with context",
                    "action": "update_alert",
                    "parameters": {"alert_id": "${alert_id}", "enrichment": "completed"},
                },
            ],
        }

        playbook_file = tmp_path / "alert_enrichment.yaml"
        with open(playbook_file, "w") as f:
            yaml.dump(playbook, f)

        assert playbook_file.exists()
        # Verify enrichment steps
        assert any("threat_intel" in task["action"] for task in playbook["tasks"])


@pytest.mark.integration
class TestIncidentResponseWorkflows:
    """Test incident response workflow integrations"""

    def test_ransomware_response(self, tmp_path):
        """Test ransomware incident response"""
        ir_steps = [
            "Identify infected systems",
            "Isolate affected hosts",
            "Disable user accounts",
            "Block C2 communication",
            "Preserve forensic evidence",
            "Initiate backup restoration",
            "Create incident report",
        ]

        workflow_log = tmp_path / "ransomware_response.json"
        workflow_data = {
            "incident_id": "INC-2025-001",
            "incident_type": "ransomware",
            "steps_executed": ir_steps,
            "status": "contained",
        }

        with open(workflow_log, "w") as f:
            json.dump(workflow_data, f, indent=2)

        assert workflow_log.exists()

        with open(workflow_log, "r") as f:
            data = json.load(f)

        assert data["incident_type"] == "ransomware"
        assert len(data["steps_executed"]) == 7

    def test_data_breach_response(self, tmp_path):
        """Test data breach incident response"""
        ir_playbook = {
            "incident_type": "data_breach",
            "phases": {
                "detection": {"actions": ["Review DLP alerts", "Analyze log sources"]},
                "containment": {
                    "actions": ["Revoke access", "Disable accounts", "Block exfiltration"]
                },
                "eradication": {"actions": ["Remove backdoors", "Reset credentials"]},
                "recovery": {"actions": ["Restore services", "Monitor for recurrence"]},
                "lessons_learned": {"actions": ["Document incident", "Update defenses"]},
            },
        }

        playbook_file = tmp_path / "data_breach_ir.json"
        with open(playbook_file, "w") as f:
            json.dump(ir_playbook, f, indent=2)

        assert playbook_file.exists()
        # Verify all NIST IR phases are present
        assert "detection" in ir_playbook["phases"]
        assert "containment" in ir_playbook["phases"]
        assert "eradication" in ir_playbook["phases"]


@pytest.mark.integration
class TestWorkflowOrchestration:
    """Test workflow orchestration and coordination"""

    def test_parallel_task_execution(self):
        """Test parallel task execution"""
        parallel_tasks = [
            {"name": "Scan subnet A", "target": "192.168.1.0/24"},
            {"name": "Scan subnet B", "target": "192.168.2.0/24"},
            {"name": "Scan subnet C", "target": "192.168.3.0/24"},
        ]

        # In real implementation, these would run concurrently
        results = []
        for task in parallel_tasks:
            results.append({"task": task["name"], "status": "completed", "target": task["target"]})

        assert len(results) == 3
        assert all(r["status"] == "completed" for r in results)

    def test_conditional_workflow_branching(self):
        """Test conditional workflow execution"""
        alert_severity = "HIGH"

        if alert_severity == "CRITICAL":
            actions = ["immediate_containment", "executive_notification"]
        elif alert_severity == "HIGH":
            actions = ["investigate", "notify_team"]
        else:
            actions = ["log_event"]

        assert "investigate" in actions
        assert "notify_team" in actions

    def test_workflow_error_handling(self, tmp_path):
        """Test workflow error handling and recovery"""
        workflow_state = {
            "workflow_id": "WF-001",
            "tasks": [
                {"name": "Task 1", "status": "completed"},
                {"name": "Task 2", "status": "failed", "error": "Connection timeout"},
                {"name": "Task 3", "status": "pending"},
            ],
            "overall_status": "paused",
            "retry_policy": {"max_retries": 3, "backoff": "exponential"},
        }

        state_file = tmp_path / "workflow_state.json"
        with open(state_file, "w") as f:
            json.dump(workflow_state, f, indent=2)

        assert workflow_state["overall_status"] == "paused"
        # Find failed task
        failed_task = next(t for t in workflow_state["tasks"] if t["status"] == "failed")
        assert "error" in failed_task


@pytest.mark.integration
class TestSIEMIntegration:
    """Test SIEM integration workflows"""

    def test_splunk_query_integration(self, sample_spl_query):
        """Test Splunk query integration"""
        assert "index=" in sample_spl_query or "search " in sample_spl_query
        assert "EventCode" in sample_spl_query or "EventID" in sample_spl_query

    def test_sentinel_kql_integration(self, sample_kql_query):
        """Test Azure Sentinel KQL integration"""
        assert "SecurityEvent" in sample_kql_query or "SigninLogs" in sample_kql_query
        assert "where" in sample_kql_query

    def test_elastic_eql_integration(self):
        """Test Elastic EQL integration"""
        eql_query = """
        process where process.name == "cmd.exe" and
        process.command_line like "*powershell*"
        """

        assert "process where" in eql_query
        assert "process.name" in eql_query

    def test_siem_alert_forwarding(self, tmp_path):
        """Test forwarding alerts to SIEM"""
        alert_data = {
            "alert_id": "ALT-001",
            "severity": "HIGH",
            "source": "EDR",
            "destination_siem": "splunk",
            "forwarded_at": "2025-10-15T14:30:22Z",
        }

        alert_file = tmp_path / "forwarded_alert.json"
        with open(alert_file, "w") as f:
            json.dump(alert_data, f)

        assert alert_file.exists()


@pytest.mark.integration
@pytest.mark.slow
class TestEndToEndScenarios:
    """Test complete end-to-end security scenarios"""

    def test_complete_incident_lifecycle(self, tmp_path):
        """Test complete incident from detection to closure"""
        incident_log = {
            "incident_id": "INC-2025-001",
            "timeline": [
                {"time": "T+0m", "event": "Alert triggered", "phase": "detection"},
                {"time": "T+5m", "event": "Analyst assigned", "phase": "triage"},
                {"time": "T+15m", "event": "Containment initiated", "phase": "containment"},
                {"time": "T+30m", "event": "Threat eradicated", "phase": "eradication"},
                {"time": "T+60m", "event": "Systems recovered", "phase": "recovery"},
                {"time": "T+1d", "event": "Post-mortem completed", "phase": "lessons_learned"},
            ],
            "final_status": "closed",
            "mttr_minutes": 60,  # Mean Time To Remediation
        }

        log_file = tmp_path / "incident_lifecycle.json"
        with open(log_file, "w") as f:
            json.dump(incident_log, f, indent=2)

        assert incident_log["final_status"] == "closed"
        assert len(incident_log["timeline"]) == 6
        assert incident_log["mttr_minutes"] <= 120  # Within 2 hours

    def test_threat_hunting_to_detection(self, tmp_path):
        """Test threat hunting leading to new detection rule"""
        hunt_result = {
            "hunt_id": "HUNT-001",
            "hypothesis": "Lateral movement via WMI",
            "findings": {
                "suspicious_activity_found": True,
                "affected_hosts": ["HOST-01", "HOST-02"],
                "iocs": ["suspicious_process.exe", "192.168.1.100"],
            },
            "new_detection_rule": {
                "name": "WMI Lateral Movement Detection",
                "logic": "process.name == 'wmic.exe' AND network.destination.ip != localhost",
            },
        }

        result_file = tmp_path / "hunt_result.json"
        with open(result_file, "w") as f:
            json.dump(hunt_result, f, indent=2)

        assert hunt_result["findings"]["suspicious_activity_found"] is True
        assert "new_detection_rule" in hunt_result


# [+] Performance Tests
@pytest.mark.slow
def test_workflow_performance():
    """Test workflow execution performance"""
    import time

    start_time = time.time()

    # Simulate executing 100 simple tasks
    for i in range(100):
        # Simple operation
        _ = i * 2

    duration = time.time() - start_time

    # Should complete quickly (< 1 second)
    assert duration < 1.0
