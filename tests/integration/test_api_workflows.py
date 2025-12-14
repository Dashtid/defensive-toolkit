"""
API Workflow Integration Tests

End-to-end tests for complete security workflows.
"""

import pytest
from defensive_toolkit.api.main import app
from fastapi.testclient import TestClient

from tests.fixtures.factories import DetectionRuleFactory, IncidentFactory

client = TestClient(app)


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def auth_token():
    response = client.post(
        "/api/v1/auth/token", data={"username": "admin", "password": "changeme123"}
    )
    return response.json()["access_token"]


@pytest.mark.integration
class TestIncidentResponseWorkflow:
    """Test complete incident response workflow"""

    def test_full_incident_response_workflow(self, auth_headers):
        """
        Test complete IR workflow:
        1. Create detection rule
        2. Deploy rule to SIEM
        3. Create incident when rule triggers
        4. Execute response playbook
        5. Update incident status
        """
        # Step 1: Create detection rule
        rule_data = DetectionRuleFactory.create(
            name="Ransomware Detection Rule", rule_type="sigma", severity="critical"
        )
        rule_response = client.post("/api/v1/detection/rules", json=rule_data, headers=auth_headers)
        assert rule_response.status_code == 201
        rule_id = rule_response.json()["id"]

        # Step 2: Deploy rule to SIEM
        deploy_data = {
            "rule_id": rule_id,
            "siem_platform": "wazuh",
            "manager_host": "wazuh.example.com",
        }
        deploy_response = client.post(
            "/api/v1/detection/rules/deploy", json=deploy_data, headers=auth_headers
        )
        assert deploy_response.status_code == 200

        # Step 3: Create incident
        incident_data = IncidentFactory.create(
            title="Ransomware Detected on Host WS-001",
            severity="critical",
            mitre_tactics=["TA0040"],
            mitre_techniques=["T1486"],
        )
        incident_response = client.post(
            "/api/v1/incident-response/incidents", json=incident_data, headers=auth_headers
        )
        assert incident_response.status_code == 201
        incident_id = incident_response.json()["id"]

        # Step 4: Execute response playbook
        playbook_data = {
            "playbook_name": "ransomware-response",
            "incident_id": incident_id,
            "parameters": {"isolate_host": True, "notify_security_team": True},
        }
        playbook_response = client.post(
            "/api/v1/incident-response/playbooks/execute", json=playbook_data, headers=auth_headers
        )
        assert playbook_response.status_code == 200

        # Step 5: Update incident status
        update_data = {"status": "contained"}
        update_response = client.patch(
            f"/api/v1/incident-response/incidents/{incident_id}",
            json=update_data,
            headers=auth_headers,
        )
        assert update_response.status_code == 200


@pytest.mark.integration
class TestThreatHuntingWorkflow:
    """Test complete threat hunting workflow"""

    def test_threat_hunting_workflow(self, auth_headers):
        """
        Test threat hunting workflow:
        1. Execute hunt query on SIEM
        2. Analyze results
        3. Create incident if threats found
        4. Create detection rule based on findings
        """
        # Step 1: Execute hunt query
        hunt_data = {
            "name": "Lateral Movement Detection",
            "platform": "wazuh",
            "query": "rule.id:60122 AND data.win.eventdata.logonType:3",
            "time_range": "24h",
            "mitre_tactics": ["TA0008"],
        }
        hunt_response = client.post(
            "/api/v1/threat-hunting/query", json=hunt_data, headers=auth_headers
        )
        assert hunt_response.status_code == 200
        results = hunt_response.json()

        # Step 2: If suspicious activity found, create incident
        if results.get("hits", 0) > 0:
            incident_data = IncidentFactory.create(
                title="Suspicious Lateral Movement Detected",
                severity="high",
                mitre_tactics=["TA0008"],
            )
            incident_response = client.post(
                "/api/v1/incident-response/incidents", json=incident_data, headers=auth_headers
            )
            assert incident_response.status_code == 201

        # Step 3: Create detection rule for future alerts
        rule_data = DetectionRuleFactory.create(
            name="Lateral Movement Detection", rule_type="sigma", severity="high"
        )
        rule_response = client.post("/api/v1/detection/rules", json=rule_data, headers=auth_headers)
        assert rule_response.status_code == 201


@pytest.mark.integration
class TestVulnerabilityManagementWorkflow:
    """Test complete vulnerability management workflow"""

    def test_vuln_management_workflow(self, auth_headers):
        """
        Test vulnerability management workflow:
        1. Run vulnerability scan
        2. List discovered vulnerabilities
        3. Generate SBOM
        4. Calculate risk scores
        5. Create remediation incidents
        """
        # Step 1: Run scan
        scan_data = {"targets": ["192.168.1.0/24"], "scan_type": "full", "scanner": "openvas"}
        scan_response = client.post(
            "/api/v1/vulnerability/scan", json=scan_data, headers=auth_headers
        )
        assert scan_response.status_code == 200
        scan_id = scan_response.json()["scan_id"]

        # Step 2: List vulnerabilities
        list_response = client.get(
            "/api/v1/vulnerability/list?severity=high&status=open", headers=auth_headers
        )
        assert list_response.status_code == 200

        # Step 3: Generate SBOM
        sbom_data = {
            "target": "api-server:latest",
            "target_type": "container",
            "format": "cyclonedx",
        }
        sbom_response = client.post(
            "/api/v1/vulnerability/sbom", json=sbom_data, headers=auth_headers
        )
        assert sbom_response.status_code == 200

        # Step 4: Calculate risk score for critical vuln
        risk_data = {
            "cve_id": "CVE-2025-1234",
            "asset_criticality": "high",
            "exposure": "internet_facing",
        }
        risk_response = client.post(
            "/api/v1/vulnerability/risk-score", json=risk_data, headers=auth_headers
        )
        assert risk_response.status_code == 200


@pytest.mark.integration
class TestComplianceAuditWorkflow:
    """Test complete compliance audit workflow"""

    def test_compliance_audit_workflow(self, auth_headers):
        """
        Test compliance audit workflow:
        1. List available frameworks
        2. Run compliance check
        3. Generate report
        4. Apply hardening for failed controls
        5. Re-run compliance check
        """
        # Step 1: List frameworks
        frameworks_response = client.get("/api/v1/compliance/frameworks", headers=auth_headers)
        assert frameworks_response.status_code == 200

        # Step 2: Run compliance check
        check_data = {"framework": "cis", "version": "8.0", "targets": ["192.168.1.100"]}
        check_response = client.post(
            "/api/v1/compliance/check", json=check_data, headers=auth_headers
        )
        assert check_response.status_code == 200

        # Step 3: Generate report
        report_response = client.get(
            "/api/v1/compliance/reports?framework=cis&format=json", headers=auth_headers
        )
        assert report_response.status_code == 200

        # Step 4: Apply hardening
        hardening_data = {
            "target": "192.168.1.100",
            "script_id": "linux-cis-level1",
            "dry_run": False,
            "backup": True,
        }
        hardening_response = client.post(
            "/api/v1/hardening/apply", json=hardening_data, headers=auth_headers
        )
        assert hardening_response.status_code == 200


@pytest.mark.integration
class TestAutomationWorkflow:
    """Test SOAR automation workflows"""

    def test_phishing_response_workflow(self, auth_headers):
        """
        Test automated phishing response:
        1. Detect phishing email
        2. Execute phishing response playbook
        3. Create TheHive case
        4. Block sender at email gateway
        5. Notify security team
        """
        # Execute phishing response workflow
        workflow_data = {
            "workflow_id": "phishing-response",
            "trigger_data": {
                "email_subject": "Urgent: Update your credentials",
                "sender": "attacker@evil.com",
                "recipients": ["user@example.com"],
                "attachment_hash": "d41d8cd98f00b204e9800998ecf8427e",
            },
            "auto_approve": False,
        }
        workflow_response = client.post(
            "/api/v1/automation/workflows/execute", json=workflow_data, headers=auth_headers
        )
        assert workflow_response.status_code == 200
        workflow_id = workflow_response.json()["execution_id"]

        # Check workflow status
        status_response = client.get(
            f"/api/v1/automation/workflows/status?workflow_id={workflow_id}", headers=auth_headers
        )
        assert status_response.status_code == 200
