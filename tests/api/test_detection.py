"""
Detection Rules API Tests

Comprehensive tests for detection rules endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app
from tests.fixtures.factories import DetectionRuleFactory

client = TestClient(app)


@pytest.fixture
def auth_headers(auth_token):
    """Fixture to get authentication headers"""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def auth_token():
    """Fixture to get authentication token"""
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "changeme123"}
    )
    return response.json()["access_token"]


class TestDetectionRulesEndpoints:
    """Test detection rules CRUD operations"""

    def test_list_rules_success(self, auth_headers):
        """Test listing detection rules"""
        response = client.get("/api/v1/detection/rules", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert "total" in data
        assert isinstance(data["rules"], list)

    def test_list_rules_with_filters(self, auth_headers):
        """Test listing rules with filters"""
        response = client.get(
            "/api/v1/detection/rules?rule_type=sigma&severity=high",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data

    def test_list_rules_unauthorized(self):
        """Test listing rules without authentication"""
        response = client.get("/api/v1/detection/rules")
        assert response.status_code == 401

    def test_create_sigma_rule_success(self, auth_headers):
        """Test creating a Sigma detection rule"""
        rule_data = DetectionRuleFactory.create(
            name="Test Sigma Rule",
            rule_type="sigma",
            severity="high"
        )
        response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Sigma Rule"
        assert data["rule_type"] == "sigma"
        assert "id" in data

    def test_create_yara_rule_success(self, auth_headers):
        """Test creating a YARA detection rule"""
        rule_data = DetectionRuleFactory.create(
            name="Test YARA Rule",
            rule_type="yara",
            content='rule test { strings: $a = "test" condition: $a }',
            severity="medium"
        )
        response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        assert response.status_code == 201

    def test_create_suricata_rule_success(self, auth_headers):
        """Test creating a Suricata detection rule"""
        rule_data = DetectionRuleFactory.create(
            name="Test Suricata Rule",
            rule_type="suricata",
            content='alert tcp any any -> any any (msg:"Test"; sid:1000001;)',
            severity="critical"
        )
        response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        assert response.status_code == 201

    def test_create_rule_missing_required_fields(self, auth_headers):
        """Test creating rule with missing required fields"""
        incomplete_rule = {"name": "Incomplete Rule"}
        response = client.post(
            "/api/v1/detection/rules",
            json=incomplete_rule,
            headers=auth_headers
        )
        assert response.status_code == 422  # Validation error

    def test_create_rule_invalid_severity(self, auth_headers):
        """Test creating rule with invalid severity"""
        rule_data = DetectionRuleFactory.create(severity="invalid")
        response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_get_rule_by_id_success(self, auth_headers):
        """Test getting a specific rule by ID"""
        # Create a rule first
        rule_data = DetectionRuleFactory.create()
        create_response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Get the rule
        response = client.get(
            f"/api/v1/detection/rules/{rule_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == rule_id

    def test_get_rule_not_found(self, auth_headers):
        """Test getting a non-existent rule"""
        response = client.get(
            "/api/v1/detection/rules/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_rule_success(self, auth_headers):
        """Test updating a rule"""
        # Create a rule first
        rule_data = DetectionRuleFactory.create()
        create_response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Update the rule
        update_data = {"name": "Updated Rule Name", "severity": "critical"}
        response = client.patch(
            f"/api/v1/detection/rules/{rule_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Rule Name"

    def test_delete_rule_success(self, auth_headers):
        """Test deleting a rule"""
        # Create a rule first
        rule_data = DetectionRuleFactory.create()
        create_response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Delete the rule
        response = client.delete(
            f"/api/v1/detection/rules/{rule_id}",
            headers=auth_headers
        )
        assert response.status_code == 200

        # Verify rule is deleted
        get_response = client.get(
            f"/api/v1/detection/rules/{rule_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404


class TestDetectionRuleDeployment:
    """Test detection rule deployment to SIEMs"""

    def test_deploy_rule_to_wazuh_success(self, auth_headers):
        """Test deploying rule to Wazuh"""
        # Create a rule first
        rule_data = DetectionRuleFactory.create()
        create_response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Deploy rule
        deploy_data = {
            "rule_id": rule_id,
            "siem_platform": "wazuh",
            "manager_host": "wazuh.example.com"
        }
        response = client.post(
            "/api/v1/detection/rules/deploy",
            json=deploy_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "deployed" or data["status"] == "success"

    def test_deploy_rule_to_elastic_success(self, auth_headers):
        """Test deploying rule to Elastic"""
        rule_data = DetectionRuleFactory.create()
        create_response = client.post(
            "/api/v1/detection/rules",
            json=rule_data,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        deploy_data = {
            "rule_id": rule_id,
            "siem_platform": "elastic",
            "manager_host": "elastic.example.com"
        }
        response = client.post(
            "/api/v1/detection/rules/deploy",
            json=deploy_data,
            headers=auth_headers
        )
        assert response.status_code == 200

    def test_deploy_rule_invalid_siem_platform(self, auth_headers):
        """Test deploying rule with invalid SIEM platform"""
        deploy_data = {
            "rule_id": "test-rule-id",
            "siem_platform": "invalid-siem",
            "manager_host": "example.com"
        }
        response = client.post(
            "/api/v1/detection/rules/deploy",
            json=deploy_data,
            headers=auth_headers
        )
        assert response.status_code == 400 or response.status_code == 422


class TestDetectionRuleValidation:
    """Test detection rule validation"""

    def test_validate_sigma_rule_success(self, auth_headers):
        """Test validating a valid Sigma rule"""
        rule_data = {
            "rule_type": "sigma",
            "content": "detection:\n  selection:\n    EventID: 4688"
        }
        response = client.post(
            "/api/v1/detection/rules/validate",
            json=rule_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True

    def test_validate_invalid_rule(self, auth_headers):
        """Test validating an invalid rule"""
        rule_data = {
            "rule_type": "sigma",
            "content": "invalid: yaml: content:"
        }
        response = client.post(
            "/api/v1/detection/rules/validate",
            json=rule_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "errors" in data


class TestDetectionRuleBulkOperations:
    """Test bulk operations on detection rules"""

    def test_bulk_create_rules_success(self, auth_headers):
        """Test bulk creating multiple rules"""
        rules = DetectionRuleFactory.create_batch(count=5)
        response = client.post(
            "/api/v1/detection/rules/bulk",
            json={"rules": rules},
            headers=auth_headers
        )
        assert response.status_code == 201 or response.status_code == 200
        data = response.json()
        assert "created" in data or "rules" in data

    def test_bulk_delete_rules_success(self, auth_headers):
        """Test bulk deleting multiple rules"""
        # Create rules first
        rules = DetectionRuleFactory.create_batch(count=3)
        create_responses = []
        for rule in rules:
            resp = client.post(
                "/api/v1/detection/rules",
                json=rule,
                headers=auth_headers
            )
            create_responses.append(resp.json()["id"])

        # Bulk delete
        response = client.post(
            "/api/v1/detection/rules/bulk-delete",
            json={"rule_ids": create_responses},
            headers=auth_headers
        )
        assert response.status_code == 200
