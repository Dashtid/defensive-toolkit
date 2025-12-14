"""
Alert Correlation Engine Router Tests (v1.7.8)

Comprehensive tests for correlation rules, correlated alerts, MITRE ATT&CK mapping,
kill chain analysis, alert clustering, and attack pattern detection.
"""

from datetime import datetime, timedelta

import pytest
from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# auth_token and auth_headers fixtures are provided by tests/api/conftest.py


@pytest.fixture
def sample_correlation_rule():
    """Sample correlation rule configuration"""
    return {
        "name": "Brute Force Detection",
        "description": "Detect multiple failed login attempts from same source",
        "rule_type": "threshold",
        "conditions": [
            {"field": "event_type", "operator": "eq", "value": "authentication_failure"},
            {"field": "source_ip", "operator": "ne", "value": "127.0.0.1"}
        ],
        "time_window_seconds": 300,
        "threshold": 5,
        "group_by": ["source_ip"],
        "severity": "high",
        "mitre_mapping": {
            "technique_ids": ["T1110"],
            "tactic_ids": ["TA0006"],
            "kill_chain_phases": ["exploitation"]
        },
        "tags": ["authentication", "brute-force"],
        "enabled": True,
        "actions": []
    }


@pytest.fixture
def sample_sequence_rule():
    """Sample sequence correlation rule"""
    return {
        "name": "Credential Compromise Sequence",
        "description": "Detect credential compromise followed by privilege escalation",
        "rule_type": "sequence",
        "conditions": [
            {"field": "event_type", "operator": "in", "value": ["credential_dump", "privilege_escalation"]}
        ],
        "time_window_seconds": 3600,
        "threshold": 2,
        "group_by": ["host"],
        "severity": "critical",
        "mitre_mapping": {
            "technique_ids": ["T1078", "T1547"],
            "tactic_ids": ["TA0006", "TA0004"],
            "kill_chain_phases": ["exploitation", "installation"]
        },
        "tags": ["credential", "privilege-escalation"],
        "enabled": True,
        "actions": []
    }


@pytest.fixture
def sample_test_alerts():
    """Sample alerts for testing"""
    now = datetime.utcnow()
    return [
        {
            "source": "siem",
            "event_type": "authentication_failure",
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "severity": "medium",
            "summary": "Failed login attempt",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "user": "admin",
            "host": "server-01",
            "raw_data": {"attempt_count": 1}
        },
        {
            "source": "siem",
            "event_type": "authentication_failure",
            "timestamp": (now - timedelta(minutes=4)).isoformat(),
            "severity": "medium",
            "summary": "Failed login attempt",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "user": "admin",
            "host": "server-01",
            "raw_data": {"attempt_count": 2}
        },
        {
            "source": "siem",
            "event_type": "authentication_failure",
            "timestamp": now.isoformat(),
            "severity": "high",
            "summary": "Failed login attempt",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "user": "admin",
            "host": "server-01",
            "raw_data": {"attempt_count": 5}
        }
    ]


@pytest.fixture
def sample_attack_pattern():
    """Sample attack pattern configuration"""
    return {
        "name": "Ransomware Attack Pattern",
        "description": "Multi-stage ransomware attack detection",
        "stages": [
            {
                "stage_number": 1,
                "name": "Initial Access",
                "description": "Phishing email delivered",
                "kill_chain_phase": "delivery",
                "required": True,
                "timeout_hours": 48,
                "conditions": [{"field": "event_type", "operator": "eq", "value": "phishing_detected"}]
            },
            {
                "stage_number": 2,
                "name": "Execution",
                "description": "Malicious payload executed",
                "kill_chain_phase": "exploitation",
                "required": True,
                "timeout_hours": 24,
                "conditions": [{"field": "event_type", "operator": "eq", "value": "malware_execution"}]
            }
        ],
        "severity": "critical",
        "mitre_mapping": {
            "technique_ids": ["T1566.001", "T1059.001"],
            "tactic_ids": ["TA0001", "TA0002"]
        },
        "tags": ["ransomware", "apt"]
    }


@pytest.fixture
def sample_suppression():
    """Sample suppression rule configuration"""
    expires = datetime.utcnow() + timedelta(hours=24)
    return {
        "name": "Maintenance Window Suppression",
        "description": "Suppress alerts during scheduled maintenance",
        "conditions": [
            {"field": "host", "operator": "in", "value": ["server-01", "server-02"]}
        ],
        "suppress_duration_minutes": 60,
        "expires_at": expires.isoformat()
    }


class TestCorrelationRules:
    """Test correlation rule CRUD operations"""

    def test_list_rules_empty(self, auth_headers):
        """Test listing rules when none exist"""
        response = client.get("/api/v1/correlation/rules", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert "total" in data
        assert "active_count" in data
        assert "disabled_count" in data

    def test_create_threshold_rule(self, auth_headers, sample_correlation_rule):
        """Test creating a threshold correlation rule"""
        response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_correlation_rule["name"]
        assert data["rule_type"] == "threshold"
        assert "id" in data
        assert data["enabled"] is True

    def test_create_sequence_rule(self, auth_headers, sample_sequence_rule):
        """Test creating a sequence correlation rule"""
        response = client.post(
            "/api/v1/correlation/rules",
            json=sample_sequence_rule,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["rule_type"] == "sequence"
        assert data["severity"] == "critical"

    def test_get_rule_by_id(self, auth_headers, sample_correlation_rule):
        """Test getting a specific rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Get rule
        response = client.get(
            f"/api/v1/correlation/rules/{rule_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == rule_id

    def test_get_nonexistent_rule(self, auth_headers):
        """Test getting a rule that doesn't exist"""
        response = client.get(
            "/api/v1/correlation/rules/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_rule(self, auth_headers, sample_correlation_rule):
        """Test updating a rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Update rule
        update_data = {
            "name": "Updated Brute Force Detection",
            "threshold": 10,
            "severity": "critical"
        }
        response = client.patch(
            f"/api/v1/correlation/rules/{rule_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Brute Force Detection"
        assert data["threshold"] == 10
        assert data["severity"] == "critical"

    def test_delete_rule(self, auth_headers, sample_correlation_rule):
        """Test deleting a rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Delete rule
        response = client.delete(
            f"/api/v1/correlation/rules/{rule_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

        # Verify deletion
        get_response = client.get(
            f"/api/v1/correlation/rules/{rule_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    def test_enable_rule(self, auth_headers, sample_correlation_rule):
        """Test enabling a disabled rule"""
        # Create disabled rule
        sample_correlation_rule["enabled"] = False
        create_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Enable rule
        response = client.post(
            f"/api/v1/correlation/rules/{rule_id}/enable",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["status"] == "active"

    def test_disable_rule(self, auth_headers, sample_correlation_rule):
        """Test disabling a rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Disable rule
        response = client.post(
            f"/api/v1/correlation/rules/{rule_id}/disable",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False
        assert data["status"] == "disabled"

    def test_list_rules_with_filters(self, auth_headers, sample_correlation_rule, sample_sequence_rule):
        """Test listing rules with filters"""
        # Create multiple rules
        client.post("/api/v1/correlation/rules", json=sample_correlation_rule, headers=auth_headers)
        client.post("/api/v1/correlation/rules", json=sample_sequence_rule, headers=auth_headers)

        # Filter by rule type
        response = client.get(
            "/api/v1/correlation/rules?rule_type=threshold",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for rule in data["rules"]:
            assert rule["rule_type"] == "threshold"


class TestRuleTesting:
    """Test correlation rule testing functionality"""

    def test_test_rule_with_matching_alerts(self, auth_headers, sample_correlation_rule, sample_test_alerts):
        """Test a rule that matches test alerts"""
        # Create rule
        create_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["id"]

        # Test rule
        test_request = {
            "rule_id": rule_id,
            "test_alerts": sample_test_alerts
        }
        response = client.post(
            "/api/v1/correlation/rules/test",
            json=test_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "alerts_tested" in data
        assert "alerts_matched" in data
        assert "would_trigger" in data
        assert "execution_time_ms" in data

    def test_test_rule_inline(self, auth_headers, sample_test_alerts):
        """Test an inline rule definition without saving"""
        rule_def = {
            "name": "Inline Test Rule",
            "rule_type": "threshold",
            "conditions": [
                {"field": "source", "operator": "eq", "value": "siem"}
            ],
            "time_window_seconds": 600,
            "threshold": 2,
            "severity": "medium"
        }

        test_request = {
            "rule": rule_def,
            "test_alerts": sample_test_alerts
        }
        response = client.post(
            "/api/v1/correlation/rules/test",
            json=test_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["alerts_tested"] == len(sample_test_alerts)


class TestCorrelatedAlerts:
    """Test correlated alert operations"""

    def test_list_correlated_alerts_empty(self, auth_headers):
        """Test listing correlated alerts when none exist"""
        response = client.get("/api/v1/correlation/alerts", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "correlated_alerts" in data
        assert "total" in data
        assert "by_status" in data
        assert "by_severity" in data

    def test_create_correlated_alert(self, auth_headers, sample_correlation_rule):
        """Test manually creating a correlated alert"""
        # Create rule first
        rule_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = rule_response.json()["id"]

        now = datetime.utcnow()
        correlated_alert = {
            "rule_id": rule_id,
            "alerts": [
                {
                    "alert_id": "alert-001",
                    "timestamp": now.isoformat(),
                    "source": "siem",
                    "event_type": "authentication_failure",
                    "severity": "medium",
                    "summary": "Failed login",
                    "raw_data": {}
                },
                {
                    "alert_id": "alert-002",
                    "timestamp": (now + timedelta(minutes=1)).isoformat(),
                    "source": "siem",
                    "event_type": "authentication_failure",
                    "severity": "medium",
                    "summary": "Failed login",
                    "raw_data": {}
                }
            ],
            "summary": "Multiple failed logins detected"
        }

        response = client.post(
            "/api/v1/correlation/alerts",
            json=correlated_alert,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["alert_count"] == 2
        assert data["status"] == "open"

    def test_get_correlated_alert_by_id(self, auth_headers, sample_correlation_rule):
        """Test getting a specific correlated alert"""
        # Create rule and correlated alert
        rule_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = rule_response.json()["id"]

        now = datetime.utcnow()
        correlated_alert = {
            "rule_id": rule_id,
            "alerts": [
                {
                    "alert_id": "alert-001",
                    "timestamp": now.isoformat(),
                    "source": "siem",
                    "event_type": "authentication_failure",
                    "severity": "medium",
                    "summary": "Test alert",
                    "raw_data": {}
                }
            ]
        }
        create_response = client.post(
            "/api/v1/correlation/alerts",
            json=correlated_alert,
            headers=auth_headers
        )
        alert_id = create_response.json()["id"]

        # Get alert
        response = client.get(
            f"/api/v1/correlation/alerts/{alert_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == alert_id

    def test_update_correlated_alert(self, auth_headers, sample_correlation_rule):
        """Test updating a correlated alert"""
        # Create rule and correlated alert
        rule_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = rule_response.json()["id"]

        now = datetime.utcnow()
        correlated_alert = {
            "rule_id": rule_id,
            "alerts": [
                {
                    "alert_id": "alert-001",
                    "timestamp": now.isoformat(),
                    "source": "siem",
                    "event_type": "test",
                    "severity": "medium",
                    "summary": "Test",
                    "raw_data": {}
                }
            ]
        }
        create_response = client.post(
            "/api/v1/correlation/alerts",
            json=correlated_alert,
            headers=auth_headers
        )
        alert_id = create_response.json()["id"]

        # Update alert
        update_data = {
            "status": "investigating",
            "assigned_to": "analyst@example.com",
            "notes": "Under investigation"
        }
        response = client.patch(
            f"/api/v1/correlation/alerts/{alert_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "investigating"
        assert data["assigned_to"] == "analyst@example.com"

    def test_resolve_correlated_alert(self, auth_headers, sample_correlation_rule):
        """Test resolving a correlated alert"""
        # Create rule and correlated alert
        rule_response = client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )
        rule_id = rule_response.json()["id"]

        now = datetime.utcnow()
        correlated_alert = {
            "rule_id": rule_id,
            "alerts": [
                {
                    "alert_id": "alert-001",
                    "timestamp": now.isoformat(),
                    "source": "siem",
                    "event_type": "test",
                    "severity": "low",
                    "summary": "Test",
                    "raw_data": {}
                }
            ]
        }
        create_response = client.post(
            "/api/v1/correlation/alerts",
            json=correlated_alert,
            headers=auth_headers
        )
        alert_id = create_response.json()["id"]

        # Resolve alert
        response = client.post(
            f"/api/v1/correlation/alerts/{alert_id}/resolve?resolution_notes=False%20positive",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "resolved"
        assert "resolved_at" in data


class TestAlertIngestion:
    """Test alert ingestion for correlation"""

    def test_ingest_alerts(self, auth_headers, sample_correlation_rule, sample_test_alerts):
        """Test ingesting alerts for correlation"""
        # Create rule first
        client.post(
            "/api/v1/correlation/rules",
            json=sample_correlation_rule,
            headers=auth_headers
        )

        # Ingest alerts
        batch = {"alerts": sample_test_alerts}
        response = client.post(
            "/api/v1/correlation/ingest",
            json=batch,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["alerts_received"] == len(sample_test_alerts)
        assert "alerts_processed" in data
        assert "correlations_triggered" in data
        assert "processing_time_ms" in data


class TestAlertClustering:
    """Test alert clustering functionality"""

    def test_cluster_alerts(self, auth_headers, sample_test_alerts):
        """Test clustering similar alerts"""
        # First ingest some alerts
        batch = {"alerts": sample_test_alerts}
        client.post("/api/v1/correlation/ingest", json=batch, headers=auth_headers)

        # Cluster alerts
        cluster_request = {
            "time_range_hours": 24,
            "config": {
                "similarity_threshold": 0.6,
                "features": ["source", "event_type", "source_ip"],
                "min_cluster_size": 2,
                "max_cluster_size": 50,
                "algorithm": "similarity"
            }
        }
        response = client.post(
            "/api/v1/correlation/cluster",
            json=cluster_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "clusters_found" in data
        assert "total_alerts_processed" in data
        assert "alerts_deduplicated" in data
        assert "deduplication_rate_percent" in data

    def test_list_clusters(self, auth_headers):
        """Test listing alert clusters"""
        response = client.get("/api/v1/correlation/clusters", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestAttackPatterns:
    """Test attack pattern operations"""

    def test_list_attack_patterns_empty(self, auth_headers):
        """Test listing attack patterns when none exist"""
        response = client.get("/api/v1/correlation/patterns", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "patterns" in data
        assert "total" in data
        assert "by_status" in data
        assert "by_severity" in data
        assert "active_attacks" in data

    def test_create_attack_pattern(self, auth_headers, sample_attack_pattern):
        """Test creating an attack pattern"""
        response = client.post(
            "/api/v1/correlation/patterns",
            json=sample_attack_pattern,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_attack_pattern["name"]
        assert "id" in data
        assert data["stages_total"] == 2

    def test_get_attack_pattern_by_id(self, auth_headers, sample_attack_pattern):
        """Test getting a specific attack pattern"""
        # Create pattern
        create_response = client.post(
            "/api/v1/correlation/patterns",
            json=sample_attack_pattern,
            headers=auth_headers
        )
        pattern_id = create_response.json()["id"]

        # Get pattern
        response = client.get(
            f"/api/v1/correlation/patterns/{pattern_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == pattern_id

    def test_update_attack_pattern(self, auth_headers, sample_attack_pattern):
        """Test updating an attack pattern"""
        # Create pattern
        create_response = client.post(
            "/api/v1/correlation/patterns",
            json=sample_attack_pattern,
            headers=auth_headers
        )
        pattern_id = create_response.json()["id"]

        # Update pattern
        update_data = {
            "status": "confirmed",
            "confidence": 0.85
        }
        response = client.patch(
            f"/api/v1/correlation/patterns/{pattern_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "confirmed"
        assert data["confidence"] == 0.85


class TestMitreAttack:
    """Test MITRE ATT&CK integration"""

    def test_list_mitre_tactics(self, auth_headers):
        """Test listing MITRE tactics"""
        response = client.get("/api/v1/correlation/mitre/tactics", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        for tactic in data:
            assert "id" in tactic
            assert "name" in tactic
            assert "description" in tactic

    def test_get_mitre_tactic(self, auth_headers):
        """Test getting a specific MITRE tactic"""
        response = client.get("/api/v1/correlation/mitre/tactics/TA0001", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "TA0001"
        assert data["name"] == "Initial Access"

    def test_get_nonexistent_tactic(self, auth_headers):
        """Test getting a tactic that doesn't exist"""
        response = client.get("/api/v1/correlation/mitre/tactics/TA9999", headers=auth_headers)
        assert response.status_code == 404

    def test_list_mitre_techniques(self, auth_headers):
        """Test listing MITRE techniques"""
        response = client.get("/api/v1/correlation/mitre/techniques", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        for technique in data:
            assert "id" in technique
            assert "name" in technique

    def test_list_techniques_by_tactic(self, auth_headers):
        """Test filtering techniques by tactic"""
        response = client.get(
            "/api/v1/correlation/mitre/techniques?tactic_id=TA0001",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for technique in data:
            assert "TA0001" in technique["tactic_ids"]

    def test_list_techniques_exclude_subtechniques(self, auth_headers):
        """Test excluding subtechniques"""
        response = client.get(
            "/api/v1/correlation/mitre/techniques?subtechniques=false",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for technique in data:
            assert technique.get("is_subtechnique", False) is False

    def test_get_mitre_technique(self, auth_headers):
        """Test getting a specific MITRE technique"""
        response = client.get("/api/v1/correlation/mitre/techniques/T1566", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "T1566"
        assert data["name"] == "Phishing"


class TestKillChainAnalysis:
    """Test kill chain analysis functionality"""

    def test_analyze_kill_chain(self, auth_headers):
        """Test kill chain analysis for a source IP"""
        analysis_request = {
            "source_ip": "192.168.1.100",
            "time_range_hours": 24,
            "include_all_severities": True
        }
        response = client.post(
            "/api/v1/correlation/killchain/analyze",
            json=analysis_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "analysis_id" in data
        assert "phases_detected" in data
        assert "phases_missing" in data
        assert "coverage_percent" in data
        assert "recommendations" in data

    def test_list_kill_chain_phases(self, auth_headers):
        """Test listing all kill chain phases"""
        response = client.get("/api/v1/correlation/killchain/phases", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 7  # Lockheed Martin kill chain has 7 phases
        for phase in data:
            assert "phase" in phase
            assert "description" in phase


class TestSuppressions:
    """Test suppression rule operations"""

    def test_list_suppressions_empty(self, auth_headers):
        """Test listing suppressions when none exist"""
        response = client.get("/api/v1/correlation/suppressions", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "suppressions" in data
        assert "total" in data
        assert "active_count" in data

    def test_create_suppression(self, auth_headers, sample_suppression):
        """Test creating a suppression rule"""
        response = client.post(
            "/api/v1/correlation/suppressions",
            json=sample_suppression,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_suppression["name"]
        assert "id" in data
        assert data["enabled"] is True

    def test_delete_suppression(self, auth_headers, sample_suppression):
        """Test deleting a suppression rule"""
        # Create suppression
        create_response = client.post(
            "/api/v1/correlation/suppressions",
            json=sample_suppression,
            headers=auth_headers
        )
        suppression_id = create_response.json()["id"]

        # Delete suppression
        response = client.delete(
            f"/api/v1/correlation/suppressions/{suppression_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestCorrelationStats:
    """Test correlation statistics and health endpoints"""

    def test_get_correlation_stats(self, auth_headers):
        """Test getting correlation engine statistics"""
        response = client.get("/api/v1/correlation/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_rules" in data
        assert "active_rules" in data
        assert "total_correlated_alerts" in data
        assert "alerts_processed_24h" in data
        assert "deduplication_rate_percent" in data
        assert "kill_chain_coverage" in data
        assert "top_triggered_rules" in data

    def test_get_correlation_health(self, auth_headers):
        """Test correlation engine health check"""
        response = client.get("/api/v1/correlation/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "rules_status" in data
        assert "processing_status" in data
        assert "queue_depth" in data
        assert "recommendations" in data


class TestCorrelationAuthentication:
    """Test authentication requirements for correlation endpoints"""

    def test_list_rules_no_auth_allowed(self):
        """Test that listing rules works without auth (read-only)"""
        response = client.get("/api/v1/correlation/rules")
        assert response.status_code == 200

    def test_create_rule_requires_auth(self, sample_correlation_rule):
        """Test that creating rules requires authentication"""
        response = client.post("/api/v1/correlation/rules", json=sample_correlation_rule)
        assert response.status_code == 401

    def test_ingest_requires_auth(self, sample_test_alerts):
        """Test that alert ingestion requires authentication"""
        batch = {"alerts": sample_test_alerts}
        response = client.post("/api/v1/correlation/ingest", json=batch)
        assert response.status_code == 401

    def test_cluster_requires_auth(self):
        """Test that clustering requires authentication"""
        cluster_request = {"time_range_hours": 24}
        response = client.post("/api/v1/correlation/cluster", json=cluster_request)
        assert response.status_code == 401


class TestCorrelationValidation:
    """Test input validation for correlation endpoints"""

    def test_create_rule_invalid_type(self, auth_headers):
        """Test creating rule with invalid type"""
        invalid_rule = {
            "name": "Invalid Rule",
            "rule_type": "invalid_type",
            "conditions": [],
            "time_window_seconds": 300,
            "threshold": 1,
            "severity": "high"
        }
        response = client.post(
            "/api/v1/correlation/rules",
            json=invalid_rule,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_create_rule_invalid_severity(self, auth_headers):
        """Test creating rule with invalid severity"""
        invalid_rule = {
            "name": "Invalid Rule",
            "rule_type": "threshold",
            "conditions": [],
            "time_window_seconds": 300,
            "threshold": 1,
            "severity": "invalid_severity"
        }
        response = client.post(
            "/api/v1/correlation/rules",
            json=invalid_rule,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_rules_invalid_limit(self, auth_headers):
        """Test listing rules with invalid limit"""
        response = client.get(
            "/api/v1/correlation/rules?limit=500",
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_alerts_invalid_hours(self, auth_headers):
        """Test listing alerts with invalid hours parameter"""
        response = client.get(
            "/api/v1/correlation/alerts?hours=500",
            headers=auth_headers
        )
        assert response.status_code == 422
