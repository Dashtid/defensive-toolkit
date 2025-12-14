"""
Asset Inventory & Management Router Tests (v1.7.10)

Comprehensive tests for asset CRUD, search, relationships, groups,
discovery scans, topology, CMDB sync, import/export, and bulk operations.
"""

import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

# auth_token and auth_headers fixtures are provided by tests/api/conftest.py


@pytest.fixture
def sample_server_asset():
    """Sample server asset configuration"""
    return {
        "name": "web-server-01",
        "hostname": "web-server-01",
        "fqdn": "web-server-01.example.com",
        "description": "Production web server",
        "asset_type": "server",
        "status": "active",
        "criticality": "high",
        "environment": "production",
        "ownership": "internal",
        "discovery_method": "agent",
        "primary_ip": "192.168.1.100",
        "mac_address": "00:11:22:33:44:55",
        "operating_system": {
            "name": "Ubuntu",
            "version": "22.04 LTS",
            "architecture": "x86_64",
            "kernel_version": "5.15.0"
        },
        "hardware_info": {
            "manufacturer": "Dell",
            "model": "PowerEdge R740",
            "cpu_cores": 16,
            "memory_gb": 64,
            "storage_gb": 1000
        },
        "location": {
            "building": "DC1",
            "floor": "2",
            "room": "Server Room A",
            "rack": "R-42"
        },
        "security_controls": {
            "edr_installed": True,
            "antivirus_installed": True,
            "firewall_enabled": True,
            "encryption_enabled": True
        },
        "tags": ["web", "production", "critical"],
        "compliance_status": "compliant",
        "is_cloud_asset": False
    }


@pytest.fixture
def sample_workstation_asset():
    """Sample workstation asset configuration"""
    return {
        "name": "ws-dev-001",
        "hostname": "ws-dev-001",
        "description": "Developer workstation",
        "asset_type": "workstation",
        "status": "active",
        "criticality": "medium",
        "environment": "development",
        "ownership": "internal",
        "discovery_method": "agent",
        "primary_ip": "192.168.10.50",
        "operating_system": {
            "name": "Windows",
            "version": "11 Pro",
            "architecture": "x86_64"
        },
        "security_controls": {
            "edr_installed": True,
            "antivirus_installed": True,
            "firewall_enabled": True,
            "encryption_enabled": True
        },
        "tags": ["workstation", "developer"],
        "compliance_status": "compliant",
        "is_cloud_asset": False
    }


@pytest.fixture
def sample_cloud_asset():
    """Sample cloud asset configuration"""
    return {
        "name": "api-gateway-prod",
        "hostname": "api-gateway-prod",
        "description": "Production API Gateway",
        "asset_type": "virtual_machine",
        "status": "active",
        "criticality": "critical",
        "environment": "production",
        "ownership": "internal",
        "discovery_method": "api",
        "primary_ip": "10.0.1.50",
        "is_cloud_asset": True,
        "cloud_metadata": {
            "provider": "aws",
            "region": "us-east-1",
            "instance_id": "i-0123456789abcdef0",
            "instance_type": "m5.xlarge",
            "vpc_id": "vpc-12345",
            "public_ip": "54.123.45.67"
        },
        "security_controls": {
            "edr_installed": True,
            "antivirus_installed": False,
            "firewall_enabled": True,
            "encryption_enabled": True
        },
        "tags": ["cloud", "api", "production"],
        "compliance_status": "compliant"
    }


@pytest.fixture
def sample_asset_group():
    """Sample static asset group"""
    return {
        "name": "Production Servers",
        "description": "All production server assets",
        "group_type": "static",
        "asset_ids": [],
        "tags": ["production", "servers"]
    }


@pytest.fixture
def sample_dynamic_group():
    """Sample dynamic asset group with filter"""
    return {
        "name": "Critical Assets",
        "description": "Dynamically includes all critical assets",
        "group_type": "dynamic",
        "filter_query": {
            "criticalities": ["critical"]
        },
        "tags": ["critical", "auto"]
    }


@pytest.fixture
def sample_discovery_scan():
    """Sample discovery scan configuration"""
    return {
        "config": {
            "name": "Network Discovery Scan",
            "scan_type": "network",
            "target_subnets": ["192.168.1.0/24", "192.168.10.0/24"],
            "enabled": True,
            "schedule": "0 2 * * *",
            "settings": {
                "ping_sweep": True,
                "port_scan": True,
                "service_detection": True
            }
        },
        "run_immediately": False
    }


class TestAssetCRUD:
    """Test asset CRUD operations"""

    def test_create_asset(self, sample_server_asset):
        """Test creating an asset"""
        response = client.post(
            "/api/v1/assets",
            json=sample_server_asset
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_server_asset["name"]
        assert data["asset_type"] == sample_server_asset["asset_type"]
        assert data["criticality"] == sample_server_asset["criticality"]
        assert "id" in data
        assert "risk_score" in data
        assert data["risk_score"]["overall_score"] is not None

    def test_list_assets(self, sample_server_asset):
        """Test listing assets"""
        # Create an asset first
        client.post("/api/v1/assets", json=sample_server_asset)

        response = client.get("/api/v1/assets")
        assert response.status_code == 200
        data = response.json()
        assert "assets" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data
        assert "has_next" in data
        assert "has_prev" in data

    def test_list_assets_with_filters(self, sample_server_asset, sample_workstation_asset):
        """Test listing assets with filters"""
        # Create assets
        client.post("/api/v1/assets", json=sample_server_asset)
        client.post("/api/v1/assets", json=sample_workstation_asset)

        # Filter by type
        response = client.get("/api/v1/assets?asset_type=server")
        assert response.status_code == 200

        # Filter by status
        response = client.get("/api/v1/assets?status=active")
        assert response.status_code == 200

        # Filter by criticality
        response = client.get("/api/v1/assets?criticality=high")
        assert response.status_code == 200

        # Filter by environment
        response = client.get("/api/v1/assets?environment=production")
        assert response.status_code == 200

        # Filter by cloud
        response = client.get("/api/v1/assets?is_cloud=false")
        assert response.status_code == 200

    def test_list_assets_with_pagination(self, sample_server_asset):
        """Test listing assets with pagination"""
        # Create asset
        client.post("/api/v1/assets", json=sample_server_asset)

        response = client.get("/api/v1/assets?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10

    def test_list_assets_with_sorting(self, sample_server_asset):
        """Test listing assets with sorting"""
        client.post("/api/v1/assets", json=sample_server_asset)

        response = client.get("/api/v1/assets?sort_by=name&sort_order=asc")
        assert response.status_code == 200

        response = client.get("/api/v1/assets?sort_by=criticality&sort_order=desc")
        assert response.status_code == 200

    def test_get_asset(self, sample_server_asset):
        """Test getting a specific asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/{asset_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == asset_id
        assert data["name"] == sample_server_asset["name"]

    def test_get_nonexistent_asset(self):
        """Test getting an asset that doesn't exist"""
        response = client.get("/api/v1/assets/nonexistent-id")
        assert response.status_code == 404

    def test_update_asset(self, sample_server_asset):
        """Test updating an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        update_data = {
            "description": "Updated production web server",
            "criticality": "critical",
            "tags": ["web", "production", "critical", "updated"]
        }
        response = client.put(f"/api/v1/assets/{asset_id}", json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated production web server"
        assert data["criticality"] == "critical"
        assert "updated" in data["tags"]

    def test_delete_asset_soft(self, sample_server_asset):
        """Test soft deleting an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/assets/{asset_id}?soft_delete=true")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify asset still exists but is decommissioned
        get_response = client.get(f"/api/v1/assets/{asset_id}")
        assert get_response.status_code == 200
        assert get_response.json()["status"] == "decommissioned"

    def test_delete_asset_hard(self, sample_server_asset):
        """Test hard deleting an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/assets/{asset_id}?soft_delete=false")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify asset is deleted
        get_response = client.get(f"/api/v1/assets/{asset_id}")
        assert get_response.status_code == 404


class TestAssetSearch:
    """Test advanced asset search"""

    def test_search_assets_basic(self, sample_server_asset):
        """Test basic asset search"""
        client.post("/api/v1/assets", json=sample_server_asset)

        search_query = {
            "query": "web-server"
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200
        data = response.json()
        assert "assets" in data
        assert "total" in data

    def test_search_assets_by_type(self, sample_server_asset, sample_workstation_asset):
        """Test search by asset type"""
        client.post("/api/v1/assets", json=sample_server_asset)
        client.post("/api/v1/assets", json=sample_workstation_asset)

        search_query = {
            "asset_types": ["server"]
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200
        data = response.json()
        for asset in data["assets"]:
            assert asset["asset_type"] == "server"

    def test_search_assets_by_criticality(self, sample_server_asset, sample_cloud_asset):
        """Test search by criticality"""
        client.post("/api/v1/assets", json=sample_server_asset)
        client.post("/api/v1/assets", json=sample_cloud_asset)

        search_query = {
            "criticalities": ["critical", "high"]
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200

    def test_search_assets_by_tags(self, sample_server_asset):
        """Test search by tags"""
        client.post("/api/v1/assets", json=sample_server_asset)

        search_query = {
            "tags": ["production", "web"],
            "tags_match_all": True
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200

    def test_search_assets_by_risk_score(self, sample_server_asset):
        """Test search by risk score range"""
        client.post("/api/v1/assets", json=sample_server_asset)

        search_query = {
            "min_risk_score": 3.0,
            "max_risk_score": 8.0
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200

    def test_search_assets_by_security_controls(self, sample_server_asset):
        """Test search by security controls"""
        client.post("/api/v1/assets", json=sample_server_asset)

        search_query = {
            "has_edr": True,
            "has_antivirus": True,
            "is_encrypted": True
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200

    def test_search_assets_cloud_filter(self, sample_cloud_asset):
        """Test search by cloud filter"""
        client.post("/api/v1/assets", json=sample_cloud_asset)

        search_query = {
            "is_cloud_asset": True,
            "cloud_provider": "aws"
        }
        response = client.post("/api/v1/assets/search", json=search_query)
        assert response.status_code == 200


class TestAssetRelationships:
    """Test asset relationship operations"""

    def test_create_relationship(self, sample_server_asset, sample_workstation_asset):
        """Test creating a relationship between assets"""
        # Create assets
        server_response = client.post("/api/v1/assets", json=sample_server_asset)
        server_id = server_response.json()["id"]
        workstation_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        workstation_id = workstation_response.json()["id"]

        relationship = {
            "target_asset_id": workstation_id,
            "relationship_type": "connects_to",
            "description": "Workstation connects to web server",
            "is_bidirectional": False,
            "confidence": 0.95
        }
        response = client.post(
            f"/api/v1/assets/{server_id}/relationships",
            json=relationship
        )
        assert response.status_code == 201
        data = response.json()
        assert data["source_asset_id"] == server_id
        assert data["target_asset_id"] == workstation_id
        assert data["relationship_type"] == "connects_to"

    def test_create_bidirectional_relationship(self, sample_server_asset, sample_workstation_asset):
        """Test creating a bidirectional relationship"""
        server_response = client.post("/api/v1/assets", json=sample_server_asset)
        server_id = server_response.json()["id"]
        workstation_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        workstation_id = workstation_response.json()["id"]

        relationship = {
            "target_asset_id": workstation_id,
            "relationship_type": "depends_on",
            "is_bidirectional": True,
            "confidence": 0.9
        }
        response = client.post(
            f"/api/v1/assets/{server_id}/relationships",
            json=relationship
        )
        assert response.status_code == 201

    def test_get_asset_relationships(self, sample_server_asset, sample_workstation_asset):
        """Test getting relationships for an asset"""
        # Create assets and relationship
        server_response = client.post("/api/v1/assets", json=sample_server_asset)
        server_id = server_response.json()["id"]
        workstation_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        workstation_id = workstation_response.json()["id"]

        relationship = {
            "target_asset_id": workstation_id,
            "relationship_type": "hosts",
            "is_bidirectional": False
        }
        client.post(f"/api/v1/assets/{server_id}/relationships", json=relationship)

        response = client.get(f"/api/v1/assets/{server_id}/relationships")
        assert response.status_code == 200
        data = response.json()
        assert "relationships" in data
        assert "total" in data

    def test_get_relationships_with_direction_filter(self, sample_server_asset, sample_workstation_asset):
        """Test getting relationships with direction filter"""
        server_response = client.post("/api/v1/assets", json=sample_server_asset)
        server_id = server_response.json()["id"]
        workstation_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        workstation_id = workstation_response.json()["id"]

        relationship = {
            "target_asset_id": workstation_id,
            "relationship_type": "hosts",
            "is_bidirectional": False
        }
        client.post(f"/api/v1/assets/{server_id}/relationships", json=relationship)

        # Get outbound relationships
        response = client.get(f"/api/v1/assets/{server_id}/relationships?direction=outbound")
        assert response.status_code == 200

        # Get inbound relationships
        response = client.get(f"/api/v1/assets/{workstation_id}/relationships?direction=inbound")
        assert response.status_code == 200

    def test_delete_relationship(self, sample_server_asset, sample_workstation_asset):
        """Test deleting a relationship"""
        server_response = client.post("/api/v1/assets", json=sample_server_asset)
        server_id = server_response.json()["id"]
        workstation_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        workstation_id = workstation_response.json()["id"]

        relationship = {
            "target_asset_id": workstation_id,
            "relationship_type": "connects_to",
            "is_bidirectional": False
        }
        create_response = client.post(
            f"/api/v1/assets/{server_id}/relationships",
            json=relationship
        )
        relationship_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/assets/relationships/{relationship_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestAssetGroups:
    """Test asset group operations"""

    def test_create_static_group(self, sample_asset_group, sample_server_asset):
        """Test creating a static asset group"""
        # Create an asset first
        asset_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = asset_response.json()["id"]

        group = sample_asset_group.copy()
        group["asset_ids"] = [asset_id]

        response = client.post("/api/v1/assets/groups", json=group)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_asset_group["name"]
        assert data["group_type"] == "static"
        assert data["asset_count"] == 1

    def test_create_dynamic_group(self, sample_dynamic_group):
        """Test creating a dynamic asset group"""
        response = client.post("/api/v1/assets/groups", json=sample_dynamic_group)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_dynamic_group["name"]
        assert data["group_type"] == "dynamic"

    def test_list_asset_groups(self, sample_asset_group):
        """Test listing asset groups"""
        client.post("/api/v1/assets/groups", json=sample_asset_group)

        response = client.get("/api/v1/assets/groups")
        assert response.status_code == 200
        data = response.json()
        assert "groups" in data
        assert "total" in data

    def test_get_asset_group(self, sample_asset_group):
        """Test getting a specific asset group"""
        create_response = client.post("/api/v1/assets/groups", json=sample_asset_group)
        group_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/groups/{group_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == group_id

    def test_update_asset_group(self, sample_asset_group):
        """Test updating an asset group"""
        create_response = client.post("/api/v1/assets/groups", json=sample_asset_group)
        group_id = create_response.json()["id"]

        update_data = {
            "name": "Updated Production Servers",
            "description": "Updated description"
        }
        response = client.put(f"/api/v1/assets/groups/{group_id}", json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Production Servers"

    def test_delete_asset_group(self, sample_asset_group):
        """Test deleting an asset group"""
        create_response = client.post("/api/v1/assets/groups", json=sample_asset_group)
        group_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/assets/groups/{group_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_get_group_assets(self, sample_asset_group, sample_server_asset):
        """Test getting assets in a group"""
        asset_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = asset_response.json()["id"]

        group = sample_asset_group.copy()
        group["asset_ids"] = [asset_id]
        group_response = client.post("/api/v1/assets/groups", json=group)
        group_id = group_response.json()["id"]

        response = client.get(f"/api/v1/assets/groups/{group_id}/assets")
        assert response.status_code == 200
        data = response.json()
        assert "assets" in data
        assert "total" in data

    def test_add_asset_to_group(self, sample_asset_group, sample_server_asset):
        """Test adding an asset to a static group"""
        asset_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = asset_response.json()["id"]

        group_response = client.post("/api/v1/assets/groups", json=sample_asset_group)
        group_id = group_response.json()["id"]

        response = client.post(f"/api/v1/assets/groups/{group_id}/assets/{asset_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_remove_asset_from_group(self, sample_asset_group, sample_server_asset):
        """Test removing an asset from a static group"""
        asset_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = asset_response.json()["id"]

        group = sample_asset_group.copy()
        group["asset_ids"] = [asset_id]
        group_response = client.post("/api/v1/assets/groups", json=group)
        group_id = group_response.json()["id"]

        response = client.delete(f"/api/v1/assets/groups/{group_id}/assets/{asset_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestDiscoveryScans:
    """Test discovery scan operations"""

    def test_create_discovery_scan(self, sample_discovery_scan):
        """Test creating a discovery scan"""
        response = client.post(
            "/api/v1/assets/discovery/scans",
            json=sample_discovery_scan
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_discovery_scan["config"]["name"]
        assert data["status"] == "pending"

    def test_create_and_run_discovery_scan(self, sample_discovery_scan):
        """Test creating and immediately running a discovery scan"""
        scan = sample_discovery_scan.copy()
        scan["run_immediately"] = True

        response = client.post("/api/v1/assets/discovery/scans", json=scan)
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "completed"
        assert data["total_hosts_scanned"] >= 0

    def test_list_discovery_scans(self, sample_discovery_scan):
        """Test listing discovery scans"""
        client.post("/api/v1/assets/discovery/scans", json=sample_discovery_scan)

        response = client.get("/api/v1/assets/discovery/scans")
        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert "total" in data

    def test_list_discovery_scans_by_status(self, sample_discovery_scan):
        """Test listing discovery scans by status"""
        client.post("/api/v1/assets/discovery/scans", json=sample_discovery_scan)

        response = client.get("/api/v1/assets/discovery/scans?status=pending")
        assert response.status_code == 200

    def test_get_discovery_scan(self, sample_discovery_scan):
        """Test getting a specific discovery scan"""
        create_response = client.post(
            "/api/v1/assets/discovery/scans",
            json=sample_discovery_scan
        )
        scan_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/discovery/scans/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan_id

    def test_run_discovery_scan(self, sample_discovery_scan):
        """Test manually running a discovery scan"""
        create_response = client.post(
            "/api/v1/assets/discovery/scans",
            json=sample_discovery_scan
        )
        scan_id = create_response.json()["id"]

        response = client.post(f"/api/v1/assets/discovery/scans/{scan_id}/run")
        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_cancel_discovery_scan(self, sample_discovery_scan):
        """Test canceling a discovery scan"""
        scan = sample_discovery_scan.copy()
        scan["run_immediately"] = True
        create_response = client.post("/api/v1/assets/discovery/scans", json=scan)
        scan_id = create_response.json()["id"]

        # Scan is already completed, so we can't cancel it
        response = client.post(f"/api/v1/assets/discovery/scans/{scan_id}/cancel")
        assert response.status_code == 400  # Scan is not running

    def test_get_scan_results(self, sample_discovery_scan):
        """Test getting scan results"""
        scan = sample_discovery_scan.copy()
        scan["run_immediately"] = True
        create_response = client.post("/api/v1/assets/discovery/scans", json=scan)
        scan_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/discovery/scans/{scan_id}/results")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert "total_hosts_scanned" in data

    def test_delete_discovery_scan(self, sample_discovery_scan):
        """Test deleting a discovery scan"""
        create_response = client.post(
            "/api/v1/assets/discovery/scans",
            json=sample_discovery_scan
        )
        scan_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/assets/discovery/scans/{scan_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestNetworkTopology:
    """Test network topology operations"""

    def test_generate_topology(self, sample_server_asset, sample_workstation_asset):
        """Test generating network topology"""
        # Create assets
        server_response = client.post("/api/v1/assets", json=sample_server_asset)
        server_id = server_response.json()["id"]
        workstation_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        workstation_id = workstation_response.json()["id"]

        # Create relationship
        relationship = {
            "target_asset_id": workstation_id,
            "relationship_type": "connects_to",
            "is_bidirectional": False
        }
        client.post(f"/api/v1/assets/{server_id}/relationships", json=relationship)

        topology_query = {
            "asset_ids": [server_id, workstation_id],
            "max_depth": 2
        }
        response = client.post("/api/v1/assets/topology", json=topology_query)
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data
        assert "total_nodes" in data
        assert "total_edges" in data

    def test_generate_topology_all_assets(self, sample_server_asset):
        """Test generating topology for all assets"""
        client.post("/api/v1/assets", json=sample_server_asset)

        topology_query = {}
        response = client.post("/api/v1/assets/topology", json=topology_query)
        assert response.status_code == 200

    def test_get_asset_topology(self, sample_server_asset):
        """Test getting topology centered on an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/{asset_id}/topology?max_depth=2")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data


class TestCMDBIntegration:
    """Test CMDB integration operations"""

    def test_create_cmdb_config(self):
        """Test creating a CMDB sync configuration"""
        config = {
            "name": "ServiceNow CMDB",
            "cmdb_type": "servicenow",
            "url": "https://example.service-now.com",
            "auth_type": "basic",
            "username": "admin",
            "sync_direction": "bidirectional",
            "enabled": True
        }
        response = client.post("/api/v1/assets/cmdb/configs", json=config)
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "success"
        assert "id" in data

    def test_list_cmdb_configs(self):
        """Test listing CMDB configurations"""
        config = {
            "name": "Test CMDB",
            "cmdb_type": "servicenow",
            "url": "https://test.service-now.com",
            "sync_direction": "import"
        }
        client.post("/api/v1/assets/cmdb/configs", json=config)

        response = client.get("/api/v1/assets/cmdb/configs")
        assert response.status_code == 200
        data = response.json()
        assert "configs" in data
        assert "total" in data

    def test_get_cmdb_config(self):
        """Test getting a specific CMDB configuration"""
        config = {
            "name": "Test CMDB",
            "cmdb_type": "servicenow",
            "url": "https://test.service-now.com",
            "sync_direction": "import"
        }
        create_response = client.post("/api/v1/assets/cmdb/configs", json=config)
        config_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/cmdb/configs/{config_id}")
        assert response.status_code == 200

    def test_trigger_cmdb_sync(self):
        """Test triggering CMDB synchronization"""
        config = {
            "name": "Test CMDB",
            "cmdb_type": "servicenow",
            "url": "https://test.service-now.com",
            "sync_direction": "import"
        }
        create_response = client.post("/api/v1/assets/cmdb/configs", json=config)
        config_id = create_response.json()["id"]

        response = client.post(f"/api/v1/assets/cmdb/configs/{config_id}/sync")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "records_processed" in data

    def test_delete_cmdb_config(self):
        """Test deleting a CMDB configuration"""
        config = {
            "name": "Test CMDB",
            "cmdb_type": "servicenow",
            "url": "https://test.service-now.com",
            "sync_direction": "import"
        }
        create_response = client.post("/api/v1/assets/cmdb/configs", json=config)
        config_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/assets/cmdb/configs/{config_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestImportExport:
    """Test import/export operations"""

    def test_export_assets(self, sample_server_asset):
        """Test exporting assets"""
        client.post("/api/v1/assets", json=sample_server_asset)

        export_config = {
            "format": "json",
            "include_relationships": True,
            "include_history": False
        }
        response = client.post("/api/v1/assets/export", json=export_config)
        assert response.status_code == 200
        data = response.json()
        assert "export_id" in data
        assert "total_assets" in data
        assert "download_url" in data

    def test_export_assets_with_filter(self, sample_server_asset, sample_workstation_asset):
        """Test exporting assets with filter"""
        client.post("/api/v1/assets", json=sample_server_asset)
        client.post("/api/v1/assets", json=sample_workstation_asset)

        export_config = {
            "format": "csv",
            "filter_query": {
                "asset_types": ["server"]
            }
        }
        response = client.post("/api/v1/assets/export", json=export_config)
        assert response.status_code == 200

    def test_download_export(self, sample_server_asset):
        """Test downloading an export"""
        client.post("/api/v1/assets", json=sample_server_asset)

        export_config = {"format": "json"}
        export_response = client.post("/api/v1/assets/export", json=export_config)
        export_id = export_response.json()["export_id"]

        response = client.get(f"/api/v1/assets/export/{export_id}/download")
        assert response.status_code == 200


class TestAssetStatistics:
    """Test asset statistics endpoints"""

    def test_get_statistics(self, sample_server_asset, sample_workstation_asset):
        """Test getting asset statistics"""
        client.post("/api/v1/assets", json=sample_server_asset)
        client.post("/api/v1/assets", json=sample_workstation_asset)

        response = client.get("/api/v1/assets/statistics")
        assert response.status_code == 200
        data = response.json()
        assert "total_assets" in data
        assert "by_status" in data
        assert "by_type" in data
        assert "by_criticality" in data
        assert "by_environment" in data
        assert "risk_distribution" in data
        assert "average_risk_score" in data

    def test_get_trends(self, sample_server_asset):
        """Test getting asset trends"""
        client.post("/api/v1/assets", json=sample_server_asset)

        response = client.get("/api/v1/assets/trends?period=daily&days=30")
        assert response.status_code == 200
        data = response.json()
        assert "period" in data
        assert "data_points" in data
        assert len(data["data_points"]) > 0

    def test_get_trends_weekly(self, sample_server_asset):
        """Test getting weekly asset trends"""
        client.post("/api/v1/assets", json=sample_server_asset)

        response = client.get("/api/v1/assets/trends?period=weekly&days=60")
        assert response.status_code == 200
        data = response.json()
        assert data["period"] == "weekly"


class TestAssetActivity:
    """Test asset activity log"""

    def test_get_asset_activity(self, sample_server_asset):
        """Test getting activity log for an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/{asset_id}/activity")
        assert response.status_code == 200
        data = response.json()
        assert "activities" in data
        assert "total" in data
        assert "page" in data


class TestBulkOperations:
    """Test bulk operations on assets"""

    def test_bulk_update(self, sample_server_asset, sample_workstation_asset):
        """Test bulk updating assets"""
        asset1_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset1_id = asset1_response.json()["id"]
        asset2_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        asset2_id = asset2_response.json()["id"]

        bulk_update = {
            "asset_ids": [asset1_id, asset2_id],
            "updates": {
                "compliance_status": "compliant"
            }
        }
        response = client.post("/api/v1/assets/bulk/update", json=bulk_update)
        assert response.status_code == 200
        data = response.json()
        assert data["updated"] == 2
        assert data["failed"] == 0

    def test_bulk_tag(self, sample_server_asset, sample_workstation_asset):
        """Test bulk tagging assets"""
        asset1_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset1_id = asset1_response.json()["id"]
        asset2_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        asset2_id = asset2_response.json()["id"]

        bulk_tag = {
            "asset_ids": [asset1_id, asset2_id],
            "tags_to_add": ["bulk-tagged", "new-tag"],
            "tags_to_remove": []
        }
        response = client.post("/api/v1/assets/bulk/tag", json=bulk_tag)
        assert response.status_code == 200
        data = response.json()
        assert data["succeeded"] == 2

    def test_bulk_delete(self, sample_server_asset, sample_workstation_asset):
        """Test bulk deleting assets"""
        asset1_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset1_id = asset1_response.json()["id"]
        asset2_response = client.post("/api/v1/assets", json=sample_workstation_asset)
        asset2_id = asset2_response.json()["id"]

        bulk_delete = {
            "asset_ids": [asset1_id, asset2_id],
            "soft_delete": True,
            "reason": "Test bulk decommission"
        }
        response = client.post("/api/v1/assets/bulk/delete", json=bulk_delete)
        assert response.status_code == 200
        data = response.json()
        assert data["succeeded"] == 2

    def test_bulk_recalculate_risk(self, sample_server_asset):
        """Test bulk recalculating risk scores"""
        asset_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = asset_response.json()["id"]

        response = client.post("/api/v1/assets/bulk/recalculate-risk", json=[asset_id])
        assert response.status_code == 200
        data = response.json()
        assert data["operation"] == "recalculate_risk"
        assert data["succeeded"] == 1


class TestRiskScore:
    """Test risk score operations"""

    def test_get_risk_score(self, sample_server_asset):
        """Test getting risk score for an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/{asset_id}/risk-score")
        assert response.status_code == 200
        data = response.json()
        assert "overall_score" in data
        assert "criticality_score" in data
        assert "vulnerability_score" in data
        assert "exposure_score" in data
        assert "threat_score" in data

    def test_recalculate_risk_score(self, sample_server_asset):
        """Test recalculating risk score for an asset"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.post(f"/api/v1/assets/{asset_id}/risk-score/recalculate")
        assert response.status_code == 200
        data = response.json()
        assert "overall_score" in data
        assert "calculated_at" in data


class TestAssetHealth:
    """Test asset health check"""

    def test_health_check(self, sample_server_asset):
        """Test health check endpoint"""
        client.post("/api/v1/assets", json=sample_server_asset)

        response = client.get("/api/v1/assets/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "database_status" in data
        assert "discovery_engine_status" in data
        assert "total_assets" in data
        assert "recommendations" in data


class TestAssetValidation:
    """Test input validation for asset endpoints"""

    def test_create_asset_missing_name(self):
        """Test creating asset without name"""
        invalid_asset = {
            "asset_type": "server",
            "status": "active"
        }
        response = client.post("/api/v1/assets", json=invalid_asset)
        assert response.status_code == 422

    def test_create_asset_invalid_type(self):
        """Test creating asset with invalid type"""
        invalid_asset = {
            "name": "test-asset",
            "asset_type": "invalid_type",
            "status": "active"
        }
        response = client.post("/api/v1/assets", json=invalid_asset)
        assert response.status_code == 422

    def test_create_asset_invalid_criticality(self):
        """Test creating asset with invalid criticality"""
        invalid_asset = {
            "name": "test-asset",
            "asset_type": "server",
            "criticality": "invalid_criticality"
        }
        response = client.post("/api/v1/assets", json=invalid_asset)
        assert response.status_code == 422

    def test_list_assets_invalid_pagination(self):
        """Test listing assets with invalid pagination"""
        response = client.get("/api/v1/assets?page=0")
        assert response.status_code == 422

        response = client.get("/api/v1/assets?page_size=1000")
        assert response.status_code == 422

    def test_trends_invalid_period(self):
        """Test trends with invalid period"""
        response = client.get("/api/v1/assets/trends?period=invalid")
        assert response.status_code == 422

    def test_trends_invalid_days(self):
        """Test trends with invalid days"""
        response = client.get("/api/v1/assets/trends?period=daily&days=500")
        assert response.status_code == 422

    def test_topology_invalid_depth(self, sample_server_asset):
        """Test topology with invalid depth"""
        create_response = client.post("/api/v1/assets", json=sample_server_asset)
        asset_id = create_response.json()["id"]

        response = client.get(f"/api/v1/assets/{asset_id}/topology?max_depth=10")
        assert response.status_code == 422
