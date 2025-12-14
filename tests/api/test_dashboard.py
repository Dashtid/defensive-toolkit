"""
Dashboard Widgets API Router Tests (v1.7.9)

Comprehensive tests for dashboard management, widgets, templates,
export/import, snapshots, and real-time streaming.
"""


import pytest
from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# auth_token and auth_headers fixtures are provided by tests/api/conftest.py


@pytest.fixture
def sample_dashboard():
    """Sample dashboard configuration"""
    return {
        "name": "Security Operations Dashboard",
        "description": "Main SOC dashboard for security monitoring",
        "layout_type": "grid",
        "columns": 24,
        "row_height": 40,
        "variables": [],
        "tags": ["soc", "security", "monitoring"],
        "is_default": False,
        "is_public": False
    }


@pytest.fixture
def sample_widget():
    """Sample widget configuration"""
    return {
        "name": "Active Threats Counter",
        "description": "Shows count of active security threats",
        "widget_type": "counter",
        "category": "threat_overview",
        "data_source": {
            "endpoint": "/api/v1/detection/threats/count",
            "method": "GET",
            "cache_ttl_seconds": 60
        },
        "config": {
            "counter": {
                "value_field": "count",
                "label": "Active Threats",
                "show_trend": True
            }
        },
        "position": {
            "x": 0,
            "y": 0,
            "width": 6,
            "height": 3
        },
        "refresh_interval": "5_minutes",
        "time_range": "last_24_hours",
        "tags": ["threats", "counter"],
        "visible": True
    }


@pytest.fixture
def sample_chart_widget():
    """Sample chart widget configuration"""
    return {
        "name": "Incident Timeline",
        "description": "Timeline of security incidents",
        "widget_type": "chart_line",
        "category": "incident_metrics",
        "data_source": {
            "endpoint": "/api/v1/incident-response/incidents/timeline",
            "method": "GET",
            "cache_ttl_seconds": 300
        },
        "config": {
            "chart": {
                "series": [
                    {"name": "Incidents", "field": "count", "color": "#3B82F6"}
                ],
                "show_legend": True,
                "smooth": True
            }
        },
        "position": {
            "x": 0,
            "y": 3,
            "width": 12,
            "height": 4
        },
        "refresh_interval": "5_minutes",
        "time_range": "last_7_days",
        "tags": ["incidents", "timeline"],
        "visible": True
    }


class TestDashboardCRUD:
    """Test dashboard CRUD operations"""

    def test_create_dashboard(self, auth_headers, sample_dashboard):
        """Test creating a dashboard"""
        response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_dashboard["name"]
        assert data["description"] == sample_dashboard["description"]
        assert data["layout_type"] == sample_dashboard["layout_type"]
        assert data["columns"] == sample_dashboard["columns"]
        assert "id" in data
        assert data["owner"] == "admin"
        assert data["widget_ids"] == []

    def test_list_dashboards(self, auth_headers, sample_dashboard):
        """Test listing dashboards"""
        # Create a dashboard first
        client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )

        response = client.get(
            "/api/v1/dashboard/dashboards",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "dashboards" in data
        assert "total" in data
        assert "owned" in data
        assert "shared" in data
        assert "public" in data
        assert isinstance(data["dashboards"], list)

    def test_list_dashboards_with_filters(self, auth_headers, sample_dashboard):
        """Test listing dashboards with filters"""
        # Create dashboard
        client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )

        # Filter by tag
        response = client.get(
            "/api/v1/dashboard/dashboards?tag=soc",
            headers=auth_headers
        )
        assert response.status_code == 200

        # Search by name
        response = client.get(
            "/api/v1/dashboard/dashboards?search=Security",
            headers=auth_headers
        )
        assert response.status_code == 200

    def test_get_dashboard(self, auth_headers, sample_dashboard):
        """Test getting a specific dashboard"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        response = client.get(
            f"/api/v1/dashboard/dashboards/{dashboard_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == dashboard_id
        assert data["name"] == sample_dashboard["name"]
        assert "view_count" in data

    def test_get_nonexistent_dashboard(self, auth_headers):
        """Test getting a dashboard that doesn't exist"""
        response = client.get(
            "/api/v1/dashboard/dashboards/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_dashboard(self, auth_headers, sample_dashboard):
        """Test updating a dashboard"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Update dashboard
        update_data = {
            "name": "Updated Dashboard Name",
            "description": "Updated description",
            "is_public": True
        }
        response = client.patch(
            f"/api/v1/dashboard/dashboards/{dashboard_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Dashboard Name"
        assert data["description"] == "Updated description"
        assert data["is_public"] is True

    def test_delete_dashboard(self, auth_headers, sample_dashboard):
        """Test deleting a dashboard"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Delete dashboard
        response = client.delete(
            f"/api/v1/dashboard/dashboards/{dashboard_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify deletion
        get_response = client.get(
            f"/api/v1/dashboard/dashboards/{dashboard_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404


class TestDashboardSharing:
    """Test dashboard sharing functionality"""

    def test_share_dashboard(self, auth_headers, sample_dashboard):
        """Test sharing a dashboard with users"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Share dashboard
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/share",
            params={"user_ids": ["user1", "user2"]},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "user1" in data["shared_with"]
        assert "user2" in data["shared_with"]

    def test_duplicate_dashboard(self, auth_headers, sample_dashboard):
        """Test duplicating a dashboard"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Duplicate dashboard
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/duplicate",
            params={"new_name": "Duplicated Dashboard"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Duplicated Dashboard"
        assert data["id"] != dashboard_id


class TestWidgetCRUD:
    """Test widget CRUD operations"""

    def test_create_widget(self, auth_headers, sample_dashboard, sample_widget):
        """Test creating a widget in a dashboard"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Create widget
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_widget["name"]
        assert data["widget_type"] == sample_widget["widget_type"]
        assert data["category"] == sample_widget["category"]
        assert "id" in data

    def test_list_widgets(self, auth_headers, sample_dashboard, sample_widget):
        """Test listing widgets"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )

        response = client.get("/api/v1/dashboard/widgets")
        assert response.status_code == 200
        data = response.json()
        assert "widgets" in data
        assert "total" in data
        assert "by_type" in data
        assert "by_category" in data

    def test_list_widgets_with_filters(self, auth_headers, sample_dashboard, sample_widget):
        """Test listing widgets with filters"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )

        # Filter by dashboard
        response = client.get(
            f"/api/v1/dashboard/widgets?dashboard_id={dashboard_id}"
        )
        assert response.status_code == 200

        # Filter by type
        response = client.get(
            "/api/v1/dashboard/widgets?widget_type=counter"
        )
        assert response.status_code == 200

        # Filter by category
        response = client.get(
            "/api/v1/dashboard/widgets?category=threat_overview"
        )
        assert response.status_code == 200

    def test_get_widget(self, auth_headers, sample_dashboard, sample_widget):
        """Test getting a specific widget"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        widget_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        widget_id = widget_response.json()["id"]

        response = client.get(f"/api/v1/dashboard/widgets/{widget_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == widget_id
        assert data["name"] == sample_widget["name"]

    def test_get_nonexistent_widget(self, auth_headers):
        """Test getting a widget that doesn't exist"""
        response = client.get("/api/v1/dashboard/widgets/nonexistent-id")
        assert response.status_code == 404

    def test_update_widget(self, auth_headers, sample_dashboard, sample_widget):
        """Test updating a widget"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        widget_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        widget_id = widget_response.json()["id"]

        # Update widget
        update_data = {
            "name": "Updated Widget Name",
            "visible": False
        }
        response = client.patch(
            f"/api/v1/dashboard/widgets/{widget_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Widget Name"
        assert data["visible"] is False

    def test_delete_widget(self, auth_headers, sample_dashboard, sample_widget):
        """Test deleting a widget"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        widget_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        widget_id = widget_response.json()["id"]

        # Delete widget
        response = client.delete(
            f"/api/v1/dashboard/widgets/{widget_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify deletion
        get_response = client.get(f"/api/v1/dashboard/widgets/{widget_id}")
        assert get_response.status_code == 404


class TestWidgetData:
    """Test widget data fetching"""

    def test_get_widget_data(self, auth_headers, sample_dashboard, sample_widget):
        """Test fetching widget data"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        widget_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        widget_id = widget_response.json()["id"]

        response = client.get(f"/api/v1/dashboard/widgets/{widget_id}/data")
        assert response.status_code == 200
        data = response.json()
        assert data["widget_id"] == widget_id
        assert "data" in data
        assert "timestamp" in data
        assert "cached" in data
        assert "query_time_ms" in data

    def test_get_widget_data_force_refresh(self, auth_headers, sample_dashboard, sample_widget):
        """Test fetching widget data with force refresh"""
        # Create dashboard and widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        widget_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        widget_id = widget_response.json()["id"]

        response = client.get(
            f"/api/v1/dashboard/widgets/{widget_id}/data?force_refresh=true"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["cached"] is False

    def test_get_widget_data_nonexistent(self, auth_headers):
        """Test fetching data for nonexistent widget"""
        response = client.get("/api/v1/dashboard/widgets/nonexistent-id/data")
        assert response.status_code == 404


class TestBulkPositionUpdate:
    """Test bulk widget position updates"""

    def test_update_widget_positions(self, auth_headers, sample_dashboard, sample_widget, sample_chart_widget):
        """Test bulk updating widget positions"""
        # Create dashboard and widgets
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        widget1_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        widget1_id = widget1_response.json()["id"]

        widget2_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_chart_widget,
            headers=auth_headers
        )
        widget2_id = widget2_response.json()["id"]

        # Bulk update positions
        update_data = {
            "updates": [
                {"widget_id": widget1_id, "position": {"x": 0, "y": 0, "width": 8, "height": 4}},
                {"widget_id": widget2_id, "position": {"x": 8, "y": 0, "width": 8, "height": 4}}
            ]
        }
        response = client.post(
            "/api/v1/dashboard/widgets/positions",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["updated"] == 2
        assert data["failed"] == 0


class TestWidgetTemplates:
    """Test widget template operations"""

    def test_list_templates(self, auth_headers):
        """Test listing widget templates"""
        response = client.get("/api/v1/dashboard/templates")
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert "total" in data
        assert "by_category" in data
        assert data["total"] >= 10  # At least 10 built-in templates

    def test_list_templates_with_filters(self, auth_headers):
        """Test listing templates with filters"""
        # Filter by category
        response = client.get(
            "/api/v1/dashboard/templates?category=threat_overview"
        )
        assert response.status_code == 200

        # Filter by widget type
        response = client.get(
            "/api/v1/dashboard/templates?widget_type=counter"
        )
        assert response.status_code == 200

        # Search by name
        response = client.get(
            "/api/v1/dashboard/templates?search=Threat"
        )
        assert response.status_code == 200

    def test_get_template(self, auth_headers):
        """Test getting a specific template"""
        response = client.get("/api/v1/dashboard/templates/tpl-threat-counter")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "tpl-threat-counter"
        assert data["name"] == "Active Threats Counter"
        assert data["is_builtin"] is True

    def test_get_nonexistent_template(self, auth_headers):
        """Test getting a template that doesn't exist"""
        response = client.get("/api/v1/dashboard/templates/nonexistent-template")
        assert response.status_code == 404

    def test_create_widget_from_template(self, auth_headers, sample_dashboard):
        """Test creating a widget from a template"""
        # Create dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Create widget from template
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets/from-template",
            params={
                "template_id": "tpl-threat-counter",
                "name": "Custom Threat Counter"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Custom Threat Counter"
        assert data["widget_type"] == "counter"
        assert data["category"] == "threat_overview"


class TestDashboardExportImport:
    """Test dashboard export/import functionality"""

    def test_export_dashboard(self, auth_headers, sample_dashboard, sample_widget):
        """Test exporting a dashboard"""
        # Create dashboard with widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )

        # Export dashboard
        response = client.get(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/export",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0"
        assert "exported_at" in data
        assert "dashboard" in data
        assert "widgets" in data
        assert len(data["widgets"]) == 1

    def test_import_dashboard(self, auth_headers, sample_dashboard, sample_widget):
        """Test importing a dashboard"""
        # Create and export dashboard
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        export_response = client.get(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/export",
            headers=auth_headers
        )
        export_data = export_response.json()

        # Import dashboard
        import_request = {
            "dashboard_export": export_data,
            "rename_to": "Imported Dashboard"
        }
        response = client.post(
            "/api/v1/dashboard/dashboards/import",
            json=import_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "dashboard_id" in data
        assert data["widgets_imported"] == 1


class TestLayoutSnapshots:
    """Test layout snapshot functionality"""

    def test_create_snapshot(self, auth_headers, sample_dashboard, sample_widget):
        """Test creating a layout snapshot"""
        # Create dashboard with widget
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )

        # Create snapshot
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/snapshots",
            params={"description": "Initial layout"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["dashboard_id"] == dashboard_id
        assert data["description"] == "Initial layout"
        assert "widgets_positions" in data

    def test_list_snapshots(self, auth_headers, sample_dashboard, sample_widget):
        """Test listing layout snapshots"""
        # Create dashboard with widget and snapshot
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/snapshots",
            params={"description": "Test snapshot"},
            headers=auth_headers
        )

        response = client.get(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/snapshots"
        )
        assert response.status_code == 200
        data = response.json()
        assert "snapshots" in data
        assert "total" in data

    def test_restore_snapshot(self, auth_headers, sample_dashboard, sample_widget):
        """Test restoring a layout snapshot"""
        # Create dashboard with widget and snapshot
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]
        client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget,
            headers=auth_headers
        )
        snapshot_response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/snapshots",
            params={"description": "Test snapshot"},
            headers=auth_headers
        )
        snapshot_id = snapshot_response.json()["id"]

        # Restore snapshot
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/snapshots/{snapshot_id}/restore",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == dashboard_id


class TestWidgetTypes:
    """Test different widget types"""

    def test_create_chart_line_widget(self, auth_headers, sample_dashboard, sample_chart_widget):
        """Test creating a line chart widget"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_chart_widget,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["widget_type"] == "chart_line"

    def test_create_table_widget(self, auth_headers, sample_dashboard):
        """Test creating a table widget"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        table_widget = {
            "name": "Top Vulnerabilities",
            "widget_type": "table",
            "category": "vulnerability",
            "data_source": {
                "endpoint": "/api/v1/vulnerability/top",
                "method": "GET",
                "cache_ttl_seconds": 600
            },
            "config": {
                "table": {
                    "columns": [
                        {"field": "cve_id", "header": "CVE ID", "width": 120},
                        {"field": "title", "header": "Title"},
                        {"field": "severity", "header": "Severity", "width": 100}
                    ],
                    "page_size": 10,
                    "show_search": True
                }
            },
            "position": {"x": 0, "y": 0, "width": 12, "height": 5},
            "refresh_interval": "5_minutes",
            "time_range": "last_24_hours",
            "tags": ["vulnerabilities"],
            "visible": True
        }

        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=table_widget,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["widget_type"] == "table"

    def test_create_gauge_widget(self, auth_headers, sample_dashboard):
        """Test creating a gauge widget"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        gauge_widget = {
            "name": "Compliance Score",
            "widget_type": "gauge",
            "category": "compliance",
            "data_source": {
                "endpoint": "/api/v1/compliance/score",
                "method": "GET",
                "cache_ttl_seconds": 1800
            },
            "config": {
                "gauge": {
                    "value_field": "score",
                    "min_value": 0,
                    "max_value": 100,
                    "unit": "%"
                }
            },
            "position": {"x": 0, "y": 0, "width": 6, "height": 4},
            "refresh_interval": "5_minutes",
            "time_range": "last_24_hours",
            "tags": ["compliance"],
            "visible": True
        }

        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=gauge_widget,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["widget_type"] == "gauge"


class TestDashboardStats:
    """Test dashboard statistics"""

    def test_get_stats(self, auth_headers):
        """Test getting dashboard statistics"""
        response = client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_dashboards" in data
        assert "total_widgets" in data
        assert "active_users_24h" in data
        assert "total_views_24h" in data
        assert "avg_widgets_per_dashboard" in data
        assert "widgets_by_type" in data
        assert "widgets_by_category" in data
        assert "most_viewed_dashboards" in data
        assert "most_used_templates" in data


class TestDashboardHealth:
    """Test dashboard health check"""

    def test_get_health(self, auth_headers):
        """Test getting dashboard health status"""
        response = client.get("/api/v1/dashboard/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "widgets_status" in data
        assert "data_sources_status" in data
        assert "cache_status" in data
        assert "realtime_connections" in data
        assert "recommendations" in data


class TestDashboardAuthentication:
    """Test authentication requirements for dashboard endpoints"""

    def test_create_dashboard_requires_auth(self, sample_dashboard):
        """Test that creating dashboards requires authentication"""
        response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard
        )
        assert response.status_code == 401

    def test_update_dashboard_requires_auth(self, auth_headers, sample_dashboard):
        """Test that updating dashboards requires authentication"""
        # Create dashboard first
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        # Try to update without auth
        response = client.patch(
            f"/api/v1/dashboard/dashboards/{dashboard_id}",
            json={"name": "Updated"}
        )
        assert response.status_code == 401

    def test_delete_dashboard_requires_auth(self, auth_headers, sample_dashboard):
        """Test that deleting dashboards requires authentication"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/dashboard/dashboards/{dashboard_id}")
        assert response.status_code == 401

    def test_create_widget_requires_auth(self, auth_headers, sample_dashboard, sample_widget):
        """Test that creating widgets requires authentication"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=sample_widget
        )
        assert response.status_code == 401

    def test_export_dashboard_requires_auth(self, auth_headers, sample_dashboard):
        """Test that exporting dashboards requires authentication"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        response = client.get(f"/api/v1/dashboard/dashboards/{dashboard_id}/export")
        assert response.status_code == 401


class TestDashboardValidation:
    """Test input validation for dashboard endpoints"""

    def test_create_dashboard_missing_name(self, auth_headers):
        """Test creating dashboard without name"""
        invalid_dashboard = {
            "description": "Test",
            "layout_type": "grid"
        }
        response = client.post(
            "/api/v1/dashboard/dashboards",
            json=invalid_dashboard,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_create_widget_invalid_type(self, auth_headers, sample_dashboard):
        """Test creating widget with invalid type"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        invalid_widget = {
            "name": "Test Widget",
            "widget_type": "invalid_type",
            "category": "threat_overview",
            "data_source": {
                "endpoint": "/api/test",
                "method": "GET",
                "cache_ttl_seconds": 60
            },
            "position": {"x": 0, "y": 0, "width": 6, "height": 3}
        }
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=invalid_widget,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_create_widget_invalid_category(self, auth_headers, sample_dashboard):
        """Test creating widget with invalid category"""
        create_response = client.post(
            "/api/v1/dashboard/dashboards",
            json=sample_dashboard,
            headers=auth_headers
        )
        dashboard_id = create_response.json()["id"]

        invalid_widget = {
            "name": "Test Widget",
            "widget_type": "counter",
            "category": "invalid_category",
            "data_source": {
                "endpoint": "/api/test",
                "method": "GET",
                "cache_ttl_seconds": 60
            },
            "position": {"x": 0, "y": 0, "width": 6, "height": 3}
        }
        response = client.post(
            f"/api/v1/dashboard/dashboards/{dashboard_id}/widgets",
            json=invalid_widget,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_dashboards_invalid_pagination(self, auth_headers):
        """Test listing dashboards with invalid pagination"""
        response = client.get(
            "/api/v1/dashboard/dashboards?skip=-1",
            headers=auth_headers
        )
        assert response.status_code == 422

        response = client.get(
            "/api/v1/dashboard/dashboards?limit=1000",
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_templates_invalid_pagination(self, auth_headers):
        """Test listing templates with invalid pagination"""
        response = client.get("/api/v1/dashboard/templates?skip=-1")
        assert response.status_code == 422

        response = client.get("/api/v1/dashboard/templates?limit=1000")
        assert response.status_code == 422
