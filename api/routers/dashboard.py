"""
Dashboard Widgets API Router (v1.7.9)

Provides endpoints for:
- Dashboard management (CRUD, sharing, export/import)
- Widget management (CRUD, positioning, data fetching)
- Widget templates library
- Real-time data streaming (SSE)
- Layout snapshots for undo/redo
- Statistics and health monitoring
"""

import uuid
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query, Depends, status, BackgroundTasks
from fastapi.responses import StreamingResponse

from api.models import (
    # Enums
    StatusEnum,
    WidgetTypeEnum,
    WidgetCategoryEnum,
    DashboardLayoutTypeEnum,
    RefreshIntervalEnum,
    TimeRangePresetEnum,
    AggregationTypeEnum,
    # Configuration Models
    WidgetThreshold,
    WidgetDataSource,
    WidgetPosition,
    ChartConfig,
    ChartSeriesConfig,
    TableConfig,
    TableColumnConfig,
    CounterConfig,
    GaugeConfig,
    MapConfig,
    HeatmapConfig,
    TimelineConfig,
    WidgetConfigUnion,
    # Widget Models
    WidgetCreate,
    Widget,
    WidgetUpdate,
    WidgetDataResponse,
    WidgetListResponse,
    # Dashboard Models
    DashboardVariable,
    DashboardCreate,
    Dashboard,
    DashboardUpdate,
    DashboardListResponse,
    # Template Models
    WidgetTemplate,
    WidgetTemplateListResponse,
    # Export/Import Models
    DashboardExport,
    DashboardImportRequest,
    DashboardImportResponse,
    # Real-time Models
    WidgetDataSubscription,
    WidgetDataEvent,
    # Statistics Models
    DashboardStats,
    DashboardHealthCheck,
    # Layout Models
    LayoutSnapshot,
    LayoutSnapshotListResponse,
    # Bulk Operations
    BulkWidgetPositionUpdate,
    BulkWidgetPositionResponse,
    # Common Models
    APIResponse,
)
from api.auth import get_current_active_user

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard Widgets"],
    responses={404: {"description": "Not found"}},
)

# =============================================================================
# In-Memory Storage (Replace with database in production)
# =============================================================================

dashboards_db: Dict[str, Dashboard] = {}
widgets_db: Dict[str, Widget] = {}
templates_db: Dict[str, WidgetTemplate] = {}
snapshots_db: Dict[str, LayoutSnapshot] = {}
widget_cache: Dict[str, Dict[str, Any]] = {}  # widget_id -> {data, expires_at}
realtime_subscriptions: Dict[str, List[str]] = {}  # widget_id -> [subscriber_ids]

# Statistics tracking
dashboard_stats = {
    "views": defaultdict(int),
    "data_fetches": 0,
    "fetch_errors": 0,
    "fetch_times_ms": [],
}


# =============================================================================
# Helper Functions
# =============================================================================

def generate_id() -> str:
    """Generate a unique ID"""
    return str(uuid.uuid4())


def get_time_range_dates(
    time_range: TimeRangePresetEnum,
    custom_start: Optional[datetime] = None,
    custom_end: Optional[datetime] = None
) -> tuple:
    """Convert time range preset to actual datetime range"""
    now = datetime.utcnow()

    if time_range == TimeRangePresetEnum.CUSTOM:
        return (custom_start or now - timedelta(hours=24), custom_end or now)

    ranges = {
        TimeRangePresetEnum.LAST_15_MINUTES: timedelta(minutes=15),
        TimeRangePresetEnum.LAST_HOUR: timedelta(hours=1),
        TimeRangePresetEnum.LAST_4_HOURS: timedelta(hours=4),
        TimeRangePresetEnum.LAST_24_HOURS: timedelta(hours=24),
        TimeRangePresetEnum.LAST_7_DAYS: timedelta(days=7),
        TimeRangePresetEnum.LAST_30_DAYS: timedelta(days=30),
        TimeRangePresetEnum.LAST_90_DAYS: timedelta(days=90),
    }

    delta = ranges.get(time_range, timedelta(hours=24))
    return (now - delta, now)


async def fetch_widget_data(widget: Widget) -> Dict[str, Any]:
    """Fetch data for a widget from its configured data source"""
    import time
    start_time = time.time()

    # Check cache first
    cache_key = widget.id
    if cache_key in widget_cache:
        cached = widget_cache[cache_key]
        if cached["expires_at"] > datetime.utcnow():
            return {
                "data": cached["data"],
                "cached": True,
                "cache_expires_at": cached["expires_at"],
                "query_time_ms": 0,
            }

    # Simulate data fetch based on widget type and category
    # In production, this would make actual API calls to widget.data_source.endpoint
    data = generate_mock_widget_data(widget)

    query_time_ms = int((time.time() - start_time) * 1000)
    dashboard_stats["data_fetches"] += 1
    dashboard_stats["fetch_times_ms"].append(query_time_ms)

    # Cache the result
    cache_ttl = widget.data_source.cache_ttl_seconds
    if cache_ttl > 0:
        widget_cache[cache_key] = {
            "data": data,
            "expires_at": datetime.utcnow() + timedelta(seconds=cache_ttl),
        }

    return {
        "data": data,
        "cached": False,
        "cache_expires_at": None,
        "query_time_ms": query_time_ms,
    }


def generate_mock_widget_data(widget: Widget) -> Any:
    """Generate mock data for demonstration purposes"""
    import random
    from datetime import datetime, timedelta

    now = datetime.utcnow()

    if widget.widget_type == WidgetTypeEnum.COUNTER:
        return {
            "value": random.randint(100, 10000),
            "trend": random.uniform(-15, 25),
            "previous_value": random.randint(80, 9000),
        }

    elif widget.widget_type in [WidgetTypeEnum.CHART_LINE, WidgetTypeEnum.CHART_AREA]:
        # Time series data
        points = []
        for i in range(24):
            points.append({
                "timestamp": (now - timedelta(hours=23-i)).isoformat(),
                "value": random.randint(50, 500),
                "series": "main",
            })
        return {"series": [{"name": "Events", "data": points}]}

    elif widget.widget_type == WidgetTypeEnum.CHART_BAR:
        categories = ["Critical", "High", "Medium", "Low", "Info"]
        return {
            "categories": categories,
            "series": [{
                "name": "Count",
                "data": [random.randint(5, 50) for _ in categories]
            }]
        }

    elif widget.widget_type == WidgetTypeEnum.CHART_PIE:
        return {
            "labels": ["Malware", "Phishing", "DDoS", "Intrusion", "Other"],
            "values": [random.randint(10, 100) for _ in range(5)],
        }

    elif widget.widget_type == WidgetTypeEnum.TABLE:
        rows = []
        for i in range(10):
            rows.append({
                "id": f"INC-{1000+i}",
                "title": f"Security Incident {i+1}",
                "severity": random.choice(["Critical", "High", "Medium", "Low"]),
                "status": random.choice(["Open", "In Progress", "Resolved"]),
                "created_at": (now - timedelta(hours=random.randint(1, 72))).isoformat(),
            })
        return {"rows": rows, "total": 156}

    elif widget.widget_type == WidgetTypeEnum.HEATMAP:
        # Hour x Day of week heatmap
        data = []
        for day in range(7):
            for hour in range(24):
                data.append({
                    "x": hour,
                    "y": day,
                    "value": random.randint(0, 100),
                })
        return {"data": data}

    elif widget.widget_type == WidgetTypeEnum.GAUGE:
        return {
            "value": random.randint(0, 100),
            "min": 0,
            "max": 100,
        }

    elif widget.widget_type == WidgetTypeEnum.MAP:
        points = []
        for _ in range(20):
            points.append({
                "lat": random.uniform(-60, 70),
                "lon": random.uniform(-180, 180),
                "label": f"Event {random.randint(1000, 9999)}",
                "value": random.randint(1, 50),
            })
        return {"points": points}

    elif widget.widget_type == WidgetTypeEnum.TIMELINE:
        events = []
        for i in range(10):
            events.append({
                "timestamp": (now - timedelta(hours=i*2)).isoformat(),
                "title": f"Event {10-i}",
                "description": f"Security event description {10-i}",
                "category": random.choice(["alert", "incident", "change"]),
                "severity": random.choice(["critical", "high", "medium", "low"]),
            })
        return {"events": events}

    elif widget.widget_type == WidgetTypeEnum.STATUS:
        return {
            "status": random.choice(["healthy", "degraded", "unhealthy"]),
            "message": "System operational",
            "last_check": now.isoformat(),
        }

    elif widget.widget_type == WidgetTypeEnum.LIST:
        items = []
        for i in range(5):
            items.append({
                "title": f"Top Threat {i+1}",
                "value": random.randint(100, 1000),
                "change": random.uniform(-10, 20),
            })
        return {"items": items}

    else:
        return {"message": "Custom widget data"}


# =============================================================================
# Initialize Built-in Templates
# =============================================================================

def initialize_templates():
    """Initialize built-in widget templates"""
    now = datetime.utcnow()

    builtin_templates = [
        {
            "id": "tpl-threat-counter",
            "name": "Active Threats Counter",
            "description": "Shows count of active security threats with trend",
            "category": WidgetCategoryEnum.THREAT_OVERVIEW,
            "widget_type": WidgetTypeEnum.COUNTER,
            "default_config": WidgetConfigUnion(
                counter=CounterConfig(
                    value_field="count",
                    label="Active Threats",
                    show_trend=True,
                    trend_field="trend_percent",
                    thresholds=[
                        WidgetThreshold(operator="gte", value=100, color="#DC2626", label="Critical"),
                        WidgetThreshold(operator="gte", value=50, color="#F59E0B", label="Warning"),
                        WidgetThreshold(operator="lt", value=50, color="#10B981", label="Normal"),
                    ],
                    icon="shield-exclamation",
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/detection/threats/count",
                method="GET",
                cache_ttl_seconds=60,
            ),
            "default_position": WidgetPosition(x=0, y=0, width=6, height=3),
            "tags": ["security", "threats", "overview"],
        },
        {
            "id": "tpl-incidents-timeline",
            "name": "Incidents Timeline",
            "description": "Timeline of recent security incidents",
            "category": WidgetCategoryEnum.INCIDENT_METRICS,
            "widget_type": WidgetTypeEnum.CHART_LINE,
            "default_config": WidgetConfigUnion(
                chart=ChartConfig(
                    series=[
                        ChartSeriesConfig(name="Incidents", field="count", color="#3B82F6"),
                    ],
                    show_legend=True,
                    smooth=True,
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/incident-response/incidents/timeline",
                method="GET",
                cache_ttl_seconds=300,
            ),
            "default_position": WidgetPosition(x=0, y=3, width=12, height=4),
            "tags": ["incidents", "timeline", "trend"],
        },
        {
            "id": "tpl-severity-distribution",
            "name": "Severity Distribution",
            "description": "Pie chart of alerts by severity",
            "category": WidgetCategoryEnum.THREAT_OVERVIEW,
            "widget_type": WidgetTypeEnum.CHART_PIE,
            "default_config": WidgetConfigUnion(
                chart=ChartConfig(show_legend=True, legend_position="right")
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/detection/alerts/by-severity",
                method="GET",
                cache_ttl_seconds=120,
            ),
            "default_position": WidgetPosition(x=12, y=0, width=6, height=4),
            "tags": ["alerts", "severity", "distribution"],
        },
        {
            "id": "tpl-vuln-table",
            "name": "Top Vulnerabilities",
            "description": "Table of critical vulnerabilities",
            "category": WidgetCategoryEnum.VULNERABILITY,
            "widget_type": WidgetTypeEnum.TABLE,
            "default_config": WidgetConfigUnion(
                table=TableConfig(
                    columns=[
                        TableColumnConfig(field="cve_id", header="CVE ID", width=120),
                        TableColumnConfig(field="title", header="Title"),
                        TableColumnConfig(field="severity", header="Severity", width=100),
                        TableColumnConfig(field="cvss_score", header="CVSS", width=80),
                        TableColumnConfig(field="affected_assets", header="Assets", width=80),
                    ],
                    page_size=10,
                    show_search=True,
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/vulnerability/top",
                method="GET",
                cache_ttl_seconds=600,
            ),
            "default_position": WidgetPosition(x=0, y=7, width=12, height=5),
            "tags": ["vulnerabilities", "cve", "critical"],
        },
        {
            "id": "tpl-attack-heatmap",
            "name": "Attack Activity Heatmap",
            "description": "Heatmap of attack activity by hour and day",
            "category": WidgetCategoryEnum.THREAT_OVERVIEW,
            "widget_type": WidgetTypeEnum.HEATMAP,
            "default_config": WidgetConfigUnion(
                heatmap=HeatmapConfig(
                    x_field="hour",
                    y_field="day",
                    value_field="count",
                    color_scale="reds",
                    show_values=False,
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/detection/attacks/heatmap",
                method="GET",
                cache_ttl_seconds=300,
            ),
            "default_position": WidgetPosition(x=12, y=4, width=12, height=4),
            "tags": ["attacks", "heatmap", "temporal"],
        },
        {
            "id": "tpl-geo-threats",
            "name": "Threat Geography",
            "description": "Geographic map of threat origins",
            "category": WidgetCategoryEnum.NETWORK,
            "widget_type": WidgetTypeEnum.MAP,
            "default_config": WidgetConfigUnion(
                map=MapConfig(
                    lat_field="lat",
                    lon_field="lon",
                    value_field="count",
                    label_field="country",
                    cluster=True,
                    initial_zoom=2,
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/threat-intel/geo",
                method="GET",
                cache_ttl_seconds=600,
            ),
            "default_position": WidgetPosition(x=0, y=12, width=12, height=5),
            "tags": ["geographic", "threats", "network"],
        },
        {
            "id": "tpl-compliance-gauge",
            "name": "Compliance Score",
            "description": "Gauge showing overall compliance score",
            "category": WidgetCategoryEnum.COMPLIANCE,
            "widget_type": WidgetTypeEnum.GAUGE,
            "default_config": WidgetConfigUnion(
                gauge=GaugeConfig(
                    value_field="score",
                    min_value=0,
                    max_value=100,
                    unit="%",
                    thresholds=[
                        WidgetThreshold(operator="gte", value=90, color="#10B981", label="Excellent"),
                        WidgetThreshold(operator="gte", value=70, color="#F59E0B", label="Good"),
                        WidgetThreshold(operator="lt", value=70, color="#DC2626", label="Needs Work"),
                    ],
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/compliance/score",
                method="GET",
                cache_ttl_seconds=1800,
            ),
            "default_position": WidgetPosition(x=18, y=0, width=6, height=4),
            "tags": ["compliance", "score", "gauge"],
        },
        {
            "id": "tpl-system-health",
            "name": "System Health Status",
            "description": "Status indicator for system health",
            "category": WidgetCategoryEnum.SYSTEM_HEALTH,
            "widget_type": WidgetTypeEnum.STATUS,
            "default_config": WidgetConfigUnion(custom={"icon": "server", "show_details": True}),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/monitoring/health",
                method="GET",
                cache_ttl_seconds=30,
            ),
            "default_position": WidgetPosition(x=18, y=4, width=6, height=2),
            "tags": ["health", "status", "system"],
        },
        {
            "id": "tpl-correlation-alerts",
            "name": "Correlated Alerts",
            "description": "Count of correlated alert groups",
            "category": WidgetCategoryEnum.CORRELATION,
            "widget_type": WidgetTypeEnum.COUNTER,
            "default_config": WidgetConfigUnion(
                counter=CounterConfig(
                    value_field="open_count",
                    label="Open Correlations",
                    show_trend=True,
                    icon="link",
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/correlation/stats",
                method="GET",
                cache_ttl_seconds=60,
            ),
            "default_position": WidgetPosition(x=6, y=0, width=6, height=3),
            "tags": ["correlation", "alerts", "count"],
        },
        {
            "id": "tpl-siem-events",
            "name": "SIEM Events Rate",
            "description": "Line chart of SIEM events per minute",
            "category": WidgetCategoryEnum.SIEM,
            "widget_type": WidgetTypeEnum.CHART_AREA,
            "default_config": WidgetConfigUnion(
                chart=ChartConfig(
                    series=[ChartSeriesConfig(name="Events/min", field="rate", color="#8B5CF6")],
                    fill=True,
                    smooth=True,
                )
            ),
            "default_data_source": WidgetDataSource(
                endpoint="/api/v1/siem/events/rate",
                method="GET",
                cache_ttl_seconds=30,
            ),
            "default_position": WidgetPosition(x=12, y=8, width=12, height=4),
            "tags": ["siem", "events", "rate"],
        },
    ]

    for tpl_data in builtin_templates:
        template = WidgetTemplate(
            id=tpl_data["id"],
            name=tpl_data["name"],
            description=tpl_data.get("description"),
            category=tpl_data["category"],
            widget_type=tpl_data["widget_type"],
            default_config=tpl_data["default_config"],
            default_data_source=tpl_data["default_data_source"],
            default_position=tpl_data["default_position"],
            tags=tpl_data.get("tags", []),
            is_builtin=True,
            usage_count=0,
            created_at=now,
        )
        templates_db[template.id] = template


# Initialize templates on module load
initialize_templates()


# =============================================================================
# Dashboard Endpoints
# =============================================================================

@router.post("/dashboards", response_model=Dashboard, status_code=status.HTTP_201_CREATED)
async def create_dashboard(
    dashboard: DashboardCreate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create a new dashboard.
    """
    dashboard_id = generate_id()
    now = datetime.utcnow()

    # If setting as default, unset other defaults for this user
    if dashboard.is_default:
        for db in dashboards_db.values():
            if db.owner == current_user and db.is_default:
                db.is_default = False

    new_dashboard = Dashboard(
        id=dashboard_id,
        name=dashboard.name,
        description=dashboard.description,
        layout_type=dashboard.layout_type,
        columns=dashboard.columns,
        row_height=dashboard.row_height,
        widgets=[],
        widget_ids=[],
        variables=dashboard.variables,
        tags=dashboard.tags,
        is_default=dashboard.is_default,
        is_public=dashboard.is_public,
        owner=current_user,
        shared_with=[],
        created_at=now,
        updated_at=now,
        view_count=0,
    )

    dashboards_db[dashboard_id] = new_dashboard
    logger.info(f"Created dashboard: {dashboard.name} (ID: {dashboard_id})")

    return new_dashboard


@router.get("/dashboards", response_model=DashboardListResponse)
async def list_dashboards(
    include_public: bool = True,
    include_shared: bool = True,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: str = Depends(get_current_active_user)
):
    """
    List dashboards accessible to the current user.
    """
    dashboards = []

    for db in dashboards_db.values():
        # Check access
        is_owner = db.owner == current_user
        is_shared = current_user in db.shared_with
        is_public = db.is_public

        if is_owner or (include_shared and is_shared) or (include_public and is_public):
            dashboards.append(db)

    # Apply filters
    if tag:
        dashboards = [d for d in dashboards if tag in d.tags]
    if search:
        search_lower = search.lower()
        dashboards = [d for d in dashboards if search_lower in d.name.lower() or
                      (d.description and search_lower in d.description.lower())]

    # Sort by last viewed
    dashboards.sort(key=lambda x: x.last_viewed_at or x.created_at, reverse=True)

    # Calculate counts
    owned = len([d for d in dashboards if d.owner == current_user])
    shared = len([d for d in dashboards if current_user in d.shared_with])
    public = len([d for d in dashboards if d.is_public and d.owner != current_user])

    total = len(dashboards)
    dashboards = dashboards[skip:skip + limit]

    return DashboardListResponse(
        dashboards=dashboards,
        total=total,
        owned=owned,
        shared=shared,
        public=public,
    )


@router.get("/dashboards/{dashboard_id}", response_model=Dashboard)
async def get_dashboard(
    dashboard_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Get a specific dashboard with all widgets.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    # Check access
    if not (dashboard.owner == current_user or
            current_user in dashboard.shared_with or
            dashboard.is_public):
        raise HTTPException(status_code=403, detail="Access denied")

    # Update view tracking
    dashboard.last_viewed_at = datetime.utcnow()
    dashboard.view_count += 1
    dashboard_stats["views"][dashboard_id] += 1

    # Load widgets
    dashboard.widgets = [widgets_db[wid] for wid in dashboard.widget_ids if wid in widgets_db]

    return dashboard


@router.patch("/dashboards/{dashboard_id}", response_model=Dashboard)
async def update_dashboard(
    dashboard_id: str,
    update: DashboardUpdate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Update a dashboard.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can update the dashboard")

    update_data = update.model_dump(exclude_unset=True)

    # If setting as default, unset others
    if update_data.get("is_default"):
        for db in dashboards_db.values():
            if db.owner == current_user and db.is_default and db.id != dashboard_id:
                db.is_default = False

    for field, value in update_data.items():
        setattr(dashboard, field, value)

    dashboard.updated_at = datetime.utcnow()
    dashboards_db[dashboard_id] = dashboard

    return dashboard


@router.delete("/dashboards/{dashboard_id}", response_model=APIResponse)
async def delete_dashboard(
    dashboard_id: str,
    delete_widgets: bool = True,
    current_user: str = Depends(get_current_active_user)
):
    """
    Delete a dashboard and optionally its widgets.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can delete the dashboard")

    # Delete associated widgets
    if delete_widgets:
        for widget_id in dashboard.widget_ids:
            if widget_id in widgets_db:
                del widgets_db[widget_id]

    del dashboards_db[dashboard_id]
    logger.info(f"Deleted dashboard: {dashboard_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Dashboard {dashboard_id} deleted successfully"
    )


@router.post("/dashboards/{dashboard_id}/share", response_model=Dashboard)
async def share_dashboard(
    dashboard_id: str,
    user_ids: List[str],
    current_user: str = Depends(get_current_active_user)
):
    """
    Share a dashboard with other users.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can share the dashboard")

    dashboard.shared_with = list(set(dashboard.shared_with + user_ids))
    dashboard.updated_at = datetime.utcnow()

    return dashboard


@router.post("/dashboards/{dashboard_id}/duplicate", response_model=Dashboard)
async def duplicate_dashboard(
    dashboard_id: str,
    new_name: Optional[str] = None,
    current_user: str = Depends(get_current_active_user)
):
    """
    Duplicate a dashboard and its widgets.
    """
    original = dashboards_db.get(dashboard_id)
    if not original:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    # Check access
    if not (original.owner == current_user or
            current_user in original.shared_with or
            original.is_public):
        raise HTTPException(status_code=403, detail="Access denied")

    now = datetime.utcnow()
    new_dashboard_id = generate_id()

    # Duplicate widgets
    new_widget_ids = []
    for widget_id in original.widget_ids:
        if widget_id in widgets_db:
            old_widget = widgets_db[widget_id]
            new_widget_id = generate_id()
            new_widget = Widget(
                **old_widget.model_dump(exclude={"id", "created_at", "updated_at", "created_by"}),
                id=new_widget_id,
                created_at=now,
                updated_at=now,
                created_by=current_user,
            )
            widgets_db[new_widget_id] = new_widget
            new_widget_ids.append(new_widget_id)

    # Create new dashboard
    new_dashboard = Dashboard(
        id=new_dashboard_id,
        name=new_name or f"{original.name} (Copy)",
        description=original.description,
        layout_type=original.layout_type,
        columns=original.columns,
        row_height=original.row_height,
        widgets=[],
        widget_ids=new_widget_ids,
        variables=original.variables,
        tags=original.tags,
        is_default=False,
        is_public=False,
        owner=current_user,
        shared_with=[],
        created_at=now,
        updated_at=now,
        view_count=0,
    )

    dashboards_db[new_dashboard_id] = new_dashboard
    return new_dashboard


# =============================================================================
# Widget Endpoints
# =============================================================================

@router.post("/dashboards/{dashboard_id}/widgets", response_model=Widget, status_code=status.HTTP_201_CREATED)
async def create_widget(
    dashboard_id: str,
    widget: WidgetCreate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create a new widget in a dashboard.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can add widgets")

    widget_id = generate_id()
    now = datetime.utcnow()

    new_widget = Widget(
        id=widget_id,
        name=widget.name,
        description=widget.description,
        widget_type=widget.widget_type,
        category=widget.category,
        data_source=widget.data_source,
        config=widget.config,
        position=widget.position,
        refresh_interval=widget.refresh_interval,
        time_range=widget.time_range,
        custom_time_start=widget.custom_time_start,
        custom_time_end=widget.custom_time_end,
        tags=widget.tags,
        visible=widget.visible,
        created_at=now,
        updated_at=now,
        created_by=current_user,
        error_count=0,
    )

    widgets_db[widget_id] = new_widget
    dashboard.widget_ids.append(widget_id)
    dashboard.updated_at = now

    logger.info(f"Created widget: {widget.name} in dashboard {dashboard_id}")
    return new_widget


@router.get("/widgets", response_model=WidgetListResponse)
async def list_widgets(
    dashboard_id: Optional[str] = None,
    widget_type: Optional[WidgetTypeEnum] = None,
    category: Optional[WidgetCategoryEnum] = None,
    tag: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List widgets with optional filtering.
    """
    widgets = list(widgets_db.values())

    if dashboard_id:
        dashboard = dashboards_db.get(dashboard_id)
        if dashboard:
            widgets = [w for w in widgets if w.id in dashboard.widget_ids]

    if widget_type:
        widgets = [w for w in widgets if w.widget_type == widget_type]
    if category:
        widgets = [w for w in widgets if w.category == category]
    if tag:
        widgets = [w for w in widgets if tag in w.tags]

    # Calculate statistics
    by_type = defaultdict(int)
    by_category = defaultdict(int)
    for w in widgets:
        by_type[w.widget_type.value] += 1
        by_category[w.category.value] += 1

    total = len(widgets)
    widgets = widgets[skip:skip + limit]

    return WidgetListResponse(
        widgets=widgets,
        total=total,
        by_type=dict(by_type),
        by_category=dict(by_category),
    )


@router.get("/widgets/{widget_id}", response_model=Widget)
async def get_widget(widget_id: str):
    """
    Get a specific widget by ID.
    """
    widget = widgets_db.get(widget_id)
    if not widget:
        raise HTTPException(status_code=404, detail=f"Widget {widget_id} not found")
    return widget


@router.patch("/widgets/{widget_id}", response_model=Widget)
async def update_widget(
    widget_id: str,
    update: WidgetUpdate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Update a widget.
    """
    widget = widgets_db.get(widget_id)
    if not widget:
        raise HTTPException(status_code=404, detail=f"Widget {widget_id} not found")

    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(widget, field, value)

    widget.updated_at = datetime.utcnow()
    widgets_db[widget_id] = widget

    # Invalidate cache
    if widget_id in widget_cache:
        del widget_cache[widget_id]

    return widget


@router.delete("/widgets/{widget_id}", response_model=APIResponse)
async def delete_widget(
    widget_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Delete a widget.
    """
    if widget_id not in widgets_db:
        raise HTTPException(status_code=404, detail=f"Widget {widget_id} not found")

    # Remove from all dashboards
    for dashboard in dashboards_db.values():
        if widget_id in dashboard.widget_ids:
            dashboard.widget_ids.remove(widget_id)
            dashboard.updated_at = datetime.utcnow()

    del widgets_db[widget_id]

    # Clean up cache
    if widget_id in widget_cache:
        del widget_cache[widget_id]

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Widget {widget_id} deleted successfully"
    )


@router.get("/widgets/{widget_id}/data", response_model=WidgetDataResponse)
async def get_widget_data(
    widget_id: str,
    force_refresh: bool = False,
):
    """
    Fetch data for a widget.
    """
    widget = widgets_db.get(widget_id)
    if not widget:
        raise HTTPException(status_code=404, detail=f"Widget {widget_id} not found")

    # Clear cache if force refresh
    if force_refresh and widget_id in widget_cache:
        del widget_cache[widget_id]

    try:
        result = await fetch_widget_data(widget)

        # Update widget metadata
        widget.last_data_fetch = datetime.utcnow()
        widgets_db[widget_id] = widget

        row_count = None
        if isinstance(result["data"], dict):
            if "rows" in result["data"]:
                row_count = len(result["data"]["rows"])
            elif "series" in result["data"]:
                row_count = sum(len(s.get("data", [])) for s in result["data"]["series"])

        return WidgetDataResponse(
            widget_id=widget_id,
            data=result["data"],
            timestamp=datetime.utcnow(),
            cached=result["cached"],
            cache_expires_at=result["cache_expires_at"],
            query_time_ms=result["query_time_ms"],
            row_count=row_count,
            truncated=False,
        )

    except Exception as e:
        widget.error_count += 1
        widget.last_error = str(e)
        widgets_db[widget_id] = widget
        dashboard_stats["fetch_errors"] += 1

        raise HTTPException(status_code=500, detail=f"Failed to fetch widget data: {str(e)}")


@router.post("/widgets/positions", response_model=BulkWidgetPositionResponse)
async def update_widget_positions(
    request: BulkWidgetPositionUpdate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Bulk update widget positions (for drag-and-drop).
    """
    updated = 0
    failed = 0
    errors = []

    for item in request.updates:
        widget_id = item.get("widget_id")
        position = item.get("position")

        if not widget_id or not position:
            failed += 1
            errors.append({"widget_id": widget_id, "error": "Missing widget_id or position"})
            continue

        widget = widgets_db.get(widget_id)
        if not widget:
            failed += 1
            errors.append({"widget_id": widget_id, "error": "Widget not found"})
            continue

        try:
            widget.position = WidgetPosition(**position)
            widget.updated_at = datetime.utcnow()
            widgets_db[widget_id] = widget
            updated += 1
        except Exception as e:
            failed += 1
            errors.append({"widget_id": widget_id, "error": str(e)})

    return BulkWidgetPositionResponse(
        status=StatusEnum.SUCCESS if failed == 0 else StatusEnum.ERROR,
        updated=updated,
        failed=failed,
        errors=errors,
    )


# =============================================================================
# Widget Templates Endpoints
# =============================================================================

@router.get("/templates", response_model=WidgetTemplateListResponse)
async def list_widget_templates(
    category: Optional[WidgetCategoryEnum] = None,
    widget_type: Optional[WidgetTypeEnum] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List available widget templates.
    """
    templates = list(templates_db.values())

    if category:
        templates = [t for t in templates if t.category == category]
    if widget_type:
        templates = [t for t in templates if t.widget_type == widget_type]
    if search:
        search_lower = search.lower()
        templates = [t for t in templates if search_lower in t.name.lower() or
                     (t.description and search_lower in t.description.lower())]

    by_category = defaultdict(int)
    for t in templates:
        by_category[t.category.value] += 1

    total = len(templates)
    templates = templates[skip:skip + limit]

    return WidgetTemplateListResponse(
        templates=templates,
        total=total,
        by_category=dict(by_category),
    )


@router.get("/templates/{template_id}", response_model=WidgetTemplate)
async def get_widget_template(template_id: str):
    """
    Get a specific widget template.
    """
    template = templates_db.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template {template_id} not found")
    return template


@router.post("/dashboards/{dashboard_id}/widgets/from-template", response_model=Widget)
async def create_widget_from_template(
    dashboard_id: str,
    template_id: str,
    name: Optional[str] = None,
    position: Optional[WidgetPosition] = None,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create a widget from a template.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can add widgets")

    template = templates_db.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template {template_id} not found")

    widget_id = generate_id()
    now = datetime.utcnow()

    new_widget = Widget(
        id=widget_id,
        name=name or template.name,
        description=template.description,
        widget_type=template.widget_type,
        category=template.category,
        data_source=template.default_data_source,
        config=template.default_config,
        position=position or template.default_position,
        refresh_interval=RefreshIntervalEnum.MINUTES_5,
        time_range=TimeRangePresetEnum.LAST_24_HOURS,
        tags=template.tags,
        visible=True,
        created_at=now,
        updated_at=now,
        created_by=current_user,
        error_count=0,
    )

    widgets_db[widget_id] = new_widget
    dashboard.widget_ids.append(widget_id)
    dashboard.updated_at = now

    # Update template usage count
    template.usage_count += 1

    return new_widget


# =============================================================================
# Export/Import Endpoints
# =============================================================================

@router.get("/dashboards/{dashboard_id}/export", response_model=DashboardExport)
async def export_dashboard(
    dashboard_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Export a dashboard configuration.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    # Check access
    if not (dashboard.owner == current_user or
            current_user in dashboard.shared_with or
            dashboard.is_public):
        raise HTTPException(status_code=403, detail="Access denied")

    # Get widgets
    widgets = [widgets_db[wid] for wid in dashboard.widget_ids if wid in widgets_db]

    return DashboardExport(
        version="1.0",
        exported_at=datetime.utcnow(),
        dashboard=dashboard,
        widgets=widgets,
    )


@router.post("/dashboards/import", response_model=DashboardImportResponse)
async def import_dashboard(
    request: DashboardImportRequest,
    current_user: str = Depends(get_current_active_user)
):
    """
    Import a dashboard from export.
    """
    export = request.dashboard_export
    now = datetime.utcnow()
    warnings = []

    # Create new dashboard
    new_dashboard_id = generate_id()

    # Import widgets with new IDs
    widget_id_map = {}
    for widget in export.widgets:
        new_widget_id = generate_id()
        widget_id_map[widget.id] = new_widget_id

        new_widget = Widget(
            **widget.model_dump(exclude={"id", "created_at", "updated_at", "created_by"}),
            id=new_widget_id,
            created_at=now,
            updated_at=now,
            created_by=current_user,
        )
        widgets_db[new_widget_id] = new_widget

    # Update widget IDs in dashboard
    new_widget_ids = [widget_id_map.get(wid, wid) for wid in export.dashboard.widget_ids]

    new_dashboard = Dashboard(
        id=new_dashboard_id,
        name=request.rename_to or export.dashboard.name,
        description=export.dashboard.description,
        layout_type=export.dashboard.layout_type,
        columns=export.dashboard.columns,
        row_height=export.dashboard.row_height,
        widgets=[],
        widget_ids=new_widget_ids,
        variables=export.dashboard.variables,
        tags=export.dashboard.tags,
        is_default=False,
        is_public=False,
        owner=current_user,
        shared_with=[],
        created_at=now,
        updated_at=now,
        view_count=0,
    )

    dashboards_db[new_dashboard_id] = new_dashboard

    return DashboardImportResponse(
        status=StatusEnum.SUCCESS,
        dashboard_id=new_dashboard_id,
        widgets_imported=len(widget_id_map),
        warnings=warnings,
    )


# =============================================================================
# Layout Snapshot Endpoints
# =============================================================================

@router.post("/dashboards/{dashboard_id}/snapshots", response_model=LayoutSnapshot)
async def create_layout_snapshot(
    dashboard_id: str,
    description: Optional[str] = None,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create a snapshot of the current dashboard layout.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can create snapshots")

    snapshot_id = generate_id()
    now = datetime.utcnow()

    # Capture current positions
    positions = {}
    for widget_id in dashboard.widget_ids:
        if widget_id in widgets_db:
            positions[widget_id] = widgets_db[widget_id].position

    snapshot = LayoutSnapshot(
        id=snapshot_id,
        dashboard_id=dashboard_id,
        widgets_positions=positions,
        created_at=now,
        created_by=current_user,
        description=description,
    )

    snapshots_db[snapshot_id] = snapshot
    return snapshot


@router.get("/dashboards/{dashboard_id}/snapshots", response_model=LayoutSnapshotListResponse)
async def list_layout_snapshots(
    dashboard_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=50),
):
    """
    List layout snapshots for a dashboard.
    """
    snapshots = [s for s in snapshots_db.values() if s.dashboard_id == dashboard_id]
    snapshots.sort(key=lambda x: x.created_at, reverse=True)

    total = len(snapshots)
    snapshots = snapshots[skip:skip + limit]

    return LayoutSnapshotListResponse(snapshots=snapshots, total=total)


@router.post("/dashboards/{dashboard_id}/snapshots/{snapshot_id}/restore", response_model=Dashboard)
async def restore_layout_snapshot(
    dashboard_id: str,
    snapshot_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Restore a dashboard layout from a snapshot.
    """
    dashboard = dashboards_db.get(dashboard_id)
    if not dashboard:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")

    if dashboard.owner != current_user:
        raise HTTPException(status_code=403, detail="Only the owner can restore snapshots")

    snapshot = snapshots_db.get(snapshot_id)
    if not snapshot or snapshot.dashboard_id != dashboard_id:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found")

    # Restore positions
    for widget_id, position in snapshot.widgets_positions.items():
        if widget_id in widgets_db:
            widgets_db[widget_id].position = position
            widgets_db[widget_id].updated_at = datetime.utcnow()

    dashboard.updated_at = datetime.utcnow()
    return dashboard


# =============================================================================
# Real-time Data Streaming (SSE)
# =============================================================================

@router.get("/widgets/{widget_id}/stream")
async def stream_widget_data(
    widget_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Stream real-time widget data using Server-Sent Events (SSE).
    """
    widget = widgets_db.get(widget_id)
    if not widget:
        raise HTTPException(status_code=404, detail=f"Widget {widget_id} not found")

    async def event_generator():
        try:
            while True:
                result = await fetch_widget_data(widget)

                event = WidgetDataEvent(
                    event_type="data",
                    widget_id=widget_id,
                    timestamp=datetime.utcnow(),
                    data=result["data"],
                )

                yield f"data: {event.model_dump_json()}\n\n"

                # Determine refresh interval
                intervals = {
                    RefreshIntervalEnum.REALTIME: 5,
                    RefreshIntervalEnum.SECONDS_10: 10,
                    RefreshIntervalEnum.SECONDS_30: 30,
                    RefreshIntervalEnum.MINUTE_1: 60,
                    RefreshIntervalEnum.MINUTES_5: 300,
                }
                delay = intervals.get(widget.refresh_interval, 60)
                await asyncio.sleep(delay)

        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


# =============================================================================
# Statistics and Health Endpoints
# =============================================================================

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Get dashboard system statistics.
    """
    dashboards = list(dashboards_db.values())
    widgets = list(widgets_db.values())
    templates = list(templates_db.values())

    # Widgets by type and category
    by_type = defaultdict(int)
    by_category = defaultdict(int)
    for w in widgets:
        by_type[w.widget_type.value] += 1
        by_category[w.category.value] += 1

    # Most viewed dashboards
    most_viewed = sorted(dashboards, key=lambda x: x.view_count, reverse=True)[:5]
    most_viewed_list = [{"id": d.id, "name": d.name, "views": d.view_count} for d in most_viewed]

    # Most used templates
    most_used = sorted(templates, key=lambda x: x.usage_count, reverse=True)[:5]
    most_used_list = [{"id": t.id, "name": t.name, "uses": t.usage_count} for t in most_used]

    # Average fetch time
    recent_times = dashboard_stats["fetch_times_ms"][-100:]
    avg_fetch_time = sum(recent_times) / max(len(recent_times), 1)

    # Average widgets per dashboard
    total_widget_count = sum(len(d.widget_ids) for d in dashboards)
    avg_widgets = total_widget_count / max(len(dashboards), 1)

    return DashboardStats(
        total_dashboards=len(dashboards),
        total_widgets=len(widgets),
        active_users_24h=len(set(d.owner for d in dashboards)),  # Simplified
        total_views_24h=sum(dashboard_stats["views"].values()),
        avg_widgets_per_dashboard=round(avg_widgets, 2),
        widgets_by_type=dict(by_type),
        widgets_by_category=dict(by_category),
        most_viewed_dashboards=most_viewed_list,
        most_used_templates=most_used_list,
        data_fetch_errors_24h=dashboard_stats["fetch_errors"],
        avg_data_fetch_time_ms=round(avg_fetch_time, 2),
    )


@router.get("/health", response_model=DashboardHealthCheck)
async def get_dashboard_health():
    """
    Health check for the dashboard system.
    """
    now = datetime.utcnow()
    widgets = list(widgets_db.values())

    # Check widgets with errors
    error_widgets = [w for w in widgets if w.error_count > 0]
    widgets_status = {
        "total": len(widgets),
        "healthy": len(widgets) - len(error_widgets),
        "with_errors": len(error_widgets),
    }

    # Check data sources
    stale_widgets = [w for w in widgets
                     if w.last_data_fetch and
                     (now - w.last_data_fetch).total_seconds() > 3600]
    data_sources_status = {
        "active": len(widgets) - len(stale_widgets),
        "stale": len(stale_widgets),
    }

    # Cache status
    cache_status = {
        "entries": len(widget_cache),
        "hit_rate": "N/A",  # Would track in production
    }

    # Determine overall health
    error_rate = len(error_widgets) / max(len(widgets), 1) * 100

    if error_rate > 20:
        status = "unhealthy"
    elif error_rate > 5 or len(stale_widgets) > len(widgets) * 0.3:
        status = "degraded"
    else:
        status = "healthy"

    recommendations = []
    if error_widgets:
        recommendations.append(f"Review {len(error_widgets)} widgets with data fetch errors")
    if stale_widgets:
        recommendations.append(f"Check data sources for {len(stale_widgets)} stale widgets")

    return DashboardHealthCheck(
        status=status,
        timestamp=now,
        widgets_status=widgets_status,
        data_sources_status=data_sources_status,
        cache_status=cache_status,
        realtime_connections=sum(len(subs) for subs in realtime_subscriptions.values()),
        recommendations=recommendations,
    )
