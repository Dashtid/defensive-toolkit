"""
Asset Inventory & Management Router (v1.7.10)

Comprehensive asset inventory system with CMDB integration, criticality scoring,
network topology, and lifecycle management following CIS Controls v8.1.

Endpoints:
- Asset CRUD operations
- Advanced search and filtering
- Asset relationships/dependencies
- Asset groups (static and dynamic)
- Discovery scans
- Network topology visualization
- CMDB synchronization
- Import/Export functionality
- Statistics and trends
- Bulk operations
"""

import logging
import math
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from api.models import (
    Asset,
    # Activity Models
    AssetActivity,
    AssetActivityListResponse,
    # Asset CRUD Models
    AssetCreate,
    AssetCriticalityEnum,
    AssetEnvironmentEnum,
    AssetExportConfig,
    AssetExportResult,
    AssetGroup,
    # Group Models
    AssetGroupCreate,
    AssetGroupListResponse,
    AssetGroupUpdate,
    # Health Check
    AssetHealthCheck,
    # Import/Export Models
    AssetImportConfig,
    AssetImportResult,
    AssetListResponse,
    AssetRelationship,
    # Relationship Models
    AssetRelationshipCreate,
    AssetRelationshipListResponse,
    AssetRiskScore,
    AssetSearchQuery,
    # Statistics Models
    AssetStatistics,
    AssetStatusEnum,
    AssetTrendData,
    # Asset Enums
    AssetTypeEnum,
    AssetUpdate,
    BulkAssetDelete,
    BulkAssetTag,
    # Bulk Models
    BulkAssetUpdate,
    BulkAssetUpdateResult,
    BulkOperationResult,
    CMDBSyncConfig,
    CMDBSyncResult,
    DiscoveryScan,
    # Discovery Scan Models
    DiscoveryScanCreate,
    DiscoveryScanListResponse,
    DiscoveryScanResult,
    NetworkTopology,
    RelationshipTypeEnum,
    StatusEnum,
    TopologyEdge,
    # Topology Models
    TopologyNode,
    TopologyQuery,
)
from fastapi import APIRouter, Body, File, HTTPException, Query, UploadFile

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Asset Inventory"])

# =============================================================================
# In-Memory Storage (Replace with database in production)
# =============================================================================

assets_store: Dict[str, Dict[str, Any]] = {}
relationships_store: Dict[str, Dict[str, Any]] = {}
groups_store: Dict[str, Dict[str, Any]] = {}
scans_store: Dict[str, Dict[str, Any]] = {}
cmdb_configs_store: Dict[str, Dict[str, Any]] = {}
activities_store: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Helper Functions
# =============================================================================


def generate_id() -> str:
    """Generate a unique ID"""
    return str(uuid.uuid4())


def calculate_risk_score(asset: Dict[str, Any]) -> AssetRiskScore:
    """Calculate comprehensive risk score for an asset"""
    # Base criticality score from criticality level
    criticality_map = {
        "critical": 10.0,
        "high": 8.0,
        "medium": 5.0,
        "low": 3.0,
        "minimal": 1.0,
    }
    criticality_score = asset.get(
        "criticality_score", criticality_map.get(asset.get("criticality", "medium"), 5.0)
    )

    # Vulnerability score
    vuln_summary = asset.get("vulnerability_summary", {})
    vuln_score = 5.0
    if vuln_summary:
        critical = vuln_summary.get("critical_count", 0)
        high = vuln_summary.get("high_count", 0)
        medium = vuln_summary.get("medium_count", 0)
        exploitable = vuln_summary.get("exploitable_count", 0)
        vuln_score = min(10.0, 1.0 + critical * 2.0 + high * 1.0 + medium * 0.3 + exploitable * 1.5)

    # Exposure score (internet-facing, public IP, etc.)
    exposure_score = 5.0
    cloud_metadata = asset.get("cloud_metadata", {})
    if cloud_metadata and cloud_metadata.get("public_ip"):
        exposure_score = 8.0
    security_controls = asset.get("security_controls", {}) or {}
    data_classification = asset.get("data_classification") or ""
    has_sensitive_data = data_classification.lower() in ["confidential", "restricted", "secret"]
    if has_sensitive_data:
        exposure_score = min(10.0, exposure_score + 2.0)

    # Threat score (based on security controls presence)
    threat_score = 5.0
    if security_controls:
        if not security_controls.get("edr_installed"):
            threat_score += 1.5
        if not security_controls.get("antivirus_installed"):
            threat_score += 1.0
        if not security_controls.get("firewall_enabled"):
            threat_score += 1.0
        if not security_controls.get("encryption_enabled") and has_sensitive_data:
            threat_score += 1.5
    threat_score = min(10.0, threat_score)

    # Calculate overall score (weighted average)
    overall_score = (
        criticality_score * 0.35 + vuln_score * 0.30 + exposure_score * 0.20 + threat_score * 0.15
    )
    overall_score = max(1.0, min(10.0, overall_score))

    return AssetRiskScore(
        overall_score=round(overall_score, 2),
        criticality_score=criticality_score,
        vulnerability_score=round(vuln_score, 2),
        exposure_score=round(exposure_score, 2),
        threat_score=round(threat_score, 2),
        has_sensitive_data=has_sensitive_data,
        is_internet_facing=bool(cloud_metadata and cloud_metadata.get("public_ip")),
        has_critical_vulnerabilities=bool(
            vuln_summary and vuln_summary.get("critical_count", 0) > 0
        ),
        days_since_last_scan=None,
        patch_compliance_percentage=None,
        active_threats_count=0,
        calculated_at=datetime.utcnow(),
        calculation_method="weighted_average",
        factors_considered=["criticality", "vulnerabilities", "exposure", "security_controls"],
    )


def log_activity(
    asset_id: str,
    activity_type: str,
    description: str,
    details: Dict[str, Any] = None,
    performed_by: str = None,
):
    """Log an activity for an asset"""
    activity_id = generate_id()
    activities_store[activity_id] = {
        "id": activity_id,
        "asset_id": asset_id,
        "activity_type": activity_type,
        "description": description,
        "details": details or {},
        "performed_by": performed_by,
        "timestamp": datetime.utcnow().isoformat(),
    }


def apply_search_filters(asset: Dict[str, Any], query: AssetSearchQuery) -> bool:
    """Check if an asset matches the search query"""
    # Full-text search
    if query.query:
        search_text = query.query.lower()
        searchable = f"{asset.get('name', '')} {asset.get('hostname', '')} {asset.get('fqdn', '')} {asset.get('description', '')} {asset.get('primary_ip', '')}"
        if search_text not in searchable.lower():
            return False

    # Type filter
    if query.asset_types and asset.get("asset_type") not in [t.value for t in query.asset_types]:
        return False

    # Status filter
    if query.statuses and asset.get("status") not in [s.value for s in query.statuses]:
        return False

    # Criticality filter
    if query.criticalities and asset.get("criticality") not in [
        c.value for c in query.criticalities
    ]:
        return False

    # Environment filter
    if query.environments and asset.get("environment") not in [e.value for e in query.environments]:
        return False

    # Discovery method filter
    if query.discovery_methods and asset.get("discovery_method") not in [
        d.value for d in query.discovery_methods
    ]:
        return False

    # Compliance status filter
    if query.compliance_statuses and asset.get("compliance_status") not in [
        c.value for c in query.compliance_statuses
    ]:
        return False

    # Cloud filters
    if query.is_cloud_asset is not None and asset.get("is_cloud_asset") != query.is_cloud_asset:
        return False

    if query.cloud_provider:
        cloud_meta = asset.get("cloud_metadata", {})
        if not cloud_meta or cloud_meta.get("provider") != query.cloud_provider:
            return False

    # Risk score filters
    if query.min_risk_score is not None:
        risk = asset.get("risk_score", {})
        if not risk or risk.get("overall_score", 0) < query.min_risk_score:
            return False

    if query.max_risk_score is not None:
        risk = asset.get("risk_score", {})
        if not risk or risk.get("overall_score", 10) > query.max_risk_score:
            return False

    # Tag filters
    if query.tags:
        asset_tags = set(asset.get("tags", []))
        query_tags = set(query.tags)
        if query.tags_match_all:
            if not query_tags.issubset(asset_tags):
                return False
        else:
            if not query_tags.intersection(asset_tags):
                return False

    # Security control filters
    security = asset.get("security_controls", {})
    if query.has_edr is not None:
        if security.get("edr_installed") != query.has_edr:
            return False

    if query.has_antivirus is not None:
        if security.get("antivirus_installed") != query.has_antivirus:
            return False

    if query.is_encrypted is not None:
        if security.get("encryption_enabled") != query.is_encrypted:
            return False

    # Vulnerability filters
    if query.has_critical_vulnerabilities is not None:
        vuln = asset.get("vulnerability_summary", {})
        has_critical = vuln.get("critical_count", 0) > 0
        if has_critical != query.has_critical_vulnerabilities:
            return False

    # OS filters
    if query.os_name:
        os_info = asset.get("operating_system", {})
        if not os_info or query.os_name.lower() not in os_info.get("name", "").lower():
            return False

    return True


# =============================================================================
# Asset CRUD Endpoints
# =============================================================================


@router.post("", response_model=Asset, status_code=201)
async def create_asset(asset: AssetCreate):
    """
    Create a new asset in the inventory.

    Automatically calculates risk score based on criticality, vulnerabilities,
    and security controls.
    """
    asset_id = generate_id()
    now = datetime.utcnow()

    asset_dict = asset.model_dump()
    asset_dict["id"] = asset_id
    asset_dict["first_seen"] = now.isoformat()
    asset_dict["last_seen"] = now.isoformat()
    asset_dict["created_at"] = now.isoformat()
    asset_dict["updated_at"] = now.isoformat()

    # Calculate initial risk score
    risk_score = calculate_risk_score(asset_dict)
    asset_dict["risk_score"] = risk_score.model_dump()

    assets_store[asset_id] = asset_dict

    # Log activity
    log_activity(
        asset_id,
        "created",
        f"Asset '{asset.name}' created",
        {
            "asset_type": asset.asset_type.value,
            "criticality": asset.criticality.value,
        },
    )

    logger.info(f"Created asset: {asset_id} - {asset.name}")
    return Asset(**asset_dict)


@router.get("", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    asset_type: Optional[AssetTypeEnum] = Query(None, description="Filter by asset type"),
    status: Optional[AssetStatusEnum] = Query(None, description="Filter by status"),
    criticality: Optional[AssetCriticalityEnum] = Query(None, description="Filter by criticality"),
    environment: Optional[AssetEnvironmentEnum] = Query(None, description="Filter by environment"),
    is_cloud: Optional[bool] = Query(None, description="Filter cloud assets"),
    sort_by: str = Query("last_seen", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
):
    """
    List all assets with pagination and filtering.
    """
    # Apply filters
    filtered = list(assets_store.values())

    if asset_type:
        filtered = [a for a in filtered if a.get("asset_type") == asset_type.value]
    if status:
        filtered = [a for a in filtered if a.get("status") == status.value]
    if criticality:
        filtered = [a for a in filtered if a.get("criticality") == criticality.value]
    if environment:
        filtered = [a for a in filtered if a.get("environment") == environment.value]
    if is_cloud is not None:
        filtered = [a for a in filtered if a.get("is_cloud_asset") == is_cloud]

    # Sort
    reverse = sort_order == "desc"
    try:
        filtered.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)
    except (TypeError, KeyError):
        pass

    # Paginate
    total = len(filtered)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    paginated = filtered[start:end]

    return AssetListResponse(
        assets=[Asset(**a) for a in paginated],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_prev=page > 1,
    )


@router.get("/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str):
    """
    Get a specific asset by ID.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")
    return Asset(**assets_store[asset_id])


@router.put("/{asset_id}", response_model=Asset)
async def update_asset(asset_id: str, update: AssetUpdate):
    """
    Update an existing asset.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset = assets_store[asset_id]
    update_data = update.model_dump(exclude_unset=True)

    # Track changes for activity log
    changes = {}
    for key, value in update_data.items():
        if key in asset and asset[key] != value:
            changes[key] = {"old": asset[key], "new": value}

    # Apply updates
    for key, value in update_data.items():
        if value is not None:
            asset[key] = value

    asset["updated_at"] = datetime.utcnow().isoformat()
    asset["last_seen"] = datetime.utcnow().isoformat()

    # Recalculate risk score
    risk_score = calculate_risk_score(asset)
    asset["risk_score"] = risk_score.model_dump()

    # Log activity
    if changes:
        log_activity(asset_id, "updated", "Asset updated", {"changes": changes})

    logger.info(f"Updated asset: {asset_id}")
    return Asset(**asset)


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str, soft_delete: bool = Query(True)):
    """
    Delete an asset. By default performs soft delete (sets status to decommissioned).
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    if soft_delete:
        assets_store[asset_id]["status"] = "decommissioned"
        assets_store[asset_id]["updated_at"] = datetime.utcnow().isoformat()
        log_activity(asset_id, "decommissioned", "Asset marked as decommissioned")
        return {"status": "success", "message": "Asset marked as decommissioned"}
    else:
        asset_name = assets_store[asset_id].get("name", "Unknown")
        del assets_store[asset_id]
        logger.info(f"Deleted asset: {asset_id}")
        return {"status": "success", "message": f"Asset '{asset_name}' permanently deleted"}


# =============================================================================
# Advanced Search
# =============================================================================


@router.post("/search", response_model=AssetListResponse)
async def search_assets(query: AssetSearchQuery):
    """
    Advanced asset search with comprehensive filtering options.
    """
    # Apply filters
    filtered = [a for a in assets_store.values() if apply_search_filters(a, query)]

    # Sort
    reverse = query.sort_order == "desc"
    try:
        filtered.sort(key=lambda x: x.get(query.sort_by, ""), reverse=reverse)
    except (TypeError, KeyError):
        pass

    # Paginate
    total = len(filtered)
    total_pages = math.ceil(total / query.page_size) if total > 0 else 1
    start = (query.page - 1) * query.page_size
    end = start + query.page_size
    paginated = filtered[start:end]

    return AssetListResponse(
        assets=[Asset(**a) for a in paginated],
        total=total,
        page=query.page,
        page_size=query.page_size,
        total_pages=total_pages,
        has_next=query.page < total_pages,
        has_prev=query.page > 1,
    )


# =============================================================================
# Asset Relationships
# =============================================================================


@router.post("/{asset_id}/relationships", response_model=AssetRelationship, status_code=201)
async def create_relationship(asset_id: str, relationship: AssetRelationshipCreate):
    """
    Create a relationship between two assets.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Source asset not found")
    if relationship.target_asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Target asset not found")

    rel_id = generate_id()
    now = datetime.utcnow()

    source_asset = assets_store[asset_id]
    target_asset = assets_store[relationship.target_asset_id]

    rel_dict = relationship.model_dump()
    rel_dict["id"] = rel_id
    rel_dict["source_asset_id"] = asset_id
    rel_dict["source_asset_name"] = source_asset.get("name", "Unknown")
    rel_dict["target_asset_name"] = target_asset.get("name", "Unknown")
    rel_dict["created_at"] = now.isoformat()
    rel_dict["updated_at"] = now.isoformat()

    relationships_store[rel_id] = rel_dict

    # Create reverse relationship if bidirectional
    if relationship.is_bidirectional:
        reverse_rel_id = generate_id()
        reverse_type_map = {
            "hosts": "hosted_by",
            "hosted_by": "hosts",
            "depends_on": "dependency_of",
            "dependency_of": "depends_on",
            "contains": "contained_by",
            "contained_by": "contains",
            "manages": "managed_by",
            "managed_by": "manages",
        }
        reverse_type = reverse_type_map.get(
            relationship.relationship_type.value, relationship.relationship_type.value
        )
        reverse_dict = {
            "id": reverse_rel_id,
            "source_asset_id": relationship.target_asset_id,
            "source_asset_name": target_asset.get("name", "Unknown"),
            "target_asset_id": asset_id,
            "target_asset_name": source_asset.get("name", "Unknown"),
            "relationship_type": reverse_type,
            "description": relationship.description,
            "metadata": relationship.metadata,
            "is_bidirectional": True,
            "confidence": relationship.confidence,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        relationships_store[reverse_rel_id] = reverse_dict

    logger.info(f"Created relationship: {asset_id} -> {relationship.target_asset_id}")
    return AssetRelationship(**rel_dict)


@router.get("/{asset_id}/relationships", response_model=AssetRelationshipListResponse)
async def get_asset_relationships(
    asset_id: str,
    relationship_type: Optional[RelationshipTypeEnum] = None,
    direction: str = Query("both", pattern="^(inbound|outbound|both)$"),
):
    """
    Get all relationships for an asset.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    relationships = []
    for rel in relationships_store.values():
        include = False

        if direction in ["outbound", "both"] and rel["source_asset_id"] == asset_id:
            include = True
        if direction in ["inbound", "both"] and rel["target_asset_id"] == asset_id:
            include = True

        if include:
            if relationship_type and rel["relationship_type"] != relationship_type.value:
                continue
            relationships.append(rel)

    return AssetRelationshipListResponse(
        relationships=[AssetRelationship(**r) for r in relationships],
        total=len(relationships),
    )


@router.delete("/relationships/{relationship_id}")
async def delete_relationship(relationship_id: str):
    """
    Delete a relationship between assets.
    """
    if relationship_id not in relationships_store:
        raise HTTPException(status_code=404, detail="Relationship not found")

    del relationships_store[relationship_id]
    return {"status": "success", "message": "Relationship deleted"}


# =============================================================================
# Asset Groups
# =============================================================================


@router.post("/groups", response_model=AssetGroup, status_code=201)
async def create_asset_group(group: AssetGroupCreate):
    """
    Create an asset group (static or dynamic).
    """
    group_id = generate_id()
    now = datetime.utcnow()

    group_dict = group.model_dump()
    group_dict["id"] = group_id
    group_dict["asset_count"] = len(group.asset_ids)
    group_dict["created_at"] = now.isoformat()
    group_dict["updated_at"] = now.isoformat()

    groups_store[group_id] = group_dict

    logger.info(f"Created asset group: {group_id} - {group.name}")
    return AssetGroup(**group_dict)


@router.get("/groups", response_model=AssetGroupListResponse)
async def list_asset_groups():
    """
    List all asset groups.
    """
    groups = list(groups_store.values())
    return AssetGroupListResponse(
        groups=[AssetGroup(**g) for g in groups],
        total=len(groups),
    )


@router.get("/groups/{group_id}", response_model=AssetGroup)
async def get_asset_group(group_id: str):
    """
    Get a specific asset group.
    """
    if group_id not in groups_store:
        raise HTTPException(status_code=404, detail="Asset group not found")
    return AssetGroup(**groups_store[group_id])


@router.put("/groups/{group_id}", response_model=AssetGroup)
async def update_asset_group(group_id: str, update: AssetGroupUpdate):
    """
    Update an asset group.
    """
    if group_id not in groups_store:
        raise HTTPException(status_code=404, detail="Asset group not found")

    group = groups_store[group_id]
    update_data = update.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        if value is not None:
            group[key] = value

    if "asset_ids" in update_data:
        group["asset_count"] = len(update_data["asset_ids"])

    group["updated_at"] = datetime.utcnow().isoformat()

    return AssetGroup(**group)


@router.delete("/groups/{group_id}")
async def delete_asset_group(group_id: str):
    """
    Delete an asset group.
    """
    if group_id not in groups_store:
        raise HTTPException(status_code=404, detail="Asset group not found")

    group_name = groups_store[group_id].get("name", "Unknown")
    del groups_store[group_id]
    return {"status": "success", "message": f"Group '{group_name}' deleted"}


@router.get("/groups/{group_id}/assets", response_model=AssetListResponse)
async def get_group_assets(
    group_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """
    Get all assets in a group.
    """
    if group_id not in groups_store:
        raise HTTPException(status_code=404, detail="Asset group not found")

    group = groups_store[group_id]

    if group["group_type"] == "static":
        # Static group - use stored asset IDs
        asset_ids = set(group.get("asset_ids", []))
        filtered = [a for a in assets_store.values() if a["id"] in asset_ids]
    else:
        # Dynamic group - apply filter query
        filter_query = group.get("filter_query")
        if filter_query:
            query = AssetSearchQuery(**filter_query)
            filtered = [a for a in assets_store.values() if apply_search_filters(a, query)]
        else:
            filtered = []

    # Paginate
    total = len(filtered)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    paginated = filtered[start:end]

    return AssetListResponse(
        assets=[Asset(**a) for a in paginated],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_prev=page > 1,
    )


@router.post("/groups/{group_id}/assets/{asset_id}")
async def add_asset_to_group(group_id: str, asset_id: str):
    """
    Add an asset to a static group.
    """
    if group_id not in groups_store:
        raise HTTPException(status_code=404, detail="Asset group not found")
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    group = groups_store[group_id]
    if group["group_type"] != "static":
        raise HTTPException(status_code=400, detail="Cannot manually add assets to dynamic groups")

    if asset_id not in group["asset_ids"]:
        group["asset_ids"].append(asset_id)
        group["asset_count"] = len(group["asset_ids"])
        group["updated_at"] = datetime.utcnow().isoformat()

    return {"status": "success", "message": "Asset added to group"}


@router.delete("/groups/{group_id}/assets/{asset_id}")
async def remove_asset_from_group(group_id: str, asset_id: str):
    """
    Remove an asset from a static group.
    """
    if group_id not in groups_store:
        raise HTTPException(status_code=404, detail="Asset group not found")

    group = groups_store[group_id]
    if group["group_type"] != "static":
        raise HTTPException(
            status_code=400, detail="Cannot manually remove assets from dynamic groups"
        )

    if asset_id in group["asset_ids"]:
        group["asset_ids"].remove(asset_id)
        group["asset_count"] = len(group["asset_ids"])
        group["updated_at"] = datetime.utcnow().isoformat()

    return {"status": "success", "message": "Asset removed from group"}


# =============================================================================
# Discovery Scans
# =============================================================================


@router.post("/discovery/scans", response_model=DiscoveryScan, status_code=201)
async def create_discovery_scan(scan_request: DiscoveryScanCreate):
    """
    Create a new asset discovery scan.
    """
    scan_id = generate_id()
    now = datetime.utcnow()

    scan_dict = {
        "id": scan_id,
        "name": scan_request.config.name,
        "config": scan_request.config.model_dump(),
        "status": "pending" if not scan_request.run_immediately else "running",
        "started_at": now.isoformat() if scan_request.run_immediately else None,
        "completed_at": None,
        "duration_seconds": None,
        "total_hosts_scanned": 0,
        "new_assets_found": 0,
        "updated_assets": 0,
        "failed_hosts": 0,
        "errors": [],
        "created_at": now.isoformat(),
        "created_by": None,
        "last_run_at": None,
    }

    scans_store[scan_id] = scan_dict

    # Simulate immediate scan completion (in production, this would be async)
    if scan_request.run_immediately:
        import random

        scan_dict["status"] = "completed"
        scan_dict["completed_at"] = datetime.utcnow().isoformat()
        scan_dict["duration_seconds"] = random.randint(30, 300)
        scan_dict["total_hosts_scanned"] = random.randint(10, 100)
        scan_dict["new_assets_found"] = random.randint(0, 10)
        scan_dict["updated_assets"] = random.randint(0, 20)
        scan_dict["last_run_at"] = scan_dict["completed_at"]

    logger.info(f"Created discovery scan: {scan_id}")
    return DiscoveryScan(**scan_dict)


@router.get("/discovery/scans", response_model=DiscoveryScanListResponse)
async def list_discovery_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
):
    """
    List all discovery scans.
    """
    scans = list(scans_store.values())
    if status:
        scans = [s for s in scans if s.get("status") == status]

    return DiscoveryScanListResponse(
        scans=[DiscoveryScan(**s) for s in scans],
        total=len(scans),
    )


@router.get("/discovery/scans/{scan_id}", response_model=DiscoveryScan)
async def get_discovery_scan(scan_id: str):
    """
    Get a specific discovery scan.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return DiscoveryScan(**scans_store[scan_id])


@router.post("/discovery/scans/{scan_id}/run")
async def run_discovery_scan(scan_id: str):
    """
    Manually trigger a discovery scan to run.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans_store[scan_id]
    if scan["status"] == "running":
        raise HTTPException(status_code=400, detail="Scan is already running")

    scan["status"] = "running"
    scan["started_at"] = datetime.utcnow().isoformat()

    # Simulate scan completion
    import random

    scan["status"] = "completed"
    scan["completed_at"] = datetime.utcnow().isoformat()
    scan["duration_seconds"] = random.randint(30, 300)
    scan["total_hosts_scanned"] = random.randint(10, 100)
    scan["new_assets_found"] = random.randint(0, 10)
    scan["updated_assets"] = random.randint(0, 20)
    scan["last_run_at"] = scan["completed_at"]

    return {"status": "success", "message": "Scan completed"}


@router.post("/discovery/scans/{scan_id}/cancel")
async def cancel_discovery_scan(scan_id: str):
    """
    Cancel a running discovery scan.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans_store[scan_id]
    if scan["status"] != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    scan["status"] = "cancelled"
    scan["completed_at"] = datetime.utcnow().isoformat()

    return {"status": "success", "message": "Scan cancelled"}


@router.get("/discovery/scans/{scan_id}/results", response_model=DiscoveryScanResult)
async def get_scan_results(scan_id: str):
    """
    Get detailed results from a completed scan.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans_store[scan_id]

    return DiscoveryScanResult(
        scan_id=scan_id,
        scan_name=scan["name"],
        status=scan["status"],
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        total_hosts_scanned=scan.get("total_hosts_scanned", 0),
        new_assets=[],
        updated_assets=[],
        failed_hosts=[],
        by_asset_type={},
        by_os={},
        by_network={},
    )


@router.delete("/discovery/scans/{scan_id}")
async def delete_discovery_scan(scan_id: str):
    """
    Delete a discovery scan configuration.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    del scans_store[scan_id]
    return {"status": "success", "message": "Scan deleted"}


# =============================================================================
# Network Topology
# =============================================================================


@router.post("/topology", response_model=NetworkTopology)
async def generate_topology(query: TopologyQuery):
    """
    Generate network topology visualization data.
    """
    nodes = []
    edges = []
    processed_assets = set()

    # Get starting assets
    if query.asset_ids:
        starting_assets = [assets_store[aid] for aid in query.asset_ids if aid in assets_store]
    elif query.asset_group_id:
        if query.asset_group_id in groups_store:
            group = groups_store[query.asset_group_id]
            starting_assets = [
                assets_store[aid] for aid in group.get("asset_ids", []) if aid in assets_store
            ]
        else:
            starting_assets = []
    else:
        # Default to all assets
        starting_assets = list(assets_store.values())

    # Apply type filter
    if query.asset_types:
        type_values = [t.value for t in query.asset_types]
        starting_assets = [a for a in starting_assets if a.get("asset_type") in type_values]

    # Create nodes
    for asset in starting_assets:
        asset_id = asset["id"]
        if asset_id in processed_assets:
            continue

        processed_assets.add(asset_id)
        nodes.append(
            TopologyNode(
                id=asset_id,
                asset_id=asset_id,
                asset_name=asset.get("name", "Unknown"),
                asset_type=AssetTypeEnum(asset.get("asset_type", "unknown")),
                ip_address=asset.get("primary_ip"),
                status=AssetStatusEnum(asset.get("status", "unknown")),
                criticality=AssetCriticalityEnum(asset.get("criticality", "medium")),
                risk_score=asset.get("risk_score", {}).get("overall_score"),
            )
        )

    # Create edges from relationships
    for rel in relationships_store.values():
        source_id = rel["source_asset_id"]
        target_id = rel["target_asset_id"]

        if source_id in processed_assets and target_id in processed_assets:
            if query.include_relationships:
                rel_type = rel["relationship_type"]
                if rel_type not in [r.value for r in query.include_relationships]:
                    continue

            edges.append(
                TopologyEdge(
                    id=rel["id"],
                    source=source_id,
                    target=target_id,
                    relationship_type=RelationshipTypeEnum(rel["relationship_type"]),
                    label=rel.get("description"),
                    weight=rel.get("confidence", 1.0),
                )
            )

    return NetworkTopology(
        nodes=nodes,
        edges=edges,
        total_nodes=len(nodes),
        total_edges=len(edges),
        generated_at=datetime.utcnow(),
        filters_applied=query.model_dump(exclude_unset=True),
        layout_algorithm=query.layout_algorithm,
    )


@router.get("/{asset_id}/topology", response_model=NetworkTopology)
async def get_asset_topology(
    asset_id: str,
    max_depth: int = Query(2, ge=1, le=5, description="Maximum depth of relationships"),
):
    """
    Get network topology centered on a specific asset.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    query = TopologyQuery(
        asset_ids=[asset_id],
        max_depth=max_depth,
    )
    return await generate_topology(query)


# =============================================================================
# CMDB Integration
# =============================================================================


@router.post("/cmdb/configs", status_code=201)
async def create_cmdb_config(config: CMDBSyncConfig):
    """
    Create a CMDB synchronization configuration.
    """
    config_id = generate_id()
    config_dict = config.model_dump()
    config_dict["id"] = config_id
    config_dict["created_at"] = datetime.utcnow().isoformat()

    cmdb_configs_store[config_id] = config_dict

    return {"id": config_id, "status": "success", "message": "CMDB config created"}


@router.get("/cmdb/configs")
async def list_cmdb_configs():
    """
    List all CMDB synchronization configurations.
    """
    return {"configs": list(cmdb_configs_store.values()), "total": len(cmdb_configs_store)}


@router.get("/cmdb/configs/{config_id}")
async def get_cmdb_config(config_id: str):
    """
    Get a specific CMDB configuration.
    """
    if config_id not in cmdb_configs_store:
        raise HTTPException(status_code=404, detail="CMDB config not found")
    return cmdb_configs_store[config_id]


@router.post("/cmdb/configs/{config_id}/sync", response_model=CMDBSyncResult)
async def trigger_cmdb_sync(config_id: str):
    """
    Manually trigger CMDB synchronization.
    """
    if config_id not in cmdb_configs_store:
        raise HTTPException(status_code=404, detail="CMDB config not found")

    now = datetime.utcnow()

    # Simulate sync result
    import random

    result = CMDBSyncResult(
        config_id=config_id,
        sync_type="manual",
        started_at=now,
        completed_at=datetime.utcnow(),
        status="completed",
        records_processed=random.randint(10, 100),
        imported=random.randint(0, 20),
        exported=random.randint(0, 20),
        updated=random.randint(0, 30),
        deleted=0,
        failed=random.randint(0, 3),
        errors=[],
    )

    # Update last sync time
    cmdb_configs_store[config_id]["last_sync_at"] = result.completed_at.isoformat()

    return result


@router.delete("/cmdb/configs/{config_id}")
async def delete_cmdb_config(config_id: str):
    """
    Delete a CMDB configuration.
    """
    if config_id not in cmdb_configs_store:
        raise HTTPException(status_code=404, detail="CMDB config not found")

    del cmdb_configs_store[config_id]
    return {"status": "success", "message": "CMDB config deleted"}


# =============================================================================
# Import/Export
# =============================================================================


@router.post("/import", response_model=AssetImportResult)
async def import_assets(
    file: UploadFile = File(...),
    config: AssetImportConfig = Body(default_factory=AssetImportConfig),
):
    """
    Import assets from a file (CSV, JSON, or XLSX).
    """
    import_id = generate_id()
    now = datetime.utcnow()

    # Simulate import
    import random

    total = random.randint(10, 50)
    imported = random.randint(int(total * 0.7), total)
    updated = random.randint(0, int(total * 0.2))
    failed = total - imported - updated

    result = AssetImportResult(
        import_id=import_id,
        filename=file.filename or "unknown",
        format=config.format,
        started_at=now,
        completed_at=datetime.utcnow(),
        status="completed",
        total_records=total,
        imported=imported,
        updated=updated,
        skipped=0,
        failed=failed,
        errors=[],
        warnings=[],
        imported_asset_ids=[],
    )

    logger.info(f"Imported assets from {file.filename}: {imported} imported, {updated} updated")
    return result


@router.post("/export", response_model=AssetExportResult)
async def export_assets(config: AssetExportConfig):
    """
    Export assets to a file (CSV, JSON, or XLSX).
    """
    export_id = generate_id()
    now = datetime.utcnow()

    # Get assets to export
    if config.filter_query:
        filtered = [
            a for a in assets_store.values() if apply_search_filters(a, config.filter_query)
        ]
    else:
        filtered = list(assets_store.values())

    result = AssetExportResult(
        export_id=export_id,
        format=config.format,
        total_assets=len(filtered),
        file_size_bytes=len(filtered) * 1024,  # Estimate
        download_url=f"/api/v1/assets/export/{export_id}/download",
        expires_at=now + timedelta(hours=24),
        created_at=now,
    )

    return result


@router.get("/export/{export_id}/download")
async def download_export(export_id: str):
    """
    Download an exported file.
    """
    # In production, this would retrieve the actual file
    return {"status": "success", "message": "Download started", "export_id": export_id}


# =============================================================================
# Statistics & Trends
# =============================================================================


@router.get("/statistics", response_model=AssetStatistics)
async def get_asset_statistics():
    """
    Get comprehensive asset inventory statistics.
    """
    assets = list(assets_store.values())
    total = len(assets)

    # Count by status
    by_status = {}
    for asset in assets:
        status = asset.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1

    # Count by type
    by_type = {}
    for asset in assets:
        asset_type = asset.get("asset_type", "unknown")
        by_type[asset_type] = by_type.get(asset_type, 0) + 1

    # Count by criticality
    by_criticality = {}
    for asset in assets:
        crit = asset.get("criticality", "unknown")
        by_criticality[crit] = by_criticality.get(crit, 0) + 1

    # Count by environment
    by_environment = {}
    for asset in assets:
        env = asset.get("environment", "unknown")
        by_environment[env] = by_environment.get(env, 0) + 1

    # Count by compliance status
    by_compliance = {}
    for asset in assets:
        comp = asset.get("compliance_status", "unknown")
        by_compliance[comp] = by_compliance.get(comp, 0) + 1

    # Risk distribution
    risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    total_risk = 0.0
    risk_count = 0
    for asset in assets:
        risk = asset.get("risk_score", {})
        if risk:
            score = risk.get("overall_score", 5.0)
            total_risk += score
            risk_count += 1
            if score <= 3:
                risk_distribution["low"] += 1
            elif score <= 5:
                risk_distribution["medium"] += 1
            elif score <= 7:
                risk_distribution["high"] += 1
            else:
                risk_distribution["critical"] += 1

    avg_risk = total_risk / risk_count if risk_count > 0 else 0.0

    # Cloud assets
    cloud_assets = sum(1 for a in assets if a.get("is_cloud_asset"))
    by_cloud_provider = {}
    for asset in assets:
        cloud = asset.get("cloud_metadata", {})
        if cloud:
            provider = cloud.get("provider", "unknown")
            by_cloud_provider[provider] = by_cloud_provider.get(provider, 0) + 1

    # Security control gaps
    assets_without_edr = sum(
        1 for a in assets if not a.get("security_controls", {}).get("edr_installed")
    )
    assets_without_av = sum(
        1 for a in assets if not a.get("security_controls", {}).get("antivirus_installed")
    )
    assets_with_critical = sum(
        1 for a in assets if a.get("vulnerability_summary", {}).get("critical_count", 0) > 0
    )

    # Recent activity (simulated)
    new_7d = sum(1 for a in assets if a.get("status") == "discovered")
    missing = sum(1 for a in assets if a.get("status") == "missing")

    return AssetStatistics(
        total_assets=total,
        by_status=by_status,
        by_type=by_type,
        by_criticality=by_criticality,
        by_environment=by_environment,
        by_compliance_status=by_compliance,
        risk_distribution=risk_distribution,
        average_risk_score=round(avg_risk, 2),
        new_assets_7d=new_7d,
        updated_assets_7d=0,
        missing_assets=missing,
        cloud_assets=cloud_assets,
        by_cloud_provider=by_cloud_provider,
        assets_without_edr=assets_without_edr,
        assets_without_antivirus=assets_without_av,
        assets_with_critical_vulns=assets_with_critical,
        generated_at=datetime.utcnow(),
    )


@router.get("/trends", response_model=AssetTrendData)
async def get_asset_trends(
    period: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    days: int = Query(30, ge=7, le=365),
):
    """
    Get asset inventory trends over time.
    """
    # Generate simulated trend data
    import random

    data_points = []
    current_date = datetime.utcnow()

    if period == "daily":
        interval = timedelta(days=1)
        num_points = min(days, 30)
    elif period == "weekly":
        interval = timedelta(weeks=1)
        num_points = min(days // 7, 12)
    else:  # monthly
        interval = timedelta(days=30)
        num_points = min(days // 30, 12)

    base_total = len(assets_store) or 100

    for i in range(num_points):
        point_date = current_date - (interval * (num_points - 1 - i))
        variation = random.uniform(-0.05, 0.1)
        total = int(base_total * (1 + variation))

        data_points.append(
            {
                "date": point_date.isoformat(),
                "total": total,
                "new": random.randint(0, 10),
                "decommissioned": random.randint(0, 5),
                "by_type": {"server": int(total * 0.3), "workstation": int(total * 0.5)},
                "by_criticality": {"critical": int(total * 0.1), "high": int(total * 0.2)},
                "avg_risk": round(random.uniform(4.0, 6.0), 2),
            }
        )

    return AssetTrendData(
        period=period,
        data_points=data_points,
    )


# =============================================================================
# Activity Log
# =============================================================================


@router.get("/{asset_id}/activity", response_model=AssetActivityListResponse)
async def get_asset_activity(
    asset_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    """
    Get activity log for an asset.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    activities = [a for a in activities_store.values() if a["asset_id"] == asset_id]
    activities.sort(key=lambda x: x["timestamp"], reverse=True)

    total = len(activities)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = activities[start:end]

    return AssetActivityListResponse(
        activities=[AssetActivity(**a) for a in paginated],
        total=total,
        page=page,
        page_size=page_size,
    )


# =============================================================================
# Bulk Operations
# =============================================================================


@router.post("/bulk/update", response_model=BulkAssetUpdateResult)
async def bulk_update_assets(bulk_update: BulkAssetUpdate):
    """
    Bulk update multiple assets.
    """
    updated = 0
    failed = 0
    errors = []

    update_data = bulk_update.updates.model_dump(exclude_unset=True)

    for asset_id in bulk_update.asset_ids:
        if asset_id not in assets_store:
            failed += 1
            errors.append({"asset_id": asset_id, "error": "Asset not found"})
            continue

        try:
            asset = assets_store[asset_id]
            for key, value in update_data.items():
                if value is not None:
                    asset[key] = value
            asset["updated_at"] = datetime.utcnow().isoformat()

            # Recalculate risk score
            risk_score = calculate_risk_score(asset)
            asset["risk_score"] = risk_score.model_dump()

            updated += 1
        except Exception as e:
            failed += 1
            errors.append({"asset_id": asset_id, "error": str(e)})

    return BulkAssetUpdateResult(
        status=StatusEnum.SUCCESS if failed == 0 else StatusEnum.PARTIAL,
        total=len(bulk_update.asset_ids),
        updated=updated,
        failed=failed,
        errors=errors,
    )


@router.post("/bulk/tag", response_model=BulkOperationResult)
async def bulk_tag_assets(bulk_tag: BulkAssetTag):
    """
    Bulk add or remove tags from assets.
    """
    succeeded = 0
    failed = 0
    errors = []

    for asset_id in bulk_tag.asset_ids:
        if asset_id not in assets_store:
            failed += 1
            errors.append({"asset_id": asset_id, "error": "Asset not found"})
            continue

        try:
            asset = assets_store[asset_id]
            current_tags = set(asset.get("tags", []))

            # Add tags
            for tag in bulk_tag.tags_to_add:
                current_tags.add(tag)

            # Remove tags
            for tag in bulk_tag.tags_to_remove:
                current_tags.discard(tag)

            asset["tags"] = list(current_tags)
            asset["updated_at"] = datetime.utcnow().isoformat()
            succeeded += 1
        except Exception as e:
            failed += 1
            errors.append({"asset_id": asset_id, "error": str(e)})

    return BulkOperationResult(
        operation="tag",
        status=StatusEnum.SUCCESS if failed == 0 else StatusEnum.PARTIAL,
        total=len(bulk_tag.asset_ids),
        succeeded=succeeded,
        failed=failed,
        errors=errors,
    )


@router.post("/bulk/delete", response_model=BulkOperationResult)
async def bulk_delete_assets(bulk_delete: BulkAssetDelete):
    """
    Bulk delete (or decommission) assets.
    """
    succeeded = 0
    failed = 0
    errors = []

    for asset_id in bulk_delete.asset_ids:
        if asset_id not in assets_store:
            failed += 1
            errors.append({"asset_id": asset_id, "error": "Asset not found"})
            continue

        try:
            if bulk_delete.soft_delete:
                assets_store[asset_id]["status"] = "decommissioned"
                assets_store[asset_id]["updated_at"] = datetime.utcnow().isoformat()
                log_activity(asset_id, "decommissioned", bulk_delete.reason or "Bulk decommission")
            else:
                del assets_store[asset_id]
            succeeded += 1
        except Exception as e:
            failed += 1
            errors.append({"asset_id": asset_id, "error": str(e)})

    return BulkOperationResult(
        operation="delete" if not bulk_delete.soft_delete else "decommission",
        status=StatusEnum.SUCCESS if failed == 0 else StatusEnum.PARTIAL,
        total=len(bulk_delete.asset_ids),
        succeeded=succeeded,
        failed=failed,
        errors=errors,
    )


@router.post("/bulk/recalculate-risk", response_model=BulkOperationResult)
async def bulk_recalculate_risk(asset_ids: List[str] = Body(None)):
    """
    Recalculate risk scores for assets (all if no IDs provided).
    """
    target_ids = asset_ids if asset_ids else list(assets_store.keys())

    succeeded = 0
    failed = 0
    errors = []

    for asset_id in target_ids:
        if asset_id not in assets_store:
            failed += 1
            errors.append({"asset_id": asset_id, "error": "Asset not found"})
            continue

        try:
            asset = assets_store[asset_id]
            risk_score = calculate_risk_score(asset)
            asset["risk_score"] = risk_score.model_dump()
            asset["updated_at"] = datetime.utcnow().isoformat()
            succeeded += 1
        except Exception as e:
            failed += 1
            errors.append({"asset_id": asset_id, "error": str(e)})

    return BulkOperationResult(
        operation="recalculate_risk",
        status=StatusEnum.SUCCESS if failed == 0 else StatusEnum.PARTIAL,
        total=len(target_ids),
        succeeded=succeeded,
        failed=failed,
        errors=errors,
    )


# =============================================================================
# Risk Score Endpoints
# =============================================================================


@router.get("/{asset_id}/risk-score", response_model=AssetRiskScore)
async def get_asset_risk_score(asset_id: str):
    """
    Get detailed risk score for an asset.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset = assets_store[asset_id]

    # Recalculate to ensure fresh score
    return calculate_risk_score(asset)


@router.post("/{asset_id}/risk-score/recalculate", response_model=AssetRiskScore)
async def recalculate_asset_risk(asset_id: str):
    """
    Force recalculation of an asset's risk score.
    """
    if asset_id not in assets_store:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset = assets_store[asset_id]
    risk_score = calculate_risk_score(asset)
    asset["risk_score"] = risk_score.model_dump()
    asset["updated_at"] = datetime.utcnow().isoformat()

    log_activity(
        asset_id, "risk_recalculated", f"Risk score recalculated: {risk_score.overall_score}"
    )

    return risk_score


# =============================================================================
# Health Check
# =============================================================================


@router.get("/health", response_model=AssetHealthCheck)
async def health_check():
    """
    Health check for the asset inventory system.
    """
    total_assets = len(assets_store)
    pending_discoveries = sum(1 for s in scans_store.values() if s.get("status") == "running")

    # Determine overall status
    issues = []
    recommendations = []

    if total_assets == 0:
        recommendations.append("No assets in inventory. Consider running a discovery scan.")

    # Check for stale assets
    stale_threshold = datetime.utcnow() - timedelta(days=7)
    stale_count = 0
    for asset in assets_store.values():
        last_seen_str = asset.get("last_seen")
        if last_seen_str:
            last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            if last_seen < stale_threshold:
                stale_count += 1

    if stale_count > 0:
        issues.append(
            {
                "type": "stale_assets",
                "count": stale_count,
                "message": f"{stale_count} assets not seen in 7+ days",
            }
        )
        recommendations.append(f"Review {stale_count} stale assets that haven't been seen recently")

    # Check security control gaps
    missing_edr = sum(
        1 for a in assets_store.values() if not a.get("security_controls", {}).get("edr_installed")
    )
    if missing_edr > total_assets * 0.2:  # More than 20% without EDR
        issues.append(
            {
                "type": "security_gap",
                "count": missing_edr,
                "message": f"{missing_edr} assets without EDR",
            }
        )
        recommendations.append(f"Deploy EDR to {missing_edr} assets")

    # Determine status
    if len(issues) > 2:
        status = "degraded"
    elif len(issues) > 0:
        status = "healthy"  # Some issues but not critical
    else:
        status = "healthy"

    return AssetHealthCheck(
        status=status,
        timestamp=datetime.utcnow(),
        database_status="healthy",
        discovery_engine_status="healthy" if pending_discoveries < 5 else "degraded",
        cmdb_sync_status="healthy",
        total_assets=total_assets,
        assets_synced_today=0,
        pending_discoveries=pending_discoveries,
        failed_syncs_24h=0,
        issues=issues,
        recommendations=recommendations,
    )
