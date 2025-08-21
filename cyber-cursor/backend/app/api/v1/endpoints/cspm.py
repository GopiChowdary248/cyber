from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json

from app.core.database import get_db
from app.core.security import get_current_user
from app.schemas.auth import User
from app.schemas.cspm_schemas import *
from app.models.cspm_models import *

router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])

# ============================================================================
# Dashboard Endpoints
# ============================================================================

@router.get("/dashboard/summary", response_model=DashboardResponse)
async def get_dashboard_summary(
    project_id: Optional[uuid.UUID] = Query(None, description="Filter by project"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get CSPM dashboard summary with risk metrics and latest findings"""
    try:
        # Build base query filters
        base_filters = []
        if project_id:
            base_filters.append(Asset.project_id == project_id)
        
        # Get summary statistics
        summary_query = select(
            func.count(Asset.id).label("total_assets"),
            func.count(Finding.id).label("total_findings"),
            func.count(Finding.id).filter(Finding.severity == FindingSeverity.CRITICAL).label("critical_findings"),
            func.count(Finding.id).filter(Finding.severity == FindingSeverity.HIGH).label("high_findings"),
            func.count(Finding.id).filter(Finding.severity == FindingSeverity.MEDIUM).label("medium_findings"),
            func.count(Finding.id).filter(Finding.severity == FindingSeverity.LOW).label("low_findings")
        ).select_from(Asset).outerjoin(Finding, Asset.id == Finding.asset_id)
        
        if base_filters:
            summary_query = summary_query.where(and_(*base_filters))
        
        summary_result = await db.execute(summary_query)
        summary_data = summary_result.first()
        
        # Calculate compliance score
        total_checks = summary_data.total_findings or 0
        failed_checks = (summary_data.critical_findings or 0) + (summary_data.high_findings or 0)
        compliance_score = max(0, 100 - (failed_checks / max(total_checks, 1)) * 100) if total_checks > 0 else 100
        
        # Get last sync time
        last_sync_query = select(func.max(Connector.last_synced)).select_from(Connector)
        if project_id:
            last_sync_query = last_sync_query.where(Connector.project_id == project_id)
        last_sync_result = await db.execute(last_sync_query)
        last_sync = last_sync_result.scalar()
        
        summary = DashboardSummary(
            total_assets=summary_data.total_assets or 0,
            total_findings=total_checks,
            critical_findings=summary_data.critical_findings or 0,
            high_findings=summary_data.high_findings or 0,
            medium_findings=summary_data.medium_findings or 0,
            low_findings=summary_data.low_findings or 0,
            compliance_score=round(compliance_score, 2),
            last_sync=last_sync
        )
        
        # Get latest findings
        latest_findings_query = select(
            Finding.id, Finding.title, Finding.severity, Finding.created_at, Finding.status,
            Asset.name.label("asset_name"), Asset.resource_type
        ).select_from(Finding).join(Asset, Finding.asset_id == Asset.id)
        
        if base_filters:
            latest_findings_query = latest_findings_query.where(and_(*base_filters))
        
        latest_findings_query = latest_findings_query.order_by(desc(Finding.created_at)).limit(10)
        latest_findings_result = await db.execute(latest_findings_query)
        latest_findings = []
        
        for row in latest_findings_result:
            latest_findings.append(FindingSummary(
                id=row.id,
                title=row.title,
                severity=row.severity,
                asset_name=row.asset_name or "Unknown",
                resource_type=row.resource_type,
                created_at=row.created_at,
                status=row.status
            ))
        
        # Get risk heatmap
        risk_heatmap_query = select(
            Asset.id, Asset.name, Asset.resource_type, Asset.risk_score,
            func.count(Finding.id).label("findings_count"),
            func.count(Finding.id).filter(Finding.severity == FindingSeverity.CRITICAL).label("critical_findings")
        ).select_from(Asset).outerjoin(Finding, Asset.id == Finding.asset_id)
        
        if base_filters:
            risk_heatmap_query = risk_heatmap_query.where(and_(*base_filters))
        
        risk_heatmap_query = risk_heatmap_query.group_by(Asset.id).order_by(desc(Asset.risk_score)).limit(20)
        risk_heatmap_result = await db.execute(risk_heatmap_query)
        
        heatmap_items = []
        high_risk_assets = 0
        
        for row in risk_heatmap_result:
            if row.risk_score and row.risk_score > 70:
                high_risk_assets += 1
            
            heatmap_items.append(RiskHeatmapItem(
                asset_id=row.id,
                asset_name=row.name or "Unknown",
                resource_type=row.resource_type,
                risk_score=row.risk_score or 0.0,
                findings_count=row.findings_count or 0,
                critical_findings=row.critical_findings or 0
            ))
        
        risk_heatmap = RiskHeatmapResponse(
            items=heatmap_items,
            total_assets=summary.total_assets,
            high_risk_assets=high_risk_assets
        )
        
        # Get top misconfigurations
        top_misconfigs_query = select(
            Policy.name, Policy.category, func.count(Finding.id).label("count")
        ).select_from(Policy).join(Finding, Policy.id == Finding.policy_id)
        
        if base_filters:
            top_misconfigs_query = top_misconfigs_query.join(Asset, Finding.asset_id == Asset.id).where(and_(*base_filters))
        
        top_misconfigs_query = top_misconfigs_query.group_by(Policy.id).order_by(desc(func.count(Finding.id))).limit(10)
        top_misconfigs_result = await db.execute(top_misconfigs_query)
        
        top_misconfigs = []
        for row in top_misconfigs_result:
            top_misconfigs.append({
                "policy_name": row.name,
                "category": row.category,
                "count": row.count
            })
        
        return DashboardResponse(
            summary=summary,
            latest_findings=latest_findings,
            risk_heatmap=risk_heatmap,
            top_misconfigs=top_misconfigs
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard summary: {str(e)}")

@router.get("/dashboard/heatmap", response_model=RiskHeatmapResponse)
async def get_risk_heatmap(
    project_id: Optional[uuid.UUID] = Query(None, description="Filter by project"),
    limit: int = Query(50, ge=1, le=100, description="Number of assets to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get risk heatmap data for assets"""
    try:
        base_filters = []
        if project_id:
            base_filters.append(Asset.project_id == project_id)
        
        query = select(
            Asset.id, Asset.name, Asset.resource_type, Asset.risk_score,
            func.count(Finding.id).label("findings_count"),
            func.count(Finding.id).filter(Finding.severity == FindingSeverity.CRITICAL).label("critical_findings")
        ).select_from(Asset).outerjoin(Finding, Asset.id == Finding.asset_id)
        
        if base_filters:
            query = query.where(and_(*base_filters))
        
        query = query.group_by(Asset.id).order_by(desc(Asset.risk_score)).limit(limit)
        result = await db.execute(query)
        
        items = []
        high_risk_assets = 0
        
        for row in result:
            if row.risk_score and row.risk_score > 70:
                high_risk_assets += 1
            
            items.append(RiskHeatmapItem(
                asset_id=row.id,
                asset_name=row.name or "Unknown",
                resource_type=row.resource_type,
                risk_score=row.risk_score or 0.0,
                findings_count=row.findings_count or 0,
                critical_findings=row.critical_findings or 0
            ))
        
        # Get total count for pagination info
        total_query = select(func.count(Asset.id)).select_from(Asset)
        if base_filters:
            total_query = total_query.where(and_(*base_filters))
        total_result = await db.execute(total_query)
        total_assets = total_result.scalar()
        
        return RiskHeatmapResponse(
            items=items,
            total_assets=total_assets,
            high_risk_assets=high_risk_assets
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get risk heatmap: {str(e)}")

# ============================================================================
# Organization & Project Endpoints
# ============================================================================

@router.post("/organizations", response_model=OrganizationResponse)
async def create_organization(
    organization: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new organization"""
    try:
        db_org = Organization(**organization.dict())
        db.add(db_org)
        await db.commit()
        await db.refresh(db_org)
        return db_org
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create organization: {str(e)}")

@router.get("/organizations", response_model=List[OrganizationResponse])
async def get_organizations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all organizations"""
    try:
        result = await db.execute(select(Organization))
        return result.scalars().all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get organizations: {str(e)}")

@router.post("/projects", response_model=ProjectResponse)
async def create_project(
    project: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new project"""
    try:
        # Verify organization exists
        org_result = await db.execute(select(Organization).where(Organization.id == project.org_id))
        if not org_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Organization not found")
        
        db_project = Project(**project.dict())
        db.add(db_project)
        await db.commit()
        await db.refresh(db_project)
        return db_project
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create project: {str(e)}")

@router.get("/projects", response_model=List[ProjectResponse])
async def get_projects(
    org_id: Optional[uuid.UUID] = Query(None, description="Filter by organization"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all projects"""
    try:
        query = select(Project)
        if org_id:
            query = query.where(Project.org_id == org_id)
        
        result = await db.execute(query)
        return result.scalars().all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get projects: {str(e)}")

# ============================================================================
# Connector Endpoints
# ============================================================================

@router.post("/connectors", response_model=ConnectorResponse)
async def create_connector(
    connector: ConnectorCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new cloud connector"""
    try:
        # Verify project exists
        project_result = await db.execute(select(Project).where(Project.id == connector.project_id))
        if not project_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found")
        
        db_connector = Connector(**connector.dict())
        db.add(db_connector)
        await db.commit()
        await db.refresh(db_connector)
        
        # TODO: Add background task to validate connector permissions
        # background_tasks.add_task(validate_connector_permissions, db_connector.id)
        
        return db_connector
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create connector: {str(e)}")

@router.get("/connectors", response_model=List[ConnectorResponse])
async def get_connectors(
    project_id: Optional[uuid.UUID] = Query(None, description="Filter by project"),
    type: Optional[CloudProvider] = Query(None, description="Filter by cloud provider"),
    status: Optional[ConnectorStatus] = Query(None, description="Filter by status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all connectors with optional filtering"""
    try:
        query = select(Connector)
        
        filters = []
        if project_id:
            filters.append(Connector.project_id == project_id)
        if type:
            filters.append(Connector.type == type)
        if status:
            filters.append(Connector.status == status)
        
        if filters:
            query = query.where(and_(*filters))
        
        result = await db.execute(query)
        return result.scalars().all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get connectors: {str(e)}")

@router.get("/connectors/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific connector details"""
    try:
        result = await db.execute(select(Connector).where(Connector.id == connector_id))
        connector = result.scalar_one_or_none()
        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")
        return connector
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get connector: {str(e)}")

@router.post("/connectors/{connector_id}/sync", response_model=ConnectorSyncResponse)
async def sync_connector(
    connector_id: uuid.UUID,
    sync_request: ConnectorSyncRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger connector synchronization"""
    try:
        # Verify connector exists
        connector_result = await db.execute(select(Connector).where(Connector.id == connector_id))
        connector = connector_result.scalar_one_or_none()
        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")
        
        # Create sync job
        job = Job(
            connector_id=connector_id,
            project_id=connector.project_id,
            type=JobType.SYNC,
            parameters=sync_request.dict()
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        
        # TODO: Add background task to perform actual sync
        # background_tasks.add_task(sync_connector_assets, job.id, connector_id)
        
        return ConnectorSyncResponse(
            job_id=job.id,
            status="pending",
            message="Sync job created successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create sync job: {str(e)}")

# ============================================================================
# Asset Endpoints
# ============================================================================

@router.get("/assets", response_model=PaginatedResponse)
async def get_assets(
    cloud: Optional[CloudProvider] = Query(None, description="Filter by cloud provider"),
    type: Optional[str] = Query(None, description="Filter by resource type"),
    region: Optional[str] = Query(None, description="Filter by region"),
    risk_score_min: Optional[float] = Query(None, ge=0, le=100, description="Minimum risk score"),
    risk_score_max: Optional[float] = Query(None, ge=0, le=100, description="Maximum risk score"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get assets with pagination and filtering"""
    try:
        # Build query with filters
        query = select(Asset)
        count_query = select(func.count(Asset.id))
        
        filters = []
        if cloud:
            filters.append(Asset.cloud == cloud)
        if type:
            filters.append(Asset.resource_type == type)
        if region:
            filters.append(Asset.region == region)
        if risk_score_min is not None:
            filters.append(Asset.risk_score >= risk_score_min)
        if risk_score_max is not None:
            filters.append(Asset.risk_score <= risk_score_max)
        
        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))
        
        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        query = query.offset((page - 1) * per_page).limit(per_page)
        query = query.order_by(desc(Asset.risk_score), desc(Asset.last_seen))
        
        result = await db.execute(query)
        assets = result.scalars().all()
        
        # Convert to response models
        asset_responses = []
        for asset in assets:
            asset_responses.append(AssetResponse(
                id=asset.id,
                connector_id=asset.connector_id,
                project_id=asset.project_id,
                cloud=asset.cloud,
                resource_id=asset.resource_id,
                resource_type=asset.resource_type,
                name=asset.name,
                region=asset.region,
                metadata=asset.metadata,
                tags=asset.tags,
                relationships=asset.relationships,
                first_seen=asset.first_seen,
                last_seen=asset.last_seen,
                risk_score=float(asset.risk_score) if asset.risk_score else 0.0
            ))
        
        pages = (total + per_page - 1) // per_page
        
        return PaginatedResponse(
            items=asset_responses,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get assets: {str(e)}")

@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific asset details"""
    try:
        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        return AssetResponse(
            id=asset.id,
            connector_id=asset.connector_id,
            project_id=asset.project_id,
            cloud=asset.cloud,
            resource_id=asset.resource_id,
            resource_type=asset.resource_type,
            name=asset.name,
            region=asset.region,
            metadata=asset.metadata,
            tags=asset.tags,
            relationships=asset.relationships,
            first_seen=asset.first_seen,
            last_seen=asset.last_seen,
            risk_score=float(asset.risk_score) if asset.risk_score else 0.0
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get asset: {str(e)}")

# ============================================================================
# Finding Endpoints
# ============================================================================

@router.get("/findings", response_model=PaginatedResponse)
async def get_findings(
    severity: Optional[FindingSeverity] = Query(None, description="Filter by severity"),
    status: Optional[FindingStatus] = Query(None, description="Filter by status"),
    asset_id: Optional[uuid.UUID] = Query(None, description="Filter by asset"),
    policy_id: Optional[uuid.UUID] = Query(None, description="Filter by policy"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get findings with pagination and filtering"""
    try:
        # Build query with filters
        query = select(Finding).join(Asset, Finding.asset_id == Asset.id)
        count_query = select(func.count(Finding.id)).select_from(Finding).join(Asset, Finding.asset_id == Asset.id)
        
        filters = []
        if severity:
            filters.append(Finding.severity == severity)
        if status:
            filters.append(Finding.status == status)
        if asset_id:
            filters.append(Finding.asset_id == asset_id)
        if policy_id:
            filters.append(Finding.policy_id == policy_id)
        
        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))
        
        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination and ordering
        query = query.offset((page - 1) * per_page).limit(per_page)
        query = query.order_by(desc(Finding.severity), desc(Finding.created_at))
        
        result = await db.execute(query)
        findings = result.scalars().all()
        
        # Convert to response models
        finding_responses = []
        for finding in findings:
            finding_responses.append(FindingResponse(
                id=finding.id,
                asset_id=finding.asset_id,
                policy_id=finding.policy_id,
                severity=finding.severity,
                status=finding.status,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                risk_score=float(finding.risk_score) if finding.risk_score else 0.0,
                owner_id=finding.owner_id,
                comments=finding.comments,
                remediation_notes=finding.remediation_notes,
                created_at=finding.created_at,
                updated_at=finding.updated_at,
                resolved_at=finding.resolved_at
            ))
        
        pages = (total + per_page - 1) // per_page
        
        return PaginatedResponse(
            items=finding_responses,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get findings: {str(e)}")

@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific finding details"""
    try:
        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        return FindingResponse(
            id=finding.id,
            asset_id=finding.asset_id,
            policy_id=finding.policy_id,
            severity=finding.severity,
            status=finding.status,
            title=finding.title,
            description=finding.description,
            evidence=finding.evidence,
            risk_score=float(finding.risk_score) if finding.risk_score else 0.0,
            owner_id=finding.owner_id,
            comments=finding.comments,
            remediation_notes=finding.remediation_notes,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            resolved_at=finding.resolved_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get finding: {str(e)}")

@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    finding_update: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update finding status and details"""
    try:
        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Update fields
        update_data = finding_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(finding, field, value)
        
        finding.updated_at = datetime.utcnow()
        
        # If status is resolved, set resolved_at
        if finding_update.status == FindingStatus.RESOLVED:
            finding.resolved_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(finding)
        
        return FindingResponse(
            id=finding.id,
            asset_id=finding.asset_id,
            policy_id=finding.policy_id,
            severity=finding.severity,
            status=finding.status,
            title=finding.title,
            description=finding.description,
            evidence=finding.evidence,
            risk_score=float(finding.risk_score) if finding.risk_score else 0.0,
            owner_id=finding.owner_id,
            comments=finding.comments,
            remediation_notes=finding.remediation_notes,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            resolved_at=finding.resolved_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update finding: {str(e)}")

@router.post("/findings/bulk", response_model=BulkFindingResponse)
async def bulk_update_findings(
    bulk_update: BulkFindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk update findings"""
    try:
        update_data = bulk_update.dict(exclude_unset=True)
        update_count = 0
        failed_ids = []
        
        for finding_id in bulk_update.finding_ids:
            try:
                result = await db.execute(select(Finding).where(Finding.id == finding_id))
                finding = result.scalar_one_or_none()
                if finding:
                    for field, value in update_data.items():
                        if field != "finding_ids":
                            setattr(finding, field, value)
                    
                    finding.updated_at = datetime.utcnow()
                    if update_data.get("status") == FindingStatus.RESOLVED:
                        finding.resolved_at = datetime.utcnow()
                    
                    update_count += 1
                else:
                    failed_ids.append(finding_id)
            except Exception:
                failed_ids.append(finding_id)
        
        await db.commit()
        
        return BulkFindingResponse(
            updated_count=update_count,
            failed_count=len(failed_ids),
            failed_ids=failed_ids
        )
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to bulk update findings: {str(e)}")

# ============================================================================
# Policy Endpoints
# ============================================================================

@router.get("/policies", response_model=List[PolicyResponse])
async def get_policies(
    framework: Optional[PolicyFramework] = Query(None, description="Filter by framework"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all policies with optional filtering"""
    try:
        query = select(Policy)
        
        filters = []
        if framework:
            filters.append(Policy.framework == framework)
        if enabled is not None:
            filters.append(Policy.enabled == enabled)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(Policy.name)
        result = await db.execute(query)
        return result.scalars().all()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get policies: {str(e)}")

@router.post("/policies", response_model=PolicyResponse)
async def create_policy(
    policy: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new policy"""
    try:
        db_policy = Policy(**policy.dict())
        db_policy.created_by = current_user.id
        db.add(db_policy)
        await db.commit()
        await db.refresh(db_policy)
        return db_policy
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create policy: {str(e)}")

@router.post("/policies/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_policies(
    evaluation_request: PolicyEvaluationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Evaluate policies against assets"""
    try:
        # Create evaluation job
        job = Job(
            project_id=uuid.uuid4(),  # TODO: Get from context
            type=JobType.POLICY_EVAL,
            parameters=evaluation_request.dict()
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        
        # TODO: Add background task to perform policy evaluation
        # background_tasks.add_task(evaluate_policies_job, job.id, evaluation_request)
        
        return PolicyEvaluationResponse(
            job_id=job.id,
            status="pending",
            message="Policy evaluation job created successfully"
        )
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create evaluation job: {str(e)}")

# ============================================================================
# Job Endpoints
# ============================================================================

@router.get("/jobs", response_model=List[JobResponse])
async def get_jobs(
    status: Optional[JobStatus] = Query(None, description="Filter by status"),
    type: Optional[JobType] = Query(None, description="Filter by job type"),
    connector_id: Optional[uuid.UUID] = Query(None, description="Filter by connector"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all jobs with optional filtering"""
    try:
        query = select(Job)
        
        filters = []
        if status:
            filters.append(Job.status == status)
        if type:
            filters.append(Job.type == type)
        if connector_id:
            filters.append(Job.connector_id == connector_id)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(Job.created_at))
        result = await db.execute(query)
        return result.scalars().all()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get jobs: {str(e)}")

@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific job details"""
    try:
        result = await db.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job: {str(e)}")

# ============================================================================
# Integration Endpoints
# ============================================================================

@router.post("/integrations", response_model=IntegrationResponse)
async def create_integration(
    integration: IntegrationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new integration"""
    try:
        # Verify project exists
        project_result = await db.execute(select(Project).where(Project.id == integration.project_id))
        if not project_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found")
        
        db_integration = Integration(**integration.dict())
        db.add(db_integration)
        await db.commit()
        await db.refresh(db_integration)
        return db_integration
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create integration: {str(e)}")

@router.post("/integrations/{integration_id}/test")
async def test_integration(
    integration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Test integration configuration"""
    try:
        result = await db.execute(select(Integration).where(Integration.id == integration_id))
        integration = result.scalar_one_or_none()
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # TODO: Implement actual integration testing based on type
        # This would test the connection and send a test message
        
        # Update test status
        integration.last_test = datetime.utcnow()
        integration.test_status = "success"
        await db.commit()
        
        return {"message": "Integration test successful", "status": "success"}
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Integration test failed: {str(e)}")

# ============================================================================
# Compliance Endpoints
# ============================================================================

@router.get("/compliance/frameworks", response_model=List[ComplianceFrameworkResponse])
async def get_compliance_frameworks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all compliance frameworks"""
    try:
        result = await db.execute(select(ComplianceFramework))
        return result.scalars().all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get compliance frameworks: {str(e)}")

@router.post("/compliance/reports", response_model=ComplianceReportResponse)
async def generate_compliance_report(
    report_request: ComplianceReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate compliance report for a framework"""
    try:
        # Verify project and framework exist
        project_result = await db.execute(select(Project).where(Project.id == report_request.project_id))
        if not project_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found")
        
        framework_result = await db.execute(select(ComplianceFramework).where(ComplianceFramework.id == report_request.framework_id))
        if not framework_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Compliance framework not found")
        
        # Create report
        report = ComplianceReport(**report_request.dict())
        db.add(report)
        await db.commit()
        await db.refresh(report)
        
        # TODO: Add background task to generate actual compliance data
        # background_tasks.add_task(generate_compliance_report_data, report.id)
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create compliance report: {str(e)}")

# ============================================================================
# Asset Relationships Endpoints
# ============================================================================

@router.post("/assets/{asset_id}/relationships", response_model=AssetRelationshipResponse)
async def create_asset_relationship(
    asset_id: uuid.UUID,
    relationship: AssetRelationshipCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a relationship between assets"""
    try:
        # Verify both assets exist
        asset_query = select(Asset).where(Asset.id.in_([asset_id, relationship.child_asset_id]))
        assets_result = await db.execute(asset_query)
        assets = assets_result.scalars().all()
        
        if len(assets) != 2:
            raise HTTPException(status_code=404, detail="One or both assets not found")
        
        # Create relationship
        db_relationship = AssetRelationship(
            parent_asset_id=asset_id,
            child_asset_id=relationship.child_asset_id,
            relationship_type=relationship.relationship_type,
            metadata=relationship.metadata
        )
        
        db.add(db_relationship)
        await db.commit()
        await db.refresh(db_relationship)
        
        return db_relationship
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create asset relationship: {str(e)}")

@router.get("/assets/{asset_id}/relationships", response_model=List[AssetRelationshipResponse])
async def get_asset_relationships(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all relationships for an asset"""
    try:
        query = select(AssetRelationship).where(
            or_(
                AssetRelationship.parent_asset_id == asset_id,
                AssetRelationship.child_asset_id == asset_id
            )
        )
        result = await db.execute(query)
        relationships = result.scalars().all()
        
        return relationships
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get asset relationships: {str(e)}")

# ============================================================================
# Policy Evaluation Endpoints
# ============================================================================

@router.post("/policies/{policy_id}/evaluate", response_model=PolicyEvaluationResultResponse)
async def evaluate_policy_on_asset(
    policy_id: uuid.UUID,
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Evaluate a specific policy against a specific asset"""
    try:
        # Get policy and asset
        policy_query = select(Policy).where(Policy.id == policy_id)
        asset_query = select(Asset).where(Asset.id == asset_id)
        
        policy_result = await db.execute(policy_query)
        asset_result = await db.execute(asset_query)
        
        policy = policy_result.scalar_one_or_none()
        asset = asset_result.scalar_one_or_none()
        
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Simple policy evaluation (you can enhance this with actual policy engine)
        import time
        start_time = time.time()
        
        # Mock evaluation logic - replace with actual policy engine
        evaluation_result = evaluate_policy_rule(policy.rule, asset.metadata)
        execution_time = int((time.time() - start_time) * 1000)
        
        # Create evaluation result
        db_result = PolicyEvaluationResult(
            asset_id=asset_id,
            policy_id=policy_id,
            result=evaluation_result,
            evidence={"evaluated_at": datetime.utcnow().isoformat()},
            execution_time_ms=execution_time
        )
        
        db.add(db_result)
        await db.commit()
        await db.refresh(db_result)
        
        return db_result
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to evaluate policy: {str(e)}")

@router.get("/policies/{policy_id}/evaluation-results", response_model=List[PolicyEvaluationResultResponse])
async def get_policy_evaluation_results(
    policy_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get evaluation results for a specific policy"""
    try:
        query = select(PolicyEvaluationResult).where(
            PolicyEvaluationResult.policy_id == policy_id
        ).order_by(desc(PolicyEvaluationResult.evaluation_date)).limit(limit)
        
        result = await db.execute(query)
        evaluation_results = result.scalars().all()
        
        return evaluation_results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get evaluation results: {str(e)}")

# ============================================================================
# Compliance Controls Endpoints
# ============================================================================

@router.post("/compliance/controls", response_model=ComplianceControlResponse)
async def create_compliance_control(
    control: ComplianceControlCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new compliance control"""
    try:
        db_control = ComplianceControl(**control.dict())
        db.add(db_control)
        await db.commit()
        await db.refresh(db_control)
        
        return db_control
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create compliance control: {str(e)}")

@router.get("/compliance/frameworks/{framework_id}/controls", response_model=List[ComplianceControlResponse])
async def get_framework_controls(
    framework_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all controls for a compliance framework"""
    try:
        query = select(ComplianceControl).where(
            ComplianceControl.framework_id == framework_id
        ).order_by(ComplianceControl.control_id)
        
        result = await db.execute(query)
        controls = result.scalars().all()
        
        return controls
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get framework controls: {str(e)}")

@router.post("/compliance/mappings", response_model=ComplianceMappingResponse)
async def create_compliance_mapping(
    mapping: ComplianceMappingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a mapping between a compliance control and a policy"""
    try:
        db_mapping = ComplianceMapping(**mapping.dict())
        db.add(db_mapping)
        await db.commit()
        await db.refresh(db_mapping)
        
        return db_mapping
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create compliance mapping: {str(e)}")

# ============================================================================
# Scan Templates Endpoints
# ============================================================================

@router.post("/scan-templates", response_model=ScanTemplateResponse)
async def create_scan_template(
    template: ScanTemplateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new scan template"""
    try:
        db_template = ScanTemplate(
            **template.dict(),
            created_by=current_user.id
        )
        db.add(db_template)
        await db.commit()
        await db.refresh(db_template)
        
        return db_template
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create scan template: {str(e)}")

@router.get("/scan-templates", response_model=List[ScanTemplateResponse])
async def get_scan_templates(
    project_id: Optional[uuid.UUID] = Query(None, description="Filter by project"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan templates"""
    try:
        query = select(ScanTemplate)
        if project_id:
            query = query.where(ScanTemplate.project_id == project_id)
        
        query = query.order_by(desc(ScanTemplate.created_at))
        result = await db.execute(query)
        templates = result.scalars().all()
        
        return templates
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan templates: {str(e)}")

@router.put("/scan-templates/{template_id}", response_model=ScanTemplateResponse)
async def update_scan_template(
    template_id: uuid.UUID,
    template_update: ScanTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a scan template"""
    try:
        query = select(ScanTemplate).where(ScanTemplate.id == template_id)
        result = await db.execute(query)
        db_template = result.scalar_one_or_none()
        
        if not db_template:
            raise HTTPException(status_code=404, detail="Scan template not found")
        
        # Update fields
        update_data = template_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_template, field, value)
        
        await db.commit()
        await db.refresh(db_template)
        
        return db_template
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update scan template: {str(e)}")

# ============================================================================
# Remediation Playbooks Endpoints
# ============================================================================

@router.post("/remediation/playbooks", response_model=RemediationPlaybookResponse)
async def create_remediation_playbook(
    playbook: RemediationPlaybookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new remediation playbook"""
    try:
        db_playbook = RemediationPlaybook(
            **playbook.dict(),
            created_by=current_user.id
        )
        db.add(db_playbook)
        await db.commit()
        await db.refresh(db_playbook)
        
        return db_playbook
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create remediation playbook: {str(e)}")

@router.get("/remediation/playbooks", response_model=List[RemediationPlaybookResponse])
async def get_remediation_playbooks(
    category: Optional[str] = Query(None, description="Filter by category"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get remediation playbooks"""
    try:
        query = select(RemediationPlaybook)
        if category:
            query = query.where(RemediationPlaybook.category == category)
        
        query = query.order_by(desc(RemediationPlaybook.created_at))
        result = await db.execute(query)
        playbooks = result.scalars().all()
        
        return playbooks
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get remediation playbooks: {str(e)}")

@router.post("/remediation/playbooks/{playbook_id}/execute", response_model=RemediationExecutionResponse)
async def execute_remediation_playbook(
    playbook_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Execute a remediation playbook against a finding"""
    try:
        # Verify playbook and finding exist
        playbook_query = select(RemediationPlaybook).where(RemediationPlaybook.id == playbook_id)
        finding_query = select(Finding).where(Finding.id == finding_id)
        
        playbook_result = await db.execute(playbook_query)
        finding_result = await db.execute(finding_query)
        
        playbook = playbook_result.scalar_one_or_none()
        finding = finding_result.scalar_one_or_none()
        
        if not playbook:
            raise HTTPException(status_code=404, detail="Remediation playbook not found")
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Create execution record
        db_execution = RemediationExecution(
            playbook_id=playbook_id,
            finding_id=finding_id,
            status="pending",
            executed_by=current_user.id
        )
        
        db.add(db_execution)
        await db.commit()
        await db.refresh(db_execution)
        
        # TODO: Queue background job to execute the playbook
        # This would typically be handled by a Celery worker
        
        return db_execution
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to execute remediation playbook: {str(e)}")

# ============================================================================
# Risk Assessment Endpoints
# ============================================================================

@router.post("/assets/{asset_id}/risk-assessment", response_model=RiskAssessmentResponse)
async def create_risk_assessment(
    asset_id: uuid.UUID,
    assessment: RiskAssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a risk assessment for an asset"""
    try:
        # Verify asset exists
        asset_query = select(Asset).where(Asset.id == asset_id)
        asset_result = await db.execute(asset_query)
        asset = asset_result.scalar_one_or_none()
        
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Create risk assessment
        db_assessment = RiskAssessment(
            asset_id=asset_id,
            overall_score=assessment.overall_score,
            factors=assessment.factors,
            recommendations=assessment.recommendations,
            assessed_by=current_user.id
        )
        
        db.add(db_assessment)
        await db.commit()
        await db.refresh(db_assessment)
        
        # Update asset risk score
        asset.risk_score = assessment.overall_score
        await db.commit()
        
        return db_assessment
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create risk assessment: {str(e)}")

@router.get("/assets/{asset_id}/risk-assessments", response_model=List[RiskAssessmentResponse])
async def get_asset_risk_assessments(
    asset_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get risk assessments for an asset"""
    try:
        query = select(RiskAssessment).where(
            RiskAssessment.asset_id == asset_id
        ).order_by(desc(RiskAssessment.assessment_date)).limit(limit)
        
        result = await db.execute(query)
        assessments = result.scalars().all()
        
        return assessments
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get risk assessments: {str(e)}")

# ============================================================================
# Integration Webhooks Endpoints
# ============================================================================

@router.post("/integrations/{integration_id}/webhooks", response_model=IntegrationWebhookResponse)
async def create_integration_webhook(
    integration_id: uuid.UUID,
    webhook: IntegrationWebhookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a webhook for an integration"""
    try:
        # Verify integration exists
        integration_query = select(Integration).where(Integration.id == integration_id)
        integration_result = await db.execute(integration_query)
        integration = integration_result.scalar_one_or_none()
        
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Create webhook
        db_webhook = IntegrationWebhook(
            integration_id=integration_id,
            webhook_url=webhook.webhook_url,
            secret_key=webhook.secret_key,
            events=webhook.events,
            enabled=webhook.enabled
        )
        
        db.add(db_webhook)
        await db.commit()
        await db.refresh(db_webhook)
        
        return db_webhook
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create webhook: {str(e)}")

@router.post("/integrations/{integration_id}/webhooks/{webhook_id}/test")
async def test_webhook(
    integration_id: uuid.UUID,
    webhook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Test a webhook by sending a test payload"""
    try:
        # Get webhook
        webhook_query = select(IntegrationWebhook).where(
            IntegrationWebhook.id == webhook_id,
            IntegrationWebhook.integration_id == integration_id
        )
        webhook_result = await db.execute(webhook_query)
        webhook = webhook_result.scalar_one_or_none()
        
        if not webhook:
            raise HTTPException(status_code=404, detail="Webhook not found")
        
        # TODO: Implement actual webhook testing
        # This would typically send a test payload to the webhook URL
        
        return {"message": "Webhook test initiated", "webhook_id": str(webhook_id)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to test webhook: {str(e)}")

# ============================================================================
# Helper Functions
# ============================================================================

def evaluate_policy_rule(rule: Dict[str, Any], asset_metadata: Dict[str, Any]) -> bool:
    """
    Simple policy evaluation function.
    In production, this would use a proper policy engine like OPA/Rego or CEL.
    """
    try:
        # This is a simplified example - replace with actual policy engine
        if "condition" in rule:
            condition = rule["condition"]
            if condition.get("type") == "field_check":
                field_path = condition.get("field")
                expected_value = condition.get("value")
                operator = condition.get("operator", "equals")
                
                # Simple field extraction (use proper JSON path library in production)
                field_value = asset_metadata.get(field_path)
                
                if operator == "equals":
                    return field_value == expected_value
                elif operator == "not_equals":
                    return field_value != expected_value
                elif operator == "contains":
                    return expected_value in str(field_value)
                elif operator == "exists":
                    return field_path in asset_metadata
                
        # Default to passing if no specific condition
        return True
        
    except Exception:
        # If evaluation fails, default to failing
        return False
