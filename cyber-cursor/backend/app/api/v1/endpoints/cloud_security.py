from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models.cloud_security import CloudResource, CloudMisconfiguration, CloudScan, ComplianceReport
from app.schemas.cloud_security import (
    CloudScanCreate, CloudScanResponse, CloudMisconfigurationResponse,
    ComplianceReportResponse, CloudResourceResponse, CloudScanStats
)
from app.services.cloud_security_service import cloud_security_service

router = APIRouter()

@router.post("/scan", response_model=CloudScanResponse)
async def start_cloud_scan(
    scan_request: CloudScanCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Start a new cloud security scan"""
    scan_data = scan_request.dict()
    scan_data["initiated_by"] = current_user.id
    
    # Start the scan asynchronously
    scan = await cloud_security_service.start_scan(db, **scan_data)
    return scan

@router.get("/scans", response_model=List[CloudScanResponse])
async def get_cloud_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    provider: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get cloud security scans"""
    scans = await CloudScan.get_scans(
        db, skip=skip, limit=limit, provider=provider, status=status
    )
    return scans

@router.get("/scans/{scan_id}", response_model=CloudScanResponse)
async def get_cloud_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get cloud scan by ID"""
    scan = await CloudScan.get_by_id(db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    return scan

@router.get("/misconfigurations", response_model=List[CloudMisconfigurationResponse])
async def get_misconfigurations(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    resource_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get cloud misconfigurations"""
    misconfigurations = await CloudMisconfiguration.get_misconfigurations(
        db, skip=skip, limit=limit, provider=provider, 
        severity=severity, resource_type=resource_type
    )
    return misconfigurations

@router.get("/misconfigurations/{misconfig_id}", response_model=CloudMisconfigurationResponse)
async def get_misconfiguration(
    misconfig_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get misconfiguration by ID"""
    misconfig = await CloudMisconfiguration.get_by_id(db, misconfig_id=misconfig_id)
    if not misconfig:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Misconfiguration not found"
        )
    return misconfig

@router.put("/misconfigurations/{misconfig_id}/status")
async def update_misconfiguration_status(
    misconfig_id: int,
    status: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Update misconfiguration status"""
    misconfig = await CloudMisconfiguration.get_by_id(db, misconfig_id=misconfig_id)
    if not misconfig:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Misconfiguration not found"
        )
    
    updated_misconfig = await misconfig.update(db, status=status)
    return updated_misconfig

@router.get("/resources", response_model=List[CloudResourceResponse])
async def get_cloud_resources(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    provider: Optional[str] = None,
    resource_type: Optional[str] = None,
    region: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get cloud resources"""
    resources = await CloudResource.get_resources(
        db, skip=skip, limit=limit, provider=provider,
        resource_type=resource_type, region=region
    )
    return resources

@router.get("/compliance/reports", response_model=List[ComplianceReportResponse])
async def get_compliance_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    framework: Optional[str] = None,
    provider: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance reports"""
    reports = await ComplianceReport.get_reports(
        db, skip=skip, limit=limit, framework=framework, provider=provider
    )
    return reports

@router.get("/stats/overview", response_model=CloudScanStats)
async def get_cloud_security_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get cloud security statistics"""
    stats = await cloud_security_service.get_stats(db)
    return stats

@router.post("/scan/aws")
async def scan_aws_resources(
    regions: List[str] = ["us-east-1"],
    services: List[str] = ["ec2", "s3", "iam", "rds"],
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Scan AWS resources for misconfigurations"""
    scan = await cloud_security_service.scan_aws_resources(db, regions, services, current_user.id)
    return {"message": "AWS scan initiated", "scan_id": scan.id}

@router.post("/scan/azure")
async def scan_azure_resources(
    subscriptions: List[str] = None,
    resource_groups: List[str] = None,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Scan Azure resources for misconfigurations"""
    scan = await cloud_security_service.scan_azure_resources(db, subscriptions, resource_groups, current_user.id)
    return {"message": "Azure scan initiated", "scan_id": scan.id}

@router.post("/scan/gcp")
async def scan_gcp_resources(
    projects: List[str] = None,
    regions: List[str] = None,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Scan GCP resources for misconfigurations"""
    scan = await cloud_security_service.scan_gcp_resources(db, projects, regions, current_user.id)
    return {"message": "GCP scan initiated", "scan_id": scan.id} 