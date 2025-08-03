from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta
import json

from app.core.database import get_db
from app.core.security import get_current_user
from app.schemas.auth import User
from app.schemas.cloud_security_schemas import *
from app.models.cloud_security import *

router = APIRouter(prefix="/api/v1/cloud-security", tags=["Cloud Security"])

# ============================================================================
# CSPM (Cloud Security Posture Management) Endpoints
# ============================================================================

@router.post("/accounts", response_model=CloudAccountResponse)
async def create_cloud_account(
    account: CloudAccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new cloud account for monitoring"""
    try:
        db_account = CloudAccount(
            account_id=account.account_id,
            name=account.name,
            provider=account.provider,
            region=account.region,
            account_metadata=account.account_metadata
        )
        db.add(db_account)
        await db.commit()
        await db.refresh(db_account)
        return db_account
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create cloud account: {str(e)}")

@router.get("/accounts", response_model=List[CloudAccountResponse])
async def get_cloud_accounts(
    provider: Optional[str] = Query(None, description="Filter by cloud provider"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all cloud accounts"""
    query = db.query(CloudAccount)
    if provider:
        query = query.filter(CloudAccount.provider == provider)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/accounts/{account_id}", response_model=CloudAccountResponse)
async def get_cloud_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific cloud account details"""
    result = await db.execute(db.query(CloudAccount).filter(CloudAccount.id == account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    return account

@router.post("/accounts/{account_id}/assets", response_model=CloudAssetResponse)
async def create_cloud_asset(
    account_id: int,
    asset: CloudAssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new cloud asset"""
    # Verify account exists
    account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    
    try:
        db_asset = CloudAsset(
            account_id=account_id,
            asset_id=asset.asset_id,
            name=asset.name,
            asset_type=asset.asset_type,
            region=asset.region,
            tags=asset.tags,
            asset_metadata=asset.asset_metadata
        )
        db.add(db_asset)
        db.commit()
        db.refresh(db_asset)
        return db_asset
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create cloud asset: {str(e)}")

@router.get("/accounts/{account_id}/assets", response_model=List[CloudAssetResponse])
async def get_cloud_assets(
    account_id: int,
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all assets for a cloud account"""
    query = db.query(CloudAsset).filter(CloudAsset.account_id == account_id)
    if asset_type:
        query = query.filter(CloudAsset.asset_type == asset_type)
    return query.all()

@router.post("/misconfigurations", response_model=MisconfigurationResponse)
async def create_misconfiguration(
    misconfig: MisconfigurationCreate,
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new misconfiguration record"""
    # Verify asset exists
    asset = db.query(CloudAsset).filter(CloudAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Cloud asset not found")
    
    try:
        db_misconfig = Misconfiguration(
            asset_id=asset_id,
            rule_id=misconfig.rule_id,
            title=misconfig.title,
            description=misconfig.description,
            severity=misconfig.severity,
            category=misconfig.category,
            compliance_standards=misconfig.compliance_standards,
            remediation_steps=misconfig.remediation_steps,
            auto_remediable=misconfig.auto_remediable
        )
        db.add(db_misconfig)
        db.commit()
        db.refresh(db_misconfig)
        return db_misconfig
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create misconfiguration: {str(e)}")

@router.get("/misconfigurations", response_model=List[MisconfigurationResponse])
async def get_misconfigurations(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all misconfigurations"""
    query = db.query(Misconfiguration)
    if severity:
        query = query.filter(Misconfiguration.severity == severity)
    if status:
        query = query.filter(Misconfiguration.status == status)
    return query.all()

@router.post("/compliance-reports", response_model=ComplianceReportResponse)
async def create_compliance_report(
    account_id: int,
    report: ComplianceReportCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new compliance report"""
    # Verify account exists
    account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    
    try:
        db_report = ComplianceReport(
            account_id=account_id,
            standard=report.standard,
            score=report.score,
            total_checks=report.total_checks,
            passed_checks=report.passed_checks,
            failed_checks=report.failed_checks,
            report_data=report.report_data
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        return db_report
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create compliance report: {str(e)}")

# ============================================================================
# CASB (Cloud Access Security Broker) Endpoints
# ============================================================================

@router.post("/saas-applications", response_model=SaaSApplicationResponse)
async def create_saas_application(
    app: SaaSApplicationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SaaS application record"""
    try:
        db_app = SaaSApplication(
            app_name=app.app_name,
            app_category=app.app_category,
            vendor=app.vendor,
            risk_score=app.risk_score,
            status=app.status,
            user_count=app.user_count,
            data_classification=app.data_classification,
            security_features=app.security_features
        )
        db.add(db_app)
        db.commit()
        db.refresh(db_app)
        return db_app
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create SaaS application: {str(e)}")

@router.get("/saas-applications", response_model=List[SaaSApplicationResponse])
async def get_saas_applications(
    status: Optional[str] = Query(None, description="Filter by status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SaaS applications"""
    query = db.query(SaaSApplication)
    if status:
        query = query.filter(SaaSApplication.status == status)
    if category:
        query = query.filter(SaaSApplication.app_category == category)
    return query.all()

@router.post("/user-activities", response_model=UserActivityResponse)
async def create_user_activity(
    app_id: int,
    activity: UserActivityCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new user activity record"""
    # Verify app exists
    app = db.query(SaaSApplication).filter(SaaSApplication.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="SaaS application not found")
    
    try:
        db_activity = UserActivity(
            user_id=activity.user_id,
            app_id=app_id,
            activity_type=activity.activity_type,
            ip_address=activity.ip_address,
            location=activity.location,
            device_info=activity.device_info,
            risk_score=activity.risk_score
        )
        db.add(db_activity)
        db.commit()
        db.refresh(db_activity)
        return db_activity
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create user activity: {str(e)}")

@router.post("/dlp-incidents", response_model=DLPIncidentResponse)
async def create_dlp_incident(
    app_id: int,
    incident: DLPIncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new DLP incident"""
    # Verify app exists
    app = db.query(SaaSApplication).filter(SaaSApplication.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="SaaS application not found")
    
    try:
        db_incident = DLPIncident(
            app_id=app_id,
            user_id=incident.user_id,
            incident_type=incident.incident_type,
            file_name=incident.file_name,
            file_size=incident.file_size,
            action_taken=incident.action_taken,
            confidence_score=incident.confidence_score,
            details=incident.details
        )
        db.add(db_incident)
        db.commit()
        db.refresh(db_incident)
        return db_incident
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create DLP incident: {str(e)}")

# ============================================================================
# Cloud-Native Security Endpoints
# ============================================================================

@router.post("/threats", response_model=CloudThreatResponse)
async def create_cloud_threat(
    account_id: int,
    threat: CloudThreatCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new cloud threat"""
    # Verify account exists
    account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    
    try:
        db_threat = CloudThreat(
            account_id=account_id,
            threat_id=threat.threat_id,
            threat_type=threat.threat_type,
            severity=threat.severity,
            source_ip=threat.source_ip,
            target_resource=threat.target_resource,
            description=threat.description,
            threat_data=threat.threat_data
        )
        db.add(db_threat)
        db.commit()
        db.refresh(db_threat)
        return db_threat
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create cloud threat: {str(e)}")

@router.get("/threats", response_model=List[CloudThreatResponse])
async def get_cloud_threats(
    account_id: Optional[int] = Query(None, description="Filter by account ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all cloud threats"""
    query = db.query(CloudThreat)
    if account_id:
        query = query.filter(CloudThreat.account_id == account_id)
    if severity:
        query = query.filter(CloudThreat.severity == severity)
    if status:
        query = query.filter(CloudThreat.status == status)
    return query.all()

@router.post("/iam-risks", response_model=IAMRiskResponse)
async def create_iam_risk(
    account_id: int,
    risk: IAMRiskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new IAM risk"""
    # Verify account exists
    account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    
    try:
        db_risk = IAMRisk(
            account_id=account_id,
            entity_id=risk.entity_id,
            entity_type=risk.entity_type,
            risk_type=risk.risk_type,
            severity=risk.severity,
            permissions=risk.permissions,
            recommendations=risk.recommendations
        )
        db.add(db_risk)
        db.commit()
        db.refresh(db_risk)
        return db_risk
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create IAM risk: {str(e)}")

@router.post("/ddos-protection", response_model=DDoSProtectionResponse)
async def create_ddos_protection(
    account_id: int,
    protection: DDoSProtectionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new DDoS protection record"""
    # Verify account exists
    account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    
    try:
        db_protection = DDoSProtection(
            account_id=account_id,
            protection_id=protection.protection_id,
            service=protection.service,
            status=protection.status,
            protected_resources=protection.protected_resources,
            attack_statistics=protection.attack_statistics
        )
        db.add(db_protection)
        db.commit()
        db.refresh(db_protection)
        return db_protection
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create DDoS protection: {str(e)}")

# ============================================================================
# Dashboard and Analytics Endpoints
# ============================================================================

@router.get("/dashboard/overview", response_model=CloudSecurityOverview)
async def get_cloud_security_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get cloud security overview dashboard"""
    try:
        # Count accounts
        total_accounts = db.query(CloudAccount).count()
        
        # Count assets
        total_assets = db.query(CloudAsset).count()
        
        # Count misconfigurations
        total_misconfigurations = db.query(Misconfiguration).count()
        
        # Count threats
        total_threats = db.query(CloudThreat).count()
        
        # Count SaaS apps
        total_saas_apps = db.query(SaaSApplication).count()
        
        # Calculate security scores
        accounts = db.query(CloudAccount).all()
        overall_security_score = sum(acc.security_score for acc in accounts) / len(accounts) if accounts else 0
        
        # Count issues by severity
        critical_issues = db.query(Misconfiguration).filter(Misconfiguration.severity == "critical").count()
        high_issues = db.query(Misconfiguration).filter(Misconfiguration.severity == "high").count()
        medium_issues = db.query(Misconfiguration).filter(Misconfiguration.severity == "medium").count()
        low_issues = db.query(Misconfiguration).filter(Misconfiguration.severity == "low").count()
        
        return CloudSecurityOverview(
            total_accounts=total_accounts,
            total_assets=total_assets,
            total_misconfigurations=total_misconfigurations,
            total_threats=total_threats,
            total_saas_apps=total_saas_apps,
            overall_security_score=overall_security_score,
            critical_issues=critical_issues,
            high_issues=high_issues,
            medium_issues=medium_issues,
            low_issues=low_issues
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get overview: {str(e)}")

@router.get("/dashboard/metrics", response_model=CloudSecurityMetrics)
async def get_cloud_security_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed cloud security metrics"""
    try:
        # Provider distribution
        provider_distribution = {}
        for provider in ["aws", "azure", "gcp"]:
            count = db.query(CloudAccount).filter(CloudAccount.provider == provider).count()
            provider_distribution[provider] = count
        
        # Asset type distribution
        asset_type_distribution = {}
        for asset_type in ["ec2", "s3", "rds", "lambda", "vpc", "iam"]:
            count = db.query(CloudAsset).filter(CloudAsset.asset_type == asset_type).count()
            asset_type_distribution[asset_type] = count
        
        # Misconfiguration trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        misconfig_trends = db.query(Misconfiguration).filter(
            Misconfiguration.detected_at >= thirty_days_ago
        ).count()
        
        # Threat trends (last 30 days)
        threat_trends = db.query(CloudThreat).filter(
            CloudThreat.detected_at >= thirty_days_ago
        ).count()
        
        # Compliance scores
        compliance_scores = {}
        for standard in ["cis", "nist", "iso27001", "pci_dss", "gdpr"]:
            reports = db.query(ComplianceReport).filter(ComplianceReport.standard == standard).all()
            if reports:
                avg_score = sum(r.score for r in reports) / len(reports)
                compliance_scores[standard] = avg_score
            else:
                compliance_scores[standard] = 0
        
        # Risk distribution
        risk_distribution = {
            "critical": db.query(Misconfiguration).filter(Misconfiguration.severity == "critical").count(),
            "high": db.query(Misconfiguration).filter(Misconfiguration.severity == "high").count(),
            "medium": db.query(Misconfiguration).filter(Misconfiguration.severity == "medium").count(),
            "low": db.query(Misconfiguration).filter(Misconfiguration.severity == "low").count()
        }
        
        return CloudSecurityMetrics(
            provider_distribution=provider_distribution,
            asset_type_distribution=asset_type_distribution,
            misconfiguration_trends={"last_30_days": misconfig_trends},
            threat_trends={"last_30_days": threat_trends},
            compliance_scores=compliance_scores,
            risk_distribution=risk_distribution
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

# ============================================================================
# Scan and Remediation Endpoints
# ============================================================================

@router.post("/scan")
async def initiate_cloud_scan(
    scan_request: CloudScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Initiate a cloud security scan"""
    try:
        # Verify account exists
        account = db.query(CloudAccount).filter(CloudAccount.id == scan_request.account_id).first()
        if not account:
            raise HTTPException(status_code=404, detail="Cloud account not found")
        
        # Update last scan timestamp
        account.last_scan = datetime.utcnow()
        db.commit()
        
        # Simulate scan process (in real implementation, this would trigger actual scanning)
        scan_result = {
            "scan_id": f"scan_{datetime.utcnow().timestamp()}",
            "account_id": scan_request.account_id,
            "scan_type": scan_request.scan_type,
            "status": "initiated",
            "estimated_completion": datetime.utcnow() + timedelta(minutes=30),
            "scan_components": {
                "assets": scan_request.include_assets,
                "misconfigurations": scan_request.include_misconfigurations,
                "compliance": scan_request.include_compliance
            }
        }
        
        return {
            "message": "Cloud security scan initiated successfully",
            "scan_details": scan_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate scan: {str(e)}")

@router.post("/remediate")
async def remediate_misconfiguration(
    remediation_request: RemediationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remediate a misconfiguration"""
    try:
        # Verify misconfiguration exists
        misconfig = db.query(Misconfiguration).filter(
            Misconfiguration.id == remediation_request.misconfiguration_id
        ).first()
        if not misconfig:
            raise HTTPException(status_code=404, detail="Misconfiguration not found")
        
        if remediation_request.auto_remediate and misconfig.auto_remediable:
            # Auto-remediation logic would go here
            misconfig.status = "remediating"
            db.commit()
            
            return RemediationResponse(
                success=True,
                message="Auto-remediation initiated",
                remediation_id=f"remediation_{datetime.utcnow().timestamp()}",
                estimated_time=15
            )
        else:
            # Manual remediation
            return RemediationResponse(
                success=True,
                message="Manual remediation required",
                remediation_id=None,
                estimated_time=60
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remediate: {str(e)}") 