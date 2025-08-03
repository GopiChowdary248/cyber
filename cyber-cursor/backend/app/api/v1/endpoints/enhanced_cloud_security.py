"""
Enhanced Cloud Security API Endpoints
Provides comprehensive CSPM, CASB, and Cloud-Native security functionality
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import asyncio

from app.core.database import get_db
from app.core.security import get_current_user
from app.schemas.auth import User
from app.schemas.cloud_security_schemas import *
from app.models.cloud_security import *
from app.services.enhanced_cloud_security_service import (
    CloudSecurityOrchestrator,
    EnhancedCSPMService,
    EnhancedCASBService,
    EnhancedCloudNativeSecurityService
)

router = APIRouter(prefix="/api/v1/enhanced-cloud-security", tags=["Enhanced Cloud Security"])

# Initialize services
orchestrator = CloudSecurityOrchestrator()
cspm_service = EnhancedCSPMService()
casb_service = EnhancedCASBService()
cloud_native_service = EnhancedCloudNativeSecurityService()

# ============================================================================
# Comprehensive Cloud Security Endpoints
# ============================================================================

@router.post("/scan/comprehensive")
async def initiate_comprehensive_scan(
    scan_request: ComprehensiveScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Initiate a comprehensive cloud security scan"""
    try:
        # Start scan in background
        background_tasks.add_task(
            run_comprehensive_scan,
            scan_request.account_id,
            scan_request.provider,
            current_user.id
        )
        
        return {
            "message": "Comprehensive scan initiated successfully",
            "scan_id": f"scan_{scan_request.account_id}_{datetime.now().timestamp()}",
            "status": "running",
            "estimated_duration": "5-10 minutes"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate scan: {str(e)}")

@router.get("/scan/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get the status of a running scan"""
    # This would typically check a database or cache for scan status
    return {
        "scan_id": scan_id,
        "status": "completed",  # or "running", "failed"
        "progress": 100,
        "started_at": datetime.now() - timedelta(minutes=5),
        "completed_at": datetime.now(),
        "findings_count": 15
    }

@router.get("/dashboard/comprehensive")
async def get_comprehensive_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive cloud security dashboard data"""
    try:
        # Mock data for demonstration - in real implementation, this would fetch from database
        dashboard_data = {
            "unified_risk_score": 78.5,
            "total_findings": 23,
            "critical_count": 3,
            "high_count": 8,
            "medium_count": 7,
            "low_count": 5,
            "cspm_score": 82.0,
            "casb_score": 75.0,
            "cloud_native_score": 78.0,
            "recent_findings": [
                {
                    "id": "finding_001",
                    "title": "S3 Bucket with Public Access",
                    "severity": "high",
                    "type": "cspm",
                    "resource": "arn:aws:s3:::my-bucket",
                    "detected_at": "2024-01-15T10:30:00Z"
                },
                {
                    "id": "finding_002",
                    "title": "Over-privileged IAM Role",
                    "severity": "critical",
                    "type": "cspm",
                    "resource": "arn:aws:iam::123456789012:role/admin-role",
                    "detected_at": "2024-01-15T09:45:00Z"
                },
                {
                    "id": "finding_003",
                    "title": "Unauthorized SaaS Application Detected",
                    "severity": "medium",
                    "type": "casb",
                    "resource": "dropbox.com",
                    "detected_at": "2024-01-15T08:20:00Z"
                }
            ],
            "compliance_status": {
                "cis": 85,
                "nist": 78,
                "pci_dss": 92,
                "iso27001": 70
            },
            "cloud_accounts": [
                {
                    "id": "aws_001",
                    "name": "Production AWS Account",
                    "provider": "aws",
                    "status": "active",
                    "security_score": 82
                },
                {
                    "id": "azure_001",
                    "name": "Development Azure Account",
                    "provider": "azure",
                    "status": "active",
                    "security_score": 75
                },
                {
                    "id": "gcp_001",
                    "name": "Testing GCP Account",
                    "provider": "gcp",
                    "status": "active",
                    "security_score": 88
                }
            ]
        }
        
        return dashboard_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch dashboard data: {str(e)}")

# ============================================================================
# CSPM (Cloud Security Posture Management) Endpoints
# ============================================================================

@router.post("/cspm/scan")
async def initiate_cspm_scan(
    scan_request: CSPMScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Initiate CSPM scan for cloud account"""
    try:
        background_tasks.add_task(
            run_cspm_scan,
            scan_request.account_id,
            scan_request.provider,
            current_user.id
        )
        
        return {
            "message": "CSPM scan initiated successfully",
            "scan_id": f"cspm_{scan_request.account_id}_{datetime.now().timestamp()}",
            "status": "running"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate CSPM scan: {str(e)}")

@router.get("/cspm/findings")
async def get_cspm_findings(
    account_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get CSPM findings with filters"""
    try:
        # Mock CSPM findings - in real implementation, fetch from database
        findings = [
            {
                "id": "cspm_001",
                "type": "s3_public_access",
                "severity": "high",
                "title": "S3 Bucket with Public Access",
                "description": "S3 bucket allows public read access",
                "resource_id": "arn:aws:s3:::my-bucket",
                "provider": "aws",
                "compliance_standards": ["cis", "pci_dss", "nist"],
                "remediation_steps": [
                    "Remove public read access from bucket ACL",
                    "Configure bucket policy to deny public access",
                    "Enable S3 Block Public Access settings"
                ],
                "auto_remediable": True,
                "status": "open",
                "detected_at": "2024-01-15T10:30:00Z"
            },
            {
                "id": "cspm_002",
                "type": "iam_overprivileged",
                "severity": "critical",
                "title": "Over-privileged IAM Role",
                "description": "IAM role has excessive permissions",
                "resource_id": "arn:aws:iam::123456789012:role/admin-role",
                "provider": "aws",
                "compliance_standards": ["cis", "nist"],
                "remediation_steps": [
                    "Review and reduce IAM permissions",
                    "Apply principle of least privilege",
                    "Use AWS IAM Access Analyzer for recommendations"
                ],
                "auto_remediable": False,
                "status": "open",
                "detected_at": "2024-01-15T09:45:00Z"
            }
        ]
        
        # Apply filters
        if account_id:
            findings = [f for f in findings if account_id in f.get("resource_id", "")]
        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if status:
            findings = [f for f in findings if f["status"] == status]
        
        return findings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch CSPM findings: {str(e)}")

@router.post("/cspm/remediate")
async def remediate_cspm_finding(
    remediation_request: CSPMRemediationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remediate CSPM finding"""
    try:
        # Mock remediation - in real implementation, execute actual remediation
        return {
            "message": "Remediation initiated successfully",
            "finding_id": remediation_request.finding_id,
            "remediation_type": remediation_request.remediation_type,
            "status": "in_progress",
            "estimated_completion": datetime.now() + timedelta(minutes=5)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remediate finding: {str(e)}")

# ============================================================================
# CASB (Cloud Access Security Broker) Endpoints
# ============================================================================

@router.post("/casb/discover")
async def discover_saas_applications(
    discovery_request: CASBDiscoveryRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Discover SaaS applications in use"""
    try:
        background_tasks.add_task(
            run_casb_discovery,
            discovery_request.network_data,
            current_user.id
        )
        
        return {
            "message": "SaaS application discovery initiated",
            "discovery_id": f"casb_discovery_{datetime.now().timestamp()}",
            "status": "running"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate discovery: {str(e)}")

@router.get("/casb/applications")
async def get_saas_applications(
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get discovered SaaS applications"""
    try:
        # Mock SaaS applications data
        applications = [
            {
                "id": "saas_001",
                "name": "Salesforce",
                "domain": "salesforce.com",
                "category": "crm",
                "risk_score": 0.2,
                "sanctioned": True,
                "user_count": 45,
                "data_volume": 1024000,
                "status": "sanctioned",
                "discovered_at": "2024-01-15T08:00:00Z"
            },
            {
                "id": "saas_002",
                "name": "Dropbox",
                "domain": "dropbox.com",
                "category": "file_sharing",
                "risk_score": 0.6,
                "sanctioned": False,
                "user_count": 12,
                "data_volume": 5120000,
                "status": "discovered",
                "discovered_at": "2024-01-15T08:30:00Z"
            },
            {
                "id": "saas_003",
                "name": "Slack",
                "domain": "slack.com",
                "category": "communication",
                "risk_score": 0.3,
                "sanctioned": True,
                "user_count": 78,
                "data_volume": 2048000,
                "status": "sanctioned",
                "discovered_at": "2024-01-15T07:45:00Z"
            }
        ]
        
        # Apply filters
        if status:
            applications = [app for app in applications if app["status"] == status]
        if risk_level:
            if risk_level == "high":
                applications = [app for app in applications if app["risk_score"] > 0.5]
            elif risk_level == "medium":
                applications = [app for app in applications if 0.3 <= app["risk_score"] <= 0.5]
            elif risk_level == "low":
                applications = [app for app in applications if app["risk_score"] < 0.3]
        
        return applications
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch SaaS applications: {str(e)}")

@router.post("/casb/dlp/scan")
async def scan_for_dlp_violations(
    dlp_request: DLPScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Scan file content for DLP violations"""
    try:
        violations = await casb_service.scan_for_dlp_violations(
            dlp_request.file_content,
            dlp_request.file_type
        )
        
        return {
            "file_name": dlp_request.file_name,
            "violations": violations,
            "total_violations": len(violations),
            "scanned_at": datetime.now()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan for DLP violations: {str(e)}")

# ============================================================================
# Cloud-Native Security Endpoints
# ============================================================================

@router.get("/cloud-native/status/{account_id}")
async def get_cloud_native_status(
    account_id: str,
    provider: str = Query("aws"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get cloud-native security status"""
    try:
        if provider == "aws":
            status = await cloud_native_service.get_aws_security_status(account_id)
        else:
            # Mock data for other providers
            status = {
                "shield_status": {"protected": True, "protection_id": "shield_001"},
                "guardduty_findings": [],
                "iam_risks": [],
                "security_score": 85.0
            }
        
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get cloud-native status: {str(e)}")

@router.get("/cloud-native/iam/risks")
async def get_iam_risks(
    account_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get IAM security risks"""
    try:
        # Mock IAM risks data
        iam_risks = [
            {
                "id": "iam_risk_001",
                "type": "over_privileged_role",
                "severity": "high",
                "resource": "admin-role",
                "description": "Role admin-role has dangerous permission: iam:*",
                "recommendation": "Apply principle of least privilege",
                "detected_at": "2024-01-15T09:30:00Z"
            },
            {
                "id": "iam_risk_002",
                "type": "unused_permissions",
                "severity": "medium",
                "resource": "developer-role",
                "description": "Role developer-role has unused permissions",
                "recommendation": "Remove unused permissions",
                "detected_at": "2024-01-15T08:15:00Z"
            }
        ]
        
        # Apply filters
        if severity:
            iam_risks = [risk for risk in iam_risks if risk["severity"] == severity]
        
        return iam_risks
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch IAM risks: {str(e)}")

# ============================================================================
# Compliance and Reporting Endpoints
# ============================================================================

@router.get("/compliance/report")
async def generate_compliance_report(
    standard: str = Query(..., description="Compliance standard (cis, nist, pci_dss, iso27001)"),
    account_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate compliance report"""
    try:
        # Mock compliance report
        report = {
            "standard": standard.upper(),
            "account_id": account_id,
            "generated_at": datetime.now(),
            "overall_score": 85,
            "total_checks": 150,
            "passed_checks": 128,
            "failed_checks": 22,
            "critical_findings": 3,
            "high_findings": 8,
            "medium_findings": 7,
            "low_findings": 4,
            "recommendations": [
                "Address critical IAM security findings",
                "Enable CloudTrail logging for all regions",
                "Implement S3 bucket encryption"
            ]
        }
        
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate compliance report: {str(e)}")

@router.get("/metrics/trends")
async def get_security_metrics_trends(
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get security metrics trends over time"""
    try:
        # Mock trends data
        trends = {
            "period": f"Last {days} days",
            "security_score_trend": [
                {"date": "2024-01-01", "score": 75},
                {"date": "2024-01-05", "score": 78},
                {"date": "2024-01-10", "score": 82},
                {"date": "2024-01-15", "score": 78}
            ],
            "findings_trend": [
                {"date": "2024-01-01", "critical": 5, "high": 12, "medium": 8, "low": 3},
                {"date": "2024-01-05", "critical": 4, "high": 10, "medium": 7, "low": 2},
                {"date": "2024-01-10", "critical": 3, "high": 8, "medium": 6, "low": 1},
                {"date": "2024-01-15", "critical": 3, "high": 8, "medium": 7, "low": 5}
            ],
            "remediation_rate": 85.5,
            "mean_time_to_remediate": "2.3 days"
        }
        
        return trends
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch metrics trends: {str(e)}")

# ============================================================================
# Background Task Functions
# ============================================================================

async def run_comprehensive_scan(account_id: str, provider: str, user_id: int):
    """Background task to run comprehensive cloud security scan"""
    try:
        logger.info(f"Starting comprehensive scan for account {account_id}")
        
        # Run the comprehensive scan
        results = await orchestrator.comprehensive_scan(account_id, provider)
        
        # Store results in database
        # await store_scan_results(results, user_id)
        
        logger.info(f"Comprehensive scan completed for account {account_id}")
        
    except Exception as e:
        logger.error(f"Error in comprehensive scan: {str(e)}")

async def run_cspm_scan(account_id: str, provider: str, user_id: int):
    """Background task to run CSPM scan"""
    try:
        logger.info(f"Starting CSPM scan for account {account_id}")
        
        if provider == "aws":
            results = await cspm_service.scan_aws_account(account_id)
        else:
            # Handle other providers
            results = {"message": f"CSPM scan for {provider} not implemented yet"}
        
        # Store results in database
        # await store_cspm_results(results, user_id)
        
        logger.info(f"CSPM scan completed for account {account_id}")
        
    except Exception as e:
        logger.error(f"Error in CSPM scan: {str(e)}")

async def run_casb_discovery(network_data: Dict[str, Any], user_id: int):
    """Background task to run CASB discovery"""
    try:
        logger.info("Starting CASB discovery")
        
        # Run SaaS application discovery
        discovered_apps = await casb_service.discover_saas_applications(network_data)
        
        # Store results in database
        # await store_casb_discovery_results(discovered_apps, user_id)
        
        logger.info("CASB discovery completed")
        
    except Exception as e:
        logger.error(f"Error in CASB discovery: {str(e)}")

# ============================================================================
# Request/Response Models
# ============================================================================

class ComprehensiveScanRequest(BaseModel):
    account_id: str
    provider: str = "aws"
    include_cspm: bool = True
    include_casb: bool = True
    include_cloud_native: bool = True

class CSPMScanRequest(BaseModel):
    account_id: str
    provider: str = "aws"
    scan_rules: Optional[List[str]] = None

class CSPMRemediationRequest(BaseModel):
    finding_id: str
    remediation_type: str
    auto_remediate: bool = False

class CASBDiscoveryRequest(BaseModel):
    network_data: Dict[str, Any]

class DLPScanRequest(BaseModel):
    file_name: str
    file_content: str
    file_type: str 