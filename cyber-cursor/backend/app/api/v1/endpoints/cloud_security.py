from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import httpx
import asyncio
from datetime import datetime, timedelta
import json

router = APIRouter()
security = HTTPBearer(auto_error=False)

# Pydantic Models for Cloud Security
class CSPMProvider(BaseModel):
    name: str
    status: str
    last_scan: datetime
    vulnerabilities_found: int
    compliance_score: float
    misconfigurations: int
    recommendations: int

class CASBProvider(BaseModel):
    name: str
    status: str
    monitored_apps: int
    dlp_violations: int
    threat_detections: int
    policy_violations: int
    last_sync: datetime

class CloudNativeProvider(BaseModel):
    name: str
    status: str
    protected_resources: int
    active_threats: int
    security_score: float
    last_updated: datetime

class SecurityFinding(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    provider: str
    category: str
    created_at: datetime
    status: str

class CloudSecurityMetrics(BaseModel):
    total_providers: int
    active_providers: int
    total_vulnerabilities: int
    average_compliance_score: float
    total_findings: int
    last_updated: datetime

# Mock Data
cspm_providers = [
    CSPMProvider(
        name="Prisma Cloud",
        status="active",
        last_scan=datetime.now() - timedelta(hours=2),
        vulnerabilities_found=15,
        compliance_score=85.5,
        misconfigurations=8,
        recommendations=23
    ),
    CSPMProvider(
        name="Dome9",
        status="active",
        last_scan=datetime.now() - timedelta(hours=1),
        vulnerabilities_found=12,
        compliance_score=92.0,
        misconfigurations=5,
        recommendations=18
    ),
    CSPMProvider(
        name="Wiz",
        status="active",
        last_scan=datetime.now() - timedelta(minutes=30),
        vulnerabilities_found=8,
        compliance_score=88.5,
        misconfigurations=3,
        recommendations=15
    )
]

casb_providers = [
    CASBProvider(
        name="Netskope",
        status="active",
        monitored_apps=45,
        dlp_violations=12,
        threat_detections=8,
        policy_violations=25,
        last_sync=datetime.now() - timedelta(minutes=15)
    ),
    CASBProvider(
        name="McAfee MVISION",
        status="active",
        monitored_apps=38,
        dlp_violations=8,
        threat_detections=5,
        policy_violations=18,
        last_sync=datetime.now() - timedelta(minutes=10)
    ),
    CASBProvider(
        name="Microsoft Defender for Cloud Apps",
        status="active",
        monitored_apps=52,
        dlp_violations=15,
        threat_detections=12,
        policy_violations=30,
        last_sync=datetime.now() - timedelta(minutes=5)
    )
]

cloud_native_providers = [
    CloudNativeProvider(
        name="AWS Shield",
        status="active",
        protected_resources=120,
        active_threats=3,
        security_score=94.0,
        last_updated=datetime.now() - timedelta(minutes=5)
    ),
    CloudNativeProvider(
        name="Azure Security Center",
        status="active",
        protected_resources=85,
        active_threats=2,
        security_score=91.5,
        last_updated=datetime.now() - timedelta(minutes=3)
    ),
    CloudNativeProvider(
        name="GCP Security Command Center",
        status="active",
        protected_resources=95,
        active_threats=1,
        security_score=96.0,
        last_updated=datetime.now() - timedelta(minutes=2)
    )
]

security_findings = [
    SecurityFinding(
        id="F001",
        severity="high",
        title="Public S3 Bucket Detected",
        description="S3 bucket is publicly accessible without proper access controls",
        provider="Prisma Cloud",
        category="CSPM",
        created_at=datetime.now() - timedelta(hours=1),
        status="open"
    ),
    SecurityFinding(
        id="F002",
        severity="medium",
        title="Unencrypted Database Instance",
        description="RDS instance is not encrypted at rest",
        provider="Dome9",
        category="CSPM",
        created_at=datetime.now() - timedelta(hours=2),
        status="open"
    ),
    SecurityFinding(
        id="F003",
        severity="low",
        title="Weak Password Policy",
        description="IAM password policy does not meet security requirements",
        provider="Wiz",
        category="CSPM",
        created_at=datetime.now() - timedelta(hours=3),
        status="open"
    )
]

# Authentication function
async def get_current_user(credentials = Depends(security)):
    """Get current authenticated user"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"id": 1, "email": "admin@cybershield.com", "role": "admin"}

@router.get("/cspm", response_model=List[CSPMProvider])
async def get_cspm_providers(current_user = Depends(get_current_user)):
    """Get all CSPM providers status and metrics"""
    return cspm_providers

@router.get("/cspm/{provider_name}", response_model=CSPMProvider)
async def get_cspm_provider(provider_name: str, current_user = Depends(get_current_user)):
    """Get specific CSPM provider details"""
    for provider in cspm_providers:
        if provider.name.lower() == provider_name.lower():
            return provider
    raise HTTPException(status_code=404, detail="CSPM provider not found")

@router.post("/cspm/{provider_name}/scan")
async def trigger_cspm_scan(provider_name: str, background_tasks: BackgroundTasks, current_user = Depends(get_current_user)):
    """Trigger a new scan for CSPM provider"""
    for provider in cspm_providers:
        if provider.name.lower() == provider_name.lower():
            # Simulate background scan
            background_tasks.add_task(simulate_cspm_scan, provider_name)
            return {"message": f"Scan initiated for {provider_name}", "status": "scanning"}
    raise HTTPException(status_code=404, detail="CSPM provider not found")

@router.get("/casb", response_model=List[CASBProvider])
async def get_casb_providers(current_user = Depends(get_current_user)):
    """Get all CASB providers status and metrics"""
    return casb_providers

@router.get("/casb/{provider_name}", response_model=CASBProvider)
async def get_casb_provider(provider_name: str, current_user = Depends(get_current_user)):
    """Get specific CASB provider details"""
    for provider in casb_providers:
        if provider.name.lower() == provider_name.lower():
            return provider
    raise HTTPException(status_code=404, detail="CASB provider not found")

@router.post("/casb/{provider_name}/sync")
async def trigger_casb_sync(provider_name: str, background_tasks: BackgroundTasks, current_user = Depends(get_current_user)):
    """Trigger a new sync for CASB provider"""
    for provider in casb_providers:
        if provider.name.lower() == provider_name.lower():
            # Simulate background sync
            background_tasks.add_task(simulate_casb_sync, provider_name)
            return {"message": f"Sync initiated for {provider_name}", "status": "syncing"}
    raise HTTPException(status_code=404, detail="CASB provider not found")

@router.get("/cloud-native", response_model=List[CloudNativeProvider])
async def get_cloud_native_providers(current_user = Depends(get_current_user)):
    """Get all Cloud-native security providers status and metrics"""
    return cloud_native_providers

@router.get("/cloud-native/{provider_name}", response_model=CloudNativeProvider)
async def get_cloud_native_provider(provider_name: str, current_user = Depends(get_current_user)):
    """Get specific Cloud-native security provider details"""
    for provider in cloud_native_providers:
        if provider.name.lower() == provider_name.lower():
            return provider
    raise HTTPException(status_code=404, detail="Cloud-native provider not found")

@router.get("/findings", response_model=List[SecurityFinding])
async def get_security_findings(
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    current_user = Depends(get_current_user)
):
    """Get security findings with optional filters"""
    filtered_findings = security_findings
    
    if severity:
        filtered_findings = [f for f in filtered_findings if f.severity.lower() == severity.lower()]
    if provider:
        filtered_findings = [f for f in filtered_findings if f.provider.lower() == provider.lower()]
    if category:
        filtered_findings = [f for f in filtered_findings if f.category.lower() == category.lower()]
    if status:
        filtered_findings = [f for f in filtered_findings if f.status.lower() == status.lower()]
    
    return filtered_findings

@router.get("/findings/{finding_id}", response_model=SecurityFinding)
async def get_security_finding(finding_id: str, current_user = Depends(get_current_user)):
    """Get specific security finding details"""
    finding = next((f for f in security_findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.put("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, status: str, current_user = Depends(get_current_user)):
    """Update security finding status"""
    finding = next((f for f in security_findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if status not in ["open", "in_progress", "resolved", "false_positive"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    finding.status = status
    finding.updated_at = datetime.now()
    
    return {"message": f"Finding status updated to {status}", "finding_id": finding_id}

# Dashboard Metrics
@router.get("/metrics", response_model=CloudSecurityMetrics)
async def get_cloud_security_metrics(current_user = Depends(get_current_user)):
    """Get overall cloud security metrics"""
    total_providers = len(cspm_providers) + len(casb_providers) + len(cloud_native_providers)
    active_providers = total_providers  # All are active in mock data
    total_vulnerabilities = sum(p.vulnerabilities_found for p in cspm_providers)
    average_compliance_score = sum(p.compliance_score for p in cspm_providers) / len(cspm_providers)
    total_findings = len(security_findings)
    
    return CloudSecurityMetrics(
        total_providers=total_providers,
        active_providers=active_providers,
        total_vulnerabilities=total_vulnerabilities,
        average_compliance_score=round(average_compliance_score, 2),
        total_findings=total_findings,
        last_updated=datetime.now()
    )

@router.get("/overview", response_model=Dict[str, Any])
async def get_cloud_security_overview(current_user = Depends(get_current_user)):
    """Get comprehensive cloud security overview"""
    return {
        "cspm": {
            "total_providers": len(cspm_providers),
            "total_vulnerabilities": sum(p.vulnerabilities_found for p in cspm_providers),
            "average_compliance_score": round(sum(p.compliance_score for p in cspm_providers) / len(cspm_providers), 2)
        },
        "casb": {
            "total_providers": len(casb_providers),
            "total_monitored_apps": sum(p.monitored_apps for p in casb_providers),
            "total_violations": sum(p.dlp_violations + p.policy_violations for p in casb_providers)
        },
        "cloud_native": {
            "total_providers": len(cloud_native_providers),
            "total_protected_resources": sum(p.protected_resources for p in cloud_native_providers),
            "total_active_threats": sum(p.active_threats for p in cloud_native_providers)
        },
        "findings": {
            "total": len(security_findings),
            "by_severity": {
                "high": len([f for f in security_findings if f.severity == "high"]),
                "medium": len([f for f in security_findings if f.severity == "medium"]),
                "low": len([f for f in security_findings if f.severity == "low"])
            }
        }
    }

# Background task functions
async def simulate_cspm_scan(provider_name: str):
    """Simulate CSPM scan process"""
    await asyncio.sleep(5)  # Simulate scan time
    print(f"CSPM scan completed for {provider_name}")

async def simulate_casb_sync(provider_name: str):
    """Simulate CASB sync process"""
    await asyncio.sleep(3)  # Simulate sync time
    print(f"CASB sync completed for {provider_name}")

# Health check
@router.get("/health")
async def cloud_security_health(current_user = Depends(get_current_user)):
    """Health check for cloud security module"""
    return {
        "status": "healthy",
        "module": "cloud_security",
        "providers": {
            "cspm": len(cspm_providers),
            "casb": len(casb_providers),
            "cloud_native": len(cloud_native_providers)
        },
        "timestamp": datetime.now().isoformat()
    } 