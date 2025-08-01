from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List, Any, Optional
import structlog
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, RoleChecker
from app.models.user import User
from app.services.compliance_service import compliance_service, ComplianceFramework, ReportType, ReportFormat
from app.schemas.compliance import (
    SecurityReportRequest, SecurityReportResponse, ComplianceReportRequest,
    ComplianceReportResponse, AuditReportRequest, AuditReportResponse,
    AuditLogResponse, ComplianceRequirementRequest, ComplianceRequirementResponse
)

logger = structlog.get_logger()
router = APIRouter()

# Role-based access control
admin_only = RoleChecker(["admin"])

@router.post("/reports/security", response_model=SecurityReportResponse)
async def generate_security_report(
    request: SecurityReportRequest,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Generate a security report"""
    try:
        report = await compliance_service.generate_security_report(
            report_type=request.report_type,
            period_start=request.period_start,
            period_end=request.period_end,
            format=request.format
        )
        
        return {
            "success": True,
            "report": {
                "id": report.id,
                "title": report.title,
                "type": report.report_type.value,
                "generated_at": report.generated_at.isoformat(),
                "period_start": report.period_start.isoformat(),
                "period_end": report.period_end.isoformat(),
                "summary": report.summary,
                "recommendations": report.recommendations,
                "data": report.data
            }
        }
    except Exception as e:
        logger.error("Error generating security report", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate security report"
        )

@router.post("/reports/compliance", response_model=ComplianceReportResponse)
async def generate_compliance_report(
    request: ComplianceReportRequest,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Generate a compliance report"""
    try:
        report = await compliance_service.generate_compliance_report(
            framework=request.framework,
            format=request.format
        )
        
        return {
            "success": True,
            "report": report
        }
    except Exception as e:
        logger.error("Error generating compliance report", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate compliance report"
        )

@router.post("/reports/audit", response_model=AuditReportResponse)
async def generate_audit_report(
    request: AuditReportRequest,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Generate an audit report"""
    try:
        report = await compliance_service.generate_audit_report(
            audit_scope=request.audit_scope,
            format=request.format
        )
        
        return {
            "success": True,
            "report": report
        }
    except Exception as e:
        logger.error("Error generating audit report", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate audit report"
        )

@router.get("/frameworks", response_model=Dict[str, Any])
async def get_compliance_frameworks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get available compliance frameworks"""
    try:
        frameworks = {}
        for framework, info in compliance_service.compliance_frameworks.items():
            frameworks[framework.value] = {
                "name": info["name"],
                "description": info["description"],
                "controls": info["controls"]
            }
            
        return {
            "success": True,
            "frameworks": frameworks
        }
    except Exception as e:
        logger.error("Error getting compliance frameworks", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance frameworks"
        )

@router.get("/frameworks/{framework}/controls")
async def get_framework_controls(
    framework: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get controls for a specific framework"""
    try:
        framework_enum = ComplianceFramework(framework)
        framework_info = compliance_service.compliance_frameworks.get(framework_enum)
        
        if not framework_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Framework not found"
            )
            
        return {
            "success": True,
            "framework": framework,
            "controls": framework_info["controls"]
        }
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid framework"
        )
    except Exception as e:
        logger.error("Error getting framework controls", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get framework controls"
        )

@router.post("/requirements/assess", response_model=ComplianceRequirementResponse)
async def assess_compliance_requirement(
    request: ComplianceRequirementRequest,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Assess a compliance requirement"""
    try:
        framework_enum = ComplianceFramework(request.framework)
        requirement = await compliance_service.assess_compliance_requirement(
            framework=framework_enum,
            control_id=request.control_id,
            evidence=request.evidence
        )
        
        return {
            "success": True,
            "requirement": {
                "id": requirement.id,
                "framework": requirement.framework.value,
                "control_id": requirement.control_id,
                "title": requirement.title,
                "description": requirement.description,
                "status": requirement.status,
                "evidence": requirement.evidence,
                "last_assessed": requirement.last_assessed.isoformat(),
                "next_assessment": requirement.next_assessment.isoformat()
            }
        }
    except Exception as e:
        logger.error("Error assessing compliance requirement", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assess compliance requirement"
        )

@router.get("/requirements", response_model=List[ComplianceRequirementResponse])
async def get_compliance_requirements(
    framework: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance requirements with filters"""
    try:
        requirements = list(compliance_service.compliance_requirements.values())
        
        if framework:
            framework_enum = ComplianceFramework(framework)
            requirements = [r for r in requirements if r.framework == framework_enum]
            
        if status:
            requirements = [r for r in requirements if r.status == status]
            
        return [
            {
                "success": True,
                "requirement": {
                    "id": req.id,
                    "framework": req.framework.value,
                    "control_id": req.control_id,
                    "title": req.title,
                    "description": req.description,
                    "status": req.status,
                    "evidence": req.evidence,
                    "last_assessed": req.last_assessed.isoformat(),
                    "next_assessment": req.next_assessment.isoformat()
                }
            }
            for req in requirements
        ]
    except Exception as e:
        logger.error("Error getting compliance requirements", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance requirements"
        )

@router.post("/audit/log")
async def log_audit_event(
    action: str,
    resource: str,
    details: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Log an audit event"""
    try:
        await compliance_service.log_audit_event(
            user_id=current_user.id,
            action=action,
            resource=resource,
            details=details
        )
        
        return {
            "success": True,
            "message": "Audit event logged successfully"
        }
    except Exception as e:
        logger.error("Error logging audit event", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to log audit event"
        )

@router.get("/audit/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Get audit logs with filters"""
    try:
        logs = await compliance_service.get_audit_logs(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            action=action
        )
        
        return [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "user_id": log.user_id,
                "action": log.action,
                "resource": log.resource,
                "details": log.details,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent
            }
            for log in logs
        ]
    except Exception as e:
        logger.error("Error getting audit logs", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get audit logs"
        )

@router.get("/reports/templates")
async def get_report_templates(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get available report templates"""
    try:
        templates = {}
        for report_type, template in compliance_service.report_templates.items():
            templates[report_type.value] = {
                "title": template["title"],
                "sections": template["sections"]
            }
            
        return {
            "success": True,
            "templates": templates
        }
    except Exception as e:
        logger.error("Error getting report templates", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get report templates"
        )

@router.get("/reports/history")
async def get_report_history(
    report_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Get report generation history"""
    try:
        # Mock report history
        history = [
            {
                "id": "report_001",
                "type": "security_report",
                "title": "Monthly Security Report - January 2024",
                "generated_at": "2024-01-31T23:59:59Z",
                "generated_by": "admin@company.com",
                "status": "completed"
            },
            {
                "id": "report_002",
                "type": "compliance_report",
                "title": "SOC 2 Compliance Report",
                "generated_at": "2024-01-15T10:30:00Z",
                "generated_by": "admin@company.com",
                "status": "completed"
            },
            {
                "id": "report_003",
                "type": "audit_report",
                "title": "Annual Security Audit Report",
                "generated_at": "2024-01-01T09:00:00Z",
                "generated_by": "admin@company.com",
                "status": "completed"
            }
        ]
        
        # Apply filters
        if report_type:
            history = [h for h in history if h["type"] == report_type]
            
        if start_date:
            history = [h for h in history if datetime.fromisoformat(h["generated_at"].replace("Z", "+00:00")) >= start_date]
            
        if end_date:
            history = [h for h in history if datetime.fromisoformat(h["generated_at"].replace("Z", "+00:00")) <= end_date]
            
        return {
            "success": True,
            "history": history
        }
    except Exception as e:
        logger.error("Error getting report history", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get report history"
        )

@router.get("/dashboard/overview")
async def get_compliance_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance dashboard overview"""
    try:
        # Mock dashboard data
        dashboard_data = {
            "compliance_status": {
                "soc2": {
                    "status": "compliant",
                    "score": 95,
                    "last_assessed": "2024-01-15T10:30:00Z",
                    "next_assessment": "2024-04-15T10:30:00Z"
                },
                "iso27001": {
                    "status": "compliant",
                    "score": 92,
                    "last_assessed": "2024-01-10T14:20:00Z",
                    "next_assessment": "2024-04-10T14:20:00Z"
                },
                "gdpr": {
                    "status": "partially_compliant",
                    "score": 78,
                    "last_assessed": "2024-01-20T16:45:00Z",
                    "next_assessment": "2024-04-20T16:45:00Z"
                }
            },
            "recent_audit_findings": [
                {
                    "id": "F001",
                    "category": "Access Control",
                    "severity": "medium",
                    "status": "open",
                    "created_at": "2024-01-25T11:15:00Z"
                },
                {
                    "id": "F002",
                    "category": "System Security",
                    "severity": "high",
                    "status": "resolved",
                    "created_at": "2024-01-20T09:30:00Z"
                }
            ],
            "upcoming_assessments": [
                {
                    "framework": "SOC 2",
                    "due_date": "2024-04-15T10:30:00Z",
                    "days_remaining": 75
                },
                {
                    "framework": "ISO 27001",
                    "due_date": "2024-04-10T14:20:00Z",
                    "days_remaining": 70
                }
            ],
            "compliance_metrics": {
                "total_requirements": 156,
                "compliant_requirements": 142,
                "non_compliant_requirements": 8,
                "partially_compliant_requirements": 6,
                "overall_compliance_score": 91
            }
        }
        
        return {
            "success": True,
            "dashboard": dashboard_data
        }
    except Exception as e:
        logger.error("Error getting compliance dashboard", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance dashboard"
        )

@router.get("/metrics/compliance")
async def get_compliance_metrics(
    framework: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance metrics"""
    try:
        # Mock compliance metrics
        metrics = {
            "overall_compliance_score": 91,
            "framework_scores": {
                "soc2": 95,
                "iso27001": 92,
                "gdpr": 78,
                "hipaa": 88,
                "pci_dss": 85
            },
            "requirement_status": {
                "compliant": 142,
                "partially_compliant": 6,
                "non_compliant": 8,
                "not_assessed": 0
            },
            "trends": {
                "last_month": 89,
                "current_month": 91,
                "trend": "improving"
            }
        }
        
        if framework:
            framework_metrics = {
                "framework": framework,
                "score": metrics["framework_scores"].get(framework, 0),
                "status": "compliant" if metrics["framework_scores"].get(framework, 0) >= 90 else "partially_compliant"
            }
            return {
                "success": True,
                "metrics": framework_metrics
            }
            
        return {
            "success": True,
            "metrics": metrics
        }
    except Exception as e:
        logger.error("Error getting compliance metrics", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance metrics"
        )

@router.get("/health")
async def get_compliance_health(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance service health status"""
    try:
        health_status = {
            "status": "healthy",
            "frameworks_loaded": len(compliance_service.compliance_frameworks),
            "requirements_assessed": len(compliance_service.compliance_requirements),
            "audit_logs_count": len(compliance_service.audit_logs),
            "last_activity": datetime.utcnow().isoformat(),
            "service_uptime": "24 hours"
        }
        
        return {
            "success": True,
            "health": health_status
        }
    except Exception as e:
        logger.error("Error getting compliance health", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance health"
        ) 