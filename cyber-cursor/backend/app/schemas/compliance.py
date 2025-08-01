from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

class ComplianceFramework(str, Enum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST = "nist"
    CIS = "cis"

class ReportType(str, Enum):
    SECURITY_REPORT = "security_report"
    COMPLIANCE_REPORT = "compliance_report"
    AUDIT_REPORT = "audit_report"
    INCIDENT_REPORT = "incident_report"
    RISK_ASSESSMENT = "risk_assessment"
    EXECUTIVE_SUMMARY = "executive_summary"

class ReportFormat(str, Enum):
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    XML = "xml"

class SecurityReportRequest(BaseModel):
    """Request model for generating security reports"""
    report_type: ReportType = Field(..., description="Type of security report to generate")
    period_start: datetime = Field(..., description="Start date for report period")
    period_end: datetime = Field(..., description="End date for report period")
    format: ReportFormat = Field(default=ReportFormat.JSON, description="Output format for report")

class SecurityReportResponse(BaseModel):
    """Response model for security reports"""
    success: bool
    report: Dict[str, Any]

class ComplianceReportRequest(BaseModel):
    """Request model for generating compliance reports"""
    framework: ComplianceFramework = Field(..., description="Compliance framework to report on")
    format: ReportFormat = Field(default=ReportFormat.JSON, description="Output format for report")

class ComplianceReportResponse(BaseModel):
    """Response model for compliance reports"""
    success: bool
    report: Dict[str, Any]

class AuditReportRequest(BaseModel):
    """Request model for generating audit reports"""
    audit_scope: Dict[str, Any] = Field(..., description="Scope of the audit")
    format: ReportFormat = Field(default=ReportFormat.JSON, description="Output format for report")

class AuditReportResponse(BaseModel):
    """Response model for audit reports"""
    success: bool
    report: Dict[str, Any]

class ComplianceRequirementRequest(BaseModel):
    """Request model for assessing compliance requirements"""
    framework: str = Field(..., description="Compliance framework")
    control_id: str = Field(..., description="Control identifier")
    evidence: List[str] = Field(..., description="Evidence for compliance assessment")

class ComplianceRequirementResponse(BaseModel):
    """Response model for compliance requirements"""
    success: bool
    requirement: Dict[str, Any]

class AuditLogResponse(BaseModel):
    """Response model for audit logs"""
    id: str
    timestamp: str
    user_id: Optional[int]
    action: str
    resource: str
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]

class ComplianceStatus(BaseModel):
    """Model for compliance status"""
    framework: ComplianceFramework
    status: str
    score: float = Field(..., ge=0.0, le=100.0)
    last_assessed: str
    next_assessment: str
    controls_assessed: int
    controls_compliant: int
    controls_non_compliant: int

class ComplianceControl(BaseModel):
    """Model for compliance controls"""
    id: str
    framework: ComplianceFramework
    title: str
    description: str
    status: str
    evidence: List[str]
    last_assessed: str
    next_assessment: str
    risk_level: str
    remediation_effort: str

class AuditFinding(BaseModel):
    """Model for audit findings"""
    id: str
    category: str
    description: str
    severity: str
    status: str
    created_at: str
    resolved_at: Optional[str]
    assigned_to: Optional[str]
    remediation_plan: Optional[str]

class ComplianceGap(BaseModel):
    """Model for compliance gaps"""
    control_id: str
    framework: ComplianceFramework
    gap_description: str
    severity: str
    remediation_effort: str
    estimated_cost: str
    timeline: str
    responsible_party: str

class RemediationPlan(BaseModel):
    """Model for remediation plans"""
    gap_id: str
    action: str
    priority: str
    timeline: str
    resources: List[str]
    estimated_cost: str
    status: str
    completion_date: Optional[str]

class ComplianceEvidence(BaseModel):
    """Model for compliance evidence"""
    id: str
    type: str
    name: str
    description: str
    file_path: Optional[str]
    uploaded_at: str
    uploaded_by: str
    status: str
    review_date: Optional[str]

class ComplianceDashboard(BaseModel):
    """Model for compliance dashboard"""
    overall_score: float = Field(..., ge=0.0, le=100.0)
    framework_scores: Dict[str, float]
    recent_findings: List[AuditFinding]
    upcoming_assessments: List[Dict[str, Any]]
    compliance_trends: Dict[str, Any]
    risk_summary: Dict[str, Any]

class ReportTemplate(BaseModel):
    """Model for report templates"""
    id: str
    name: str
    type: ReportType
    description: str
    sections: List[str]
    created_at: str
    updated_at: str
    is_default: bool

class ComplianceMetrics(BaseModel):
    """Model for compliance metrics"""
    total_requirements: int
    compliant_requirements: int
    non_compliant_requirements: int
    partially_compliant_requirements: int
    overall_compliance_score: float = Field(..., ge=0.0, le=100.0)
    framework_breakdown: Dict[str, Dict[str, Any]]
    trend_analysis: Dict[str, Any]

class AuditScope(BaseModel):
    """Model for audit scope"""
    systems: List[str]
    time_period: Dict[str, str]
    frameworks: List[ComplianceFramework]
    controls: List[str]
    objectives: List[str]
    exclusions: List[str]

class ComplianceAssessment(BaseModel):
    """Model for compliance assessment"""
    id: str
    framework: ComplianceFramework
    assessment_date: str
    assessor: str
    scope: Dict[str, Any]
    findings: List[AuditFinding]
    overall_status: str
    score: float = Field(..., ge=0.0, le=100.0)
    recommendations: List[str]

class ComplianceReport(BaseModel):
    """Model for compliance report"""
    id: str
    title: str
    framework: ComplianceFramework
    generated_at: str
    period: Dict[str, str]
    executive_summary: str
    detailed_findings: List[Dict[str, Any]]
    recommendations: List[str]
    appendices: List[Dict[str, Any]]

class SecurityReport(BaseModel):
    """Model for security report"""
    id: str
    title: str
    type: ReportType
    generated_at: str
    period: Dict[str, str]
    executive_summary: Dict[str, Any]
    incident_overview: List[Dict[str, Any]]
    threat_analysis: Dict[str, Any]
    vulnerability_assessment: Dict[str, Any]
    security_metrics: Dict[str, Any]
    recommendations: List[str]

class AuditReport(BaseModel):
    """Model for audit report"""
    id: str
    title: str
    audit_date: str
    scope: AuditScope
    methodology: str
    findings: List[AuditFinding]
    risk_assessment: Dict[str, Any]
    compliance_status: Dict[str, Any]
    recommendations: List[str]
    conclusion: str

class ComplianceHealth(BaseModel):
    """Model for compliance service health"""
    status: str
    frameworks_loaded: int
    requirements_assessed: int
    audit_logs_count: int
    last_activity: str
    service_uptime: str
    performance_metrics: Dict[str, Any]

class ComplianceTrend(BaseModel):
    """Model for compliance trends"""
    framework: ComplianceFramework
    period: str
    score: float = Field(..., ge=0.0, le=100.0)
    trend: str
    change_percentage: float
    factors: List[str]

class ComplianceRisk(BaseModel):
    """Model for compliance risks"""
    id: str
    category: str
    description: str
    likelihood: str
    impact: str
    risk_level: str
    mitigation_strategies: List[str]
    responsible_party: str
    due_date: str
    status: str 