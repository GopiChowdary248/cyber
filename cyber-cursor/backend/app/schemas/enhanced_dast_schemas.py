"""
Enhanced DAST Schemas
Pydantic schemas for enhanced DAST models with AI intelligence capabilities.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

# ============================================================================
# Enhanced DAST Enums
# ============================================================================

class VulnerabilityConfidence(str, Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"

class AIDetectionMethod(str, Enum):
    MACHINE_LEARNING = "machine_learning"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"

# ============================================================================
# Enhanced DAST Base Schemas
# ============================================================================

class EnhancedDASTVulnerabilityBase(BaseModel):
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed vulnerability description")
    severity: str = Field(..., description="Vulnerability severity level")
    confidence: VulnerabilityConfidence = Field(VulnerabilityConfidence.MEDIUM, description="AI confidence level")
    vulnerability_type: str = Field(..., description="Type of vulnerability")
    attack_vector: Optional[str] = Field(None, description="Attack vector used")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept details")
    tags: Optional[List[str]] = Field(default_factory=list, description="Vulnerability tags")

class DASTAIAnalysisBase(BaseModel):
    ai_model_version: Optional[str] = Field(None, description="AI model version used")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="AI confidence score (0.0-1.0)")
    false_positive_probability: float = Field(..., ge=0.0, le=1.0, description="False positive probability")
    request_patterns: Optional[Dict[str, Any]] = Field(None, description="Request pattern analysis")
    response_anomalies: Optional[Dict[str, Any]] = Field(None, description="Response anomaly analysis")
    analysis_notes: Optional[str] = Field(None, description="Analysis notes and observations")

# ============================================================================
# Enhanced DAST Create Schemas
# ============================================================================

class EnhancedDASTVulnerabilityCreate(EnhancedDASTVulnerabilityBase):
    project_id: uuid.UUID = Field(..., description="DAST project ID")
    scan_id: uuid.UUID = Field(..., description="DAST scan ID")
    
    # AI-powered intelligence
    ai_detection_method: Optional[AIDetectionMethod] = Field(None, description="AI detection method used")
    ai_confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="AI confidence score")
    ai_false_positive_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="False positive probability")

class DASTAIAnalysisCreate(DASTAIAnalysisBase):
    vulnerability_id: uuid.UUID = Field(..., description="Enhanced DAST vulnerability ID")

# ============================================================================
# Enhanced DAST Update Schemas
# ============================================================================

class EnhancedDASTVulnerabilityUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[VulnerabilityConfidence] = None
    vulnerability_type: Optional[str] = None
    attack_vector: Optional[str] = None
    proof_of_concept: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    
    # AI intelligence updates
    ai_confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    ai_false_positive_probability: Optional[float] = Field(None, ge=0.0, le=1.0)

class DASTAIAnalysisUpdate(BaseModel):
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    false_positive_probability: Optional[float] = Field(None, ge=0.0, le=1.0)
    request_patterns: Optional[Dict[str, Any]] = None
    response_anomalies: Optional[Dict[str, Any]] = None
    analysis_notes: Optional[str] = None
    analyst_review: Optional[bool] = None

# ============================================================================
# Enhanced DAST Response Schemas
# ============================================================================

class DASTAIAnalysisResponse(DASTAIAnalysisBase):
    id: uuid.UUID
    vulnerability_id: uuid.UUID
    analysis_timestamp: datetime
    analyst_review: bool
    
    class Config:
        from_attributes = True

class EnhancedDASTVulnerabilityResponse(EnhancedDASTVulnerabilityBase):
    id: uuid.UUID
    project_id: uuid.UUID
    scan_id: uuid.UUID
    
    # AI-powered intelligence
    ai_detection_method: Optional[AIDetectionMethod]
    ai_confidence_score: Optional[float]
    ai_false_positive_probability: Optional[float]
    
    # Metadata
    discovered_at: datetime
    status: str
    
    # Relationships
    ai_analysis: Optional[DASTAIAnalysisResponse] = None
    
    class Config:
        from_attributes = True

# ============================================================================
# Enhanced DAST Analysis Schemas
# ============================================================================

class AIAnalysisRequest(BaseModel):
    vulnerability_id: uuid.UUID = Field(..., description="Vulnerability to analyze")
    analysis_type: str = Field("comprehensive", description="Type of analysis to perform")
    include_behavioral_analysis: bool = Field(True, description="Include behavioral analysis")
    include_pattern_recognition: bool = Field(True, description="Include pattern recognition")

class AIAnalysisResult(BaseModel):
    analysis_id: str
    vulnerability_id: uuid.UUID
    analysis_status: str
    confidence_score: float
    false_positive_probability: float
    detection_method: AIDetectionMethod
    analysis_duration: float  # seconds
    started_at: datetime
    completed_at: Optional[datetime]
    findings: Dict[str, Any]
    recommendations: List[str]

# ============================================================================
# Enhanced DAST Dashboard Schemas
# ============================================================================

class EnhancedDASTDashboard(BaseModel):
    total_vulnerabilities: int
    ai_analyzed_vulnerabilities: int
    high_confidence_findings: int
    low_confidence_findings: int
    false_positive_rate: float
    average_confidence_score: float
    ai_analysis_coverage: float
    recent_ai_findings: List[Dict[str, Any]]
    ai_performance_metrics: Dict[str, Any]

class DASTSecurityMetrics(BaseModel):
    vulnerability_distribution: Dict[str, int]
    confidence_distribution: Dict[str, int]
    ai_detection_methods: Dict[str, int]
    false_positive_trends: Dict[str, float]
    remediation_effectiveness: Dict[str, float]
    ai_model_performance: Dict[str, Any]

# ============================================================================
# Enhanced DAST Integration Schemas
# ============================================================================

class DASTCloudSecurityCorrelation(BaseModel):
    dast_vulnerability_id: uuid.UUID
    cloud_security_finding_id: uuid.UUID
    correlation_type: str
    correlation_score: float
    correlation_evidence: Dict[str, Any]
    unified_risk_assessment: Dict[str, Any]

class UnifiedSecurityDashboard(BaseModel):
    dast_security_score: float
    cloud_security_score: float
    unified_security_score: float
    correlated_findings: List[DASTCloudSecurityCorrelation]
    overall_risk_assessment: Dict[str, Any]
    security_trends: Dict[str, Any]
