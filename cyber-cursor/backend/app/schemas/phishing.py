from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EmailType(str, Enum):
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    SPAM = "spam"
    MALWARE = "malware"
    SUSPICIOUS = "suspicious"

class EmailAnalysisCreate(BaseModel):
    subject: str = Field(..., description="Email subject")
    body_text: Optional[str] = Field(None, description="Plain text body")
    body_html: Optional[str] = Field(None, description="HTML body")
    sender: str = Field(..., description="Sender email address")
    recipients: List[str] = Field(..., description="Recipient email addresses")
    attachments: Optional[List[Dict[str, Any]]] = Field(None, description="Email attachments")

class EmailAnalysisResponse(BaseModel):
    id: int
    subject: str
    body_text: Optional[str]
    body_html: Optional[str]
    sender: str
    recipients: List[str]
    threat_level: ThreatLevel
    email_type: EmailType
    confidence_score: float
    ai_analysis: Dict[str, Any]
    analyzed_by: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class EmailAttachmentResponse(BaseModel):
    id: int
    filename: str
    content_type: str
    size: int
    is_malicious: bool
    threat_indicators: List[str]
    created_at: datetime

    class Config:
        from_attributes = True

class EmailResponseCreate(BaseModel):
    analysis_id: int = Field(..., description="Email analysis ID")
    response_type: str = Field(..., description="Type of response")
    action_taken: str = Field(..., description="Action taken")
    notes: Optional[str] = Field(None, description="Additional notes")

class EmailResponseResponse(BaseModel):
    id: int
    analysis_id: int
    response_type: str
    action_taken: str
    notes: Optional[str]
    created_by: int
    created_at: datetime

    class Config:
        from_attributes = True

class PhishingTemplateCreate(BaseModel):
    name: str = Field(..., description="Template name")
    description: str = Field(..., description="Template description")
    template_type: str = Field(..., description="Template type")
    content: str = Field(..., description="Template content")
    is_active: bool = Field(True, description="Whether template is active")

class PhishingTemplateResponse(BaseModel):
    id: int
    name: str
    description: str
    template_type: str
    content: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class ThreatIntelligenceResponse(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    threat_level: ThreatLevel
    confidence_score: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    metadata: Dict[str, Any]

    class Config:
        from_attributes = True

class PhishingStats(BaseModel):
    total_analyses: int
    phishing_count: int
    spam_count: int
    malware_count: int
    legitimate_count: int
    threat_level_distribution: Dict[str, int]
    daily_trends: List[Dict[str, Any]]
    top_senders: List[Dict[str, Any]]
    top_indicators: List[Dict[str, Any]]
