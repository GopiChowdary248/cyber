from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum

from app.core.database import Base

class EmailStatus(str, Enum):
    PENDING = "pending"
    ANALYZED = "analyzed"
    QUARANTINED = "quarantined"
    RELEASED = "released"
    DELETED = "deleted"

class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EmailType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"

class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String(255), nullable=False)  # External email ID
    message_id = Column(String(255), nullable=True)  # Email message ID
    
    # Email details
    sender = Column(String(255), nullable=False)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    
    # Analysis results
    threat_level = Column(String(20), default=ThreatLevel.SAFE)
    email_type = Column(String(20), default=EmailType.LEGITIMATE)
    confidence_score = Column(Float, nullable=True)  # 0-100 confidence in analysis
    
    # AI analysis
    ai_analysis = Column(JSON, nullable=True)  # Detailed AI analysis results
    detected_threats = Column(JSON, nullable=True)  # Array of detected threats
    indicators = Column(JSON, nullable=True)  # Indicators of compromise
    
    # Status
    status = Column(String(20), default=EmailStatus.PENDING)
    is_quarantined = Column(Boolean, default=False)
    quarantine_reason = Column(Text, nullable=True)
    
    # Timestamps
    received_at = Column(DateTime, nullable=True)
    analyzed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    attachments = relationship("EmailAttachment", back_populates="email")
    responses = relationship("EmailResponse", back_populates="email")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, analysis_id: int) -> Optional["EmailAnalysis"]:
        """Get email analysis by ID"""
        result = await db.execute(select(cls).where(cls.id == analysis_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_threat_level(cls, db: AsyncSession, threat_level: str) -> List["EmailAnalysis"]:
        """Get emails by threat level"""
        result = await db.execute(select(cls).where(cls.threat_level == threat_level).order_by(cls.created_at.desc()))
        return result.scalars().all()
    
    @classmethod
    async def get_quarantined(cls, db: AsyncSession) -> List["EmailAnalysis"]:
        """Get quarantined emails"""
        result = await db.execute(select(cls).where(cls.is_quarantined == True).order_by(cls.created_at.desc()))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<EmailAnalysis(id={self.id}, sender='{self.sender}', threat_level='{self.threat_level}')>"

class EmailAttachment(Base):
    __tablename__ = "email_attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_analyses.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=True)
    file_size = Column(Integer, nullable=True)
    
    # Security analysis
    is_malicious = Column(Boolean, default=False)
    threat_type = Column(String(100), nullable=True)
    malware_signature = Column(String(255), nullable=True)
    
    # File details
    file_hash = Column(String(64), nullable=True)  # SHA-256 hash
    file_path = Column(String(500), nullable=True)  # Path to stored file
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    email = relationship("EmailAnalysis", back_populates="attachments")
    
    def __repr__(self):
        return f"<EmailAttachment(id={self.id}, filename='{self.filename}', is_malicious={self.is_malicious})>"

class EmailResponse(Base):
    __tablename__ = "email_responses"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_analyses.id"), nullable=False)
    response_type = Column(String(50), nullable=False)  # auto_reply, quarantine, delete, forward
    
    # Response details
    action_taken = Column(Text, nullable=False)
    response_message = Column(Text, nullable=True)
    recipient_notified = Column(Boolean, default=False)
    
    # AI-generated response
    ai_generated = Column(Boolean, default=False)
    response_template = Column(String(100), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    executed_at = Column(DateTime, nullable=True)
    
    # Relationships
    email = relationship("EmailAnalysis", back_populates="responses")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    def __repr__(self):
        return f"<EmailResponse(id={self.id}, type='{self.response_type}', action='{self.action_taken}')>"

class PhishingTemplate(Base):
    __tablename__ = "phishing_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Template details
    template_type = Column(String(50), nullable=False)  # response, notification, report
    content = Column(Text, nullable=False)
    variables = Column(JSON, nullable=True)  # Template variables
    
    # Usage
    is_active = Column(Boolean, default=True)
    usage_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    def __repr__(self):
        return f"<PhishingTemplate(id={self.id}, name='{self.name}', type='{self.template_type}')>"

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(50), nullable=False)  # domain, ip, email, url, hash
    indicator_value = Column(String(500), nullable=False)
    
    # Threat details
    threat_type = Column(String(100), nullable=True)
    confidence_score = Column(Float, nullable=True)
    severity = Column(String(20), default=ThreatLevel.MEDIUM)
    
    # Intelligence data
    source = Column(String(100), nullable=True)  # Threat feed source
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    tags = Column(JSON, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_whitelisted = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        return f"<ThreatIntelligence(id={self.id}, type='{self.indicator_type}', value='{self.indicator_value}')>"

class EmailRule(Base):
    __tablename__ = "email_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Rule conditions
    conditions = Column(JSON, nullable=False)  # Rule matching conditions
    actions = Column(JSON, nullable=False)  # Actions to take when matched
    
    # Rule settings
    priority = Column(Integer, default=100)  # Higher number = higher priority
    is_active = Column(Boolean, default=True)
    
    # Usage
    match_count = Column(Integer, default=0)
    last_matched = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    def __repr__(self):
        return f"<EmailRule(id={self.id}, name='{self.name}', priority={self.priority})>" 