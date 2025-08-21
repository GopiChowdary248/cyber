"""
Enhanced DAST Models with AI Intelligence
Advanced Dynamic Application Security Testing models with AI-powered vulnerability detection.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum
import uuid
from datetime import datetime

class VulnerabilityConfidence(str, enum.Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"

class AIDetectionMethod(str, enum.Enum):
    MACHINE_LEARNING = "machine_learning"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"

class EnhancedDASTVulnerability(Base):
    """Enhanced DAST vulnerability with AI intelligence"""
    __tablename__ = "enhanced_dast_vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("dast_scans.id"), nullable=False)
    
    # Enhanced vulnerability details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)
    confidence = Column(Enum(VulnerabilityConfidence), default=VulnerabilityConfidence.MEDIUM)
    
    # AI-powered intelligence
    ai_detection_method = Column(Enum(AIDetectionMethod), nullable=True)
    ai_confidence_score = Column(Float, default=0.0)
    ai_false_positive_probability = Column(Float, default=0.0)
    
    # Advanced technical details
    vulnerability_type = Column(String(100), nullable=False)
    attack_vector = Column(String(100), nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    
    # Metadata
    discovered_at = Column(DateTime, default=func.now())
    status = Column(String(50), default="open")
    tags = Column(JSON, nullable=True)

class DASTAIAnalysis(Base):
    """AI analysis results for DAST vulnerabilities"""
    __tablename__ = "dast_ai_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("enhanced_dast_vulnerabilities.id"), nullable=False)
    
    # AI analysis details
    analysis_timestamp = Column(DateTime, default=func.now())
    ai_model_version = Column(String(100), nullable=True)
    confidence_score = Column(Float, nullable=False)
    false_positive_probability = Column(Float, nullable=False)
    
    # Behavioral analysis
    request_patterns = Column(JSON, nullable=True)
    response_anomalies = Column(JSON, nullable=True)
    
    # Analysis metadata
    analysis_notes = Column(Text, nullable=True)
    analyst_review = Column(Boolean, default=False)
