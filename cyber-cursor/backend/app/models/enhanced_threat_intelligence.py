"""
Enhanced Threat Intelligence Models with AI Capabilities
Advanced threat intelligence models with AI-powered analysis and correlation.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum
import uuid
from datetime import datetime

class AIThreatClassification(str, enum.Enum):
    CERTAIN = "certain"
    HIGH_CONFIDENCE = "high_confidence"
    MEDIUM_CONFIDENCE = "medium_confidence"
    LOW_CONFIDENCE = "low_confidence"
    UNCERTAIN = "uncertain"

class ThreatCorrelationType(str, enum.Enum):
    CLOUD_SECURITY = "cloud_security"
    DAST_VULNERABILITY = "dast_vulnerability"
    NETWORK_ACTIVITY = "network_activity"
    USER_BEHAVIOR = "user_behavior"

class AIThreatAnalysis(Base):
    """AI-powered threat analysis and classification"""
    __tablename__ = "ai_threat_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_indicator_id = Column(UUID(as_uuid=True), ForeignKey("threat_indicators.id"), nullable=False)
    
    # AI analysis details
    analysis_timestamp = Column(DateTime, default=func.now())
    ai_model_version = Column(String(100), nullable=True)
    confidence_score = Column(Float, nullable=False)
    false_positive_probability = Column(Float, nullable=False)
    
    # AI detection methods
    detection_methods = Column(JSON, nullable=True)
    behavioral_indicators = Column(JSON, nullable=True)
    pattern_matches = Column(JSON, nullable=True)
    
    # Analysis metadata
    analysis_notes = Column(Text, nullable=True)
    analyst_review = Column(Boolean, default=False)

class ThreatIntelligenceCorrelation(Base):
    """Correlation between threat intelligence and other security domains"""
    __tablename__ = "threat_intelligence_correlations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_indicator_id = Column(UUID(as_uuid=True), ForeignKey("threat_indicators.id"), nullable=False)
    
    # Correlation details
    correlation_type = Column(Enum(ThreatCorrelationType), nullable=False)
    correlation_score = Column(Float, nullable=False)
    correlation_evidence = Column(JSON, nullable=True)
    
    # Integration IDs
    cloud_security_finding_id = Column(UUID(as_uuid=True), nullable=True)
    dast_vulnerability_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Metadata
    correlation_timestamp = Column(DateTime, default=func.now())
    automated_correlation = Column(Boolean, default=True)

class PredictiveThreatIntelligence(Base):
    """AI-powered predictive threat intelligence"""
    __tablename__ = "predictive_threat_intelligence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Prediction details
    threat_type = Column(String(100), nullable=False)
    predicted_severity = Column(String(50), nullable=False)
    prediction_confidence = Column(Float, nullable=False)
    prediction_horizon = Column(Integer, nullable=False)  # days
    
    # AI prediction data
    prediction_model = Column(String(100), nullable=True)
    contributing_factors = Column(JSON, nullable=True)
    mitigation_recommendations = Column(JSON, nullable=True)
    
    # Metadata
    predicted_at = Column(DateTime, default=func.now())
    prediction_status = Column(String(50), default="active")
