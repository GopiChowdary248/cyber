from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnomalyType(str, Enum):
    LOGIN_ANOMALY = "login_anomaly"
    NETWORK_ANOMALY = "network_anomaly"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    SYSTEM_ANOMALY = "system_anomaly"
    DATA_ANOMALY = "data_anomaly"

class ThreatAnalysisRequest(BaseModel):
    """Request model for threat analysis"""
    data: Dict[str, Any] = Field(..., description="Data to analyze for threats")

class ThreatIndicator(BaseModel):
    """Model for threat indicators"""
    id: str
    name: str
    description: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    threat_level: ThreatLevel
    source: str
    timestamp: str
    metadata: Dict[str, Any]

class ThreatAnalysisResponse(BaseModel):
    """Response model for threat analysis"""
    success: bool
    indicators: List[ThreatIndicator]
    total_indicators: int
    analysis_timestamp: str

class AnomalyDetectionRequest(BaseModel):
    """Request model for anomaly detection"""
    data: Dict[str, Any] = Field(..., description="Data to analyze for anomalies")

class AnomalyDetection(BaseModel):
    """Model for anomaly detections"""
    id: str
    type: AnomalyType
    severity: float = Field(..., ge=0.0, le=1.0)
    description: str
    user_id: Optional[int]
    timestamp: str
    features: Dict[str, float]
    metadata: Dict[str, Any]

class AnomalyDetectionResponse(BaseModel):
    """Response model for anomaly detection"""
    success: bool
    anomalies: List[AnomalyDetection]
    total_anomalies: int
    detection_timestamp: str

class ThreatPredictionResponse(BaseModel):
    """Response model for threat predictions"""
    threat_type: str
    probability: float = Field(..., ge=0.0, le=1.0)
    timeframe: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    indicators: List[str]
    recommendations: List[str]

class IncidentClassificationRequest(BaseModel):
    """Request model for incident classification"""
    incident_data: Dict[str, Any] = Field(..., description="Incident data to classify")

class IncidentClassificationResponse(BaseModel):
    """Response model for incident classification"""
    success: bool
    classification: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    probabilities: Dict[str, float]
    classification_timestamp: str

class SecurityInsightsResponse(BaseModel):
    """Response model for security insights"""
    success: bool
    insights: Dict[str, Any]
    generated_at: str

class ModelTrainingRequest(BaseModel):
    """Request model for model training"""
    training_data: List[Dict[str, Any]] = Field(..., description="Training data for models")

class ThreatLandscape(BaseModel):
    """Model for threat landscape analysis"""
    overall_risk_level: str
    threat_distribution: Dict[str, float]
    trending_threats: List[Dict[str, Any]]
    top_attack_vectors: List[str]
    geographic_hotspots: List[Dict[str, str]]
    analysis_timestamp: str

class SecurityMetrics(BaseModel):
    """Model for security metrics"""
    incident_metrics: Dict[str, Any]
    response_metrics: Dict[str, Any]
    detection_metrics: Dict[str, Any]
    threat_metrics: Dict[str, Any]
    user_metrics: Dict[str, Any]
    system_metrics: Dict[str, Any]
    calculated_at: str

class SecurityTrends(BaseModel):
    """Model for security trends"""
    incident_trends: Dict[str, List[int]]
    threat_trends: Dict[str, List[int]]
    response_trends: Dict[str, List[float]]
    timeframe: str
    generated_at: str

class ModelStatus(BaseModel):
    """Model for AI/ML model status"""
    loaded: bool
    type: str
    parameters: str

class AIMLHealth(BaseModel):
    """Model for AI/ML service health"""
    status: str
    models_loaded: int
    service_uptime: str
    last_training: str
    model_accuracy: Dict[str, float]
    performance_metrics: Dict[str, Any]
    checked_at: str

class SecurityRecommendation(BaseModel):
    """Model for security recommendations"""
    recommendation: str
    priority: str
    estimated_impact: str
    implementation_effort: str
    category: str
    rationale: str

class ThreatPrediction(BaseModel):
    """Model for threat predictions"""
    threat_type: str
    probability: float = Field(..., ge=0.0, le=1.0)
    timeframe: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    indicators: List[str]
    recommendations: List[str]
    risk_score: float = Field(..., ge=0.0, le=10.0)

class AnomalyScore(BaseModel):
    """Model for anomaly scores"""
    user_id: Optional[int]
    anomaly_type: AnomalyType
    score: float = Field(..., ge=0.0, le=1.0)
    threshold: float = Field(..., ge=0.0, le=1.0)
    is_anomaly: bool
    features: Dict[str, float]
    timestamp: str

class ModelPerformance(BaseModel):
    """Model for model performance metrics"""
    model_name: str
    accuracy: float = Field(..., ge=0.0, le=1.0)
    precision: float = Field(..., ge=0.0, le=1.0)
    recall: float = Field(..., ge=0.0, le=1.0)
    f1_score: float = Field(..., ge=0.0, le=1.0)
    training_samples: int
    last_updated: str

class FeatureImportance(BaseModel):
    """Model for feature importance analysis"""
    feature_name: str
    importance_score: float = Field(..., ge=0.0, le=1.0)
    rank: int
    category: str

class PredictionConfidence(BaseModel):
    """Model for prediction confidence intervals"""
    prediction: str
    confidence_lower: float = Field(..., ge=0.0, le=1.0)
    confidence_upper: float = Field(..., ge=0.0, le=1.0)
    confidence_level: float = Field(..., ge=0.0, le=1.0)

class BehavioralProfile(BaseModel):
    """Model for user behavioral profiles"""
    user_id: int
    risk_score: float = Field(..., ge=0.0, le=10.0)
    behavior_patterns: Dict[str, Any]
    anomaly_history: List[Dict[str, Any]]
    last_updated: str

class ThreatIntelligence(BaseModel):
    """Model for threat intelligence data"""
    threat_id: str
    threat_name: str
    threat_type: str
    severity: ThreatLevel
    description: str
    indicators: List[str]
    mitigation_strategies: List[str]
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str
    timestamp: str

class ModelConfiguration(BaseModel):
    """Model for AI/ML model configuration"""
    model_name: str
    parameters: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    training_config: Dict[str, Any]
    version: str
    created_at: str

class TrainingJob(BaseModel):
    """Model for training job status"""
    job_id: str
    model_name: str
    status: str
    progress: float = Field(..., ge=0.0, le=1.0)
    start_time: str
    estimated_completion: str
    training_samples: int
    validation_samples: int 