from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum, UUID, SmallInteger, Numeric, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
import enum
import uuid

Base = declarative_base()

# Enums
class AnomalyType(str, enum.Enum):
    BEHAVIORAL = "behavioral"
    NETWORK = "network"
    ACCESS = "access"
    RESOURCE = "resource"
    TIMING = "timing"
    VOLUME = "volume"

class AnomalySeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class MLModelType(str, enum.Enum):
    ANOMALY_DETECTION = "anomaly_detection"
    RISK_PREDICTION = "risk_prediction"
    BEHAVIOR_ANALYSIS = "behavior_analysis"
    THREAT_CLASSIFICATION = "threat_classification"
    COMPLIANCE_PREDICTION = "compliance_prediction"

class ModelStatus(str, enum.Enum):
    TRAINING = "training"
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETIRED = "retired"
    ERROR = "error"

# User and Entity Behavior Analytics (UEBA)
class UserBehavior(Base):
    __tablename__ = "user_behaviors"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    session_id = Column(String(255))
    timestamp = Column(DateTime(timezone=True), nullable=False)
    action_type = Column(String(100), nullable=False)  # login, logout, access, modify, delete
    resource_type = Column(String(100))  # asset, policy, finding, etc.
    resource_id = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    location = Column(JSONB, default={})  # Geographic location
    device_info = Column(JSONB, default={})  # Device fingerprint
    success = Column(Boolean, default=True)
    risk_score = Column(Numeric(5, 2), default=0.0)
    context = Column(JSONB, default={})  # Additional context
    
    # Relationships
    user = relationship("User")
    anomalies = relationship("BehaviorAnomaly", back_populates="behavior")

class BehaviorBaseline(Base):
    __tablename__ = "behavior_baselines"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    baseline_type = Column(String(100), nullable=False)  # login_time, access_pattern, resource_usage
    time_window = Column(String(50))  # daily, weekly, monthly
    start_date = Column(DateTime(timezone=True), nullable=False)
    end_date = Column(DateTime(timezone=True), nullable=False)
    metrics = Column(JSONB, default={})  # Statistical metrics (mean, std, percentiles)
    patterns = Column(JSONB, default={})  # Behavioral patterns
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User")

class BehaviorAnomaly(Base):
    __tablename__ = "behavior_anomalies"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    behavior_id = Column(PGUUID(as_uuid=True), ForeignKey("user_behaviors.id"), nullable=False)
    baseline_id = Column(PGUUID(as_uuid=True), ForeignKey("behavior_baselines.id"))
    anomaly_type = Column(Enum(AnomalyType), nullable=False)
    severity = Column(Enum(AnomalySeverity), nullable=False)
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    deviation_score = Column(Numeric(5, 2), default=0.0)  # How far from baseline
    description = Column(Text)
    indicators = Column(JSONB, default={})  # Anomaly indicators
    risk_factors = Column(JSONB, default=[])  # Contributing risk factors
    mitigation_recommendations = Column(JSONB, default=[])
    status = Column(String(50), default="open")  # open, investigating, resolved, false_positive
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationships
    behavior = relationship("UserBehavior", back_populates="anomalies")
    baseline = relationship("BehaviorBaseline")

# Machine Learning Models
class MLModel(Base):
    __tablename__ = "ml_models"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_name = Column(String(255), nullable=False)
    model_type = Column(Enum(MLModelType), nullable=False)
    version = Column(String(50), nullable=False)
    description = Column(Text)
    algorithm = Column(String(100))  # Random Forest, Neural Network, etc.
    hyperparameters = Column(JSONB, default={})
    training_data_size = Column(BigInteger)
    training_accuracy = Column(Numeric(5, 4))  # 0.0000-1.0000
    validation_accuracy = Column(Numeric(5, 4))
    model_file_path = Column(String(500))  # Path to saved model
    feature_importance = Column(JSONB, default={})
    status = Column(Enum(ModelStatus), default=ModelStatus.TRAINING)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())
    deployed_at = Column(DateTime(timezone=True))
    
    # Relationships
    predictions = relationship("MLPrediction", back_populates="model")
    training_runs = relationship("ModelTrainingRun", back_populates="model")

class ModelTrainingRun(Base):
    __tablename__ = "model_training_runs"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_id = Column(PGUUID(as_uuid=True), ForeignKey("ml_models.id"), nullable=False)
    run_id = Column(String(255), nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True))
    status = Column(String(50))  # running, completed, failed
    training_metrics = Column(JSONB, default={})  # Loss, accuracy, etc.
    validation_metrics = Column(JSONB, default={})
    hyperparameters = Column(JSONB, default={})
    data_sources = Column(JSONB, default=[])  # Training data sources
    error_message = Column(Text)
    
    # Relationships
    model = relationship("MLModel", back_populates="training_runs")

class MLPrediction(Base):
    __tablename__ = "ml_predictions"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_id = Column(PGUUID(as_uuid=True), ForeignKey("ml_models.id"), nullable=False)
    input_data = Column(JSONB, nullable=False)  # Input features
    prediction = Column(JSONB, nullable=False)  # Model output
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    prediction_timestamp = Column(DateTime(timezone=True), server_default=func.now())
    metadata = Column(JSONB, default={})  # Additional metadata
    
    # Relationships
    model = relationship("MLModel", back_populates="predictions")

# Risk Prediction and Scoring
class RiskPrediction(Base):
    __tablename__ = "risk_predictions"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    model_id = Column(PGUUID(as_uuid=True), ForeignKey("ml_models.id"))
    predicted_risk_score = Column(Numeric(5, 2), nullable=False)
    confidence_interval = Column(JSONB, default={})  # Lower and upper bounds
    prediction_horizon = Column(Integer)  # Days into the future
    risk_factors = Column(JSONB, default=[])  # Contributing factors
    trend_direction = Column(String(50))  # increasing, decreasing, stable
    prediction_date = Column(DateTime(timezone=True), server_default=func.now())
    actual_risk_score = Column(Numeric(5, 2))  # Actual score when available
    accuracy = Column(Numeric(5, 4))  # Prediction accuracy
    
    # Relationships
    asset = relationship("Asset")
    model = relationship("MLModel")

class RiskTrend(Base):
    __tablename__ = "risk_trends"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    trend_period = Column(String(50))  # daily, weekly, monthly
    start_date = Column(DateTime(timezone=True), nullable=False)
    end_date = Column(DateTime(timezone=True), nullable=False)
    risk_scores = Column(JSONB, default=[])  # Array of risk scores over time
    trend_analysis = Column(JSONB, default={})  # Trend statistics and patterns
    seasonality = Column(JSONB, default={})  # Seasonal patterns
    volatility = Column(Numeric(5, 2))  # Risk score volatility
    forecast = Column(JSONB, default={})  # Future risk predictions
    
    # Relationships
    asset = relationship("Asset")

# Anomaly Detection
class AnomalyDetection(Base):
    __tablename__ = "anomaly_detections"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    anomaly_type = Column(Enum(AnomalyType), nullable=False)
    severity = Column(Enum(AnomalySeverity), nullable=False)
    detection_method = Column(String(100))  # ML model, rule-based, statistical
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    anomaly_score = Column(Numeric(5, 2), default=0.0)
    description = Column(Text)
    context = Column(JSONB, default={})  # Anomaly context
    baseline_comparison = Column(JSONB, default={})  # Comparison with normal behavior
    risk_assessment = Column(JSONB, default={})  # Risk factors and scoring
    mitigation_recommendations = Column(JSONB, default=[])
    status = Column(String(50), default="detected")  # detected, investigating, resolved, false_positive
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationships
    asset = relationship("Asset")
    related_anomalies = relationship("AnomalyCorrelation", back_populates="anomaly")

class AnomalyCorrelation(Base):
    __tablename__ = "anomaly_correlations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    anomaly_id = Column(PGUUID(as_uuid=True), ForeignKey("anomaly_detections.id"), nullable=False)
    correlated_anomaly_id = Column(PGUUID(as_uuid=True), ForeignKey("anomaly_detections.id"), nullable=False)
    correlation_type = Column(String(100))  # temporal, spatial, causal, etc.
    correlation_strength = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    correlation_evidence = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    anomaly = relationship("AnomalyDetection", foreign_keys=[anomaly_id], back_populates="related_anomalies")
    correlated_anomaly = relationship("AnomalyDetection", foreign_keys=[correlated_anomaly_id])

# Cross-Asset Risk Correlation
class AssetRiskCorrelation(Base):
    __tablename__ = "asset_risk_correlations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    target_asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    correlation_type = Column(String(100))  # dependency, network, data_flow, etc.
    correlation_strength = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    risk_propagation_factor = Column(Numeric(3, 2), default=0.0)  # How risk spreads
    shared_vulnerabilities = Column(JSONB, default=[])
    shared_threats = Column(JSONB, default=[])
    mitigation_impact = Column(JSONB, default={})  # Impact of mitigation on correlation
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    source_asset = relationship("Asset", foreign_keys=[source_asset_id])
    target_asset = relationship("Asset", foreign_keys=[target_asset_id])

# Advanced Analytics Summary
class AdvancedAnalyticsSummary(Base):
    __tablename__ = "advanced_analytics_summary"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    summary_date = Column(DateTime(timezone=True), nullable=False)
    
    # Behavioral Analysis
    total_user_sessions = Column(Integer, default=0)
    anomalous_behaviors = Column(Integer, default=0)
    high_risk_users = Column(Integer, default=0)
    
    # ML Models
    active_models = Column(Integer, default=0)
    model_accuracy_avg = Column(Numeric(5, 4), default=0.0)
    total_predictions = Column(Integer, default=0)
    
    # Anomaly Detection
    total_anomalies = Column(Integer, default=0)
    critical_anomalies = Column(Integer, default=0)
    anomaly_detection_rate = Column(Numeric(5, 2), default=0.0)
    
    # Risk Prediction
    avg_prediction_accuracy = Column(Numeric(5, 4), default=0.0)
    risk_trends_analyzed = Column(Integer, default=0)
    
    # Cross-Asset Analysis
    asset_correlations = Column(Integer, default=0)
    high_correlation_assets = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project")
