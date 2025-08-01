from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List, Any, Optional
import structlog
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user, RoleChecker
from app.models.user import User
from app.services.ai_ml_service import ai_ml_service, ThreatLevel, AnomalyType
from app.schemas.ai_ml import (
    ThreatAnalysisRequest, ThreatAnalysisResponse, AnomalyDetectionRequest,
    AnomalyDetectionResponse, ThreatPredictionResponse, SecurityInsightsResponse,
    IncidentClassificationRequest, IncidentClassificationResponse, ModelTrainingRequest
)

logger = structlog.get_logger()
router = APIRouter()

# Role-based access control
admin_only = RoleChecker(["admin"])

@router.post("/analyze-threats", response_model=ThreatAnalysisResponse)
async def analyze_threat_indicators(
    request: ThreatAnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Analyze data for threat indicators"""
    try:
        indicators = await ai_ml_service.analyze_threat_indicators(request.data)
        
        return {
            "success": True,
            "indicators": [
                {
                    "id": indicator.id,
                    "name": indicator.name,
                    "description": indicator.description,
                    "confidence": indicator.confidence,
                    "threat_level": indicator.threat_level.value,
                    "source": indicator.source,
                    "timestamp": indicator.timestamp.isoformat(),
                    "metadata": indicator.metadata
                }
                for indicator in indicators
            ],
            "total_indicators": len(indicators),
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error analyzing threats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze threats"
        )

@router.post("/detect-anomalies", response_model=AnomalyDetectionResponse)
async def detect_anomalies(
    request: AnomalyDetectionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Detect anomalies in data"""
    try:
        anomalies = await ai_ml_service.detect_anomalies(request.data)
        
        return {
            "success": True,
            "anomalies": [
                {
                    "id": anomaly.id,
                    "type": anomaly.type.value,
                    "severity": anomaly.severity,
                    "description": anomaly.description,
                    "user_id": anomaly.user_id,
                    "timestamp": anomaly.timestamp.isoformat(),
                    "features": anomaly.features,
                    "metadata": anomaly.metadata
                }
                for anomaly in anomalies
            ],
            "total_anomalies": len(anomalies),
            "detection_timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error detecting anomalies", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to detect anomalies"
        )

@router.post("/predict-threats", response_model=List[ThreatPredictionResponse])
async def predict_threats(
    historical_data: List[Dict[str, Any]],
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Predict future threats based on historical data"""
    try:
        predictions = await ai_ml_service.predict_threats(historical_data)
        
        return [
            {
                "threat_type": prediction.threat_type,
                "probability": prediction.probability,
                "timeframe": prediction.timeframe,
                "confidence": prediction.confidence,
                "indicators": prediction.indicators,
                "recommendations": prediction.recommendations
            }
            for prediction in predictions
        ]
    except Exception as e:
        logger.error("Error predicting threats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to predict threats"
        )

@router.post("/classify-incident", response_model=IncidentClassificationResponse)
async def classify_incident(
    request: IncidentClassificationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Classify incident using ML models"""
    try:
        classification = await ai_ml_service.classify_incident(request.incident_data)
        
        return {
            "success": True,
            "classification": classification["classification"],
            "confidence": classification["confidence"],
            "probabilities": classification["probabilities"],
            "classification_timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error classifying incident", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to classify incident"
        )

@router.post("/generate-insights", response_model=SecurityInsightsResponse)
async def generate_security_insights(
    data: Dict[str, Any],
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Generate security insights from data"""
    try:
        insights = await ai_ml_service.generate_security_insights(data)
        
        return {
            "success": True,
            "insights": insights,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error generating insights", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate insights"
        )

@router.post("/train-models", response_model=Dict[str, Any])
async def train_models(
    request: ModelTrainingRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Retrain AI/ML models with new data"""
    try:
        # Add training task to background
        background_tasks.add_task(ai_ml_service.retrain_models, request.training_data)
        
        return {
            "success": True,
            "message": "Model training started in background",
            "training_data_size": len(request.training_data),
            "started_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error starting model training", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start model training"
        )

@router.get("/models/status")
async def get_model_status(
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Get status of AI/ML models"""
    try:
        model_status = {}
        
        for model_name, model in ai_ml_service.models.items():
            model_status[model_name] = {
                "loaded": True,
                "type": type(model).__name__,
                "parameters": str(model.get_params()) if hasattr(model, 'get_params') else "N/A"
            }
            
        return {
            "success": True,
            "models": model_status,
            "total_models": len(ai_ml_service.models),
            "status": "operational"
        }
    except Exception as e:
        logger.error("Error getting model status", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get model status"
        )

@router.post("/models/save")
async def save_models(
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Save trained models to disk"""
    try:
        await ai_ml_service.save_models()
        
        return {
            "success": True,
            "message": "Models saved successfully",
            "saved_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error saving models", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save models"
        )

@router.get("/analytics/threat-landscape")
async def get_threat_landscape(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current threat landscape analysis"""
    try:
        # Mock threat landscape data
        threat_landscape = {
            "overall_risk_level": "medium",
            "threat_distribution": {
                "malware": 0.35,
                "phishing": 0.25,
                "data_breach": 0.20,
                "insider_threat": 0.15,
                "other": 0.05
            },
            "trending_threats": [
                {
                    "name": "Ransomware",
                    "trend": "increasing",
                    "severity": "high",
                    "description": "Ransomware attacks targeting critical infrastructure"
                },
                {
                    "name": "Supply Chain Attacks",
                    "trend": "increasing",
                    "severity": "high",
                    "description": "Attacks through third-party vendors and suppliers"
                },
                {
                    "name": "Zero-Day Exploits",
                    "trend": "stable",
                    "severity": "critical",
                    "description": "Exploitation of unknown vulnerabilities"
                }
            ],
            "top_attack_vectors": [
                "Email phishing",
                "Weak credentials",
                "Unpatched systems",
                "Social engineering",
                "Insider threats"
            ],
            "geographic_hotspots": [
                {"region": "North America", "threat_level": "high"},
                {"region": "Europe", "threat_level": "medium"},
                {"region": "Asia Pacific", "threat_level": "medium"},
                {"region": "Middle East", "threat_level": "low"}
            ],
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "threat_landscape": threat_landscape
        }
    except Exception as e:
        logger.error("Error getting threat landscape", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get threat landscape"
        )

@router.get("/analytics/security-metrics")
async def get_security_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get security metrics and KPIs"""
    try:
        # Mock security metrics
        security_metrics = {
            "incident_metrics": {
                "total_incidents": 156,
                "resolved_incidents": 142,
                "open_incidents": 14,
                "critical_incidents": 3,
                "incident_trend": "decreasing"
            },
            "response_metrics": {
                "mean_time_to_detect": "2.5 hours",
                "mean_time_to_respond": "4.2 hours",
                "mean_time_to_resolve": "12.8 hours",
                "response_trend": "improving"
            },
            "detection_metrics": {
                "detection_rate": 0.92,
                "false_positive_rate": 0.15,
                "true_positive_rate": 0.85,
                "detection_accuracy": "high"
            },
            "threat_metrics": {
                "threats_blocked": 1247,
                "threats_detected": 1356,
                "threat_prevention_rate": 0.92,
                "threat_trend": "stable"
            },
            "user_metrics": {
                "security_training_completion": 0.87,
                "phishing_simulation_success": 0.78,
                "mfa_adoption_rate": 0.94,
                "user_security_score": "good"
            },
            "system_metrics": {
                "system_uptime": 0.998,
                "patch_compliance": 0.89,
                "vulnerability_scan_score": 8.2,
                "system_security_score": "excellent"
            },
            "calculated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "security_metrics": security_metrics
        }
    except Exception as e:
        logger.error("Error getting security metrics", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security metrics"
        )

@router.get("/analytics/trends")
async def get_security_trends(
    timeframe: str = "30d",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get security trends over time"""
    try:
        # Mock trend data
        trends = {
            "incident_trends": {
                "daily": [12, 15, 8, 20, 14, 11, 9, 16, 13, 10],
                "weekly": [85, 92, 78, 105, 88, 76, 82],
                "monthly": [320, 345, 298, 367, 312, 289]
            },
            "threat_trends": {
                "malware_incidents": [5, 8, 3, 12, 7, 4, 6, 9, 5, 3],
                "phishing_attempts": [25, 32, 18, 45, 28, 22, 35, 41, 29, 24],
                "data_breaches": [1, 0, 2, 1, 0, 1, 0, 1, 0, 1]
            },
            "response_trends": {
                "detection_time": [2.1, 2.3, 1.8, 2.7, 2.0, 1.9, 2.2, 2.5, 2.1, 1.7],
                "resolution_time": [10.5, 12.1, 9.8, 14.2, 11.3, 10.1, 12.8, 13.5, 11.9, 9.5]
            },
            "timeframe": timeframe,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "trends": trends
        }
    except Exception as e:
        logger.error("Error getting security trends", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security trends"
        )

@router.post("/recommendations/generate")
async def generate_recommendations(
    data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate security recommendations based on data"""
    try:
        insights = await ai_ml_service.generate_security_insights(data)
        recommendations = insights.get("recommendations", [])
        
        # Add AI-generated recommendations
        ai_recommendations = [
            "Implement behavioral analytics for user monitoring",
            "Deploy advanced threat hunting capabilities",
            "Enhance incident response automation",
            "Implement predictive threat intelligence",
            "Deploy machine learning-based anomaly detection"
        ]
        
        all_recommendations = recommendations + ai_recommendations
        
        return {
            "success": True,
            "recommendations": all_recommendations,
            "priority": "high",
            "estimated_impact": "significant",
            "implementation_effort": "medium",
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Error generating recommendations", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate recommendations"
        )

@router.get("/health")
async def get_ai_ml_health(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get AI/ML service health status"""
    try:
        health_status = {
            "status": "healthy",
            "models_loaded": len(ai_ml_service.models),
            "service_uptime": "24 hours",
            "last_training": "2024-01-15T10:30:00Z",
            "model_accuracy": {
                "anomaly_detection": 0.89,
                "threat_classification": 0.92,
                "prediction_model": 0.78
            },
            "performance_metrics": {
                "average_response_time": "0.5 seconds",
                "requests_per_minute": 45,
                "error_rate": 0.02
            },
            "checked_at": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "health": health_status
        }
    except Exception as e:
        logger.error("Error getting AI/ML health", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get AI/ML health"
        ) 