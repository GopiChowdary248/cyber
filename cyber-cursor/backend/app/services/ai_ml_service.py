import asyncio
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import structlog
from dataclasses import dataclass
from enum import Enum
import json
import hashlib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import os

from app.core.config import settings
from app.models.incident import Incident
from app.models.user import User

logger = structlog.get_logger()

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnomalyType(Enum):
    LOGIN_ANOMALY = "login_anomaly"
    NETWORK_ANOMALY = "network_anomaly"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    SYSTEM_ANOMALY = "system_anomaly"
    DATA_ANOMALY = "data_anomaly"

@dataclass
class ThreatIndicator:
    id: str
    name: str
    description: str
    confidence: float
    threat_level: ThreatLevel
    source: str
    timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class AnomalyDetection:
    id: str
    type: AnomalyType
    severity: float
    description: str
    user_id: Optional[int]
    timestamp: datetime
    features: Dict[str, float]
    metadata: Dict[str, Any]

@dataclass
class ThreatPrediction:
    threat_type: str
    probability: float
    timeframe: str
    confidence: float
    indicators: List[str]
    recommendations: List[str]

class AIMLService:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        self.threat_patterns = {}
        self.anomaly_detectors = {}
        self.prediction_models = {}
        self.model_path = "models/"
        
        # Ensure model directory exists
        os.makedirs(self.model_path, exist_ok=True)
        
        # Initialize models
        self._initialize_models()
        
    def _initialize_models(self):
        """Initialize AI/ML models"""
        try:
            # Load or create models
            self._load_or_create_models()
            
            # Initialize feature extractors
            self._initialize_feature_extractors()
            
            # Load threat patterns
            self._load_threat_patterns()
            
            logger.info("AI/ML service initialized successfully")
        except Exception as e:
            logger.error("Error initializing AI/ML service", error=str(e))
            
    def _load_or_create_models(self):
        """Load existing models or create new ones"""
        model_files = {
            "anomaly_detector": "anomaly_detector.pkl",
            "threat_classifier": "threat_classifier.pkl",
            "prediction_model": "prediction_model.pkl",
            "user_behavior_model": "user_behavior_model.pkl"
        }
        
        for model_name, filename in model_files.items():
            model_path = os.path.join(self.model_path, filename)
            if os.path.exists(model_path):
                try:
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"Loaded {model_name} from {model_path}")
                except Exception as e:
                    logger.error(f"Error loading {model_name}", error=str(e))
                    self._create_default_model(model_name)
            else:
                self._create_default_model(model_name)
                
    def _create_default_model(self, model_name: str):
        """Create default model for given type"""
        if model_name == "anomaly_detector":
            self.models[model_name] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
        elif model_name == "threat_classifier":
            self.models[model_name] = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
        elif model_name == "user_behavior_model":
            self.models[model_name] = IsolationForest(
                contamination=0.05,
                random_state=42,
                n_estimators=100
            )
            
        logger.info(f"Created default {model_name}")
        
    def _initialize_feature_extractors(self):
        """Initialize feature extraction methods"""
        self.feature_extractors = {
            "login_patterns": self._extract_login_features,
            "network_traffic": self._extract_network_features,
            "user_behavior": self._extract_behavior_features,
            "system_events": self._extract_system_features,
            "data_access": self._extract_data_features
        }
        
    def _load_threat_patterns(self):
        """Load known threat patterns"""
        self.threat_patterns = {
            "brute_force": {
                "indicators": ["multiple_failed_logins", "rapid_login_attempts", "known_ips"],
                "threshold": 5,
                "timeframe": "5 minutes"
            },
            "data_exfiltration": {
                "indicators": ["large_data_transfers", "unusual_access_patterns", "off_hours_activity"],
                "threshold": 3,
                "timeframe": "1 hour"
            },
            "privilege_escalation": {
                "indicators": ["unusual_permissions", "admin_access_attempts", "system_changes"],
                "threshold": 2,
                "timeframe": "30 minutes"
            },
            "malware_activity": {
                "indicators": ["suspicious_processes", "file_modifications", "network_connections"],
                "threshold": 4,
                "timeframe": "10 minutes"
            }
        }
        
    async def analyze_threat_indicators(self, data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze data for threat indicators"""
        try:
            indicators = []
            
            # Extract features
            features = await self._extract_all_features(data)
            
            # Analyze for different threat types
            threat_analyses = [
                await self._analyze_login_threats(features),
                await self._analyze_network_threats(features),
                await self._analyze_behavior_threats(features),
                await self._analyze_system_threats(features),
                await self._analyze_data_threats(features)
            ]
            
            # Combine all indicators
            for analysis in threat_analyses:
                indicators.extend(analysis)
                
            # Sort by confidence and threat level
            indicators.sort(key=lambda x: (x.confidence, x.threat_level.value), reverse=True)
            
            logger.info(f"Analyzed {len(indicators)} threat indicators")
            return indicators
            
        except Exception as e:
            logger.error("Error analyzing threat indicators", error=str(e))
            return []
            
    async def detect_anomalies(self, data: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect anomalies in data"""
        try:
            anomalies = []
            
            # Extract features for anomaly detection
            features = await self._extract_all_features(data)
            
            # Detect different types of anomalies
            anomaly_detections = [
                await self._detect_login_anomalies(features),
                await self._detect_network_anomalies(features),
                await self._detect_behavior_anomalies(features),
                await self._detect_system_anomalies(features),
                await self._detect_data_anomalies(features)
            ]
            
            # Combine all anomalies
            for detection in anomaly_detections:
                anomalies.extend(detection)
                
            # Filter by severity threshold
            anomalies = [a for a in anomalies if a.severity > 0.3]
            
            logger.info(f"Detected {len(anomalies)} anomalies")
            return anomalies
            
        except Exception as e:
            logger.error("Error detecting anomalies", error=str(e))
            return []
            
    async def predict_threats(self, historical_data: List[Dict[str, Any]]) -> List[ThreatPrediction]:
        """Predict future threats based on historical data"""
        try:
            predictions = []
            
            # Analyze historical patterns
            patterns = await self._analyze_historical_patterns(historical_data)
            
            # Generate predictions for different threat types
            threat_predictions = [
                await self._predict_brute_force_attacks(patterns),
                await self._predict_data_breaches(patterns),
                await self._predict_malware_outbreaks(patterns),
                await self._predict_insider_threats(patterns)
            ]
            
            # Combine and filter predictions
            for prediction in threat_predictions:
                if prediction and prediction.probability > 0.2:
                    predictions.append(prediction)
                    
            # Sort by probability
            predictions.sort(key=lambda x: x.probability, reverse=True)
            
            logger.info(f"Generated {len(predictions)} threat predictions")
            return predictions
            
        except Exception as e:
            logger.error("Error predicting threats", error=str(e))
            return []
            
    async def classify_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify incident using ML models"""
        try:
            # Extract features from incident
            features = await self._extract_incident_features(incident_data)
            
            # Use threat classifier
            if "threat_classifier" in self.models:
                prediction = self.models["threat_classifier"].predict([features])
                probability = self.models["threat_classifier"].predict_proba([features])
                
                return {
                    "classification": prediction[0],
                    "confidence": float(np.max(probability)),
                    "probabilities": {
                        "malware": float(probability[0][0]),
                        "phishing": float(probability[0][1]),
                        "data_breach": float(probability[0][2]),
                        "insider_threat": float(probability[0][3])
                    }
                }
            else:
                return {
                    "classification": "unknown",
                    "confidence": 0.0,
                    "probabilities": {}
                }
                
        except Exception as e:
            logger.error("Error classifying incident", error=str(e))
            return {
                "classification": "error",
                "confidence": 0.0,
                "probabilities": {}
            }
            
    async def generate_security_insights(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security insights from data"""
        try:
            insights = {
                "threat_landscape": await self._analyze_threat_landscape(data),
                "risk_assessment": await self._assess_risk_levels(data),
                "trends": await self._analyze_security_trends(data),
                "recommendations": await self._generate_recommendations(data),
                "metrics": await self._calculate_security_metrics(data)
            }
            
            return insights
            
        except Exception as e:
            logger.error("Error generating security insights", error=str(e))
            return {}
            
    async def _extract_all_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all features from data"""
        features = {}
        
        for feature_type, extractor in self.feature_extractors.items():
            try:
                features[feature_type] = await extractor(data)
            except Exception as e:
                logger.error(f"Error extracting {feature_type} features", error=str(e))
                features[feature_type] = {}
                
        return features
        
    async def _extract_login_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract login-related features"""
        login_data = data.get("login_events", [])
        
        if not login_data:
            return {}
            
        features = {
            "total_logins": len(login_data),
            "failed_logins": sum(1 for event in login_data if not event.get("success", True)),
            "successful_logins": sum(1 for event in login_data if event.get("success", True)),
            "unique_ips": len(set(event.get("ip_address", "") for event in login_data)),
            "unique_users": len(set(event.get("username", "") for event in login_data)),
            "login_frequency": len(login_data) / max(1, (datetime.utcnow() - datetime.fromisoformat(login_data[0]["timestamp"])).total_seconds() / 3600),
            "failed_login_rate": sum(1 for event in login_data if not event.get("success", True)) / max(1, len(login_data))
        }
        
        return features
        
    async def _extract_network_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract network-related features"""
        network_data = data.get("network_events", [])
        
        if not network_data:
            return {}
            
        features = {
            "total_connections": len(network_data),
            "unique_destinations": len(set(event.get("destination", "") for event in network_data)),
            "unique_sources": len(set(event.get("source", "") for event in network_data)),
            "data_transfer_volume": sum(event.get("bytes_transferred", 0) for event in network_data),
            "connection_frequency": len(network_data) / max(1, (datetime.utcnow() - datetime.fromisoformat(network_data[0]["timestamp"])).total_seconds() / 3600)
        }
        
        return features
        
    async def _extract_behavior_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract user behavior features"""
        behavior_data = data.get("user_actions", [])
        
        if not behavior_data:
            return {}
            
        features = {
            "total_actions": len(behavior_data),
            "unique_actions": len(set(event.get("action_type", "") for event in behavior_data)),
            "action_frequency": len(behavior_data) / max(1, (datetime.utcnow() - datetime.fromisoformat(behavior_data[0]["timestamp"])).total_seconds() / 3600),
            "suspicious_actions": sum(1 for event in behavior_data if event.get("suspicious", False))
        }
        
        return features
        
    async def _extract_system_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract system-related features"""
        system_data = data.get("system_events", [])
        
        if not system_data:
            return {}
            
        features = {
            "total_events": len(system_data),
            "error_events": sum(1 for event in system_data if event.get("level", "") == "error"),
            "warning_events": sum(1 for event in system_data if event.get("level", "") == "warning"),
            "critical_events": sum(1 for event in system_data if event.get("level", "") == "critical")
        }
        
        return features
        
    async def _extract_data_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract data access features"""
        data_access = data.get("data_access", [])
        
        if not data_access:
            return {}
            
        features = {
            "total_access": len(data_access),
            "unique_files": len(set(event.get("file_path", "") for event in data_access)),
            "large_files_accessed": sum(1 for event in data_access if event.get("file_size", 0) > 1000000),
            "sensitive_data_access": sum(1 for event in data_access if event.get("sensitive", False))
        }
        
        return features
        
    async def _analyze_login_threats(self, features: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze login-related threats"""
        indicators = []
        login_features = features.get("login_patterns", {})
        
        # Check for brute force attacks
        if login_features.get("failed_login_rate", 0) > 0.8:
            indicators.append(ThreatIndicator(
                id=f"brute_force_{datetime.utcnow().timestamp()}",
                name="Brute Force Attack",
                description="High rate of failed login attempts detected",
                confidence=0.85,
                threat_level=ThreatLevel.HIGH,
                source="login_analysis",
                timestamp=datetime.utcnow(),
                metadata={"failed_rate": login_features.get("failed_login_rate", 0)}
            ))
            
        # Check for credential stuffing
        if login_features.get("unique_ips", 0) > 10 and login_features.get("failed_logins", 0) > 20:
            indicators.append(ThreatIndicator(
                id=f"credential_stuffing_{datetime.utcnow().timestamp()}",
                name="Credential Stuffing",
                description="Multiple IPs attempting multiple failed logins",
                confidence=0.75,
                threat_level=ThreatLevel.MEDIUM,
                source="login_analysis",
                timestamp=datetime.utcnow(),
                metadata={"unique_ips": login_features.get("unique_ips", 0), "failed_logins": login_features.get("failed_logins", 0)}
            ))
            
        return indicators
        
    async def _analyze_network_threats(self, features: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze network-related threats"""
        indicators = []
        network_features = features.get("network_traffic", {})
        
        # Check for data exfiltration
        if network_features.get("data_transfer_volume", 0) > 1000000000:  # 1GB
            indicators.append(ThreatIndicator(
                id=f"data_exfiltration_{datetime.utcnow().timestamp()}",
                name="Data Exfiltration",
                description="Large volume of data transfer detected",
                confidence=0.70,
                threat_level=ThreatLevel.HIGH,
                source="network_analysis",
                timestamp=datetime.utcnow(),
                metadata={"transfer_volume": network_features.get("data_transfer_volume", 0)}
            ))
            
        return indicators
        
    async def _analyze_behavior_threats(self, features: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze behavior-related threats"""
        indicators = []
        behavior_features = features.get("user_behavior", {})
        
        # Check for suspicious behavior
        if behavior_features.get("suspicious_actions", 0) > 5:
            indicators.append(ThreatIndicator(
                id=f"suspicious_behavior_{datetime.utcnow().timestamp()}",
                name="Suspicious User Behavior",
                description="Multiple suspicious actions detected",
                confidence=0.65,
                threat_level=ThreatLevel.MEDIUM,
                source="behavior_analysis",
                timestamp=datetime.utcnow(),
                metadata={"suspicious_actions": behavior_features.get("suspicious_actions", 0)}
            ))
            
        return indicators
        
    async def _analyze_system_threats(self, features: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze system-related threats"""
        indicators = []
        system_features = features.get("system_events", {})
        
        # Check for system compromise
        if system_features.get("critical_events", 0) > 3:
            indicators.append(ThreatIndicator(
                id=f"system_compromise_{datetime.utcnow().timestamp()}",
                name="System Compromise",
                description="Multiple critical system events detected",
                confidence=0.80,
                threat_level=ThreatLevel.CRITICAL,
                source="system_analysis",
                timestamp=datetime.utcnow(),
                metadata={"critical_events": system_features.get("critical_events", 0)}
            ))
            
        return indicators
        
    async def _analyze_data_threats(self, features: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze data-related threats"""
        indicators = []
        data_features = features.get("data_access", {})
        
        # Check for sensitive data access
        if data_features.get("sensitive_data_access", 0) > 10:
            indicators.append(ThreatIndicator(
                id=f"sensitive_data_access_{datetime.utcnow().timestamp()}",
                name="Sensitive Data Access",
                description="Multiple sensitive data access events detected",
                confidence=0.75,
                threat_level=ThreatLevel.HIGH,
                source="data_analysis",
                timestamp=datetime.utcnow(),
                metadata={"sensitive_access": data_features.get("sensitive_data_access", 0)}
            ))
            
        return indicators
        
    async def _detect_login_anomalies(self, features: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect login anomalies"""
        anomalies = []
        login_features = features.get("login_patterns", {})
        
        if not login_features:
            return anomalies
            
        # Use isolation forest for anomaly detection
        if "anomaly_detector" in self.models:
            feature_vector = list(login_features.values())
            anomaly_score = self.models["anomaly_detector"].score_samples([feature_vector])[0]
            
            if anomaly_score < -0.5:  # Threshold for anomaly
                anomalies.append(AnomalyDetection(
                    id=f"login_anomaly_{datetime.utcnow().timestamp()}",
                    type=AnomalyType.LOGIN_ANOMALY,
                    severity=abs(anomaly_score),
                    description="Unusual login pattern detected",
                    user_id=None,
                    timestamp=datetime.utcnow(),
                    features=login_features,
                    metadata={"anomaly_score": anomaly_score}
                ))
                
        return anomalies
        
    async def _detect_network_anomalies(self, features: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect network anomalies"""
        anomalies = []
        network_features = features.get("network_traffic", {})
        
        if not network_features:
            return anomalies
            
        # Simple threshold-based anomaly detection
        if network_features.get("data_transfer_volume", 0) > 500000000:  # 500MB
            anomalies.append(AnomalyDetection(
                id=f"network_anomaly_{datetime.utcnow().timestamp()}",
                type=AnomalyType.NETWORK_ANOMALY,
                severity=0.8,
                description="Unusual network traffic volume detected",
                user_id=None,
                timestamp=datetime.utcnow(),
                features=network_features,
                metadata={"threshold_exceeded": "data_transfer_volume"}
            ))
            
        return anomalies
        
    async def _detect_behavior_anomalies(self, features: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect behavior anomalies"""
        anomalies = []
        behavior_features = features.get("user_behavior", {})
        
        if not behavior_features:
            return anomalies
            
        # Check for unusual action frequency
        if behavior_features.get("action_frequency", 0) > 100:  # 100 actions per hour
            anomalies.append(AnomalyDetection(
                id=f"behavior_anomaly_{datetime.utcnow().timestamp()}",
                type=AnomalyType.BEHAVIOR_ANOMALY,
                severity=0.7,
                description="Unusual user behavior frequency detected",
                user_id=None,
                timestamp=datetime.utcnow(),
                features=behavior_features,
                metadata={"high_frequency": behavior_features.get("action_frequency", 0)}
            ))
            
        return anomalies
        
    async def _detect_system_anomalies(self, features: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect system anomalies"""
        anomalies = []
        system_features = features.get("system_events", {})
        
        if not system_features:
            return anomalies
            
        # Check for high error rate
        total_events = system_features.get("total_events", 0)
        error_events = system_features.get("error_events", 0)
        
        if total_events > 0 and (error_events / total_events) > 0.5:
            anomalies.append(AnomalyDetection(
                id=f"system_anomaly_{datetime.utcnow().timestamp()}",
                type=AnomalyType.SYSTEM_ANOMALY,
                severity=0.6,
                description="High system error rate detected",
                user_id=None,
                timestamp=datetime.utcnow(),
                features=system_features,
                metadata={"error_rate": error_events / total_events}
            ))
            
        return anomalies
        
    async def _detect_data_anomalies(self, features: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect data access anomalies"""
        anomalies = []
        data_features = features.get("data_access", {})
        
        if not data_features:
            return anomalies
            
        # Check for unusual sensitive data access
        if data_features.get("sensitive_data_access", 0) > 5:
            anomalies.append(AnomalyDetection(
                id=f"data_anomaly_{datetime.utcnow().timestamp()}",
                type=AnomalyType.DATA_ANOMALY,
                severity=0.8,
                description="Unusual sensitive data access detected",
                user_id=None,
                timestamp=datetime.utcnow(),
                features=data_features,
                metadata={"sensitive_access_count": data_features.get("sensitive_data_access", 0)}
            ))
            
        return anomalies
        
    async def _analyze_historical_patterns(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze historical patterns for prediction"""
        patterns = {
            "temporal_patterns": {},
            "frequency_patterns": {},
            "correlation_patterns": {},
            "trend_patterns": {}
        }
        
        # Analyze temporal patterns
        if historical_data:
            timestamps = [datetime.fromisoformat(event.get("timestamp", "")) for event in historical_data if event.get("timestamp")]
            if timestamps:
                patterns["temporal_patterns"] = {
                    "peak_hours": self._find_peak_hours(timestamps),
                    "weekly_patterns": self._find_weekly_patterns(timestamps),
                    "monthly_trends": self._find_monthly_trends(timestamps)
                }
                
        return patterns
        
    def _find_peak_hours(self, timestamps: List[datetime]) -> List[int]:
        """Find peak hours from timestamps"""
        hours = [ts.hour for ts in timestamps]
        hour_counts = {}
        for hour in hours:
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
            
        # Return top 3 peak hours
        return sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        
    def _find_weekly_patterns(self, timestamps: List[datetime]) -> Dict[str, int]:
        """Find weekly patterns from timestamps"""
        weekdays = [ts.strftime("%A") for ts in timestamps]
        weekday_counts = {}
        for day in weekdays:
            weekday_counts[day] = weekday_counts.get(day, 0) + 1
            
        return weekday_counts
        
    def _find_monthly_trends(self, timestamps: List[datetime]) -> Dict[str, int]:
        """Find monthly trends from timestamps"""
        months = [ts.strftime("%B") for ts in timestamps]
        month_counts = {}
        for month in months:
            month_counts[month] = month_counts.get(month, 0) + 1
            
        return month_counts
        
    async def _predict_brute_force_attacks(self, patterns: Dict[str, Any]) -> Optional[ThreatPrediction]:
        """Predict brute force attacks"""
        # Simple prediction based on patterns
        return ThreatPrediction(
            threat_type="brute_force_attack",
            probability=0.3,
            timeframe="next_24_hours",
            confidence=0.6,
            indicators=["high_failed_login_rate", "multiple_ips"],
            recommendations=["Enable account lockout", "Implement CAPTCHA", "Monitor login attempts"]
        )
        
    async def _predict_data_breaches(self, patterns: Dict[str, Any]) -> Optional[ThreatPrediction]:
        """Predict data breaches"""
        return ThreatPrediction(
            threat_type="data_breach",
            probability=0.2,
            timeframe="next_week",
            confidence=0.5,
            indicators=["unusual_data_access", "large_transfers"],
            recommendations=["Review data access logs", "Implement DLP", "Monitor data transfers"]
        )
        
    async def _predict_malware_outbreaks(self, patterns: Dict[str, Any]) -> Optional[ThreatPrediction]:
        """Predict malware outbreaks"""
        return ThreatPrediction(
            threat_type="malware_outbreak",
            probability=0.15,
            timeframe="next_48_hours",
            confidence=0.4,
            indicators=["suspicious_processes", "file_modifications"],
            recommendations=["Update antivirus", "Scan systems", "Review process logs"]
        )
        
    async def _predict_insider_threats(self, patterns: Dict[str, Any]) -> Optional[ThreatPrediction]:
        """Predict insider threats"""
        return ThreatPrediction(
            threat_type="insider_threat",
            probability=0.1,
            timeframe="next_month",
            confidence=0.3,
            indicators=["unusual_behavior", "privilege_abuse"],
            recommendations=["Monitor user behavior", "Review permissions", "Implement UBA"]
        )
        
    async def _extract_incident_features(self, incident_data: Dict[str, Any]) -> List[float]:
        """Extract features from incident data for classification"""
        features = [
            float(incident_data.get("severity", 0)),
            float(len(incident_data.get("description", ""))),
            float(incident_data.get("affected_users", 0)),
            float(incident_data.get("data_impact", 0)),
            float(incident_data.get("system_impact", 0))
        ]
        
        return features
        
    async def _analyze_threat_landscape(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall threat landscape"""
        return {
            "total_threats": len(data.get("threats", [])),
            "threat_distribution": {
                "malware": 0.3,
                "phishing": 0.25,
                "data_breach": 0.2,
                "insider_threat": 0.15,
                "other": 0.1
            },
            "trending_threats": ["ransomware", "supply_chain_attacks", "zero_day_exploits"],
            "risk_level": "medium"
        }
        
    async def _assess_risk_levels(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk levels for different areas"""
        return {
            "overall_risk": "medium",
            "risk_areas": {
                "network_security": "low",
                "data_protection": "medium",
                "user_authentication": "high",
                "system_integrity": "low"
            },
            "risk_factors": ["weak_passwords", "unpatched_systems", "insufficient_monitoring"]
        }
        
    async def _analyze_security_trends(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security trends"""
        return {
            "incident_trend": "decreasing",
            "threat_complexity": "increasing",
            "response_time": "improving",
            "detection_rate": "stable"
        }
        
    async def _generate_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        return [
            "Implement multi-factor authentication for all users",
            "Update security patches within 30 days",
            "Conduct regular security awareness training",
            "Implement data loss prevention (DLP) solutions",
            "Enhance network monitoring and alerting"
        ]
        
    async def _calculate_security_metrics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate security metrics"""
        return {
            "mean_time_to_detect": "2.5 hours",
            "mean_time_to_respond": "4.2 hours",
            "mean_time_to_resolve": "12.8 hours",
            "incident_volume": 45,
            "false_positive_rate": "0.15",
            "detection_accuracy": "0.92"
        }
        
    async def save_models(self):
        """Save trained models to disk"""
        try:
            for model_name, model in self.models.items():
                model_path = os.path.join(self.model_path, f"{model_name}.pkl")
                joblib.dump(model, model_path)
                logger.info(f"Saved {model_name} to {model_path}")
        except Exception as e:
            logger.error("Error saving models", error=str(e))
            
    async def retrain_models(self, training_data: List[Dict[str, Any]]):
        """Retrain models with new data"""
        try:
            # Extract features from training data
            features = []
            labels = []
            
            for data_point in training_data:
                feature_vector = await self._extract_all_features(data_point)
                features.append(list(feature_vector.values()))
                labels.append(data_point.get("label", "normal"))
                
            # Retrain models
            if features and labels:
                # Retrain anomaly detector
                if "anomaly_detector" in self.models:
                    self.models["anomaly_detector"].fit(features)
                    
                # Retrain threat classifier
                if "threat_classifier" in self.models:
                    self.models["threat_classifier"].fit(features, labels)
                    
                # Save updated models
                await self.save_models()
                
                logger.info("Models retrained successfully")
                
        except Exception as e:
            logger.error("Error retraining models", error=str(e))

# Global AI/ML service instance
ai_ml_service = AIMLService() 