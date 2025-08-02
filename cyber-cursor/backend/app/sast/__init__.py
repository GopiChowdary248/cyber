"""
SAST (Static Application Security Testing) Module

This module provides comprehensive static code analysis capabilities including:
- Multi-language code scanning
- Vulnerability detection
- AI-powered recommendations
- Risk scoring and prioritization
"""

from .scanner import SASTScanner, SASTScanManager
from .ai_recommendations import AIRecommendationEngine, RiskScoringEngine

__all__ = [
    "SASTScanner",
    "SASTScanManager", 
    "AIRecommendationEngine",
    "RiskScoringEngine"
] 