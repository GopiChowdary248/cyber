"""
SAST (Static Application Security Testing) Module

This module provides comprehensive static code analysis capabilities including:
- Multi-language code scanning
- Vulnerability detection
- AI-powered recommendations
- Risk scoring and prioritization
"""

from .scanner import SASTScanner, PerformanceOptimizedSASTScanner
from .ai_recommendations import AIRecommendationEngine, RiskScoringEngine
from ..services.sast_scanner import SASTScanManager

__all__ = [
    "SASTScanner",
    "PerformanceOptimizedSASTScanner", 
    "AIRecommendationEngine",
    "RiskScoringEngine",
    "SASTScanManager"
] 