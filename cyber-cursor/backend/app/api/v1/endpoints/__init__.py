"""
API v1 Endpoints Module

This module contains all API endpoint routers for version 1 of the CyberShield API.
"""

# Import all endpoint routers
from .auth import router as auth_router
from .users import router as users_router
from .health import router as health_router
# from .sast import router as sast_router  # Temporarily disabled due to missing sast_service
from .endpoint_antivirus_edr import router as endpoint_antivirus_edr_router
from .device_control import router as device_control_router
from .cloud_security import router as cloud_security_router
from .dast import router as dast_router
# from .enhanced_cloud_security import router as enhanced_cloud_security_router  # Temporarily disabled due to AWS region issue
from .rasp import router as rasp_router
from .siem_soar import router as siem_soar_router
from .network_security import router as network_security_router
# from .threat_intelligence import router as threat_intelligence_router  # Temporarily disabled due to missing validators dependency
from .monitoring_siem_soar import router as monitoring_siem_soar_router
from .data_protection import router as data_protection_router
from .security import router as security_router
# from .workflows import router as workflows_router  # Temporarily disabled due to async_generator error
# from .analytics import router as analytics_router  # Temporarily disabled due to PhishingReport import error
# from .websocket import router as websocket_router  # Temporarily disabled due to verify_token import error
# from .compliance import router as compliance_router  # Temporarily disabled due to RoleChecker import error
# from .ai_ml import router as ai_ml_router  # Temporarily disabled due to RoleChecker import error
# from .integrations import router as integrations_router  # Temporarily disabled due to RoleChecker import error
# from .mfa import router as mfa_router  # Temporarily disabled due to MFASetupResponse import error
# from .user import router as user_router  # Temporarily disabled due to missing app.schemas.user module
# from .admin import router as admin_router  # Temporarily disabled due to CloudMisconfiguration import error
# from .dashboard import router as dashboard_router  # Temporarily disabled due to CloudMisconfiguration import error
# from .phishing import router as phishing_router  # Temporarily disabled due to missing app.schemas.phishing module
# from .incidents import router as incidents_router  # Temporarily disabled due to IncidentList import error
# from .endpoint_security import router as endpoint_security_router  # Removed during cleanup
from .iam import router as iam_router
from .data_security import router as data_security_router

__all__ = [
    "auth_router",
    "users_router", 
    "health_router",
    # "sast_router",  # Temporarily disabled
    "endpoint_antivirus_edr_router",
    "device_control_router",
    "cloud_security_router",
    "dast_router",
    # "enhanced_cloud_security_router",  # Temporarily disabled
    "rasp_router",
    "siem_soar_router",
    "network_security_router",
    # "threat_intelligence_router",  # Temporarily disabled
    "monitoring_siem_soar_router",
    "data_protection_router",
    "security_router",
    # "workflows_router",  # Temporarily disabled
    # "analytics_router",  # Temporarily disabled
    # "websocket_router",  # Temporarily disabled
    # "compliance_router",  # Temporarily disabled
    # "ai_ml_router",  # Temporarily disabled
    # "integrations_router",  # Temporarily disabled
    # "mfa_router",  # Temporarily disabled
    # "user_router",  # Temporarily disabled
    # "admin_router",  # Temporarily disabled
    # "dashboard_router",  # Temporarily disabled
    # "phishing_router",  # Temporarily disabled
    # "incidents_router",  # Temporarily disabled
    # "endpoint_security_router",  # Removed during cleanup
    "iam_router",
    "data_security_router"
] 