from fastapi import APIRouter

from app.api.v1.endpoints import auth, users, incidents, cloud_security, phishing, dashboard, mfa, integrations, ai_ml, compliance, health, websocket, analytics, workflows, security, network_security, endpoint_security, application_security, data_protection, monitoring_siem_soar, threat_intelligence, simple_sast, siem_soar, dast

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(cloud_security.router, prefix="/cloud-security", tags=["cloud-security"])
api_router.include_router(phishing.router, prefix="/phishing", tags=["phishing"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(mfa.router, prefix="/mfa", tags=["mfa"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])
api_router.include_router(ai_ml.router, prefix="/ai-ml", tags=["ai-ml"])
api_router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
api_router.include_router(health.router, prefix="/health", tags=["health"])

# Enhanced features endpoints
api_router.include_router(websocket.router, prefix="/ws", tags=["websocket"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(workflows.router, prefix="/workflows", tags=["workflows"])
api_router.include_router(security.router, prefix="/security", tags=["security"])
api_router.include_router(network_security.router, prefix="/network-security", tags=["network-security"])
api_router.include_router(endpoint_security.router, prefix="/endpoint-security", tags=["endpoint-security"])
api_router.include_router(application_security.router, prefix="/application-security", tags=["application-security"])
api_router.include_router(data_protection.router, prefix="/data-protection", tags=["data-protection"])
api_router.include_router(monitoring_siem_soar.router, prefix="/monitoring-siem-soar", tags=["monitoring-siem-soar"])
api_router.include_router(threat_intelligence.router, prefix="/threat-intelligence", tags=["threat-intelligence"])
api_router.include_router(simple_sast.router, prefix="/sast", tags=["sast"])
api_router.include_router(siem_soar.router, prefix="/siem-soar", tags=["siem-soar"])
api_router.include_router(dast.router, prefix="/dast", tags=["dast"]) 