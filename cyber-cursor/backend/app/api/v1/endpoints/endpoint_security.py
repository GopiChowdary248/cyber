"""
Endpoint Security API Endpoints
Provides REST API for endpoint security management including:
- Antivirus scanning and management
- EDR (Endpoint Detection and Response) alerts
- Application whitelisting and blacklisting
- Endpoint monitoring and compliance
- Threat detection and response
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import structlog

from app.core.security import get_current_user
from app.services.endpoint_security_service import (
    endpoint_security_service,
    ScanStatus,
    ThreatLevel,
    EndpointStatus,
    WhitelistAction
)

logger = structlog.get_logger()
router = APIRouter()

# Endpoint Management Endpoints
@router.get("/endpoints", response_model=List[Dict[str, Any]])
async def get_endpoints(current_user = Depends(get_current_user)):
    """Get all registered endpoints"""
    try:
        endpoints = await endpoint_security_service.get_endpoints()
        return endpoints
    except Exception as e:
        logger.error("Error getting endpoints", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve endpoints")

@router.get("/endpoints/{endpoint_id}", response_model=Dict[str, Any])
async def get_endpoint_details(endpoint_id: str, current_user = Depends(get_current_user)):
    """Get detailed information about a specific endpoint"""
    try:
        endpoint = await endpoint_security_service.get_endpoint_details(endpoint_id)
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return endpoint
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting endpoint details", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve endpoint details")

@router.post("/endpoints", response_model=Dict[str, str])
async def register_endpoint(endpoint_data: Dict[str, Any], current_user = Depends(get_current_user)):
    """Register a new endpoint"""
    try:
        endpoint_id = await endpoint_security_service.register_endpoint(endpoint_data)
        return {"endpoint_id": endpoint_id, "message": "Endpoint registered successfully"}
    except Exception as e:
        logger.error("Error registering endpoint", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to register endpoint")

@router.put("/endpoints/{endpoint_id}/status")
async def update_endpoint_status(
    endpoint_id: str, 
    status: EndpointStatus, 
    current_user = Depends(get_current_user)
):
    """Update endpoint status"""
    try:
        success = await endpoint_security_service.update_endpoint_status(endpoint_id, status)
        if not success:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        return {"message": "Endpoint status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating endpoint status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update endpoint status")

# Antivirus Management Endpoints
@router.post("/antivirus/scan", response_model=Dict[str, str])
async def start_antivirus_scan(
    endpoint_id: str = Query(..., description="Endpoint ID to scan"),
    scan_type: str = Query("quick", description="Scan type: quick, full, custom"),
    scan_path: str = Query("C:\\", description="Path to scan"),
    current_user = Depends(get_current_user)
):
    """Start an antivirus scan on an endpoint"""
    try:
        scan_id = await endpoint_security_service.start_antivirus_scan(
            endpoint_id=endpoint_id,
            scan_type=scan_type,
            scan_path=scan_path
        )
        return {"scan_id": scan_id, "message": "Antivirus scan started successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("Error starting antivirus scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start antivirus scan")

@router.get("/antivirus/scan/{scan_id}", response_model=Dict[str, Any])
async def get_scan_status(scan_id: str, current_user = Depends(get_current_user)):
    """Get the status of an antivirus scan"""
    try:
        scan = await endpoint_security_service.get_scan_status(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting scan status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scan status")

@router.get("/antivirus/endpoint/{endpoint_id}/scans", response_model=List[Dict[str, Any]])
async def get_endpoint_scans(endpoint_id: str, current_user = Depends(get_current_user)):
    """Get all antivirus scans for an endpoint"""
    try:
        scans = await endpoint_security_service.get_endpoint_scans(endpoint_id)
        return scans
    except Exception as e:
        logger.error("Error getting endpoint scans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve endpoint scans")

# EDR Management Endpoints
@router.post("/edr/alerts", response_model=Dict[str, str])
async def create_edr_alert(
    endpoint_id: str = Query(..., description="Endpoint ID"),
    alert_data: Dict[str, Any] = None,
    current_user = Depends(get_current_user)
):
    """Create a new EDR alert"""
    try:
        if not alert_data:
            alert_data = {}
        
        alert_id = await endpoint_security_service.create_edr_alert(endpoint_id, alert_data)
        return {"alert_id": alert_id, "message": "EDR alert created successfully"}
    except Exception as e:
        logger.error("Error creating EDR alert", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create EDR alert")

@router.get("/edr/alerts", response_model=List[Dict[str, Any]])
async def get_edr_alerts(
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint ID"),
    status: Optional[str] = Query(None, description="Filter by alert status"),
    current_user = Depends(get_current_user)
):
    """Get EDR alerts with optional filtering"""
    try:
        alerts = await endpoint_security_service.get_edr_alerts(endpoint_id=endpoint_id, status=status)
        return alerts
    except Exception as e:
        logger.error("Error getting EDR alerts", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve EDR alerts")

@router.put("/edr/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str = Query(..., description="New alert status"),
    current_user = Depends(get_current_user)
):
    """Update the status of an EDR alert"""
    try:
        success = await endpoint_security_service.update_alert_status(alert_id, status)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"message": "Alert status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating alert status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update alert status")

# Application Whitelisting Endpoints
@router.post("/whitelist", response_model=Dict[str, str])
async def add_whitelist_entry(
    entry_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Add a new application to the whitelist"""
    try:
        entry_id = await endpoint_security_service.add_whitelist_entry(entry_data)
        return {"entry_id": entry_id, "message": "Whitelist entry added successfully"}
    except Exception as e:
        logger.error("Error adding whitelist entry", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to add whitelist entry")

@router.delete("/whitelist/{entry_id}")
async def remove_whitelist_entry(entry_id: str, current_user = Depends(get_current_user)):
    """Remove an application from the whitelist"""
    try:
        success = await endpoint_security_service.remove_whitelist_entry(entry_id)
        if not success:
            raise HTTPException(status_code=404, detail="Whitelist entry not found")
        return {"message": "Whitelist entry removed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error removing whitelist entry", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to remove whitelist entry")

@router.get("/whitelist", response_model=List[Dict[str, Any]])
async def get_whitelist_entries(current_user = Depends(get_current_user)):
    """Get all whitelist entries"""
    try:
        entries = await endpoint_security_service.get_whitelist_entries()
        return entries
    except Exception as e:
        logger.error("Error getting whitelist entries", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve whitelist entries")

@router.post("/whitelist/check", response_model=Dict[str, Any])
async def check_application_whitelist(
    app_path: str = Query(..., description="Application path"),
    app_hash: str = Query(..., description="Application hash"),
    current_user = Depends(get_current_user)
):
    """Check if an application is whitelisted"""
    try:
        action = await endpoint_security_service.check_application_whitelist(app_path, app_hash)
        return {
            "app_path": app_path,
            "app_hash": app_hash,
            "action": action.value,
            "is_whitelisted": action == WhitelistAction.ALLOW
        }
    except Exception as e:
        logger.error("Error checking application whitelist", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to check application whitelist")

# Reporting Endpoints
@router.get("/summary", response_model=Dict[str, Any])
async def get_endpoint_security_summary(current_user = Depends(get_current_user)):
    """Get a summary of endpoint security status"""
    try:
        summary = await endpoint_security_service.get_endpoint_security_summary()
        return summary
    except Exception as e:
        logger.error("Error getting endpoint security summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve endpoint security summary")

@router.get("/threat-analysis", response_model=Dict[str, Any])
async def get_threat_analysis(
    days: int = Query(7, description="Number of days for analysis"),
    current_user = Depends(get_current_user)
):
    """Get threat analysis for the specified period"""
    try:
        analysis = await endpoint_security_service.get_threat_analysis(days)
        return analysis
    except Exception as e:
        logger.error("Error getting threat analysis", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve threat analysis")

# Bulk Operations
@router.post("/bulk/scan")
async def start_bulk_scan(
    endpoint_ids: List[str] = Query(..., description="List of endpoint IDs to scan"),
    scan_type: str = Query("quick", description="Scan type: quick, full, custom"),
    current_user = Depends(get_current_user)
):
    """Start antivirus scans on multiple endpoints"""
    try:
        scan_results = []
        for endpoint_id in endpoint_ids:
            try:
                scan_id = await endpoint_security_service.start_antivirus_scan(
                    endpoint_id=endpoint_id,
                    scan_type=scan_type
                )
                scan_results.append({
                    "endpoint_id": endpoint_id,
                    "scan_id": scan_id,
                    "status": "started"
                })
            except Exception as e:
                scan_results.append({
                    "endpoint_id": endpoint_id,
                    "error": str(e),
                    "status": "failed"
                })
        
        return {
            "message": "Bulk scan operation completed",
            "results": scan_results
        }
    except Exception as e:
        logger.error("Error starting bulk scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start bulk scan")

@router.post("/bulk/quarantine")
async def quarantine_endpoints(
    endpoint_ids: List[str] = Query(..., description="List of endpoint IDs to quarantine"),
    current_user = Depends(get_current_user)
):
    """Quarantine multiple endpoints"""
    try:
        quarantine_results = []
        for endpoint_id in endpoint_ids:
            try:
                success = await endpoint_security_service.update_endpoint_status(
                    endpoint_id, 
                    EndpointStatus.QUARANTINED
                )
                quarantine_results.append({
                    "endpoint_id": endpoint_id,
                    "status": "quarantined" if success else "failed"
                })
            except Exception as e:
                quarantine_results.append({
                    "endpoint_id": endpoint_id,
                    "error": str(e),
                    "status": "failed"
                })
        
        return {
            "message": "Bulk quarantine operation completed",
            "results": quarantine_results
        }
    except Exception as e:
        logger.error("Error quarantining endpoints", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to quarantine endpoints")

# Health Check
@router.get("/health")
async def endpoint_security_health_check(current_user = Depends(get_current_user)):
    """Health check for endpoint security service"""
    try:
        summary = await endpoint_security_service.get_endpoint_security_summary()
        return {
            "status": "healthy",
            "service": "endpoint_security",
            "timestamp": datetime.now().isoformat(),
            "endpoints_online": summary["online_endpoints"],
            "total_endpoints": summary["total_endpoints"],
            "active_alerts": summary["new_alerts"]
        }
    except Exception as e:
        logger.error("Endpoint security health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "service": "endpoint_security",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        } 