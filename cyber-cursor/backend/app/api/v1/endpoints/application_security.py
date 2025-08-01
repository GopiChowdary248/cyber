"""
Application Security API Endpoints
Provides REST API for application security management including:
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- SCA (Software Composition Analysis)
- WAF (Web Application Firewall)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

from app.core.security import get_current_user
from app.services.application_security_service import (
    application_security_service,
    ScanType,
    VulnerabilitySeverity,
    WAFRuleAction
)

logger = structlog.get_logger()
router = APIRouter()

# Application Management Endpoints
@router.get("/applications", response_model=List[Dict[str, Any]])
async def get_applications(current_user = Depends(get_current_user)):
    """Get all registered applications"""
    try:
        applications = await application_security_service.get_applications()
        return applications
    except Exception as e:
        logger.error("Error getting applications", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve applications")

@router.post("/applications", response_model=Dict[str, str])
async def register_application(
    app_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Register a new application"""
    try:
        app_id = await application_security_service.register_application(app_data)
        return {"app_id": app_id, "message": "Application registered successfully"}
    except Exception as e:
        logger.error("Error registering application", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to register application")

# SAST Endpoints
@router.post("/sast/scan", response_model=Dict[str, str])
async def start_sast_scan(
    app_id: str = Query(..., description="Application ID to scan"),
    scan_config: Dict[str, Any] = None,
    current_user = Depends(get_current_user)
):
    """Start a SAST scan for an application"""
    try:
        if not scan_config:
            scan_config = {}
        
        scan_id = await application_security_service.start_sast_scan(app_id, scan_config)
        return {"scan_id": scan_id, "message": "SAST scan started successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("Error starting SAST scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start SAST scan")

@router.get("/sast/scans", response_model=List[Dict[str, Any]])
async def get_sast_scans(current_user = Depends(get_current_user)):
    """Get all SAST scans"""
    try:
        scans = await application_security_service.get_sast_scans()
        return scans
    except Exception as e:
        logger.error("Error getting SAST scans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve SAST scans")

# DAST Endpoints
@router.post("/dast/scan", response_model=Dict[str, str])
async def start_dast_scan(
    target_url: str = Query(..., description="Target URL to scan"),
    scan_config: Dict[str, Any] = None,
    current_user = Depends(get_current_user)
):
    """Start a DAST scan for a target URL"""
    try:
        if not scan_config:
            scan_config = {}
        
        scan_id = await application_security_service.start_dast_scan(target_url, scan_config)
        return {"scan_id": scan_id, "message": "DAST scan started successfully"}
    except Exception as e:
        logger.error("Error starting DAST scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start DAST scan")

@router.get("/dast/scans", response_model=List[Dict[str, Any]])
async def get_dast_scans(current_user = Depends(get_current_user)):
    """Get all DAST scans"""
    try:
        scans = await application_security_service.get_dast_scans()
        return scans
    except Exception as e:
        logger.error("Error getting DAST scans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve DAST scans")

# SCA Endpoints
@router.post("/sca/scan", response_model=Dict[str, str])
async def start_sca_scan(
    app_id: str = Query(..., description="Application ID to scan"),
    manifest_files: List[str] = Query(..., description="List of manifest files"),
    current_user = Depends(get_current_user)
):
    """Start a SCA scan for an application"""
    try:
        scan_id = await application_security_service.start_sca_scan(app_id, manifest_files)
        return {"scan_id": scan_id, "message": "SCA scan started successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("Error starting SCA scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start SCA scan")

@router.get("/sca/scans", response_model=List[Dict[str, Any]])
async def get_sca_scans(current_user = Depends(get_current_user)):
    """Get all SCA scans"""
    try:
        scans = await application_security_service.get_sca_scans()
        return scans
    except Exception as e:
        logger.error("Error getting SCA scans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve SCA scans")

# WAF Endpoints
@router.post("/waf/rules", response_model=Dict[str, str])
async def create_waf_rule(
    rule_data: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Create a new WAF rule"""
    try:
        rule_id = await application_security_service.create_waf_rule(rule_data)
        return {"rule_id": rule_id, "message": "WAF rule created successfully"}
    except Exception as e:
        logger.error("Error creating WAF rule", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create WAF rule")

@router.get("/waf/rules", response_model=List[Dict[str, Any]])
async def get_waf_rules(current_user = Depends(get_current_user)):
    """Get all WAF rules"""
    try:
        rules = await application_security_service.get_waf_rules()
        return rules
    except Exception as e:
        logger.error("Error getting WAF rules", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve WAF rules")

# Vulnerability Management Endpoints
@router.get("/vulnerabilities", response_model=List[Dict[str, Any]])
async def get_vulnerabilities(
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user = Depends(get_current_user)
):
    """Get vulnerabilities with optional filtering"""
    try:
        vulnerabilities = await application_security_service.get_vulnerabilities()
        
        # Apply filters if provided
        if scan_type:
            vulnerabilities = [v for v in vulnerabilities if v.get("scan_type") == scan_type]
        if severity:
            vulnerabilities = [v for v in vulnerabilities if v.get("severity") == severity]
        
        return vulnerabilities
    except Exception as e:
        logger.error("Error getting vulnerabilities", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")

@router.put("/vulnerabilities/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: str,
    status: str = Query(..., description="New vulnerability status"),
    current_user = Depends(get_current_user)
):
    """Update vulnerability status"""
    try:
        success = await application_security_service.update_vulnerability_status(vuln_id, status)
        if not success:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return {"message": "Vulnerability status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating vulnerability status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update vulnerability status")

# Reporting Endpoints
@router.get("/summary", response_model=Dict[str, Any])
async def get_application_security_summary(current_user = Depends(get_current_user)):
    """Get application security summary"""
    try:
        summary = await application_security_service.get_application_security_summary()
        return summary
    except Exception as e:
        logger.error("Error getting security summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve security summary")

# Bulk Operations
@router.post("/bulk/sast-scan")
async def start_bulk_sast_scan(
    app_ids: List[str] = Query(..., description="List of application IDs to scan"),
    current_user = Depends(get_current_user)
):
    """Start SAST scans on multiple applications"""
    try:
        scan_results = []
        for app_id in app_ids:
            try:
                scan_id = await application_security_service.start_sast_scan(app_id, {})
                scan_results.append({
                    "app_id": app_id,
                    "scan_id": scan_id,
                    "status": "started"
                })
            except Exception as e:
                scan_results.append({
                    "app_id": app_id,
                    "error": str(e),
                    "status": "failed"
                })
        
        return {
            "message": "Bulk SAST scan operation completed",
            "results": scan_results
        }
    except Exception as e:
        logger.error("Error starting bulk SAST scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start bulk SAST scan")

@router.post("/bulk/dast-scan")
async def start_bulk_dast_scan(
    target_urls: List[str] = Query(..., description="List of target URLs to scan"),
    current_user = Depends(get_current_user)
):
    """Start DAST scans on multiple URLs"""
    try:
        scan_results = []
        for target_url in target_urls:
            try:
                scan_id = await application_security_service.start_dast_scan(target_url, {})
                scan_results.append({
                    "target_url": target_url,
                    "scan_id": scan_id,
                    "status": "started"
                })
            except Exception as e:
                scan_results.append({
                    "target_url": target_url,
                    "error": str(e),
                    "status": "failed"
                })
        
        return {
            "message": "Bulk DAST scan operation completed",
            "results": scan_results
        }
    except Exception as e:
        logger.error("Error starting bulk DAST scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start bulk DAST scan")

# Health Check
@router.get("/health")
async def application_security_health_check(current_user = Depends(get_current_user)):
    """Health check for application security service"""
    try:
        summary = await application_security_service.get_application_security_summary()
        return {
            "status": "healthy",
            "service": "application_security",
            "timestamp": datetime.now().isoformat(),
            "total_applications": summary["total_applications"],
            "total_vulnerabilities": summary["total_vulnerabilities"],
            "active_waf_rules": summary["active_waf_rules"]
        }
    except Exception as e:
        logger.error("Application security health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "service": "application_security",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        } 