"""
Network Security API Endpoints
Provides REST API for network security management including:
- Firewall rules management
- IDS/IPS alerts and monitoring
- VPN connection management
- Network Access Control (NAC)
- DNS security
- Network segmentation
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import structlog

from app.core.database import get_db
from app.core.security import get_current_active_user, require_admin
from app.services.network_security_service import NetworkSecurityService
from app.schemas.network_security import (
    NetworkDevice, NetworkDeviceCreate, NetworkDeviceUpdate,
    FirewallLog, FirewallLogCreate,
    IDSAlert, IDSAlertCreate, IDSAlertUpdate,
    VPNSession, VPNSessionCreate, VPNSessionUpdate,
    NACLog, NACLogCreate,
    NetworkSecurityOverview, FirewallStats, IDSStats, VPNStats, NACStats,
    DeviceListResponse, FirewallLogsResponse, IDSAlertsResponse,
    VPNSessionsResponse, NACLogsResponse, NetworkSecurityFilter
)

logger = structlog.get_logger()
router = APIRouter()

# Network Devices Endpoints
@router.get("/devices", response_model=DeviceListResponse)
async def get_network_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_type: Optional[str] = Query(None, description="Filter by device type"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get network devices with pagination"""
    try:
        service = NetworkSecurityService(db)
        if device_type:
            devices = await service.get_devices_by_type(device_type)
            total = len(devices)
        else:
            devices = await service.get_all_devices(skip, limit)
            total = len(devices)  # In production, you'd want a separate count query
        
        return DeviceListResponse(
            devices=devices,
            total=total,
            page=skip // limit + 1,
            limit=limit
        )
    except Exception as e:
        logger.error("Failed to get network devices", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve network devices"
        )

@router.post("/devices", response_model=NetworkDevice)
async def create_network_device(
    device_data: NetworkDeviceCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create a new network device"""
    try:
        service = NetworkSecurityService(db)
        device = await service.create_device(device_data)
        return device
    except Exception as e:
        logger.error("Failed to create network device", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create network device"
        )

@router.get("/devices/{device_id}", response_model=NetworkDevice)
async def get_network_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get a specific network device"""
    try:
        service = NetworkSecurityService(db)
        device = await service.get_device(device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Network device not found"
            )
        return device
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get network device", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve network device"
        )

# Firewall Endpoints
@router.get("/firewall/logs", response_model=FirewallLogsResponse)
async def get_firewall_logs(
    device_id: Optional[int] = Query(None, description="Filter by device ID"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get firewall logs"""
    try:
        service = NetworkSecurityService(db)
        if device_id:
            logs = await service.get_firewall_logs(device_id=device_id)
        else:
            logs = await service.get_firewall_logs(hours=hours)
        
        # Apply pagination
        total = len(logs)
        logs = logs[skip:skip + limit]
        
        return FirewallLogsResponse(
            logs=logs,
            total=total,
            page=skip // limit + 1,
            limit=limit
        )
    except Exception as e:
        logger.error("Failed to get firewall logs", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve firewall logs"
        )

@router.post("/firewall/logs", response_model=FirewallLog)
async def create_firewall_log(
    log_data: FirewallLogCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create a new firewall log entry"""
    try:
        service = NetworkSecurityService(db)
        log = await service.create_firewall_log(log_data)
        return log
    except Exception as e:
        logger.error("Failed to create firewall log", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create firewall log"
        )

@router.get("/firewall/stats", response_model=FirewallStats)
async def get_firewall_stats(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get firewall statistics"""
    try:
        service = NetworkSecurityService(db)
        stats = await service.get_firewall_stats(hours)
        return FirewallStats(**stats)
    except Exception as e:
        logger.error("Failed to get firewall stats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve firewall statistics"
        )

# IDS Endpoints
@router.get("/ids/alerts", response_model=IDSAlertsResponse)
async def get_ids_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get IDS alerts"""
    try:
        service = NetworkSecurityService(db)
        alerts = await service.get_ids_alerts(severity=severity, hours=hours)
        
        # Apply pagination
        total = len(alerts)
        alerts = alerts[skip:skip + limit]
        
        return IDSAlertsResponse(
            alerts=alerts,
            total=total,
            page=skip // limit + 1,
            limit=limit
        )
    except Exception as e:
        logger.error("Failed to get IDS alerts", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve IDS alerts"
        )

@router.post("/ids/alerts", response_model=IDSAlert)
async def create_ids_alert(
    alert_data: IDSAlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create a new IDS alert"""
    try:
        service = NetworkSecurityService(db)
        alert = await service.create_ids_alert(alert_data)
        return alert
    except Exception as e:
        logger.error("Failed to create IDS alert", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create IDS alert"
        )

@router.put("/ids/alerts/{alert_id}", response_model=IDSAlert)
async def update_alert_status(
    alert_id: int,
    alert_update: IDSAlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Update alert status"""
    try:
        service = NetworkSecurityService(db)
        alert = await service.update_alert_status(alert_id, alert_update.status)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        return alert
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update alert status", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update alert status"
        )

@router.get("/ids/stats", response_model=IDSStats)
async def get_ids_stats(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get IDS statistics"""
    try:
        service = NetworkSecurityService(db)
        stats = await service.get_ids_stats(hours)
        return IDSStats(**stats)
    except Exception as e:
        logger.error("Failed to get IDS stats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve IDS statistics"
        )

# VPN Endpoints
@router.get("/vpn/sessions", response_model=VPNSessionsResponse)
async def get_vpn_sessions(
    active_only: bool = Query(True, description="Get only active sessions"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get VPN sessions"""
    try:
        service = NetworkSecurityService(db)
        if active_only:
            sessions = await service.get_active_vpn_sessions()
        else:
            # In production, you'd want a method to get all sessions
            sessions = await service.get_active_vpn_sessions()
        
        # Apply pagination
        total = len(sessions)
        sessions = sessions[skip:skip + limit]
        
        return VPNSessionsResponse(
            sessions=sessions,
            total=total,
            page=skip // limit + 1,
            limit=limit
        )
    except Exception as e:
        logger.error("Failed to get VPN sessions", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve VPN sessions"
        )

@router.post("/vpn/sessions", response_model=VPNSession)
async def create_vpn_session(
    session_data: VPNSessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create a new VPN session"""
    try:
        service = NetworkSecurityService(db)
        session = await service.create_vpn_session(session_data)
        return session
    except Exception as e:
        logger.error("Failed to create VPN session", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create VPN session"
        )

@router.put("/vpn/sessions/{session_id}/end", response_model=VPNSession)
async def end_vpn_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """End a VPN session"""
    try:
        service = NetworkSecurityService(db)
        session = await service.end_vpn_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="VPN session not found or already ended"
            )
        return session
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to end VPN session", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to end VPN session"
        )

@router.get("/vpn/stats", response_model=VPNStats)
async def get_vpn_stats(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get VPN statistics"""
    try:
        service = NetworkSecurityService(db)
        stats = await service.get_vpn_stats()
        return VPNStats(**stats)
    except Exception as e:
        logger.error("Failed to get VPN stats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve VPN statistics"
        )

# NAC Endpoints
@router.get("/nac/logs", response_model=NACLogsResponse)
async def get_nac_logs(
    action: Optional[str] = Query(None, description="Filter by action"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get NAC logs"""
    try:
        service = NetworkSecurityService(db)
        logs = await service.get_nac_logs(action=action, hours=hours)
        
        # Apply pagination
        total = len(logs)
        logs = logs[skip:skip + limit]
        
        return NACLogsResponse(
            logs=logs,
            total=total,
            page=skip // limit + 1,
            limit=limit
        )
    except Exception as e:
        logger.error("Failed to get NAC logs", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve NAC logs"
        )

@router.post("/nac/logs", response_model=NACLog)
async def create_nac_log(
    log_data: NACLogCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Create a new NAC log entry"""
    try:
        service = NetworkSecurityService(db)
        log = await service.create_nac_log(log_data)
        return log
    except Exception as e:
        logger.error("Failed to create NAC log", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create NAC log"
        )

@router.get("/nac/stats", response_model=NACStats)
async def get_nac_stats(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get NAC statistics"""
    try:
        service = NetworkSecurityService(db)
        stats = await service.get_nac_stats(hours)
        return NACStats(**stats)
    except Exception as e:
        logger.error("Failed to get NAC stats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve NAC statistics"
        )

# Dashboard Overview
@router.get("/overview", response_model=NetworkSecurityOverview)
async def get_network_security_overview(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get network security overview for dashboard"""
    try:
        service = NetworkSecurityService(db)
        overview = await service.get_network_security_overview()
        return NetworkSecurityOverview(**overview)
    except Exception as e:
        logger.error("Failed to get network security overview", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve network security overview"
        ) 