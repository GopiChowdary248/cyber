"""
Device Control API Endpoints
Provides REST API for device control functionality including:
- Device inventory management
- Device policy management
- Device event logging and monitoring
- USB/media access control
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

from app.core.security import get_current_user
from app.core.database import get_db
from app.models.device_control import Device, DevicePolicy, DeviceEvent, DeviceType, DeviceStatus, PolicyAction, EventType
from app.models.user import User

logger = structlog.get_logger()
router = APIRouter()

# Device Inventory Endpoints
@router.get("/devices", response_model=List[Dict[str, Any]])
async def list_devices(
    device_type: Optional[str] = Query(None, description="Filter by device type"),
    status: Optional[str] = Query(None, description="Filter by device status"),
    skip: int = Query(0, description="Number of records to skip"),
    limit: int = Query(100, description="Maximum number of records to return"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all devices with optional filtering"""
    try:
        if device_type and status:
            devices = await Device.get_by_type(db, device_type)
            devices = [d for d in devices if d.status == status]
        elif device_type:
            devices = await Device.get_by_type(db, device_type)
        elif status:
            devices = await Device.get_by_status(db, status)
        else:
            devices = await Device.get_all(db, skip, limit)
        
        return [
            {
                "id": str(device.id),
                "device_name": device.device_name,
                "device_type": device.device_type,
                "vendor": device.vendor,
                "model": device.model,
                "serial_number": device.serial_number,
                "device_id": device.device_id,
                "capacity": device.capacity,
                "file_system": device.file_system,
                "is_encrypted": device.is_encrypted,
                "is_approved": device.is_approved,
                "status": device.status,
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                "first_seen": device.first_seen.isoformat(),
                "endpoint_id": device.endpoint_id,
                "created_at": device.created_at.isoformat(),
                "updated_at": device.updated_at.isoformat()
            }
            for device in devices
        ]
    except Exception as e:
        logger.error("Error getting devices", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve devices")

@router.get("/devices/{device_id}", response_model=Dict[str, Any])
async def get_device_details(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed information about a specific device"""
    try:
        device = await Device.get_by_id(db, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return {
            "id": str(device.id),
            "device_name": device.device_name,
            "device_type": device.device_type,
            "vendor": device.vendor,
            "model": device.model,
            "serial_number": device.serial_number,
            "device_id": device.device_id,
            "capacity": device.capacity,
            "file_system": device.file_system,
            "is_encrypted": device.is_encrypted,
            "is_approved": device.is_approved,
            "status": device.status,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "first_seen": device.first_seen.isoformat(),
            "endpoint_id": device.endpoint_id,
            "created_at": device.created_at.isoformat(),
            "updated_at": device.updated_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting device details", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve device details")

@router.post("/devices", response_model=Dict[str, str])
async def register_device(
    device_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Register a new device"""
    try:
        device = Device(
            device_name=device_data.get("device_name"),
            device_type=device_data.get("device_type"),
            vendor=device_data.get("vendor"),
            model=device_data.get("model"),
            serial_number=device_data.get("serial_number"),
            device_id=device_data.get("device_id"),
            capacity=device_data.get("capacity"),
            file_system=device_data.get("file_system"),
            endpoint_id=device_data.get("endpoint_id"),
            user_id=current_user.id
        )
        db.add(device)
        await db.commit()
        await db.refresh(device)
        
        # Log device registration event
        event = DeviceEvent(
            device_id=device.id,
            event_type=EventType.CONNECT.value,
            action_taken="register",
            reason="Device registered",
            severity="info",
            endpoint_id=device.endpoint_id,
            user_id=current_user.id
        )
        db.add(event)
        await db.commit()
        
        return {"device_id": str(device.id), "message": "Device registered successfully"}
    except Exception as e:
        logger.error("Error registering device", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to register device")

@router.put("/devices/{device_id}/status")
async def update_device_status(
    device_id: str,
    status: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update device status"""
    try:
        device = await Device.get_by_id(db, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        old_status = device.status
        device.status = status
        device.last_seen = datetime.utcnow()
        await db.commit()
        
        # Log status change event
        event = DeviceEvent(
            device_id=device.id,
            event_type=EventType.CONNECT.value if status == DeviceStatus.CONNECTED.value else EventType.DISCONNECT.value,
            action_taken=status,
            reason=f"Status changed from {old_status} to {status}",
            severity="info",
            endpoint_id=device.endpoint_id,
            user_id=current_user.id
        )
        db.add(event)
        await db.commit()
        
        return {"message": "Device status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating device status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update device status")

# Device Policy Endpoints
@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies(
    device_type: Optional[str] = Query(None, description="Filter by device type"),
    active_only: bool = Query(True, description="Show only active policies"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all device policies"""
    try:
        if device_type:
            policies = await DevicePolicy.get_by_device_type(db, device_type)
        elif active_only:
            policies = await DevicePolicy.get_active_policies(db)
        else:
            policies = await DevicePolicy.get_all(db)
        
        return [
            {
                "id": str(policy.id),
                "policy_name": policy.policy_name,
                "description": policy.description,
                "device_type": policy.device_type,
                "vendor": policy.vendor,
                "model": policy.model,
                "device_id": policy.device_id,
                "action": policy.action,
                "auto_encrypt": policy.auto_encrypt,
                "require_approval": policy.require_approval,
                "max_capacity": policy.max_capacity,
                "allowed_file_types": policy.allowed_file_types,
                "blocked_file_types": policy.blocked_file_types,
                "is_active": policy.is_active,
                "priority": policy.priority,
                "created_at": policy.created_at.isoformat(),
                "updated_at": policy.updated_at.isoformat()
            }
            for policy in policies
        ]
    except Exception as e:
        logger.error("Error getting policies", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve policies")

@router.post("/policies", response_model=Dict[str, str])
async def create_policy(
    policy_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new device policy"""
    try:
        policy = DevicePolicy(
            policy_name=policy_data.get("policy_name"),
            description=policy_data.get("description"),
            device_type=policy_data.get("device_type"),
            vendor=policy_data.get("vendor"),
            model=policy_data.get("model"),
            device_id=policy_data.get("device_id"),
            action=policy_data.get("action", PolicyAction.BLOCK.value),
            auto_encrypt=policy_data.get("auto_encrypt", False),
            require_approval=policy_data.get("require_approval", False),
            max_capacity=policy_data.get("max_capacity"),
            allowed_file_types=policy_data.get("allowed_file_types"),
            blocked_file_types=policy_data.get("blocked_file_types"),
            priority=policy_data.get("priority", 100),
            created_by=current_user.id
        )
        db.add(policy)
        await db.commit()
        await db.refresh(policy)
        
        return {"policy_id": str(policy.id), "message": "Policy created successfully"}
    except Exception as e:
        logger.error("Error creating policy", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create policy")

@router.put("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    policy_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update a device policy"""
    try:
        policy = await DevicePolicy.get_by_id(db, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        # Update policy fields
        for key, value in policy_data.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        await db.commit()
        return {"message": "Policy updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating policy", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update policy")

# Device Events Endpoints
@router.get("/events", response_model=List[Dict[str, Any]])
async def get_device_events(
    device_id: Optional[str] = Query(None, description="Filter by device ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    hours: int = Query(24, description="Number of hours to look back"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get device events with optional filtering"""
    try:
        if device_id:
            events = await DeviceEvent.get_by_device(db, device_id)
        elif event_type:
            events = await DeviceEvent.get_by_type(db, event_type)
        elif severity:
            events = await DeviceEvent.get_by_severity(db, severity)
        else:
            events = await DeviceEvent.get_recent_events(db, hours)
        
        return [
            {
                "id": str(event.id),
                "device_id": str(event.device_id),
                "policy_id": str(event.policy_id) if event.policy_id else None,
                "event_type": event.event_type,
                "event_time": event.event_time.isoformat(),
                "endpoint_id": event.endpoint_id,
                "process_name": event.process_name,
                "file_path": event.file_path,
                "action_taken": event.action_taken,
                "reason": event.reason,
                "severity": event.severity,
                "metadata": event.metadata,
                "created_at": event.created_at.isoformat()
            }
            for event in events
        ]
    except Exception as e:
        logger.error("Error getting device events", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve device events")

# Device Control Summary
@router.get("/summary", response_model=Dict[str, Any])
async def get_device_control_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get device control summary statistics"""
    try:
        # Get device counts
        total_devices = len(await Device.get_all(db))
        connected_devices = len(await Device.get_connected_devices(db))
        blocked_devices = len(await Device.get_by_status(db, DeviceStatus.BLOCKED.value))
        quarantined_devices = len(await Device.get_by_status(db, DeviceStatus.QUARANTINED.value))
        
        # Get policy counts
        active_policies = await DevicePolicy.get_active_policies(db)
        
        # Get recent events
        recent_events = await DeviceEvent.get_recent_events(db, 24)
        
        return {
            "devices": {
                "total": total_devices,
                "connected": connected_devices,
                "blocked": blocked_devices,
                "quarantined": quarantined_devices
            },
            "policies": {
                "active": len(active_policies)
            },
            "events": {
                "last_24_hours": len(recent_events)
            }
        }
    except Exception as e:
        logger.error("Error getting device control summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve device control summary")

# Health Check
@router.get("/health")
async def device_control_health_check(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Health check for device control service"""
    try:
        summary = await get_device_control_summary(current_user, db)
        return {
            "status": "healthy",
            "service": "device_control",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": summary
        }
    except Exception as e:
        logger.error("Device control health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "service": "device_control",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }