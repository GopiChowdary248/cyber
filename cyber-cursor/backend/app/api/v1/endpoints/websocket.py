from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer
from typing import List, Dict, Any, Optional
import json
import structlog
from datetime import datetime, timedelta
import asyncio
from enum import Enum

from app.core.security import verify_token, get_current_user
from app.services.notification_service import notification_service
from app.models.user import User
from app.core.database import get_db

logger = structlog.get_logger()
router = APIRouter()

class NotificationType(Enum):
    INCIDENT = "incident"
    SECURITY_ALERT = "security_alert"
    TRAINING_REMINDER = "training_reminder"
    SYSTEM_UPDATE = "system_update"
    COMPLIANCE_ALERT = "compliance_alert"
    PHISHING_ALERT = "phishing_alert"
    CLOUD_SECURITY = "cloud_security"
    USER_ACTIVITY = "user_activity"

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[Dict[str, Any]] = []
        self.connection_groups: Dict[str, List[int]] = {
            "admins": [],
            "users": [],
            "security_team": []
        }
        self.heartbeat_interval = 30  # seconds
        self.connection_timeout = 300  # 5 minutes

    async def connect(self, websocket: WebSocket, user_id: int, user_role: str, user_preferences: Dict[str, Any] = None):
        await websocket.accept()
        connection = {
            "websocket": websocket,
            "user_id": user_id,
            "user_role": user_role,
            "connected_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "last_heartbeat": datetime.utcnow(),
            "preferences": user_preferences or {},
            "subscriptions": self._get_default_subscriptions(user_role)
        }
        self.active_connections.append(connection)
        
        # Add to role-based groups
        if user_role == "admin":
            self.connection_groups["admins"].append(user_id)
        elif user_role == "security_analyst":
            self.connection_groups["security_team"].append(user_id)
        else:
            self.connection_groups["users"].append(user_id)
        
        await notification_service.add_connection(user_id, websocket)
        
        # Send welcome message with connection info
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to CyberShield real-time notifications",
            "user_id": user_id,
            "user_role": user_role,
            "timestamp": datetime.utcnow().isoformat(),
            "subscriptions": connection["subscriptions"],
            "server_time": datetime.utcnow().isoformat()
        })
        
        logger.info("WebSocket connection established", user_id=user_id, user_role=user_role)

    def _get_default_subscriptions(self, user_role: str) -> List[str]:
        """Get default notification subscriptions based on user role"""
        if user_role == "admin":
            return [nt.value for nt in NotificationType]
        elif user_role == "security_analyst":
            return [
                NotificationType.INCIDENT.value,
                NotificationType.SECURITY_ALERT.value,
                NotificationType.PHISHING_ALERT.value,
                NotificationType.CLOUD_SECURITY.value,
                NotificationType.COMPLIANCE_ALERT.value
            ]
        else:
            return [
                NotificationType.TRAINING_REMINDER.value,
                NotificationType.SYSTEM_UPDATE.value,
                NotificationType.USER_ACTIVITY.value
            ]

    def disconnect(self, websocket: WebSocket):
        connection = next((conn for conn in self.active_connections if conn["websocket"] == websocket), None)
        if connection:
            self.active_connections.remove(connection)
            user_id = connection["user_id"]
            user_role = connection["user_role"]
            
            # Remove from role-based groups
            if user_role == "admin" and user_id in self.connection_groups["admins"]:
                self.connection_groups["admins"].remove(user_id)
            elif user_role == "security_analyst" and user_id in self.connection_groups["security_team"]:
                self.connection_groups["security_team"].remove(user_id)
            elif user_id in self.connection_groups["users"]:
                self.connection_groups["users"].remove(user_id)
            
            notification_service.remove_connection(user_id)
            logger.info("WebSocket connection removed", user_id=user_id)

    async def send_personal_message(self, message: Dict[str, Any], user_id: int):
        for connection in self.active_connections:
            if connection["user_id"] == user_id:
                try:
                    # Check if user is subscribed to this notification type
                    notification_type = message.get("notification_type")
                    if notification_type and notification_type not in connection["subscriptions"]:
                        continue
                    
                    await connection["websocket"].send_json(message)
                    connection["last_activity"] = datetime.utcnow()
                except Exception as e:
                    logger.error("Failed to send personal message", error=str(e), user_id=user_id)
                    # Remove dead connection
                    self.active_connections.remove(connection)

    async def broadcast(self, message: Dict[str, Any], exclude_user_id: int = None, notification_type: str = None):
        disconnected = []
        for connection in self.active_connections:
            if exclude_user_id and connection["user_id"] == exclude_user_id:
                continue
            
            # Check notification type subscription
            if notification_type and notification_type not in connection["subscriptions"]:
                continue
            
            try:
                await connection["websocket"].send_json(message)
                connection["last_activity"] = datetime.utcnow()
            except Exception as e:
                logger.error("Failed to broadcast message", error=str(e), user_id=connection["user_id"])
                disconnected.append(connection)
        
        # Remove dead connections
        for connection in disconnected:
            self.disconnect(connection["websocket"])

    async def send_to_role(self, message: Dict[str, Any], role: str, notification_type: str = None):
        for connection in self.active_connections:
            if connection["user_role"] == role:
                # Check notification type subscription
                if notification_type and notification_type not in connection["subscriptions"]:
                    continue
                
                try:
                    await connection["websocket"].send_json(message)
                    connection["last_activity"] = datetime.utcnow()
                except Exception as e:
                    logger.error("Failed to send role message", error=str(e), user_id=connection["user_id"])
                    # Remove dead connection
                    self.disconnect(connection["websocket"])

    async def send_to_group(self, message: Dict[str, Any], group_name: str, notification_type: str = None):
        """Send message to a specific group of users"""
        user_ids = self.connection_groups.get(group_name, [])
        for user_id in user_ids:
            await self.send_personal_message(message, user_id)

    async def update_subscriptions(self, user_id: int, subscriptions: List[str]):
        """Update user's notification subscriptions"""
        for connection in self.active_connections:
            if connection["user_id"] == user_id:
                connection["subscriptions"] = subscriptions
                await connection["websocket"].send_json({
                    "type": "subscriptions_updated",
                    "subscriptions": subscriptions,
                    "timestamp": datetime.utcnow().isoformat()
                })
                break

    async def start_heartbeat_monitor(self):
        """Monitor connections and send heartbeat messages"""
        while True:
            try:
                current_time = datetime.utcnow()
                disconnected = []
                
                for connection in self.active_connections:
                    # Check if connection is still alive
                    if (current_time - connection["last_heartbeat"]).seconds > self.connection_timeout:
                        disconnected.append(connection)
                        continue
                    
                    # Send heartbeat
                    try:
                        await connection["websocket"].send_json({
                            "type": "heartbeat",
                            "timestamp": current_time.isoformat()
                        })
                        connection["last_heartbeat"] = current_time
                    except Exception as e:
                        logger.error("Failed to send heartbeat", error=str(e), user_id=connection["user_id"])
                        disconnected.append(connection)
                
                # Remove dead connections
                for connection in disconnected:
                    self.disconnect(connection["websocket"])
                
                await asyncio.sleep(self.heartbeat_interval)
                
            except Exception as e:
                logger.error("Heartbeat monitor error", error=str(e))
                await asyncio.sleep(self.heartbeat_interval)

manager = ConnectionManager()

@router.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        # Verify token and get user info
        payload = verify_token(token)
        if not payload:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        
        user_id = payload.get("sub")
        user_role = payload.get("role", "user")
        
        # Get user notification preferences
        user_preferences = await notification_service.get_user_notification_preferences(user_id)
        
        await manager.connect(websocket, user_id, user_role, user_preferences)
        
        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Update last activity
                connection = next((conn for conn in manager.active_connections if conn["websocket"] == websocket), None)
                if connection:
                    connection["last_activity"] = datetime.utcnow()
                
                # Handle different message types
                if message.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                elif message.get("type") == "notification_preferences":
                    # Handle notification preference updates
                    preferences = message.get("preferences", {})
                    await notification_service.update_user_notification_preferences(user_id, preferences)
                    await websocket.send_json({
                        "type": "preferences_updated",
                        "message": "Notification preferences updated",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                elif message.get("type") == "update_subscriptions":
                    # Handle subscription updates
                    subscriptions = message.get("subscriptions", [])
                    await manager.update_subscriptions(user_id, subscriptions)
                elif message.get("type") == "get_notifications":
                    # Send recent notifications
                    notifications = await notification_service.get_user_notifications(user_id, 10)
                    await websocket.send_json({
                        "type": "notifications",
                        "notifications": notifications,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            logger.error("WebSocket error", error=str(e))
            manager.disconnect(websocket)
            
    except Exception as e:
        logger.error("WebSocket connection error", error=str(e))
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)

@router.get("/notifications")
async def get_user_notifications(
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=100)
):
    """Get user's notifications"""
    try:
        notifications = await notification_service.get_user_notifications(current_user.id, limit)
        return {"notifications": notifications, "total": len(notifications)}
    except Exception as e:
        logger.error("Error getting notifications", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get notifications")

@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user)
):
    """Mark a notification as read"""
    try:
        await notification_service.mark_notification_read(notification_id, current_user.id)
        return {"message": "Notification marked as read"}
    except Exception as e:
        logger.error("Error marking notification read", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to mark notification as read")

@router.get("/notifications/settings")
async def get_notification_settings(
    current_user: User = Depends(get_current_user)
):
    """Get user's notification settings"""
    try:
        # In a real implementation, this would query user notification preferences
        return {
            "email_notifications": True,
            "in_app_notifications": True,
            "slack_notifications": False,
            "sms_notifications": False,
            "incident_alerts": True,
            "training_reminders": True,
            "security_tips": True,
            "system_updates": False
        }
    except Exception as e:
        logger.error("Error getting notification settings", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get notification settings")

@router.put("/notifications/settings")
async def update_notification_settings(
    settings: Dict[str, Any],
    current_user: User = Depends(get_current_user)
):
    """Update user's notification settings"""
    try:
        # In a real implementation, this would update user notification preferences
        logger.info("Notification settings updated", user_id=current_user.id, settings=settings)
        return {"message": "Notification settings updated successfully"}
    except Exception as e:
        logger.error("Error updating notification settings", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update notification settings")

@router.get("/websocket/status")
async def get_websocket_status(
    current_user: User = Depends(get_current_user)
):
    """Get WebSocket connection status"""
    try:
        connection = next((conn for conn in manager.active_connections if conn["user_id"] == current_user.id), None)
        return {
            "connected": connection is not None,
            "connected_at": connection["connected_at"].isoformat() if connection else None,
            "last_activity": connection["last_activity"].isoformat() if connection else None,
            "total_connections": len(manager.active_connections)
        }
    except Exception as e:
        logger.error("Error getting WebSocket status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get WebSocket status") 