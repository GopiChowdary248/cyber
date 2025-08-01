import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from enum import Enum

from app.core.config import settings
from app.models.user import User
from app.models.incident import Incident

logger = structlog.get_logger()

class NotificationType(Enum):
    INCIDENT = "incident"
    SECURITY_ALERT = "security_alert"
    TRAINING_REMINDER = "training_reminder"
    SYSTEM_UPDATE = "system_update"
    COMPLIANCE_ALERT = "compliance_alert"
    PHISHING_ALERT = "phishing_alert"
    CLOUD_SECURITY = "cloud_security"
    USER_ACTIVITY = "user_activity"

class NotificationPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class NotificationService:
    def __init__(self):
        self.notification_queue = asyncio.Queue()
        self.active_connections: List[Dict[str, Any]] = []
        self.notification_preferences: Dict[int, Dict[str, Any]] = {}
    
    async def start_notification_worker(self):
        """Start the notification worker process"""
        logger.info("Starting notification service worker")
        asyncio.create_task(self._process_notifications())
        asyncio.create_task(self._cleanup_old_notifications())
    
    async def _process_notifications(self):
        """Process notifications from the queue"""
        while True:
            try:
                notification = await self.notification_queue.get()
                await self._send_notification(notification)
                self.notification_queue.task_done()
            except Exception as e:
                logger.error("Error processing notification", error=str(e))
    
    async def _send_notification(self, notification: Dict[str, Any]):
        """Send a notification through various channels"""
        try:
            recipient_id = notification.get("recipient_id")
            
            # Check user preferences
            user_preferences = await self.get_user_notification_preferences(recipient_id)
            notification_type = notification.get("notification_type")
            
            # Check if user wants this type of notification
            if notification_type and not user_preferences.get(f"{notification_type}_enabled", True):
                logger.info("Notification skipped due to user preferences", 
                           user_id=recipient_id, 
                           notification_type=notification_type)
                return
            
            # Send through enabled channels
            channels = notification.get("channels", ["in_app"])
            
            for channel in channels:
                if channel == "in_app" and user_preferences.get("in_app_notifications", True):
                    await self._send_in_app_notification(notification)
                elif channel == "email" and user_preferences.get("email_notifications", True):
                    await self._send_email_notification(notification)
                elif channel == "slack" and user_preferences.get("slack_notifications", False):
                    await self._send_slack_notification(notification)
                elif channel == "sms" and user_preferences.get("sms_notifications", False):
                    await self._send_sms_notification(notification)
            
            # Store notification in database
            await self._store_notification(notification)
            
            logger.info("Notification sent successfully", 
                       type=notification.get("type"),
                       recipient=recipient_id,
                       channels=channels)
                       
        except Exception as e:
            logger.error("Failed to send notification", 
                        error=str(e),
                        notification=notification)
    
    async def _send_in_app_notification(self, notification: Dict[str, Any]):
        """Send in-app notification to connected users"""
        recipient_id = notification.get("recipient_id")
        message = notification.get("message", "")
        notification_type = notification.get("notification_type", "info")
        priority = notification.get("priority", "medium")
        
        # Send to WebSocket connections if available
        for connection in self.active_connections:
            if connection.get("user_id") == recipient_id:
                try:
                    await connection["websocket"].send_json({
                        "type": "notification",
                        "message": message,
                        "notification_type": notification_type,
                        "priority": priority,
                        "timestamp": datetime.utcnow().isoformat(),
                        "id": notification.get("id"),
                        "action_url": notification.get("action_url"),
                        "metadata": notification.get("metadata", {})
                    })
                except Exception as e:
                    logger.error("Failed to send WebSocket notification", error=str(e))
                    # Remove dead connection
                    self.active_connections.remove(connection)
    
    async def _send_email_notification(self, notification: Dict[str, Any]):
        """Send email notification"""
        if not settings.SMTP_HOST:
            logger.warning("SMTP not configured, skipping email notification")
            return
        
        # Enhanced email notification logic
        try:
            subject = notification.get("subject", "CyberShield Notification")
            message = notification.get("message", "")
            recipient_email = notification.get("email")
            priority = notification.get("priority", "medium")
            
            # Add priority to subject for high/critical notifications
            if priority in ["high", "critical"]:
                subject = f"[{priority.upper()}] {subject}"
            
            # Placeholder for actual email sending
            logger.info("Email notification sent", 
                       to=recipient_email,
                       subject=subject,
                       priority=priority)
            
        except Exception as e:
            logger.error("Failed to send email notification", error=str(e))
    
    async def _send_slack_notification(self, notification: Dict[str, Any]):
        """Send Slack notification"""
        if not settings.SLACK_WEBHOOK_URL:
            logger.warning("Slack not configured, skipping Slack notification")
            return
        
        try:
            message = notification.get("message", "")
            channel = notification.get("channel", "#security-alerts")
            priority = notification.get("priority", "medium")
            
            # Format Slack message based on priority
            if priority == "critical":
                message = f"🚨 *CRITICAL*: {message}"
            elif priority == "high":
                message = f"⚠️ *HIGH*: {message}"
            elif priority == "medium":
                message = f"ℹ️ *MEDIUM*: {message}"
            else:
                message = f"📝 *LOW*: {message}"
            
            # Placeholder for actual Slack sending
            logger.info("Slack notification sent", 
                       channel=channel,
                       message=message,
                       priority=priority)
            
        except Exception as e:
            logger.error("Failed to send Slack notification", error=str(e))
    
    async def _send_sms_notification(self, notification: Dict[str, Any]):
        """Send SMS notification"""
        try:
            message = notification.get("message", "")
            phone_number = notification.get("phone_number")
            priority = notification.get("priority", "medium")
            
            # Only send SMS for high/critical notifications
            if priority in ["high", "critical"]:
                # Placeholder for actual SMS sending
                logger.info("SMS notification sent", 
                           to=phone_number,
                           message=message,
                           priority=priority)
            else:
                logger.info("SMS notification skipped - not high priority", priority=priority)
                
        except Exception as e:
            logger.error("Failed to send SMS notification", error=str(e))
    
    async def _store_notification(self, notification: Dict[str, Any]):
        """Store notification in database for history"""
        try:
            # This would store the notification in a database table
            # For now, we'll just log it
            logger.info("Notification stored", 
                       recipient_id=notification.get("recipient_id"),
                       type=notification.get("notification_type"),
                       timestamp=datetime.utcnow().isoformat())
        except Exception as e:
            logger.error("Failed to store notification", error=str(e))

    async def get_user_notification_preferences(self, user_id: int) -> Dict[str, Any]:
        """Get user's notification preferences"""
        try:
            # In a real implementation, this would query the database
            # For now, return default preferences
            return {
                "in_app_notifications": True,
                "email_notifications": True,
                "slack_notifications": False,
                "sms_notifications": False,
                "incident_enabled": True,
                "security_alert_enabled": True,
                "training_reminder_enabled": True,
                "system_update_enabled": False,
                "compliance_alert_enabled": True,
                "phishing_alert_enabled": True,
                "cloud_security_enabled": True,
                "user_activity_enabled": False,
                "quiet_hours_start": "22:00",
                "quiet_hours_end": "08:00",
                "timezone": "UTC"
            }
        except Exception as e:
            logger.error("Failed to get user notification preferences", error=str(e))
            return {}
    
    async def update_user_notification_preferences(self, user_id: int, preferences: Dict[str, Any]):
        """Update user's notification preferences"""
        try:
            # In a real implementation, this would update the database
            logger.info("User notification preferences updated", 
                       user_id=user_id,
                       preferences=preferences)
        except Exception as e:
            logger.error("Failed to update user notification preferences", error=str(e))

    async def add_connection(self, user_id: int, websocket):
        """Add a WebSocket connection for a user"""
        connection = {
            "user_id": user_id,
            "websocket": websocket,
            "connected_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        self.active_connections.append(connection)
        logger.info("WebSocket connection added", user_id=user_id)

    async def remove_connection(self, user_id: int):
        """Remove a WebSocket connection for a user"""
        self.active_connections = [
            conn for conn in self.active_connections 
            if conn.get("user_id") != user_id
        ]
        logger.info("WebSocket connection removed", user_id=user_id)

    async def send_incident_notification(
        self, 
        incident: Incident, 
        notification_type: str = "incident_created",
        db: AsyncSession = None
    ):
        """Send incident-related notifications"""
        try:
            # Determine priority based on incident severity
            priority = "medium"
            if incident.severity == "critical":
                priority = "critical"
            elif incident.severity == "high":
                priority = "high"
            elif incident.severity == "low":
                priority = "low"
            
            # Create notification for incident reporter
            notification = {
                "recipient_id": incident.reported_by,
                "type": "in_app",
                "notification_type": "incident",
                "priority": priority,
                "message": f"Incident {incident.id} status updated: {incident.status}",
                "subject": f"Incident Update - {incident.title}",
                "action_url": f"/incidents/{incident.id}",
                "metadata": {
                    "incident_id": incident.id,
                    "incident_title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status
                },
                "channels": ["in_app", "email"]
            }
            
            await self.queue_notification(notification)
            
            # Send to admins for critical incidents
            if incident.severity in ["critical", "high"]:
                await self.notify_admins_critical_incident(incident, db)
                
        except Exception as e:
            logger.error("Failed to send incident notification", error=str(e))

    async def notify_admins_critical_incident(self, incident: Incident, db: AsyncSession):
        """Notify administrators of critical incidents"""
        try:
            # In a real implementation, this would query for admin users
            admin_user_ids = [1, 2, 3]  # Placeholder admin IDs
            
            for admin_id in admin_user_ids:
                notification = {
                    "recipient_id": admin_id,
                    "type": "in_app",
                    "notification_type": "security_alert",
                    "priority": "critical",
                    "message": f"Critical incident {incident.id} requires immediate attention",
                    "subject": f"Critical Incident Alert - {incident.title}",
                    "action_url": f"/incidents/{incident.id}",
                    "metadata": {
                        "incident_id": incident.id,
                        "incident_title": incident.title,
                        "severity": incident.severity,
                        "reported_by": incident.reported_by
                    },
                    "channels": ["in_app", "email", "slack"]
                }
                
                await self.queue_notification(notification)
                
        except Exception as e:
            logger.error("Failed to notify admins of critical incident", error=str(e))

    async def send_security_alert(
        self, 
        alert_type: str, 
        message: str, 
        severity: str = "medium",
        user_id: Optional[int] = None,
        broadcast: bool = False
    ):
        """Send security alerts"""
        try:
            priority = severity
            
            if user_id and not broadcast:
                # Send to specific user
                notification = {
                    "recipient_id": user_id,
                    "type": "in_app",
                    "notification_type": "security_alert",
                    "priority": priority,
                    "message": message,
                    "subject": f"Security Alert - {alert_type}",
                    "metadata": {
                        "alert_type": alert_type,
                        "severity": severity
                    },
                    "channels": ["in_app", "email"]
                }
                await self.queue_notification(notification)
            elif broadcast:
                # Broadcast to all users (in a real implementation, this would query all users)
                user_ids = [1, 2, 3, 4, 5]  # Placeholder user IDs
                
                for uid in user_ids:
                    notification = {
                        "recipient_id": uid,
                        "type": "in_app",
                        "notification_type": "security_alert",
                        "priority": priority,
                        "message": message,
                        "subject": f"Security Alert - {alert_type}",
                        "metadata": {
                            "alert_type": alert_type,
                            "severity": severity
                        },
                        "channels": ["in_app", "email"]
                    }
                    await self.queue_notification(notification)
                    
        except Exception as e:
            logger.error("Failed to send security alert", error=str(e))

    async def send_training_reminder(self, user_id: int, module_name: str):
        """Send training reminder notifications"""
        try:
            notification = {
                "recipient_id": user_id,
                "type": "in_app",
                "notification_type": "training_reminder",
                "priority": "low",
                "message": f"Reminder: Complete your {module_name} security training",
                "subject": f"Training Reminder - {module_name}",
                "action_url": f"/training/{module_name}",
                "metadata": {
                    "module_name": module_name,
                    "reminder_type": "training"
                },
                "channels": ["in_app", "email"]
            }
            
            await self.queue_notification(notification)
            
        except Exception as e:
            logger.error("Failed to send training reminder", error=str(e))

    async def send_system_alert(self, message: str, severity: str = "info"):
        """Send system-wide alerts"""
        try:
            priority = severity
            
            # In a real implementation, this would query all users
            user_ids = [1, 2, 3, 4, 5]  # Placeholder user IDs
            
            for user_id in user_ids:
                notification = {
                    "recipient_id": user_id,
                    "type": "in_app",
                    "notification_type": "system_update",
                    "priority": priority,
                    "message": message,
                    "subject": "System Update",
                    "metadata": {
                        "system_alert": True,
                        "severity": severity
                    },
                    "channels": ["in_app"]
                }
                
                await self.queue_notification(notification)
                
        except Exception as e:
            logger.error("Failed to send system alert", error=str(e))

    async def queue_notification(self, notification: Dict[str, Any]):
        """Queue a notification for processing"""
        try:
            # Add timestamp if not present
            if "timestamp" not in notification:
                notification["timestamp"] = datetime.utcnow().isoformat()
            
            # Add unique ID if not present
            if "id" not in notification:
                notification["id"] = f"notif_{datetime.utcnow().timestamp()}"
            
            await self.notification_queue.put(notification)
            logger.info("Notification queued", 
                       recipient_id=notification.get("recipient_id"),
                       type=notification.get("notification_type"))
                       
        except Exception as e:
            logger.error("Failed to queue notification", error=str(e))

    async def get_user_notifications(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's recent notifications"""
        try:
            # In a real implementation, this would query the database
            # For now, return mock notifications
            return [
                {
                    "id": 1,
                    "type": "incident",
                    "message": "Incident #123 has been resolved",
                    "timestamp": datetime.utcnow().isoformat(),
                    "read": False,
                    "priority": "medium"
                },
                {
                    "id": 2,
                    "type": "training_reminder",
                    "message": "Complete your phishing awareness training",
                    "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                    "read": True,
                    "priority": "low"
                }
            ]
        except Exception as e:
            logger.error("Failed to get user notifications", error=str(e))
            return []

    async def mark_notification_read(self, notification_id: int, user_id: int):
        """Mark a notification as read"""
        try:
            # In a real implementation, this would update the database
            logger.info("Notification marked as read", 
                       notification_id=notification_id,
                       user_id=user_id)
        except Exception as e:
            logger.error("Failed to mark notification as read", error=str(e))

    async def _cleanup_old_notifications(self):
        """Clean up old notifications periodically"""
        while True:
            try:
                # In a real implementation, this would delete old notifications from database
                logger.info("Cleaning up old notifications")
                await asyncio.sleep(3600)  # Run every hour
            except Exception as e:
                logger.error("Failed to cleanup old notifications", error=str(e))
                await asyncio.sleep(3600)

# Global instance
notification_service = NotificationService() 