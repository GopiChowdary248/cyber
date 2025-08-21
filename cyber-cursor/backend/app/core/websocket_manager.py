import asyncio
import json
import logging
from typing import Dict, List, Set, Optional, Any
from datetime import datetime
from uuid import UUID
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}  # project_id -> {user_id: websocket}
        self.user_projects: Dict[str, Set[str]] = {}  # user_id -> set of project_ids
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}  # connection_id -> metadata
        
    async def connect(self, websocket: WebSocket, project_id: str, user_id: str):
        """Connect a user to a project's WebSocket"""
        try:
            await websocket.accept()
            
            # Store connection
            if project_id not in self.active_connections:
                self.active_connections[project_id] = {}
            
            self.active_connections[project_id][user_id] = websocket
            
            # Track user's projects
            if user_id not in self.user_projects:
                self.user_projects[user_id] = set()
            self.user_projects[user_id].add(project_id)
            
            # Store connection metadata
            connection_id = f"{project_id}_{user_id}"
            self.connection_metadata[connection_id] = {
                "project_id": project_id,
                "user_id": user_id,
                "connected_at": datetime.utcnow(),
                "last_activity": datetime.utcnow()
            }
            
            logger.info(f"User {user_id} connected to project {project_id}")
            
            # Send connection confirmation
            await self.send_personal_message(
                websocket,
                {
                    "type": "connection_established",
                    "project_id": project_id,
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f"Error connecting WebSocket: {e}")
            raise
    
    def disconnect(self, websocket: WebSocket, project_id: str, user_id: str):
        """Disconnect a user from a project's WebSocket"""
        try:
            # Remove from active connections
            if project_id in self.active_connections:
                if user_id in self.active_connections[project_id]:
                    del self.active_connections[project_id][user_id]
                
                # Clean up empty project connections
                if not self.active_connections[project_id]:
                    del self.active_connections[project_id]
            
            # Remove from user projects
            if user_id in self.user_projects:
                self.user_projects[user_id].discard(project_id)
                if not self.user_projects[user_id]:
                    del self.user_projects[user_id]
            
            # Clean up connection metadata
            connection_id = f"{project_id}_{user_id}"
            if connection_id in self.connection_metadata:
                del self.connection_metadata[connection_id]
            
            logger.info(f"User {user_id} disconnected from project {project_id}")
            
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket: {e}")
    
    async def send_personal_message(self, websocket: WebSocket, message: Dict[str, Any]):
        """Send a message to a specific WebSocket connection"""
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
    
    async def broadcast_to_project(self, project_id: str, message: Dict[str, Any], exclude_user: Optional[str] = None):
        """Broadcast a message to all users in a project"""
        if project_id not in self.active_connections:
            return
        
        disconnected_users = []
        
        for user_id, websocket in self.active_connections[project_id].items():
            if user_id == exclude_user:
                continue
                
            try:
                await self.send_personal_message(websocket, message)
            except Exception as e:
                logger.error(f"Error broadcasting to user {user_id}: {e}")
                disconnected_users.append(user_id)
        
        # Clean up disconnected users
        for user_id in disconnected_users:
            self.disconnect(self.active_connections[project_id][user_id], project_id, user_id)
    
    async def broadcast_to_user(self, user_id: str, message: Dict[str, Any]):
        """Broadcast a message to a specific user across all their projects"""
        if user_id not in self.user_projects:
            return
        
        for project_id in self.user_projects[user_id]:
            if project_id in self.active_connections and user_id in self.active_connections[project_id]:
                try:
                    await self.send_personal_message(
                        self.active_connections[project_id][user_id], 
                        message
                    )
                except Exception as e:
                    logger.error(f"Error broadcasting to user {user_id} in project {project_id}: {e}")
    
    async def send_scan_update(self, project_id: str, scan_data: Dict[str, Any]):
        """Send scan update to all users in a project"""
        message = {
            "type": "scan_update",
            "data": scan_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(project_id, message)
    
    async def send_traffic_update(self, project_id: str, traffic_data: Dict[str, Any]):
        """Send traffic update to all users in a project"""
        message = {
            "type": "traffic_update",
            "data": traffic_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(project_id, message)
    
    async def send_issue_update(self, project_id: str, issue_data: Dict[str, Any]):
        """Send issue update to all users in a project"""
        message = {
            "type": "issue_update",
            "data": issue_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(project_id, message)
    
    async def send_crawler_update(self, project_id: str, crawler_data: Dict[str, Any]):
        """Send crawler update to all users in a project"""
        message = {
            "type": "crawler_update",
            "data": crawler_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(project_id, message)
    
    async def send_intruder_update(self, project_id: str, intruder_data: Dict[str, Any]):
        """Send intruder update to all users in a project"""
        message = {
            "type": "intruder_update",
            "data": intruder_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(project_id, message)
    
    async def send_notification(self, project_id: str, user_id: str, notification_data: Dict[str, Any]):
        """Send notification to a specific user"""
        message = {
            "type": "notification",
            "data": notification_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_user(user_id, message)
    
    async def send_system_message(self, project_id: str, message_text: str, severity: str = "info"):
        """Send system message to all users in a project"""
        message = {
            "type": "system_message",
            "data": {
                "message": message_text,
                "severity": severity
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_project(project_id, message)
    
    def get_project_connections_count(self, project_id: str) -> int:
        """Get the number of active connections for a project"""
        if project_id in self.active_connections:
            return len(self.active_connections[project_id])
        return 0
    
    def get_user_connections_count(self, user_id: str) -> int:
        """Get the number of active connections for a user"""
        if user_id in self.user_projects:
            return len(self.user_projects[user_id])
        return 0
    
    def get_active_projects(self) -> List[str]:
        """Get list of projects with active connections"""
        return list(self.active_connections.keys())
    
    def get_active_users(self) -> List[str]:
        """Get list of users with active connections"""
        return list(self.user_projects.keys())
    
    async def cleanup_inactive_connections(self):
        """Clean up inactive connections"""
        current_time = datetime.utcnow()
        inactive_connections = []
        
        for connection_id, metadata in self.connection_metadata.items():
            # Check if connection has been inactive for more than 5 minutes
            if (current_time - metadata["last_activity"]).total_seconds() > 300:
                inactive_connections.append(connection_id)
        
        for connection_id in inactive_connections:
            metadata = self.connection_metadata[connection_id]
            project_id = metadata["project_id"]
            user_id = metadata["user_id"]
            
            if project_id in self.active_connections and user_id in self.active_connections[project_id]:
                websocket = self.active_connections[project_id][user_id]
                try:
                    await websocket.close(code=1000, reason="Inactive connection")
                except Exception as e:
                    logger.error(f"Error closing inactive connection: {e}")
                
                self.disconnect(websocket, project_id, user_id)
    
    async def get_updates(self, project_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get updates for a specific user in a project"""
        # This method can be used to implement custom update logic
        # For now, return None to indicate no updates
        return None
    
    async def start_cleanup_task(self):
        """Start the cleanup task for inactive connections"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute
                await self.cleanup_inactive_connections()
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        total_connections = sum(len(connections) for connections in self.active_connections.values())
        total_projects = len(self.active_connections)
        total_users = len(self.user_projects)
        
        return {
            "total_connections": total_connections,
            "total_projects": total_projects,
            "total_users": total_users,
            "active_projects": self.get_active_projects(),
            "active_users": self.get_active_users()
        }

# Global WebSocket manager instance
websocket_manager = WebSocketManager()
