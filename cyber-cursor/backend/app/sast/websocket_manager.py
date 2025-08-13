#!/usr/bin/env python3
"""
WebSocket Manager for Real-time SAST Notifications
Handles live updates and real-time communication with frontend
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """Types of WebSocket messages"""
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SCAN_PROGRESS = "scan_progress"
    ANALYSIS_COMPLETE = "analysis_complete"
    REAL_TIME_UPDATE = "real_time_update"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"

class SubscriptionType(Enum):
    """Types of subscriptions"""
    PROJECT = "project"
    SCAN = "scan"
    VULNERABILITIES = "vulnerabilities"
    REAL_TIME = "real_time"
    ALL = "all"

@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    id: str
    type: MessageType
    timestamp: datetime
    data: Dict[str, Any]
    project_id: Optional[str] = None
    scan_id: Optional[str] = None
    user_id: Optional[str] = None

class ConnectionManager:
    """Manages WebSocket connections and subscriptions"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}
        self.subscriptions: Dict[str, Set[str]] = {}  # subscription_type -> set of connection_ids
        self.project_subscriptions: Dict[str, Set[str]] = {}  # project_id -> set of connection_ids
        self.scan_subscriptions: Dict[str, Set[str]] = {}  # scan_id -> set of connection_ids
        
        # Message handlers
        self.message_handlers: Dict[MessageType, List[Callable]] = {
            MessageType.SUBSCRIBE: [self._handle_subscribe],
            MessageType.UNSUBSCRIBE: [self._handle_unsubscribe],
            MessageType.HEARTBEAT: [self._handle_heartbeat]
        }
    
    async def connect(self, websocket: WebSocket, connection_id: str, user_id: Optional[str] = None):
        """Connect a new WebSocket client"""
        try:
            await websocket.accept()
            self.active_connections[connection_id] = websocket
            self.connection_metadata[connection_id] = {
                'user_id': user_id,
                'connected_at': datetime.now(),
                'last_heartbeat': datetime.now(),
                'subscriptions': set()
            }
            
            logger.info(f"WebSocket connected: {connection_id} (user: {user_id})")
            
            # Send welcome message
            welcome_msg = WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.HEARTBEAT,
                timestamp=datetime.now(),
                data={'message': 'Connected to SAST Real-time Monitor', 'connection_id': connection_id}
            )
            await self.send_personal_message(connection_id, welcome_msg)
            
        except Exception as e:
            logger.error(f"Error connecting WebSocket {connection_id}: {e}")
            raise
    
    def disconnect(self, connection_id: str):
        """Disconnect a WebSocket client"""
        try:
            # Remove from all subscriptions
            if connection_id in self.connection_metadata:
                subscriptions = self.connection_metadata[connection_id].get('subscriptions', set())
                for sub_type in subscriptions:
                    if sub_type in self.subscriptions:
                        self.subscriptions[sub_type].discard(connection_id)
                
                # Remove from project subscriptions
                for project_id in list(self.project_subscriptions.keys()):
                    self.project_subscriptions[project_id].discard(connection_id)
                    if not self.project_subscriptions[project_id]:
                        del self.project_subscriptions[project_id]
                
                # Remove from scan subscriptions
                for scan_id in list(self.scan_subscriptions.keys()):
                    self.scan_subscriptions[scan_id].discard(connection_id)
                    if not self.scan_subscriptions[scan_id]:
                        del self.scan_subscriptions[scan_id]
                
                # Clean up metadata
                del self.connection_metadata[connection_id]
            
            # Remove connection
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
            
            logger.info(f"WebSocket disconnected: {connection_id}")
            
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket {connection_id}: {e}")
    
    async def send_personal_message(self, connection_id: str, message: WebSocketMessage):
        """Send a message to a specific connection"""
        try:
            if connection_id in self.active_connections:
                websocket = self.active_connections[connection_id]
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(json.dumps(asdict(message), default=str))
                else:
                    # Connection is closed, clean it up
                    self.disconnect(connection_id)
        except Exception as e:
            logger.error(f"Error sending personal message to {connection_id}: {e}")
            self.disconnect(connection_id)
    
    async def broadcast(self, message: WebSocketMessage):
        """Broadcast a message to all connected clients"""
        disconnected = []
        
        for connection_id in list(self.active_connections.keys()):
            try:
                await self.send_personal_message(connection_id, message)
            except Exception as e:
                logger.error(f"Error broadcasting to {connection_id}: {e}")
                disconnected.append(connection_id)
        
        # Clean up disconnected connections
        for connection_id in disconnected:
            self.disconnect(connection_id)
    
    async def broadcast_to_subscribers(self, message: WebSocketMessage, subscription_type: SubscriptionType):
        """Broadcast a message to subscribers of a specific type"""
        if subscription_type.value not in self.subscriptions:
            return
        
        subscribers = self.subscriptions[subscription_type.value].copy()
        for connection_id in subscribers:
            try:
                await self.send_personal_message(connection_id, message)
            except Exception as e:
                logger.error(f"Error broadcasting to subscriber {connection_id}: {e}")
                self.disconnect(connection_id)
    
    async def broadcast_to_project(self, message: WebSocketMessage, project_id: str):
        """Broadcast a message to subscribers of a specific project"""
        if project_id not in self.project_subscriptions:
            return
        
        subscribers = self.project_subscriptions[project_id].copy()
        for connection_id in subscribers:
            try:
                await self.send_personal_message(connection_id, message)
            except Exception as e:
                logger.error(f"Error broadcasting to project subscriber {connection_id}: {e}")
                self.disconnect(connection_id)
    
    async def broadcast_to_scan(self, message: WebSocketMessage, scan_id: str):
        """Broadcast a message to subscribers of a specific scan"""
        if scan_id not in self.scan_subscriptions:
            return
        
        subscribers = self.scan_subscriptions[scan_id].copy()
        for connection_id in subscribers:
            try:
                await self.send_personal_message(connection_id, message)
            except Exception as e:
                logger.error(f"Error broadcasting to scan subscriber {connection_id}: {e}")
                self.disconnect(connection_id)
    
    async def handle_message(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle incoming WebSocket messages"""
        try:
            message_type = MessageType(message_data.get('type'))
            
            if message_type in self.message_handlers:
                for handler in self.message_handlers[message_type]:
                    await handler(connection_id, message_data)
            else:
                logger.warning(f"Unknown message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error handling message from {connection_id}: {e}")
            # Send error response
            error_msg = WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.ERROR,
                timestamp=datetime.now(),
                data={'error': 'Invalid message format', 'details': str(e)}
            )
            await self.send_personal_message(connection_id, error_msg)
    
    async def _handle_subscribe(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle subscription requests"""
        try:
            subscription_type = message_data.get('subscription_type')
            project_id = message_data.get('project_id')
            scan_id = message_data.get('scan_id')
            
            if subscription_type:
                # General subscription
                if subscription_type not in self.subscriptions:
                    self.subscriptions[subscription_type] = set()
                self.subscriptions[subscription_type].add(connection_id)
                
                # Update connection metadata
                if connection_id in self.connection_metadata:
                    self.connection_metadata[connection_id]['subscriptions'].add(subscription_type)
            
            if project_id:
                # Project-specific subscription
                if project_id not in self.project_subscriptions:
                    self.project_subscriptions[project_id] = set()
                self.project_subscriptions[project_id].add(connection_id)
            
            if scan_id:
                # Scan-specific subscription
                if scan_id not in self.scan_subscriptions:
                    self.scan_subscriptions[scan_id] = set()
                self.scan_subscriptions[scan_id].add(connection_id)
            
            # Send confirmation
            confirm_msg = WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.HEARTBEAT,
                timestamp=datetime.now(),
                data={'message': 'Subscription successful', 'subscription_type': subscription_type}
            )
            await self.send_personal_message(connection_id, confirm_msg)
            
            logger.info(f"Connection {connection_id} subscribed to {subscription_type}")
            
        except Exception as e:
            logger.error(f"Error handling subscription for {connection_id}: {e}")
    
    async def _handle_unsubscribe(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle unsubscription requests"""
        try:
            subscription_type = message_data.get('subscription_type')
            project_id = message_data.get('project_id')
            scan_id = message_data.get('scan_id')
            
            if subscription_type and subscription_type in self.subscriptions:
                self.subscriptions[subscription_type].discard(connection_id)
                
                # Update connection metadata
                if connection_id in self.connection_metadata:
                    self.connection_metadata[connection_id]['subscriptions'].discard(subscription_type)
            
            if project_id and project_id in self.project_subscriptions:
                self.project_subscriptions[project_id].discard(connection_id)
            
            if scan_id and scan_id in self.scan_subscriptions:
                self.scan_subscriptions[scan_id].discard(connection_id)
            
            # Send confirmation
            confirm_msg = WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.HEARTBEAT,
                timestamp=datetime.now(),
                data={'message': 'Unsubscription successful'}
            )
            await self.send_personal_message(connection_id, confirm_msg)
            
            logger.info(f"Connection {connection_id} unsubscribed from {subscription_type}")
            
        except Exception as e:
            logger.error(f"Error handling unsubscription for {connection_id}: {e}")
    
    async def _handle_heartbeat(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle heartbeat messages"""
        try:
            if connection_id in self.connection_metadata:
                self.connection_metadata[connection_id]['last_heartbeat'] = datetime.now()
            
            # Send heartbeat response
            heartbeat_msg = WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.HEARTBEAT,
                timestamp=datetime.now(),
                data={'message': 'pong'}
            )
            await self.send_personal_message(connection_id, heartbeat_msg)
            
        except Exception as e:
            logger.error(f"Error handling heartbeat for {connection_id}: {e}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            'total_connections': len(self.active_connections),
            'subscription_counts': {
                sub_type: len(connections) 
                for sub_type, connections in self.subscriptions.items()
            },
            'project_subscriptions': len(self.project_subscriptions),
            'scan_subscriptions': len(self.scan_subscriptions),
            'connections_by_user': {}
        }
    
    async def cleanup_inactive_connections(self):
        """Clean up inactive connections"""
        current_time = datetime.now()
        inactive_connections = []
        
        for connection_id, metadata in self.connection_metadata.items():
            last_heartbeat = metadata.get('last_heartbeat')
            if last_heartbeat and (current_time - last_heartbeat).total_seconds() > 300:  # 5 minutes
                inactive_connections.append(connection_id)
        
        for connection_id in inactive_connections:
            logger.info(f"Cleaning up inactive connection: {connection_id}")
            self.disconnect(connection_id)

class WebSocketManager:
    """Main WebSocket manager for SAST real-time features"""
    
    def __init__(self):
        self.connection_manager = ConnectionManager()
        self.cleanup_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start the WebSocket manager"""
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("WebSocket manager started")
    
    async def stop(self):
        """Stop the WebSocket manager"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        for connection_id in list(self.connection_manager.active_connections.keys()):
            self.connection_manager.disconnect(connection_id)
        
        logger.info("WebSocket manager stopped")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of inactive connections"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute
                await self.connection_manager.cleanup_inactive_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def connect_client(self, websocket: WebSocket, connection_id: str, user_id: Optional[str] = None):
        """Connect a new client"""
        await self.connection_manager.connect(websocket, connection_id, user_id)
    
    def disconnect_client(self, connection_id: str):
        """Disconnect a client"""
        self.connection_manager.disconnect(connection_id)
    
    async def handle_client_message(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle a message from a client"""
        await self.connection_manager.handle_message(connection_id, message_data)
    
    async def notify_vulnerability_detected(self, vulnerability_data: Dict[str, Any], project_id: Optional[str] = None):
        """Notify clients about a detected vulnerability"""
        message = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=MessageType.VULNERABILITY_DETECTED,
            timestamp=datetime.now(),
            data=vulnerability_data,
            project_id=project_id
        )
        
        # Broadcast to all vulnerability subscribers
        await self.connection_manager.broadcast_to_subscribers(message, SubscriptionType.VULNERABILITIES)
        
        # Broadcast to project-specific subscribers
        if project_id:
            await self.connection_manager.broadcast_to_project(message, project_id)
    
    async def notify_scan_progress(self, scan_data: Dict[str, Any], scan_id: str):
        """Notify clients about scan progress"""
        message = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=MessageType.SCAN_PROGRESS,
            timestamp=datetime.now(),
            data=scan_data,
            scan_id=scan_id
        )
        
        # Broadcast to scan subscribers
        await self.connection_manager.broadcast_to_scan(message, scan_id)
        
        # Broadcast to general subscribers
        await self.connection_manager.broadcast_to_subscribers(message, SubscriptionType.SCAN)
    
    async def notify_analysis_complete(self, analysis_data: Dict[str, Any], project_id: Optional[str] = None):
        """Notify clients about completed analysis"""
        message = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=MessageType.ANALYSIS_COMPLETE,
            timestamp=datetime.now(),
            data=analysis_data,
            project_id=project_id
        )
        
        # Broadcast to all subscribers
        await self.connection_manager.broadcast_to_subscribers(message, SubscriptionType.ALL)
        
        # Broadcast to project-specific subscribers
        if project_id:
            await self.connection_manager.broadcast_to_project(message, project_id)
    
    async def notify_real_time_update(self, update_data: Dict[str, Any], project_id: Optional[str] = None):
        """Notify clients about real-time updates"""
        message = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=MessageType.REAL_TIME_UPDATE,
            timestamp=datetime.now(),
            data=update_data,
            project_id=project_id
        )
        
        # Broadcast to real-time subscribers
        await self.connection_manager.broadcast_to_subscribers(message, SubscriptionType.REAL_TIME)
        
        # Broadcast to project-specific subscribers
        if project_id:
            await self.connection_manager.broadcast_to_project(message, project_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics"""
        return {
            'connection_manager': self.connection_manager.get_connection_stats(),
            'manager_status': 'running' if self.cleanup_task and not self.cleanup_task.done() else 'stopped'
        }

# Global WebSocket manager instance
_websocket_manager: Optional[WebSocketManager] = None

async def get_websocket_manager() -> WebSocketManager:
    """Get the global WebSocket manager instance"""
    global _websocket_manager
    if _websocket_manager is None:
        _websocket_manager = WebSocketManager()
        await _websocket_manager.start()
    return _websocket_manager

async def stop_websocket_manager():
    """Stop the global WebSocket manager"""
    global _websocket_manager
    if _websocket_manager:
        await _websocket_manager.stop()
        _websocket_manager = None
