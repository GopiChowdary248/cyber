"""
Network Security Service
Implements comprehensive network security technologies including:
- Firewall management
- IDS/IPS monitoring
- VPN management
- Network Access Control (NAC)
- DNS security
- DDoS protection
- Port security
- Network segmentation
"""

import asyncio
import structlog
import ipaddress
import subprocess
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
import socket
import threading
import queue

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, and_, or_
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import structlog

# Import SQLAlchemy models (not Pydantic schemas)
from app.models.network_security import (
    NetworkDevice, FirewallLog, IDSAlert as IDSAlertModel, VPNSession, NACLog
)
from app.schemas.network_security import (
    NetworkDeviceCreate, NetworkDeviceUpdate,
    FirewallLogCreate, IDSAlertCreate, VPNSessionCreate, NACLogCreate
)

logger = structlog.get_logger()

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"

class NetworkSegment(Enum):
    DMZ = "dmz"
    INTERNAL = "internal"
    GUEST = "guest"
    FINANCE = "finance"
    DEVELOPMENT = "development"
    ADMIN = "admin"
    IoT = "iot"

@dataclass
class FirewallRule:
    id: str
    name: str
    action: str  # allow, deny, drop
    protocol: str  # tcp, udp, icmp, any
    source_ip: str
    source_port: Optional[str]
    destination_ip: str
    destination_port: Optional[str]
    direction: str  # inbound, outbound, both
    priority: int
    enabled: bool
    description: str
    created_at: datetime
    updated_at: datetime

@dataclass
class IDSAlert:
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    threat_type: ThreatType
    severity: SecurityLevel
    description: str
    signature_id: str
    packet_data: Optional[str]
    action_taken: str
    status: str  # new, investigating, resolved, false_positive

@dataclass
class VPNConnection:
    id: str
    user_id: str
    username: str
    ip_address: str
    connected_at: datetime
    last_activity: datetime
    bytes_sent: int
    bytes_received: int
    status: str  # connected, disconnected, idle
    client_info: Dict[str, Any]

@dataclass
class NACPolicy:
    id: str
    name: str
    description: str
    device_requirements: Dict[str, Any]
    network_access: List[str]
    time_restrictions: Dict[str, Any]
    enabled: bool
    priority: int

class NetworkSecurityService:
    """Service class for Network Security operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    # Network Device Operations
    async def create_device(self, device_data: NetworkDeviceCreate) -> NetworkDevice:
        """Create a new network device"""
        try:
            device = await NetworkDevice.create_device(
                self.db,
                device_name=device_data.device_name,
                device_type=device_data.device_type,
                ip_address=device_data.ip_address,
                vendor=device_data.vendor,
                model=device_data.model,
                port=device_data.port,
                api_key=device_data.api_key,
                username=device_data.username,
                password_hash=device_data.password if device_data.password else None
            )
            logger.info("Network device created", device_id=device.id, device_name=device.device_name)
            return device
        except Exception as e:
            logger.error("Failed to create network device", error=str(e))
            raise
    
    async def get_device(self, device_id: int) -> Optional[NetworkDevice]:
        """Get device by ID"""
        return await NetworkDevice.get_by_id(self.db, device_id)
    
    async def get_devices_by_type(self, device_type: str) -> List[NetworkDevice]:
        """Get devices by type"""
        return await NetworkDevice.get_by_type(self.db, device_type)
    
    async def get_all_devices(self, skip: int = 0, limit: int = 100) -> List[NetworkDevice]:
        """Get all devices with pagination"""
        return await NetworkDevice.get_all(self.db, skip, limit)
    
    async def update_device_status(self, device_id: int, status: str) -> Optional[NetworkDevice]:
        """Update device status"""
        try:
            device = await self.get_device(device_id)
            if device:
                device.status = status
                device.last_seen = datetime.utcnow()
                await self.db.commit()
                await self.db.refresh(device)
                logger.info("Device status updated", device_id=device_id, status=status)
                return device
        except Exception as e:
            logger.error("Failed to update device status", error=str(e))
            raise
        return None
    
    # Firewall Operations
    async def create_firewall_log(self, log_data: FirewallLogCreate) -> FirewallLog:
        """Create a new firewall log entry"""
        try:
            log = FirewallLog(**log_data.dict())
            self.db.add(log)
            await self.db.commit()
            await self.db.refresh(log)
            logger.info("Firewall log created", log_id=log.id, device_id=log.device_id)
            return log
        except Exception as e:
            logger.error("Failed to create firewall log", error=str(e))
            raise
    
    async def get_firewall_logs(self, device_id: Optional[int] = None, hours: int = 24) -> List[FirewallLog]:
        """Get firewall logs"""
        if device_id:
            return await FirewallLog.get_by_device(self.db, device_id)
        else:
            return await FirewallLog.get_recent_logs(self.db, hours)
    
    async def get_firewall_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get firewall statistics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Total logs
            total_logs = await self.db.execute(
                select(func.count(FirewallLog.id)).where(FirewallLog.log_time >= cutoff_time)
            )
            total_logs = total_logs.scalar()
            
            # Action counts
            action_counts = await self.db.execute(
                select(FirewallLog.action, func.count(FirewallLog.id))
                .where(FirewallLog.log_time >= cutoff_time)
                .group_by(FirewallLog.action)
            )
            action_counts = action_counts.all()
            
            # Top source IPs
            top_source_ips = await self.db.execute(
                select(FirewallLog.source_ip, func.count(FirewallLog.id))
                .where(FirewallLog.log_time >= cutoff_time)
                .group_by(FirewallLog.source_ip)
                .order_by(func.count(FirewallLog.id).desc())
                .limit(10)
            )
            top_source_ips = top_source_ips.all()
            
            # Top destination IPs
            top_dest_ips = await self.db.execute(
                select(FirewallLog.dest_ip, func.count(FirewallLog.id))
                .where(FirewallLog.log_time >= cutoff_time)
                .group_by(FirewallLog.dest_ip)
                .order_by(func.count(FirewallLog.id).desc())
                .limit(10)
            )
            top_dest_ips = top_dest_ips.all()
            
            return {
                "total_logs": total_logs,
                "action_counts": {action: count for action, count in action_counts},
                "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_source_ips],
                "top_dest_ips": [{"ip": ip, "count": count} for ip, count in top_dest_ips]
            }
        except Exception as e:
            logger.error("Failed to get firewall stats", error=str(e))
            raise
    
    # IDS Operations
    async def create_ids_alert(self, alert_data: IDSAlertCreate) -> IDSAlertModel:
        """Create a new IDS alert"""
        try:
            alert = IDSAlertModel(**alert_data.dict())
            self.db.add(alert)
            await self.db.commit()
            await self.db.refresh(alert)
            logger.info("IDS alert created", alert_id=alert.id, severity=alert.severity)
            return alert
        except Exception as e:
            logger.error("Failed to create IDS alert", error=str(e))
            raise
    
    async def get_ids_alerts(self, severity: Optional[str] = None, hours: int = 24) -> List[IDSAlertModel]:
        """Get IDS alerts"""
        if severity:
            return await IDSAlertModel.get_by_severity(self.db, severity)
        else:
            return await IDSAlertModel.get_recent_alerts(self.db, hours)
    
    async def update_alert_status(self, alert_id: int, status: str) -> Optional[IDSAlertModel]:
        """Update alert status"""
        try:
            result = await self.db.execute(select(IDSAlertModel).where(IDSAlertModel.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.status = status
                await self.db.commit()
                await self.db.refresh(alert)
                logger.info("Alert status updated", alert_id=alert_id, status=status)
                return alert
        except Exception as e:
            logger.error("Failed to update alert status", error=str(e))
            raise
        return None
    
    async def get_ids_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get IDS statistics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Total alerts
            total_alerts = await self.db.execute(
                select(func.count(IDSAlertModel.id)).where(IDSAlertModel.alert_time >= cutoff_time)
            )
            total_alerts = total_alerts.scalar()
            
            # Severity counts
            severity_counts = await self.db.execute(
                select(IDSAlertModel.severity, func.count(IDSAlertModel.id))
                .where(IDSAlertModel.alert_time >= cutoff_time)
                .group_by(IDSAlertModel.severity)
            )
            severity_counts = severity_counts.all()
            
            # Top categories
            top_categories = await self.db.execute(
                select(IDSAlertModel.category, func.count(IDSAlertModel.id))
                .where(and_(IDSAlertModel.alert_time >= cutoff_time, IDSAlertModel.category.isnot(None)))
                .group_by(IDSAlertModel.category)
                .order_by(func.count(IDSAlertModel.id).desc())
                .limit(10)
            )
            top_categories = top_categories.all()
            
            return {
                "total_alerts": total_alerts,
                "severity_counts": {severity: count for severity, count in severity_counts},
                "top_categories": [{"category": cat, "count": count} for cat, count in top_categories]
            }
        except Exception as e:
            logger.error("Failed to get IDS stats", error=str(e))
            raise
    
    # VPN Operations
    async def create_vpn_session(self, session_data: VPNSessionCreate) -> VPNSession:
        """Create a new VPN session"""
        try:
            session = VPNSession(**session_data.dict())
            self.db.add(session)
            await self.db.commit()
            await self.db.refresh(session)
            logger.info("VPN session created", session_id=session.id, username=session.username)
            return session
        except Exception as e:
            logger.error("Failed to create VPN session", error=str(e))
            raise
    
    async def get_active_vpn_sessions(self) -> List[VPNSession]:
        """Get active VPN sessions"""
        return await VPNSession.get_active_sessions(self.db)
    
    async def end_vpn_session(self, session_id: int) -> Optional[VPNSession]:
        """End a VPN session"""
        try:
            result = await self.db.execute(select(VPNSession).where(VPNSession.id == session_id))
            session = result.scalar_one_or_none()
            if session and session.status == "active":
                session.connection_end = datetime.utcnow()
                session.status = "disconnected"
                if session.connection_start:
                    session.session_duration = int((session.connection_end - session.connection_start).total_seconds())
                await self.db.commit()
                await self.db.refresh(session)
                logger.info("VPN session ended", session_id=session_id)
                return session
        except Exception as e:
            logger.error("Failed to end VPN session", error=str(e))
            raise
        return None
    
    async def get_vpn_stats(self) -> Dict[str, Any]:
        """Get VPN statistics"""
        try:
            # Active sessions
            active_sessions = await self.db.execute(
                select(func.count(VPNSession.id)).where(VPNSession.status == "active")
            )
            active_sessions = active_sessions.scalar()
            
            # Total users
            total_users = await self.db.execute(
                select(func.count(func.distinct(VPNSession.username)))
            )
            total_users = total_users.scalar()
            
            # Top users
            top_users = await self.db.execute(
                select(VPNSession.username, func.count(VPNSession.id))
                .group_by(VPNSession.username)
                .order_by(func.count(VPNSession.id).desc())
                .limit(10)
            )
            top_users = top_users.all()
            
            return {
                "active_sessions": active_sessions,
                "total_users": total_users,
                "top_users": [{"username": user, "count": count} for user, count in top_users]
            }
        except Exception as e:
            logger.error("Failed to get VPN stats", error=str(e))
            raise
    
    # NAC Operations
    async def create_nac_log(self, log_data: NACLogCreate) -> NACLog:
        """Create a new NAC log entry"""
        try:
            log = NACLog(**log_data.dict())
            self.db.add(log)
            await self.db.commit()
            await self.db.refresh(log)
            logger.info("NAC log created", log_id=log.id, action=log.action)
            return log
        except Exception as e:
            logger.error("Failed to create NAC log", error=str(e))
            raise
    
    async def get_nac_logs(self, action: Optional[str] = None, hours: int = 24) -> List[NACLog]:
        """Get NAC logs"""
        if action:
            return await NACLog.get_by_action(self.db, action)
        else:
            return await NACLog.get_recent_logs(self.db, hours)
    
    async def get_nac_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get NAC statistics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Total events
            total_events = await self.db.execute(
                select(func.count(NACLog.id)).where(NACLog.event_time >= cutoff_time)
            )
            total_events = total_events.scalar()
            
            # Action counts
            action_counts = await self.db.execute(
                select(NACLog.action, func.count(NACLog.id))
                .where(NACLog.event_time >= cutoff_time)
                .group_by(NACLog.action)
            )
            action_counts = action_counts.all()
            
            # Top policies
            top_policies = await self.db.execute(
                select(NACLog.policy_name, func.count(NACLog.id))
                .where(and_(NACLog.event_time >= cutoff_time, NACLog.policy_name.isnot(None)))
                .group_by(NACLog.policy_name)
                .order_by(func.count(NACLog.id).desc())
                .limit(10)
            )
            top_policies = top_policies.all()
            
            return {
                "total_events": total_events,
                "action_counts": {action: count for action, count in action_counts},
                "top_policies": [{"policy": policy, "count": count} for policy, count in top_policies]
            }
        except Exception as e:
            logger.error("Failed to get NAC stats", error=str(e))
            raise
    
    # Dashboard Overview
    async def get_network_security_overview(self) -> Dict[str, Any]:
        """Get network security overview for dashboard"""
        try:
            # Device counts
            total_devices = await self.db.execute(select(func.count(NetworkDevice.id)))
            total_devices = total_devices.scalar()
            
            online_devices = await self.db.execute(
                select(func.count(NetworkDevice.id)).where(NetworkDevice.status == "online")
            )
            online_devices = online_devices.scalar()
            
            # 24-hour activity
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            firewall_logs_24h = await self.db.execute(
                select(func.count(FirewallLog.id)).where(FirewallLog.log_time >= cutoff_time)
            )
            firewall_logs_24h = firewall_logs_24h.scalar()
            
            ids_alerts_24h = await self.db.execute(
                select(func.count(IDSAlertModel.id)).where(IDSAlertModel.alert_time >= cutoff_time)
            )
            ids_alerts_24h = ids_alerts_24h.scalar()
            
            active_vpn_sessions = await self.db.execute(
                select(func.count(VPNSession.id)).where(VPNSession.status == "active")
            )
            active_vpn_sessions = active_vpn_sessions.scalar()
            
            nac_events_24h = await self.db.execute(
                select(func.count(NACLog.id)).where(NACLog.event_time >= cutoff_time)
            )
            nac_events_24h = nac_events_24h.scalar()
            
            # Alert severity counts
            severity_counts = await self.db.execute(
                select(IDSAlertModel.severity, func.count(IDSAlertModel.id))
                .where(IDSAlertModel.alert_time >= cutoff_time)
                .group_by(IDSAlertModel.severity)
            )
            severity_counts = severity_counts.all()
            
            return {
                "total_devices": total_devices,
                "online_devices": online_devices,
                "offline_devices": total_devices - online_devices,
                "firewall_logs_24h": firewall_logs_24h,
                "ids_alerts_24h": ids_alerts_24h,
                "active_vpn_sessions": active_vpn_sessions,
                "nac_events_24h": nac_events_24h,
                "critical_alerts": next((count for severity, count in severity_counts if severity == "critical"), 0),
                "high_alerts": next((count for severity, count in severity_counts if severity == "high"), 0),
                "medium_alerts": next((count for severity, count in severity_counts if severity == "medium"), 0),
                "low_alerts": next((count for severity, count in severity_counts if severity == "low"), 0)
            }
        except Exception as e:
            logger.error("Failed to get network security overview", error=str(e))
            raise 