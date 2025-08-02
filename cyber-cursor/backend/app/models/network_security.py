from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List

from app.core.database import Base

class NetworkDevice(Base):
    __tablename__ = "network_devices"
    
    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)  # firewall, ids, vpn, nac
    ip_address = Column(String(50), nullable=False)
    vendor = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    status = Column(String(20), default="offline")  # online, offline, maintenance
    last_seen = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Configuration
    api_key = Column(String(500), nullable=True)
    username = Column(String(100), nullable=True)
    password_hash = Column(String(255), nullable=True)
    port = Column(Integer, default=22)
    
    # Relationships
    firewall_logs = relationship("FirewallLog", back_populates="device")
    ids_alerts = relationship("IDSAlert", back_populates="device")
    vpn_sessions = relationship("VPNSession", back_populates="device")
    nac_logs = relationship("NACLog", back_populates="device")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, device_id: int) -> Optional["NetworkDevice"]:
        """Get device by ID"""
        result = await db.execute(select(cls).where(cls.id == device_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_type(cls, db: AsyncSession, device_type: str) -> List["NetworkDevice"]:
        """Get devices by type"""
        result = await db.execute(select(cls).where(cls.device_type == device_type))
        return result.scalars().all()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["NetworkDevice"]:
        """Get all devices with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    @classmethod
    async def create_device(cls, db: AsyncSession, **kwargs) -> "NetworkDevice":
        """Create a new network device"""
        device = cls(**kwargs)
        db.add(device)
        await db.commit()
        await db.refresh(device)
        return device

class FirewallLog(Base):
    __tablename__ = "firewall_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"), nullable=False)
    log_time = Column(DateTime, nullable=False)
    source_ip = Column(String(50), nullable=False)
    dest_ip = Column(String(50), nullable=False)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    action = Column(String(20), nullable=False)  # allow, deny, drop
    protocol = Column(String(20), nullable=True)  # tcp, udp, icmp
    application = Column(String(100), nullable=True)
    rule_name = Column(String(255), nullable=True)
    session_id = Column(String(100), nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    bytes_received = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    # Relationship
    device = relationship("NetworkDevice", back_populates="firewall_logs")
    
    @classmethod
    async def get_by_device(cls, db: AsyncSession, device_id: int, limit: int = 1000) -> List["FirewallLog"]:
        """Get firewall logs by device"""
        result = await db.execute(
            select(cls)
            .where(cls.device_id == device_id)
            .order_by(cls.log_time.desc())
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_recent_logs(cls, db: AsyncSession, hours: int = 24) -> List["FirewallLog"]:
        """Get recent firewall logs"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(cls)
            .where(cls.log_time >= cutoff_time)
            .order_by(cls.log_time.desc())
        )
        return result.scalars().all()

class IDSAlert(Base):
    __tablename__ = "ids_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"), nullable=False)
    alert_time = Column(DateTime, nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    alert_type = Column(String(100), nullable=False)  # signature, anomaly, policy
    description = Column(Text, nullable=False)
    source_ip = Column(String(50), nullable=True)
    dest_ip = Column(String(50), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    signature_id = Column(String(100), nullable=True)
    signature_name = Column(String(255), nullable=True)
    category = Column(String(100), nullable=True)  # malware, dos, reconnaissance
    status = Column(String(20), default="new")  # new, acknowledged, resolved
    created_at = Column(DateTime, default=func.now())
    
    # Relationship
    device = relationship("NetworkDevice", back_populates="ids_alerts")
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str, limit: int = 1000) -> List["IDSAlert"]:
        """Get alerts by severity"""
        result = await db.execute(
            select(cls)
            .where(cls.severity == severity)
            .order_by(cls.alert_time.desc())
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_recent_alerts(cls, db: AsyncSession, hours: int = 24) -> List["IDSAlert"]:
        """Get recent IDS alerts"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(cls)
            .where(cls.alert_time >= cutoff_time)
            .order_by(cls.alert_time.desc())
        )
        return result.scalars().all()

class VPNSession(Base):
    __tablename__ = "vpn_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"), nullable=False)
    username = Column(String(255), nullable=False)
    ip_address = Column(String(50), nullable=False)
    connection_start = Column(DateTime, nullable=False)
    connection_end = Column(DateTime, nullable=True)
    status = Column(String(20), default="active")  # active, disconnected, expired
    vpn_type = Column(String(50), nullable=True)  # ssl, ipsec, l2tp
    client_ip = Column(String(50), nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    bytes_received = Column(Integer, nullable=True)
    session_duration = Column(Integer, nullable=True)  # in seconds
    created_at = Column(DateTime, default=func.now())
    
    # Relationship
    device = relationship("NetworkDevice", back_populates="vpn_sessions")
    
    @classmethod
    async def get_active_sessions(cls, db: AsyncSession) -> List["VPNSession"]:
        """Get active VPN sessions"""
        result = await db.execute(
            select(cls)
            .where(cls.status == "active")
            .order_by(cls.connection_start.desc())
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_user(cls, db: AsyncSession, username: str, limit: int = 100) -> List["VPNSession"]:
        """Get VPN sessions by user"""
        result = await db.execute(
            select(cls)
            .where(cls.username == username)
            .order_by(cls.connection_start.desc())
            .limit(limit)
        )
        return result.scalars().all()

class NACLog(Base):
    __tablename__ = "nac_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"), nullable=False)
    event_time = Column(DateTime, nullable=False)
    device_mac = Column(String(50), nullable=False)
    device_ip = Column(String(50), nullable=True)
    device_name = Column(String(255), nullable=True)
    action = Column(String(20), nullable=False)  # allowed, blocked, quarantined
    description = Column(Text, nullable=True)
    user_name = Column(String(255), nullable=True)
    switch_port = Column(String(100), nullable=True)
    vlan = Column(String(50), nullable=True)
    policy_name = Column(String(255), nullable=True)
    reason = Column(String(255), nullable=True)  # policy violation, unknown device
    created_at = Column(DateTime, default=func.now())
    
    # Relationship
    device = relationship("NetworkDevice", back_populates="nac_logs")
    
    @classmethod
    async def get_by_action(cls, db: AsyncSession, action: str, limit: int = 1000) -> List["NACLog"]:
        """Get NAC logs by action"""
        result = await db.execute(
            select(cls)
            .where(cls.action == action)
            .order_by(cls.event_time.desc())
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_recent_logs(cls, db: AsyncSession, hours: int = 24) -> List["NACLog"]:
        """Get recent NAC logs"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(cls)
            .where(cls.event_time >= cutoff_time)
            .order_by(cls.event_time.desc())
        )
        return result.scalars().all() 