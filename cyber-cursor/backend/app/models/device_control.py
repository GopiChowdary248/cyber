from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float, UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum
import uuid

from app.core.database import Base

class DeviceType(str, Enum):
    USB = "usb"
    CD_DVD = "cd_dvd"
    EXTERNAL_HDD = "external_hdd"
    NETWORK_DEVICE = "network_device"
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    OTHER = "other"

class DeviceStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    APPROVED = "approved"
    PENDING = "pending"

class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    AUDIT = "audit"
    ENCRYPT = "encrypt"

class EventType(str, Enum):
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    ACCESS = "access"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    POLICY_VIOLATION = "policy_violation"
    ENCRYPTION = "encryption"

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)  # usb, cd_dvd, external_hdd, etc.
    vendor = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    serial_number = Column(String(255), nullable=True)
    device_id = Column(String(255), nullable=True)  # USB device ID, MAC address, etc.
    
    # Device metadata
    capacity = Column(Float, nullable=True)  # Storage capacity in GB
    file_system = Column(String(50), nullable=True)  # FAT32, NTFS, etc.
    is_encrypted = Column(Boolean, default=False)
    is_approved = Column(Boolean, default=False)
    
    # Status and tracking
    status = Column(String(20), default=DeviceStatus.DISCONNECTED.value)
    last_seen = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, default=func.now())
    
    # Endpoint association
    endpoint_id = Column(String(255), nullable=True)  # Associated endpoint
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    events = relationship("DeviceEvent", back_populates="device")
    # policies = relationship("DevicePolicy", back_populates="device", primaryjoin="Device.id == DevicePolicy.device_id")
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, device_id: str) -> Optional["Device"]:
        """Get device by ID"""
        result = await db.execute(select(cls).where(cls.id == device_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_type(cls, db: AsyncSession, device_type: str) -> List["Device"]:
        """Get devices by type"""
        result = await db.execute(select(cls).where(cls.device_type == device_type))
        return result.scalars().all()
    
    @classmethod
    async def get_by_status(cls, db: AsyncSession, status: str) -> List["Device"]:
        """Get devices by status"""
        result = await db.execute(select(cls).where(cls.status == status))
        return result.scalars().all()
    
    @classmethod
    async def get_connected_devices(cls, db: AsyncSession) -> List["Device"]:
        """Get all currently connected devices"""
        result = await db.execute(select(cls).where(cls.status == DeviceStatus.CONNECTED.value))
        return result.scalars().all()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["Device"]:
        """Get all devices with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<Device(id={self.id}, name='{self.device_name}', type='{self.device_type}')>"

class DevicePolicy(Base):
    __tablename__ = "device_policies"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Policy scope
    device_type = Column(String(50), nullable=True)  # Specific device type
    vendor = Column(String(100), nullable=True)  # Specific vendor
    model = Column(String(100), nullable=True)  # Specific model
    device_id = Column(String(255), nullable=True)  # Specific device ID
    
    # Policy actions
    action = Column(String(20), nullable=False, default=PolicyAction.BLOCK.value)
    auto_encrypt = Column(Boolean, default=False)
    require_approval = Column(Boolean, default=False)
    
    # Policy conditions
    max_capacity = Column(Float, nullable=True)  # Maximum device capacity allowed
    allowed_file_types = Column(JSON, nullable=True)  # Allowed file extensions
    blocked_file_types = Column(JSON, nullable=True)  # Blocked file extensions
    
    # Policy metadata
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=100)  # Higher number = higher priority
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Created by
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    # Relationships
    # device = relationship("Device", back_populates="policies", primaryjoin="DevicePolicy.device_id == Device.id")
    events = relationship("DeviceEvent", back_populates="policy")
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["DevicePolicy"]:
        """Get all policies with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, policy_id: str) -> Optional["DevicePolicy"]:
        """Get policy by ID"""
        result = await db.execute(select(cls).where(cls.id == policy_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_active_policies(cls, db: AsyncSession) -> List["DevicePolicy"]:
        """Get all active policies"""
        result = await db.execute(select(cls).where(cls.is_active == True).order_by(cls.priority.desc()))
        return result.scalars().all()
    
    @classmethod
    async def get_by_device_type(cls, db: AsyncSession, device_type: str) -> List["DevicePolicy"]:
        """Get policies for specific device type"""
        result = await db.execute(
            select(cls)
            .where(cls.device_type == device_type)
            .where(cls.is_active == True)
            .order_by(cls.priority.desc())
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DevicePolicy(id={self.id}, name='{self.policy_name}', action='{self.action}')>"

class DeviceEvent(Base):
    __tablename__ = "device_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("device_policies.id"), nullable=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # connect, disconnect, access, block, etc.
    event_time = Column(DateTime, default=func.now())
    
    # Event context
    endpoint_id = Column(String(255), nullable=True)  # Associated endpoint
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    process_name = Column(String(255), nullable=True)  # Process that triggered the event
    file_path = Column(Text, nullable=True)  # File being accessed
    
    # Event metadata
    action_taken = Column(String(50), nullable=True)  # allow, block, quarantine, encrypt
    reason = Column(Text, nullable=True)  # Reason for action
    severity = Column(String(20), default="info")  # info, warning, error, critical
    
    # Additional data
    event_metadata = Column(JSON, nullable=True)  # Additional event data
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="events")
    policy = relationship("DevicePolicy", back_populates="events")
    user = relationship("User")
    
    @classmethod
    async def get_by_device(cls, db: AsyncSession, device_id: str, limit: int = 1000) -> List["DeviceEvent"]:
        """Get events for a specific device"""
        result = await db.execute(
            select(cls)
            .where(cls.device_id == device_id)
            .order_by(cls.event_time.desc())
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_type(cls, db: AsyncSession, event_type: str, limit: int = 1000) -> List["DeviceEvent"]:
        """Get events by type"""
        result = await db.execute(
            select(cls)
            .where(cls.event_type == event_type)
            .order_by(cls.event_time.desc())
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_recent_events(cls, db: AsyncSession, hours: int = 24) -> List["DeviceEvent"]:
        """Get recent events"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(cls)
            .where(cls.event_time >= cutoff_time)
            .order_by(cls.event_time.desc())
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str, limit: int = 1000) -> List["DeviceEvent"]:
        """Get events by severity"""
        result = await db.execute(
            select(cls)
            .where(cls.severity == severity)
            .order_by(cls.event_time.desc())
            .limit(limit)
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DeviceEvent(id={self.id}, device_id={self.device_id}, type='{self.event_type}')>" 