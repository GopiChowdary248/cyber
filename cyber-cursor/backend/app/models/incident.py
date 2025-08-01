from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum

from app.core.database import Base

class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

class IncidentType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    NETWORK_ATTACK = "network_attack"
    OTHER = "other"

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    incident_type = Column(String(50), nullable=False)
    severity = Column(String(20), default=IncidentSeverity.MEDIUM)
    status = Column(String(20), default=IncidentStatus.OPEN)
    
    # Source information
    source = Column(String(100), nullable=True)  # email, cloud_scan, siem, manual
    source_id = Column(String(255), nullable=True)  # external ID from source
    
    # Assignment
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # Additional data
    tags = Column(JSON, nullable=True)  # JSON array of tags
    incident_metadata = Column(JSON, nullable=True)  # Additional incident data
    ioc_data = Column(JSON, nullable=True)  # Indicators of Compromise
    
    # Relationships
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    creator = relationship("User", foreign_keys=[created_by])
    responses = relationship("IncidentResponse", back_populates="incident")
    playbooks = relationship("ResponsePlaybook", back_populates="incident")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, incident_id: int) -> Optional["Incident"]:
        """Get incident by ID"""
        result = await db.execute(select(cls).where(cls.id == incident_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["Incident"]:
        """Get all incidents with pagination"""
        result = await db.execute(select(cls).order_by(cls.created_at.desc()).offset(skip).limit(limit))
        return result.scalars().all()
    
    @classmethod
    async def get_by_status(cls, db: AsyncSession, status: str) -> List["Incident"]:
        """Get incidents by status"""
        result = await db.execute(select(cls).where(cls.status == status).order_by(cls.created_at.desc()))
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str) -> List["Incident"]:
        """Get incidents by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity).order_by(cls.created_at.desc()))
        return result.scalars().all()
    
    @classmethod
    async def create_incident(cls, db: AsyncSession, **kwargs) -> "Incident":
        """Create a new incident"""
        incident = cls(**kwargs)
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        return incident
    
    async def update(self, db: AsyncSession, **kwargs) -> "Incident":
        """Update incident information"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        self.updated_at = datetime.utcnow()
        
        # Update timestamps based on status changes
        if kwargs.get("status") == IncidentStatus.RESOLVED and not self.resolved_at:
            self.resolved_at = datetime.utcnow()
        elif kwargs.get("status") == IncidentStatus.CLOSED and not self.closed_at:
            self.closed_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(self)
        return self
    
    def __repr__(self):
        return f"<Incident(id={self.id}, title='{self.title}', status='{self.status}')>"

class IncidentResponse(Base):
    __tablename__ = "incident_responses"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    response_type = Column(String(50), nullable=False)  # action, note, escalation
    description = Column(Text, nullable=False)
    performed_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    performed_at = Column(DateTime, default=func.now())
    
    # Response details
    action_taken = Column(Text, nullable=True)
    outcome = Column(String(100), nullable=True)  # success, failure, pending
    response_metadata = Column(JSON, nullable=True)
    
    # Relationships
    incident = relationship("Incident", back_populates="responses")
    user = relationship("User")
    
    def __repr__(self):
        return f"<IncidentResponse(id={self.id}, incident_id={self.incident_id}, type='{self.response_type}')>"

class ResponsePlaybook(Base):
    __tablename__ = "response_playbooks"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    steps = Column(JSON, nullable=False)  # Array of playbook steps
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    incident = relationship("Incident", back_populates="playbooks")
    
    def __repr__(self):
        return f"<ResponsePlaybook(id={self.id}, name='{self.name}', incident_id={self.incident_id})>" 