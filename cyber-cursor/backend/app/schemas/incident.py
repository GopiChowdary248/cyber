from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

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

class IncidentBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    incident_type: IncidentType
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    source: Optional[str] = None
    source_id: Optional[str] = None
    tags: Optional[List[str]] = None
    incident_metadata: Optional[Dict[str, Any]] = None
    ioc_data: Optional[Dict[str, Any]] = None

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[int] = None
    tags: Optional[List[str]] = None
    incident_metadata: Optional[Dict[str, Any]] = None
    ioc_data: Optional[Dict[str, Any]] = None

class IncidentInDB(IncidentBase):
    id: int
    status: IncidentStatus = IncidentStatus.OPEN
    assigned_to: Optional[int] = None
    created_by: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class Incident(IncidentInDB):
    assigned_user: Optional["User"] = None
    creator: "User"
    response_count: int = 0
    playbook_count: int = 0

class IncidentResponseBase(BaseModel):
    response_type: str = Field(..., min_length=1, max_length=50)
    description: str = Field(..., min_length=1)
    action_taken: Optional[str] = None
    outcome: Optional[str] = None
    response_metadata: Optional[Dict[str, Any]] = None

class IncidentResponseCreate(IncidentResponseBase):
    incident_id: int

class IncidentResponseUpdate(BaseModel):
    description: Optional[str] = None
    action_taken: Optional[str] = None
    outcome: Optional[str] = None
    response_metadata: Optional[Dict[str, Any]] = None

class IncidentResponseInDB(IncidentResponseBase):
    id: int
    incident_id: int
    performed_by: int
    performed_at: datetime
    
    class Config:
        from_attributes = True

class IncidentResponse(IncidentResponseInDB):
    user: "User"

class ResponsePlaybookBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    steps: List[Dict[str, Any]] = Field(..., min_items=1)
    is_active: bool = True

class ResponsePlaybookCreate(ResponsePlaybookBase):
    incident_id: int

class ResponsePlaybookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    steps: Optional[List[Dict[str, Any]]] = None
    is_active: Optional[bool] = None

class ResponsePlaybookInDB(ResponsePlaybookBase):
    id: int
    incident_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ResponsePlaybook(ResponsePlaybookInDB):
    pass

class PlaybookStep(BaseModel):
    step_number: int
    title: str
    description: str
    action_type: str  # manual, automated, notification
    action_details: Dict[str, Any]
    estimated_time: Optional[int] = None  # minutes
    dependencies: Optional[List[int]] = None
    required_approval: bool = False

class IncidentFilter(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    incident_type: Optional[IncidentType] = None
    assigned_to: Optional[int] = None
    created_by: Optional[int] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    tags: Optional[List[str]] = None
    search: Optional[str] = None

class IncidentStats(BaseModel):
    total_incidents: int
    open_incidents: int
    in_progress_incidents: int
    resolved_incidents: int
    closed_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    avg_resolution_time: Optional[float] = None  # hours
    incidents_by_type: Dict[str, int]
    incidents_by_severity: Dict[str, int]

class IncidentBulkUpdate(BaseModel):
    incident_ids: List[int]
    updates: IncidentUpdate

# Import User for forward references
from app.schemas.auth import User

# Update forward references
Incident.model_rebuild()
IncidentResponse.model_rebuild() 