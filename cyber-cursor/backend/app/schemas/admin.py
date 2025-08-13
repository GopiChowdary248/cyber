from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class AdminDashboardResponse(BaseModel):
    system_overview: Dict[str, Any]
    security_metrics: Dict[str, Any]
    user_management: Dict[str, Any]
    infrastructure: Dict[str, Any]

class SystemHealthResponse(BaseModel):
    status: str
    uptime: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_status: str
    last_check: datetime

class UserManagementResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime]
    created_at: datetime
    status: str

    class Config:
        from_attributes = True

class SecurityMetricsResponse(BaseModel):
    total_incidents: int
    critical_alerts: int
    failed_logins: int
    suspicious_activities: int
    security_score: float
    last_updated: datetime

class InfrastructureResponse(BaseModel):
    cloud_resources: int
    misconfigurations: int
    compliance_score: float
    backup_status: str
    last_backup: Optional[datetime]
    system_health: str
