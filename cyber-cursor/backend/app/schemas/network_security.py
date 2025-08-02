from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# Network Device Schemas
class NetworkDeviceBase(BaseModel):
    device_name: str = Field(..., description="Device name")
    device_type: str = Field(..., description="Device type: firewall, ids, vpn, nac")
    ip_address: str = Field(..., description="Device IP address")
    vendor: Optional[str] = Field(None, description="Device vendor")
    model: Optional[str] = Field(None, description="Device model")
    port: Optional[int] = Field(22, description="Connection port")

class NetworkDeviceCreate(NetworkDeviceBase):
    api_key: Optional[str] = Field(None, description="API key for device access")
    username: Optional[str] = Field(None, description="Username for device access")
    password: Optional[str] = Field(None, description="Password for device access")

class NetworkDeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    status: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

class NetworkDevice(NetworkDeviceBase):
    id: int
    status: str
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Firewall Log Schemas
class FirewallLogBase(BaseModel):
    device_id: int
    log_time: datetime
    source_ip: str
    dest_ip: str
    action: str = Field(..., description="Action: allow, deny, drop")
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    application: Optional[str] = None
    rule_name: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

class FirewallLogCreate(FirewallLogBase):
    pass

class FirewallLog(FirewallLogBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# IDS Alert Schemas
class IDSAlertBase(BaseModel):
    device_id: int
    alert_time: datetime
    severity: str = Field(..., description="Severity: low, medium, high, critical")
    alert_type: str = Field(..., description="Alert type: signature, anomaly, policy")
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None
    category: Optional[str] = None

class IDSAlertCreate(IDSAlertBase):
    pass

class IDSAlertUpdate(BaseModel):
    status: Optional[str] = Field(None, description="Status: new, acknowledged, resolved")

class IDSAlert(IDSAlertBase):
    id: int
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

# VPN Session Schemas
class VPNSessionBase(BaseModel):
    device_id: int
    username: str
    ip_address: str
    connection_start: datetime
    vpn_type: Optional[str] = Field(None, description="VPN type: ssl, ipsec, l2tp")
    client_ip: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

class VPNSessionCreate(VPNSessionBase):
    pass

class VPNSessionUpdate(BaseModel):
    connection_end: Optional[datetime] = None
    status: Optional[str] = Field(None, description="Status: active, disconnected, expired")
    session_duration: Optional[int] = None

class VPNSession(VPNSessionBase):
    id: int
    connection_end: Optional[datetime] = None
    status: str
    session_duration: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True

# NAC Log Schemas
class NACLogBase(BaseModel):
    device_id: int
    event_time: datetime
    device_mac: str
    action: str = Field(..., description="Action: allowed, blocked, quarantined")
    device_ip: Optional[str] = None
    device_name: Optional[str] = None
    description: Optional[str] = None
    user_name: Optional[str] = None
    switch_port: Optional[str] = None
    vlan: Optional[str] = None
    policy_name: Optional[str] = None
    reason: Optional[str] = None

class NACLogCreate(NACLogBase):
    pass

class NACLog(NACLogBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Dashboard and Analytics Schemas
class NetworkSecurityOverview(BaseModel):
    total_devices: int
    online_devices: int
    offline_devices: int
    firewall_logs_24h: int
    ids_alerts_24h: int
    active_vpn_sessions: int
    nac_events_24h: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int

class FirewallStats(BaseModel):
    total_logs: int
    allowed_connections: int
    denied_connections: int
    dropped_connections: int
    top_source_ips: List[dict]
    top_dest_ips: List[dict]
    top_applications: List[dict]

class IDSStats(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    top_categories: List[dict]
    top_signatures: List[dict]
    top_source_ips: List[dict]

class VPNStats(BaseModel):
    active_sessions: int
    total_users: int
    total_traffic: int
    top_users: List[dict]
    session_duration_avg: float

class NACStats(BaseModel):
    total_events: int
    allowed_devices: int
    blocked_devices: int
    quarantined_devices: int
    top_policies: List[dict]
    top_vlans: List[dict]

# Search and Filter Schemas
class NetworkSecurityFilter(BaseModel):
    device_type: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: Optional[int] = 100

# Response Schemas
class NetworkSecurityResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None

class DeviceListResponse(BaseModel):
    devices: List[NetworkDevice]
    total: int
    page: int
    limit: int

class FirewallLogsResponse(BaseModel):
    logs: List[FirewallLog]
    total: int
    page: int
    limit: int

class IDSAlertsResponse(BaseModel):
    alerts: List[IDSAlert]
    total: int
    page: int
    limit: int

class VPNSessionsResponse(BaseModel):
    sessions: List[VPNSession]
    total: int
    page: int
    limit: int

class NACLogsResponse(BaseModel):
    logs: List[NACLog]
    total: int
    page: int
    limit: int 