from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.monitoring_siem_soar_service import (
    monitoring_siem_soar_service,
    LogLevel, IncidentSeverity, IncidentStatus, AlertType, AnomalyType, AutomationAction
)

router = APIRouter()

# Pydantic models for request/response
class LogEntryCreate(BaseModel):
    level: LogLevel
    source: str
    message: str
    metadata: Optional[Dict[str, Any]] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None

class LogEntryResponse(BaseModel):
    id: str
    timestamp: datetime
    level: LogLevel
    source: str
    message: str
    metadata: Dict[str, Any]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None

class SecurityEventCreate(BaseModel):
    event_type: str
    severity: IncidentSeverity
    source: str
    description: str
    raw_data: Optional[Dict[str, Any]] = None
    indicators: Optional[List[str]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None

class SecurityEventResponse(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    severity: IncidentSeverity
    source: str
    description: str
    raw_data: Dict[str, Any]
    indicators: List[str]
    threat_intelligence: Dict[str, Any]

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: IncidentSeverity
    tags: Optional[List[str]] = None
    playbook: Optional[str] = None

class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None

class IncidentResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    tags: List[str]
    related_events: List[str]
    playbook: Optional[str] = None
    sla_deadline: Optional[datetime] = None

class AlertCreate(BaseModel):
    title: str
    description: str
    alert_type: AlertType
    severity: IncidentSeverity
    source: str
    metadata: Optional[Dict[str, Any]] = None

class AlertAcknowledge(BaseModel):
    acknowledged_by: str

class AlertResponse(BaseModel):
    id: str
    title: str
    description: str
    alert_type: AlertType
    severity: IncidentSeverity
    timestamp: datetime
    source: str
    acknowledged: bool
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    metadata: Dict[str, Any]

class AnomalyCreate(BaseModel):
    anomaly_type: AnomalyType
    severity: IncidentSeverity
    source: str
    description: str
    confidence_score: float
    baseline_data: Optional[Dict[str, Any]] = None
    current_data: Optional[Dict[str, Any]] = None

class AnomalyResponse(BaseModel):
    id: str
    anomaly_type: AnomalyType
    severity: IncidentSeverity
    timestamp: datetime
    source: str
    description: str
    confidence_score: float
    baseline_data: Dict[str, Any]
    current_data: Dict[str, Any]
    status: str

class AutomationRuleCreate(BaseModel):
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    actions: List[AutomationAction]
    priority: Optional[int] = 0

class AutomationRuleResponse(BaseModel):
    id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    actions: List[AutomationAction]
    enabled: bool
    priority: int
    created_at: datetime

class PlaybookCreate(BaseModel):
    name: str
    description: str
    steps: List[Dict[str, Any]]
    triggers: List[str]
    estimated_duration: Optional[int] = 0

class PlaybookResponse(BaseModel):
    id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    triggers: List[str]
    enabled: bool
    estimated_duration: int

class MonitoringSummaryResponse(BaseModel):
    total_logs: int
    total_events: int
    open_incidents: int
    active_alerts: int
    anomalies_detected: int
    automation_rules: int
    playbooks: int
    system_health: str
    last_updated: datetime

# Log Management Endpoints
@router.post("/logs", response_model=LogEntryResponse)
async def create_log(log_data: LogEntryCreate):
    """Create a new log entry"""
    try:
        log_entry = await monitoring_siem_soar_service.add_log(
            level=log_data.level,
            source=log_data.source,
            message=log_data.message,
            metadata=log_data.metadata,
            user_id=log_data.user_id,
            session_id=log_data.session_id,
            ip_address=log_data.ip_address
        )
        return log_entry
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create log entry: {str(e)}")

@router.get("/logs", response_model=List[LogEntryResponse])
async def get_logs(
    level: Optional[LogLevel] = Query(None, description="Filter by log level"),
    source: Optional[str] = Query(None, description="Filter by source"),
    limit: int = Query(100, description="Maximum number of logs to return")
):
    """Get logs with optional filtering"""
    try:
        logs = await monitoring_siem_soar_service.get_logs(
            level=level,
            source=source,
            limit=limit
        )
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")

# Security Event Management Endpoints
@router.post("/events", response_model=SecurityEventResponse)
async def create_security_event(event_data: SecurityEventCreate):
    """Create a new security event"""
    try:
        event = await monitoring_siem_soar_service.add_security_event(
            event_type=event_data.event_type,
            severity=event_data.severity,
            source=event_data.source,
            description=event_data.description,
            raw_data=event_data.raw_data,
            indicators=event_data.indicators,
            threat_intelligence=event_data.threat_intelligence
        )
        return event
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create security event: {str(e)}")

@router.get("/events", response_model=List[SecurityEventResponse])
async def get_security_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity"),
    limit: int = Query(100, description="Maximum number of events to return")
):
    """Get security events with optional filtering"""
    try:
        events = await monitoring_siem_soar_service.get_security_events(
            event_type=event_type,
            severity=severity,
            limit=limit
        )
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve security events: {str(e)}")

# Incident Management Endpoints
@router.post("/incidents", response_model=IncidentResponse)
async def create_incident(incident_data: IncidentCreate):
    """Create a new incident"""
    try:
        incident = await monitoring_siem_soar_service.create_incident(
            title=incident_data.title,
            description=incident_data.description,
            severity=incident_data.severity,
            tags=incident_data.tags,
            playbook=incident_data.playbook
        )
        return incident
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create incident: {str(e)}")

@router.put("/incidents/{incident_id}", response_model=IncidentResponse)
async def update_incident(incident_id: str, update_data: IncidentUpdate):
    """Update an incident"""
    try:
        incident = await monitoring_siem_soar_service.update_incident(
            incident_id=incident_id,
            status=update_data.status,
            assigned_to=update_data.assigned_to,
            tags=update_data.tags
        )
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update incident: {str(e)}")

@router.get("/incidents", response_model=List[IncidentResponse])
async def get_incidents(
    status: Optional[IncidentStatus] = Query(None, description="Filter by status"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst"),
    limit: int = Query(100, description="Maximum number of incidents to return")
):
    """Get incidents with optional filtering"""
    try:
        incidents = await monitoring_siem_soar_service.get_incidents(
            status=status,
            severity=severity,
            assigned_to=assigned_to,
            limit=limit
        )
        return incidents
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve incidents: {str(e)}")

@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str):
    """Get a specific incident by ID"""
    try:
        incidents = await monitoring_siem_soar_service.get_incidents()
        for incident in incidents:
            if incident.id == incident_id:
                return incident
        raise HTTPException(status_code=404, detail="Incident not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve incident: {str(e)}")

# Alert Management Endpoints
@router.post("/alerts", response_model=AlertResponse)
async def create_alert(alert_data: AlertCreate):
    """Create a new alert"""
    try:
        alert = await monitoring_siem_soar_service.create_alert(
            title=alert_data.title,
            description=alert_data.description,
            alert_type=alert_data.alert_type,
            severity=alert_data.severity,
            source=alert_data.source,
            metadata=alert_data.metadata
        )
        return alert
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create alert: {str(e)}")

@router.put("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(alert_id: str, acknowledge_data: AlertAcknowledge):
    """Acknowledge an alert"""
    try:
        alert = await monitoring_siem_soar_service.acknowledge_alert(
            alert_id=alert_id,
            acknowledged_by=acknowledge_data.acknowledged_by
        )
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to acknowledge alert: {str(e)}")

@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    alert_type: Optional[AlertType] = Query(None, description="Filter by alert type"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledgment status"),
    limit: int = Query(100, description="Maximum number of alerts to return")
):
    """Get alerts with optional filtering"""
    try:
        alerts = await monitoring_siem_soar_service.get_alerts(
            alert_type=alert_type,
            severity=severity,
            acknowledged=acknowledged,
            limit=limit
        )
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve alerts: {str(e)}")

# Anomaly Management Endpoints
@router.post("/anomalies", response_model=AnomalyResponse)
async def create_anomaly(anomaly_data: AnomalyCreate):
    """Create a new anomaly"""
    try:
        anomaly = await monitoring_siem_soar_service.add_anomaly(
            anomaly_type=anomaly_data.anomaly_type,
            severity=anomaly_data.severity,
            source=anomaly_data.source,
            description=anomaly_data.description,
            confidence_score=anomaly_data.confidence_score,
            baseline_data=anomaly_data.baseline_data,
            current_data=anomaly_data.current_data
        )
        return anomaly
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create anomaly: {str(e)}")

@router.get("/anomalies", response_model=List[AnomalyResponse])
async def get_anomalies(
    anomaly_type: Optional[AnomalyType] = Query(None, description="Filter by anomaly type"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity"),
    limit: int = Query(100, description="Maximum number of anomalies to return")
):
    """Get anomalies with optional filtering"""
    try:
        anomalies = await monitoring_siem_soar_service.get_anomalies(
            anomaly_type=anomaly_type,
            severity=severity,
            limit=limit
        )
        return anomalies
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve anomalies: {str(e)}")

# Automation Rule Management Endpoints
@router.post("/automation-rules", response_model=AutomationRuleResponse)
async def create_automation_rule(rule_data: AutomationRuleCreate):
    """Create a new automation rule"""
    try:
        rule = await monitoring_siem_soar_service.create_automation_rule(
            name=rule_data.name,
            description=rule_data.description,
            conditions=rule_data.conditions,
            actions=rule_data.actions,
            priority=rule_data.priority
        )
        return rule
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create automation rule: {str(e)}")

@router.get("/automation-rules", response_model=List[AutomationRuleResponse])
async def get_automation_rules(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status")
):
    """Get automation rules with optional filtering"""
    try:
        rules = await monitoring_siem_soar_service.get_automation_rules(enabled=enabled)
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve automation rules: {str(e)}")

# Playbook Management Endpoints
@router.post("/playbooks", response_model=PlaybookResponse)
async def create_playbook(playbook_data: PlaybookCreate):
    """Create a new playbook"""
    try:
        playbook = await monitoring_siem_soar_service.create_playbook(
            name=playbook_data.name,
            description=playbook_data.description,
            steps=playbook_data.steps,
            triggers=playbook_data.triggers,
            estimated_duration=playbook_data.estimated_duration
        )
        return playbook
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create playbook: {str(e)}")

@router.get("/playbooks", response_model=List[PlaybookResponse])
async def get_playbooks(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status")
):
    """Get playbooks with optional filtering"""
    try:
        playbooks = await monitoring_siem_soar_service.get_playbooks(enabled=enabled)
        return playbooks
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve playbooks: {str(e)}")

# Summary and Analytics Endpoints
@router.get("/summary", response_model=MonitoringSummaryResponse)
async def get_monitoring_summary():
    """Get monitoring summary statistics"""
    try:
        summary = await monitoring_siem_soar_service.get_monitoring_summary()
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve monitoring summary: {str(e)}")

# Bulk Operations
@router.post("/bulk/logs")
async def bulk_create_logs(logs_data: List[LogEntryCreate]):
    """Create multiple log entries"""
    try:
        created_logs = []
        for log_data in logs_data:
            log_entry = await monitoring_siem_soar_service.add_log(
                level=log_data.level,
                source=log_data.source,
                message=log_data.message,
                metadata=log_data.metadata,
                user_id=log_data.user_id,
                session_id=log_data.session_id,
                ip_address=log_data.ip_address
            )
            created_logs.append(log_entry)
        return {"message": f"Created {len(created_logs)} log entries", "logs": created_logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create bulk logs: {str(e)}")

@router.post("/bulk/events")
async def bulk_create_events(events_data: List[SecurityEventCreate]):
    """Create multiple security events"""
    try:
        created_events = []
        for event_data in events_data:
            event = await monitoring_siem_soar_service.add_security_event(
                event_type=event_data.event_type,
                severity=event_data.severity,
                source=event_data.source,
                description=event_data.description,
                raw_data=event_data.raw_data,
                indicators=event_data.indicators,
                threat_intelligence=event_data.threat_intelligence
            )
            created_events.append(event)
        return {"message": f"Created {len(created_events)} security events", "events": created_events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create bulk events: {str(e)}")

# Health Check
@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        summary = await monitoring_siem_soar_service.get_monitoring_summary()
        return {
            "status": "healthy",
            "service": "monitoring_siem_soar",
            "summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service unhealthy: {str(e)}") 