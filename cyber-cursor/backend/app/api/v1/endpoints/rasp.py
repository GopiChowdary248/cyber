"""
RASP (Runtime Application Self-Protection) API Endpoints
Provides comprehensive REST API for RASP functionality including:
- Agent management and monitoring
- Attack detection and logging
- Rule management
- Vulnerability tracking
- Virtual patching
- Telemetry and alerts
- SIEM/SOAR integrations
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid

from app.core.database import get_db
from app.schemas.rasp import *
from app.models.rasp import *
from app.core.security import get_current_user

router = APIRouter()

# Dashboard endpoints
@router.get("/overview", response_model=RASPDashboardOverview)
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get RASP dashboard overview with summary metrics"""
    try:
        # Get counts
        result = await db.execute(db.select(db.func.count(RASPApp.id)))
        apps_count = result.scalar()
        
        result = await db.execute(db.select(db.func.count(RASPAgent.id)))
        agents_count = result.scalar()
        
        # Get 24h metrics
        since_24h = datetime.utcnow() - timedelta(hours=24)
        result = await db.execute(
            db.select(db.func.count(RASPIncident.id)).where(
                RASPIncident.created_at >= since_24h
            )
        )
        attacks_last_24h = result.scalar()
        
        result = await db.execute(
            db.select(db.func.count(RASPIncident.id)).where(
                RASPIncident.created_at >= since_24h,
                RASPIncident.action_taken == RASPAction.BLOCKED
            )
        )
        blocked_last_24h = result.scalar()
        
        # Get top apps by attack volume
        result = await db.execute(
            db.select(
                RASPApp.id,
                RASPApp.name,
                RASPApp.risk_score
            ).join(RASPIncident).group_by(RASPApp.id).order_by(
                db.func.count(RASPIncident.id).desc()
            ).limit(10)
        )
        top_apps = result.all()
        
        return RASPDashboardOverview(
            apps_count=apps_count,
            agents_count=agents_count,
            attacks_last_24h=attacks_last_24h,
            blocked_last_24h=blocked_last_24h,
            top_apps=[{"id": app.id, "name": app.name, "risk_score": app.risk_score} for app in top_apps]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching dashboard data: {str(e)}")

@router.get("/dashboard/overview", response_model=Dict[str, Any])
async def get_dashboard_overview_alt(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Alternative dashboard overview endpoint for frontend compatibility"""
    try:
        # Mock data for now - can be enhanced with actual database queries
        dashboard_data = {
            "total_applications": 24,
            "active_agents": 18,
            "attacks_blocked_24h": 156,
            "attacks_monitored_24h": 23,
            "security_score": 87,
            "recent_incidents": 12,
            "top_threats": [
                {"type": "SQL Injection", "count": 45, "severity": "high"},
                {"type": "XSS", "count": 32, "severity": "medium"},
                {"type": "Path Traversal", "count": 28, "severity": "medium"},
                {"type": "RCE", "count": 15, "severity": "critical"}
            ],
            "applications_by_environment": {
                "production": 8,
                "staging": 6,
                "development": 7,
                "testing": 3
            }
        }
        return dashboard_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching dashboard data: {str(e)}")

@router.get("/metrics", response_model=RASPMetricsResponse)
async def get_metrics(
    app_id: Optional[str] = Query(None),
    since: datetime = Query(...),
    until: datetime = Query(...),
    metric: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get time series metrics for charts"""
    try:
        query = db.select(RASPMetric).where(
            RASPMetric.timestamp >= since,
            RASPMetric.timestamp <= until
        )
        
        if app_id:
            query = query.where(RASPMetric.app_id == app_id)
            
        result = await db.execute(query.order_by(RASPMetric.timestamp))
        metrics = result.scalars().all()
        
        data = [{"timestamp": m.timestamp, "value": m.metric_value} for m in metrics]
        labels = [m.timestamp.strftime("%Y-%m-%d %H:%M") for m in metrics]
        
        return RASPMetricsResponse(data=data, labels=labels)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching metrics: {str(e)}")

@router.get("/incidents/recent", response_model=List[RASPIncident])
async def get_recent_incidents(
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get recent incidents for dashboard feed"""
    try:
        result = await db.execute(
            db.select(RASPIncident).order_by(
                RASPIncident.created_at.desc()
            ).limit(limit)
        )
        incidents = result.scalars().all()
        return incidents
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching recent incidents: {str(e)}")

# Applications endpoints
@router.get("/apps", response_model=RASPListResponse)
async def get_applications(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    framework: Optional[str] = Query(None),
    language: Optional[RASPLanguage] = Query(None),
    environment: Optional[RASPEnvironment] = Query(None),
    tags: Optional[str] = Query(None),
    risk_score_min: Optional[float] = Query(None),
    risk_score_max: Optional[float] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get applications with filtering and pagination"""
    try:
        query = db.select(RASPApp)
        
        # Apply filters
        if framework:
            query = query.where(RASPApp.framework == framework)
        if language:
            query = query.where(RASPApp.language == language)
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]
            query = query.where(RASPApp.tags.overlap(tag_list))
        if risk_score_min is not None:
            query = query.where(RASPApp.risk_score >= risk_score_min)
        if risk_score_max is not None:
            query = query.where(RASPApp.risk_score <= risk_score_max)
            
        # Get total count
        count_result = await db.execute(db.select(db.func.count()).select_from(query.subquery()))
        total = count_result.scalar()
        
        # Get paginated results
        result = await db.execute(
            query.offset((page - 1) * size).limit(size)
        )
        apps = result.scalars().all()
        
        pages = (total + size - 1) // size
        
        return RASPListResponse(
            items=apps,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching applications: {str(e)}")

# Projects endpoint (alias for applications)
@router.get("/projects", response_model=RASPListResponse)
async def get_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(12, ge=1, le=100),
    framework: Optional[str] = Query(None),
    language: Optional[RASPLanguage] = Query(None),
    environment: Optional[RASPEnvironment] = Query(None),
    tags: Optional[str] = Query(None),
    risk_score_min: Optional[float] = Query(None),
    risk_score_max: Optional[float] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get RASP projects (applications) with filtering and pagination"""
    try:
        query = db.select(RASPApp)
        
        # Apply filters
        if framework:
            query = query.where(RASPApp.framework == framework)
        if language:
            query = query.where(RASPApp.language == language)
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]
            query = query.where(RASPApp.tags.overlap(tag_list))
        if risk_score_min is not None:
            query = query.where(RASPApp.risk_score >= risk_score_min)
        if risk_score_max is not None:
            query = query.where(RASPApp.risk_score <= risk_score_max)
            
        # Get total count
        count_result = await db.execute(db.select(db.func.count()).select_from(query.subquery()))
        total = count_result.scalar()
        
        # Get paginated results using skip/limit
        result = await db.execute(
            query.offset(skip).limit(limit)
        )
        projects = result.scalars().all()
        
        # Calculate page info for compatibility
        page = (skip // limit) + 1
        pages = (total + limit - 1) // limit
        
        return RASPListResponse(
            items=projects,
            total=total,
            page=page,
            size=limit,
            pages=pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching projects: {str(e)}")

@router.post("/apps", response_model=RASPApp, status_code=status.HTTP_201_CREATED)
async def create_application(
    app_data: RASPAppCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new RASP application"""
    try:
        app_id = f"app-{uuid.uuid4().hex[:8]}"
        db_app = RASPApp(
            id=app_id,
            **app_data.dict(),
            risk_score=0.0
        )
        db.add(db_app)
        await db.commit()
        await db.refresh(db_app)
        return db_app
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating application: {str(e)}")

@router.get("/apps/{app_id}", response_model=RASPApp)
async def get_application(
    app_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get application details by ID"""
    try:
        result = await db.execute(
            db.select(RASPApp).where(RASPApp.id == app_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
        return app
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching application: {str(e)}")

@router.put("/apps/{app_id}", response_model=RASPApp)
async def update_application(
    app_id: str,
    app_data: RASPAppUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update application details"""
    try:
        result = await db.execute(
            db.select(RASPApp).where(RASPApp.id == app_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
            
        for field, value in app_data.dict(exclude_unset=True).items():
            setattr(app, field, value)
            
        app.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(app)
        return app
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating application: {str(e)}")

@router.post("/projects/{project_id}/duplicate", response_model=RASPApp)
async def duplicate_project(
    project_id: str,
    duplicate_data: Dict[str, str],
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Duplicate an existing project/application"""
    try:
        # Get original project
        result = await db.execute(
            db.select(RASPApp).where(RASPApp.id == project_id)
        )
        original_app = result.scalar_one_or_none()
        if not original_app:
            raise HTTPException(status_code=404, detail="Project not found")
            
        # Create new app with duplicated data
        new_app_id = f"app-{uuid.uuid4().hex[:8]}"
        new_app_data = {
            "id": new_app_id,
            "name": duplicate_data.get("name", f"{original_app.name} (Copy)"),
            "key": duplicate_data.get("key", f"{original_app.key}_copy"),
            "framework": original_app.framework,
            "language": original_app.language,
            "env": original_app.env,
            "tags": original_app.tags,
            "risk_score": 0.0,  # Reset risk score for new copy
            "created_by": current_user.id,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        db_new_app = RASPApp(**new_app_data)
        db.add(db_new_app)
        await db.commit()
        await db.refresh(db_new_app)
        
        return db_new_app
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error duplicating project: {str(e)}")

@router.get("/apps/{app_id}/findings", response_model=List[RASPVulnerability])
async def get_application_findings(
    app_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get runtime findings/vulnerabilities for an application"""
    try:
        result = await db.execute(
            db.select(RASPVulnerability).where(
                RASPVulnerability.app_id == app_id
            )
        )
        findings = result.scalars().all()
        return findings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching findings: {str(e)}")

# Agents endpoints
@router.post("/agents/register", response_model=RASPAgent)
async def register_agent(
    agent_data: RASPAgentRegister,
    db: AsyncSession = Depends(get_db)
):
    """Register a new RASP agent"""
    try:
        agent_id = f"agent-{uuid.uuid4().hex[:8]}"
        pairing_token = f"token-{uuid.uuid4().hex[:16]}"
        
        # Get app policies
        result = await db.execute(
            db.select(RASPPolicy).where(
                (RASPPolicy.app_id == agent_data.app_id) | (RASPPolicy.is_global == True)
            )
        )
        policies = result.scalars().all()
        
        config = {
            "pollInterval": 60,
            "policies": [p.id for p in policies]
        }
        
        db_agent = RASPAgent(
            id=agent_id,
            **agent_data.dict(),
            pairing_token=pairing_token,
            config=config
        )
        db.add(db_agent)
        await db.commit()
        await db.refresh(db_agent)
        return db_agent
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error registering agent: {str(e)}")

@router.get("/agents", response_model=RASPListResponse)
async def get_agents(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    app_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    language: Optional[RASPLanguage] = Query(None),
    environment: Optional[RASPEnvironment] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get agents with filtering and pagination"""
    try:
        query = db.select(RASPAgent)
        
        if app_id:
            query = query.where(RASPAgent.app_id == app_id)
        if status:
            query = query.where(RASPAgent.status == status)
        if language:
            query = query.where(RASPAgent.language == language)
        if environment:
            query = query.where(RASPAgent.env == environment)
            
        # Get total count
        count_result = await db.execute(db.select(db.func.count()).select_from(query.subquery()))
        total = count_result.scalar()
        
        # Get paginated results
        result = await db.execute(
            query.offset((page - 1) * size).limit(size)
        )
        agents = result.scalars().all()
        
        pages = (total + size - 1) // size
        
        return RASPListResponse(
            items=agents,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agents: {str(e)}")

@router.get("/agents/{agent_id}/config")
async def get_agent_config(
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get agent configuration and policies"""
    try:
        result = await db.execute(
            db.select(RASPAgent).where(RASPAgent.id == agent_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        # Get policies
        result = await db.execute(
            db.select(RASPPolicy).where(
                (RASPPolicy.app_id == agent.app_id) | (RASPPolicy.is_global == True)
            )
        )
        policies = result.scalars().all()
        
        return {
            "agentId": agent.id,
            "config": agent.config,
            "policies": [p.id for p in policies],
            "pairingTokenStatus": "active" if agent.pairing_token else "inactive"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agent config: {str(e)}")

@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    heartbeat_data: RASPAgentHeartbeat,
    db: AsyncSession = Depends(get_db)
):
    """Update agent heartbeat and metrics"""
    try:
        result = await db.execute(
            db.select(RASPAgent).where(RASPAgent.id == agent_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        agent.last_heartbeat = datetime.utcnow()
        if heartbeat_data.cpu is not None:
            agent.config = agent.config or {}
            agent.config["cpu"] = heartbeat_data.cpu
        if heartbeat_data.mem_mb is not None:
            agent.config = agent.config or {}
            agent.config["mem_mb"] = heartbeat_data.mem_mb
            
        await db.commit()
        return {"status": "updated"}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating heartbeat: {str(e)}")

@router.post("/agents/{agent_id}/events")
async def post_agent_events(
    agent_id: str,
    events_data: RASPEventsBatch,
    db: AsyncSession = Depends(get_db)
):
    """Post agent events (attacks, traces, etc.)"""
    try:
        result = await db.execute(
            db.select(RASPAgent).where(RASPAgent.id == agent_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
            
        # Store events
        for event_data in events_data.events:
            event_id = f"event-{uuid.uuid4().hex[:8]}"
            db_event = RASPEvent(
                id=event_id,
                agent_id=agent_id,
                **event_data.dict()
            )
            db.add(db_event)
            
            # If it's an attack event, create incident
            if event_data.event_type == "attack":
                incident_id = f"incident-{uuid.uuid4().hex[:8]}"
                db_incident = RASPIncident(
                    id=incident_id,
                    app_id=agent.app_id,
                    signature=event_data.signature or "unknown",
                    severity=event_data.severity or RASPIncidentSeverity.MEDIUM,
                    action_taken=event_data.action_taken or RASPAction.MONITORED,
                    evidence=event_data.evidence,
                    stack_trace=event_data.stack_trace,
                    request_data=event_data.request_data,
                    first_seen=event_data.timestamp,
                    last_seen=event_data.timestamp
                )
                db.add(db_incident)
        
        await db.commit()
        return {"status": "events_processed", "count": len(events_data.events)}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error processing events: {str(e)}")

# Incidents endpoints
@router.get("/incidents", response_model=RASPListResponse)
async def get_incidents(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    severity: Optional[RASPIncidentSeverity] = Query(None),
    status: Optional[RASPIncidentStatus] = Query(None),
    app_id: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    signature: Optional[str] = Query(None),
    ip_address: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get incidents with filtering and pagination"""
    try:
        query = db.select(RASPIncident)
        
        if severity:
            query = query.where(RASPIncident.severity == severity)
        if status:
            query = query.where(RASPIncident.status == status)
        if app_id:
            query = query.where(RASPIncident.app_id == app_id)
        if since:
            query = query.where(RASPIncident.created_at >= since)
        if until:
            query = query.where(RASPIncident.created_at <= until)
        if signature:
            query = query.where(RASPIncident.signature.contains(signature))
        if ip_address:
            query = query.where(RASPIncident.ip_address == ip_address)
        if user_id:
            query = query.where(RASPIncident.user_id == user_id)
            
        # Get total count
        count_result = await db.execute(db.select(db.func.count()).select_from(query.subquery()))
        total = count_result.scalar()
        
        # Get paginated results
        result = await db.execute(
            query.order_by(RASPIncident.created_at.desc()).offset((page - 1) * size).limit(size)
        )
        incidents = result.scalars().all()
        
        pages = (total + size - 1) // size
        
        return RASPListResponse(
            items=incidents,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching incidents: {str(e)}")

@router.get("/incidents/{incident_id}", response_model=RASPIncident)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get incident details by ID"""
    try:
        result = await db.execute(
            db.select(RASPIncident).where(RASPIncident.id == incident_id)
        )
        incident = result.scalar_one_or_none()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching incident: {str(e)}")

@router.post("/incidents/{incident_id}/actions")
async def perform_incident_action(
    incident_id: str,
    action_data: RASPIncidentActionCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Perform an action on an incident"""
    try:
        result = await db.execute(
            db.select(RASPIncident).where(RASPIncident.id == incident_id)
        )
        incident = result.scalar_one_or_none()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        action_id = f"action-{uuid.uuid4().hex[:8]}"
        db_action = RASPIncidentAction(
            id=action_id,
            incident_id=incident_id,
            analyst_id=current_user.id,
            **action_data.dict()
        )
        db.add(db_action)
        
        # Update incident based on action
        if action_data.action_type == "mark_fp":
            incident.status = RASPIncidentStatus.FALSE_POSITIVE
        elif action_data.action_type == "ignore":
            incident.status = RASPIncidentStatus.IGNORED
        elif action_data.action_type == "block_signature":
            # Create blocking rule
            pass  # TODO: Implement rule creation
            
        await db.commit()
        return {"status": "action_performed", "action_id": action_id}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error performing action: {str(e)}")

@router.post("/incidents/{incident_id}/comments", response_model=RASPIncidentComment)
async def add_incident_comment(
    incident_id: str,
    comment_data: RASPIncidentCommentCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Add a comment to an incident"""
    try:
        result = await db.execute(
            db.select(RASPIncident).where(RASPIncident.id == incident_id)
        )
        incident = result.scalar_one_or_none()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        comment_id = f"comment-{uuid.uuid4().hex[:8]}"
        db_comment = RASPIncidentComment(
            id=comment_id,
            incident_id=incident_id,
            analyst_id=current_user.id,
            **comment_data.dict()
        )
        db.add(db_comment)
        await db.commit()
        await db.refresh(db_comment)
        return db_comment
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error adding comment: {str(e)}")

# Policies and Rules endpoints
@router.get("/policies", response_model=List[RASPPolicy])
async def get_policies(
    app_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get policies (global and app-specific)"""
    try:
        query = db.select(RASPPolicy)
        if app_id:
            query = query.where(
                (RASPPolicy.app_id == app_id) | (RASPPolicy.is_global == True)
            )
        result = await db.execute(query)
        policies = result.scalars().all()
        return policies
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching policies: {str(e)}")

@router.post("/policies", response_model=RASPPolicy, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_data: RASPPolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new policy"""
    try:
        policy_id = f"policy-{uuid.uuid4().hex[:8]}"
        db_policy = RASPPolicy(
            id=policy_id,
            **policy_data.dict()
        )
        db.add(db_policy)
        await db.commit()
        await db.refresh(db_policy)
        return db_policy
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating policy: {str(e)}")

@router.get("/policies/{policy_id}/rules", response_model=List[RASPRule])
async def get_policy_rules(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get rules for a specific policy"""
    try:
        result = await db.execute(
            db.select(RASPRule).where(RASPRule.policy_id == policy_id)
        )
        rules = result.scalars().all()
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching rules: {str(e)}")

@router.post("/policies/{policy_id}/rules", response_model=RASPRule, status_code=status.HTTP_201_CREATED)
async def create_rule(
    policy_id: str,
    rule_data: RASPRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new rule in a policy"""
    try:
        # Verify policy exists
        result = await db.execute(
            db.select(RASPPolicy).where(RASPPolicy.id == policy_id)
        )
        policy = result.scalar_one_or_none()
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
            
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        db_rule = RASPRule(
            id=rule_id,
            policy_id=policy_id,
            **rule_data.dict()
        )
        db.add(db_rule)
        await db.commit()
        await db.refresh(db_rule)
        return db_rule
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating rule: {str(e)}")

@router.post("/policies/{policy_id}/rules/{rule_id}/simulate", response_model=RASPRuleSimulationResponse)
async def simulate_rule(
    policy_id: str,
    rule_id: str,
    simulation_data: RASPRuleSimulation,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Simulate a rule against a sample request"""
    try:
        result = await db.execute(
            db.select(RASPRule).where(
                RASPRule.id == rule_id,
                RASPRule.policy_id == policy_id
            )
        )
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
            
        # Simple simulation logic (can be enhanced)
        would_match = True  # TODO: Implement actual rule matching logic
        matched_rules = [rule.name] if would_match else []
        explanation = f"Rule '{rule.name}' would {'match' if would_match else 'not match'} the sample request"
        
        return RASPRuleSimulationResponse(
            would_match=would_match,
            matched_rules=matched_rules,
            explanation=explanation
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error simulating rule: {str(e)}")

# Vulnerabilities endpoints
@router.get("/vulnerabilities", response_model=RASPListResponse)
async def get_vulnerabilities(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    app_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[RASPIncidentSeverity] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get runtime vulnerabilities with filtering and pagination"""
    try:
        query = db.select(RASPVulnerability)
        
        if app_id:
            query = query.where(RASPVulnerability.app_id == app_id)
        if status:
            query = query.where(RASPVulnerability.status == status)
        if severity:
            query = query.where(RASPVulnerability.severity == severity)
            
        # Get total count
        count_result = await db.execute(db.select(db.func.count()).select_from(query.subquery()))
        total = count_result.scalar()
        
        # Get paginated results
        result = await db.execute(
            query.order_by(RASPVulnerability.created_at.desc()).offset((page - 1) * size).limit(size)
        )
        vulnerabilities = result.scalars().all()
        
        pages = (total + size - 1) // size
        
        return RASPListResponse(
            items=vulnerabilities,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching vulnerabilities: {str(e)}")

# Traces endpoints
@router.get("/traces", response_model=RASPListResponse)
async def get_traces(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    app_id: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get traces with filtering and pagination"""
    try:
        query = db.select(RASPTrace)
        
        if app_id:
            query = query.where(RASPTrace.app_id == app_id)
        if since:
            query = query.where(RASPTrace.created_at >= since)
            
        # Get total count
        count_result = await db.execute(db.select(db.func.count()).select_from(query.subquery()))
        total = count_result.scalar()
        
        # Get paginated results
        result = await db.execute(
            query.order_by(RASPTrace.created_at.desc()).offset((page - 1) * size).limit(size)
        )
        traces = result.scalars().all()
        
        pages = (total + size - 1) // size
        
        return RASPListResponse(
            items=traces,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching traces: {str(e)}")

# Scans endpoints
@router.get("/scans/recent", response_model=List[Dict[str, Any]])
async def get_recent_scans(
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get recent scans for dashboard feed"""
    try:
        # Mock data for now - can be enhanced with actual scan models
        recent_scans = [
            {
                "id": f"scan-{i}",
                "project_id": f"app-{i % 5 + 1}",
                "status": "completed" if i % 3 == 0 else "running" if i % 3 == 1 else "failed",
                "started_at": (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                "duration": f"{i * 2 + 5}m",
                "findings": i * 3 + 1,
                "scan_type": "full" if i % 2 == 0 else "incremental"
            }
            for i in range(1, limit + 1)
        ]
        return recent_scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching recent scans: {str(e)}")

@router.post("/projects/{project_id}/scans", response_model=Dict[str, Any])
async def start_project_scan(
    project_id: str,
    scan_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Start a new scan for a project"""
    try:
        # Verify project exists
        result = await db.execute(
            db.select(RASPApp).where(RASPApp.id == project_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="Project not found")
            
        # Create scan record (mock for now)
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        scan_record = {
            "id": scan_id,
            "project_id": project_id,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "scan_type": scan_data.get("scan_type", "full"),
            "priority": scan_data.get("priority", "normal"),
            "initiated_by": current_user.id
        }
        
        return {
            "message": "Scan started successfully",
            "scan_id": scan_id,
            "status": "running"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting scan: {str(e)}")

# Attacks endpoints
@router.get("/attacks/recent", response_model=List[Dict[str, Any]])
async def get_recent_attacks(
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get recent attacks for dashboard feed"""
    try:
        # Mock data for now - can be enhanced with actual attack models
        recent_attacks = [
            {
                "id": f"attack-{i}",
                "project_id": f"app-{i % 5 + 1}",
                "type": "sql_injection" if i % 4 == 0 else "xss" if i % 4 == 1 else "rce" if i % 4 == 2 else "path_traversal",
                "severity": "high" if i % 3 == 0 else "medium" if i % 3 == 1 else "low",
                "timestamp": (datetime.utcnow() - timedelta(minutes=i * 15)).isoformat(),
                "blocked": i % 2 == 0,
                "ip_address": f"192.168.1.{i % 255 + 1}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            for i in range(1, limit + 1)
        ]
        return recent_attacks
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching recent attacks: {str(e)}")

@router.get("/attacks", response_model=List[Dict[str, Any]])
async def get_attacks(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get attacks for dashboard display"""
    try:
        # Mock data for now - can be enhanced with actual attack models
        attacks = [
            {
                "id": f"attack-{i}",
                "type": "sql_injection" if i % 4 == 0 else "xss" if i % 4 == 1 else "rce" if i % 4 == 2 else "path_traversal",
                "severity": "high" if i % 3 == 0 else "medium" if i % 3 == 1 else "low",
                "timestamp": (datetime.utcnow() - timedelta(minutes=i * 15)).isoformat(),
                "blocked": i % 2 == 0,
                "ip_address": f"192.168.1.{i % 255 + 1}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "status": "blocked" if i % 2 == 0 else "monitored"
            }
            for i in range(1, limit + 1)
        ]
        return {"attacks": attacks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching attacks: {str(e)}")

# Integrations endpoints
@router.get("/integrations", response_model=List[RASPIntegration])
async def get_integrations(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all integrations"""
    try:
        result = await db.execute(db.select(RASPIntegration))
        integrations = result.scalars().all()
        return integrations
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching integrations: {str(e)}")

@router.post("/integrations", response_model=RASPIntegration, status_code=status.HTTP_201_CREATED)
async def create_integration(
    integration_data: RASPIntegrationCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new integration"""
    try:
        integration_id = f"integration-{uuid.uuid4().hex[:8]}"
        db_integration = RASPIntegration(
            id=integration_id,
            **integration_data.dict()
        )
        db.add(db_integration)
        await db.commit()
        await db.refresh(db_integration)
        return db_integration
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating integration: {str(e)}")

@router.post("/webhooks/test")
async def test_webhook(
    webhook_url: str,
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Test a webhook endpoint"""
    try:
        # TODO: Implement actual webhook testing
        return {"status": "test_sent", "url": webhook_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error testing webhook: {str(e)}") 