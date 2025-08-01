from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models.incident import Incident, IncidentResponse, ResponsePlaybook
from app.schemas.incident import (
    IncidentCreate, IncidentUpdate, IncidentResponse as IncidentResponseSchema,
    IncidentList, IncidentStats, ResponsePlaybookCreate, ResponsePlaybookResponse
)
from app.services.ai_service import ai_service

router = APIRouter()

@router.post("/", response_model=IncidentResponseSchema)
async def create_incident(
    incident: IncidentCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Create a new incident"""
    # Use AI to classify the incident if not provided
    if not incident.incident_type or not incident.severity:
        classification = await ai_service.classify_incident(
            incident.title, incident.description, incident.source_data
        )
        incident.incident_type = incident.incident_type or classification.get("incident_type", "other")
        incident.severity = incident.severity or classification.get("severity", "medium")
    
    incident_data = incident.dict()
    incident_data["reported_by"] = current_user.id
    incident_data["assigned_to"] = incident_data.get("assigned_to") or current_user.id
    
    new_incident = await Incident.create_incident(db, **incident_data)
    return new_incident

@router.get("/", response_model=IncidentList)
async def get_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    assigned_to: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get incidents with filtering and pagination"""
    incidents = await Incident.get_incidents(
        db, skip=skip, limit=limit, status=status, severity=severity,
        incident_type=incident_type, assigned_to=assigned_to
    )
    total = await Incident.count_incidents(db, status=status, severity=severity,
                                         incident_type=incident_type, assigned_to=assigned_to)
    
    return {
        "incidents": incidents,
        "total": total,
        "skip": skip,
        "limit": limit
    }

@router.get("/{incident_id}", response_model=IncidentResponseSchema)
async def get_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get incident by ID"""
    incident = await Incident.get_by_id(db, incident_id=incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    return incident

@router.put("/{incident_id}", response_model=IncidentResponseSchema)
async def update_incident(
    incident_id: int,
    incident_update: IncidentUpdate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Update incident"""
    incident = await Incident.get_by_id(db, incident_id=incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    updated_incident = await incident.update(db, **incident_update.dict(exclude_unset=True))
    return updated_incident

@router.delete("/{incident_id}")
async def delete_incident(
    incident_id: int,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Delete incident"""
    incident = await Incident.get_by_id(db, incident_id=incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    await incident.delete(db)
    return {"message": "Incident deleted successfully"}

@router.get("/stats/overview", response_model=IncidentStats)
async def get_incident_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get incident statistics"""
    stats = await Incident.get_stats(db)
    return stats

@router.post("/{incident_id}/responses", response_model=IncidentResponseSchema)
async def add_incident_response(
    incident_id: int,
    response: IncidentResponseCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Add response to incident"""
    incident = await Incident.get_by_id(db, incident_id=incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    response_data = response.dict()
    response_data["incident_id"] = incident_id
    response_data["created_by"] = current_user.id
    
    new_response = await IncidentResponse.create_response(db, **response_data)
    return new_response

@router.get("/playbooks/", response_model=List[ResponsePlaybookResponse])
async def get_response_playbooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all response playbooks"""
    playbooks = await ResponsePlaybook.get_all(db)
    return playbooks

@router.post("/playbooks/", response_model=ResponsePlaybookResponse)
async def create_response_playbook(
    playbook: ResponsePlaybookCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Create a new response playbook"""
    playbook_data = playbook.dict()
    playbook_data["created_by"] = current_user.id
    
    new_playbook = await ResponsePlaybook.create_playbook(db, **playbook_data)
    return new_playbook 