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
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging
import json

from app.core.database import get_db
from app.models.rasp import (
    RASPAgent, RASPAttack, RASPRule, RASPVulnerability, RASPVirtualPatch,
    RASPTelemetry, RASPAlert, RASPIntegration,
    AgentStatus, AttackSeverity, VulnerabilityStatus, AlertStatus, PatchStatus
)
from app.services.rasp_service import RASPService
from app.schemas.rasp import (
    AgentCreate, AgentUpdate, AgentResponse,
    AttackResponse, AttackCreate,
    RuleCreate, RuleUpdate, RuleResponse,
    VulnerabilityResponse, VulnerabilityUpdate,
    VirtualPatchCreate, VirtualPatchResponse,
    AlertResponse, AlertUpdate,
    IntegrationCreate, IntegrationResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()


# Agent Management Endpoints
@router.get("/agents", response_model=List[AgentResponse])
async def get_agents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = None,
    language: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get all RASP agents with optional filtering"""
    try:
        service = RASPService(db)
        agents = await service.get_agents(skip=skip, limit=limit, status=status, language=language)
        return agents
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific RASP agent by ID"""
    try:
        service = RASPService(db)
        agent = await service.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/agents", response_model=AgentResponse)
async def create_agent(agent_data: AgentCreate, db: AsyncSession = Depends(get_db)):
    """Create a new RASP agent"""
    try:
        service = RASPService(db)
        agent = await service.create_agent(agent_data)
        return agent
    except Exception as e:
        logger.error(f"Error creating agent: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/agents/{agent_id}", response_model=AgentResponse)
async def update_agent(agent_id: int, agent_data: AgentUpdate, db: AsyncSession = Depends(get_db)):
    """Update an existing RASP agent"""
    try:
        service = RASPService(db)
        agent = await service.update_agent(agent_id, agent_data)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a RASP agent"""
    try:
        service = RASPService(db)
        success = await service.delete_agent(agent_id)
        if not success:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"message": "Agent deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Attack Management Endpoints
@router.get("/attacks", response_model=List[AttackResponse])
async def get_attacks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    agent_id: Optional[int] = None,
    vuln_type: Optional[str] = None,
    severity: Optional[str] = None,
    blocked: Optional[bool] = None,
    hours: int = Query(24, ge=1, le=168),  # Default 24 hours, max 1 week
    db: AsyncSession = Depends(get_db)
):
    """Get recent attacks with optional filtering"""
    try:
        service = RASPService(db)
        attacks = await service.get_attacks(
            skip=skip, limit=limit, agent_id=agent_id, vuln_type=vuln_type,
            severity=severity, blocked=blocked, hours=hours
        )
        return attacks
    except Exception as e:
        logger.error(f"Error getting attacks: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/attacks/{attack_id}", response_model=AttackResponse)
async def get_attack(attack_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific attack by ID"""
    try:
        service = RASPService(db)
        attack = await service.get_attack(attack_id)
        if not attack:
            raise HTTPException(status_code=404, detail="Attack not found")
        return attack
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting attack {attack_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/attacks", response_model=AttackResponse)
async def create_attack(attack_data: AttackCreate, db: AsyncSession = Depends(get_db)):
    """Create a new attack record (typically called by agents)"""
    try:
        service = RASPService(db)
        attack = await service.create_attack(attack_data)
        return attack
    except Exception as e:
        logger.error(f"Error creating attack: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Rule Management Endpoints
@router.get("/rules", response_model=List[RuleResponse])
async def get_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    language: Optional[str] = None,
    vuln_type: Optional[str] = None,
    enabled: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get detection rules with optional filtering"""
    try:
        service = RASPService(db)
        rules = await service.get_rules(skip=skip, limit=limit, language=language, vuln_type=vuln_type, enabled=enabled)
        return rules
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/rules/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific rule by ID"""
    try:
        service = RASPService(db)
        rule = await service.get_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        return rule
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/rules", response_model=RuleResponse)
async def create_rule(rule_data: RuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new detection rule"""
    try:
        service = RASPService(db)
        rule = await service.create_rule(rule_data)
        return rule
    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: int, rule_data: RuleUpdate, db: AsyncSession = Depends(get_db)):
    """Update an existing detection rule"""
    try:
        service = RASPService(db)
        rule = await service.update_rule(rule_id, rule_data)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        return rule
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a detection rule"""
    try:
        service = RASPService(db)
        success = await service.delete_rule(rule_id)
        if not success:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"message": "Rule deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Vulnerability Management Endpoints
@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    agent_id: Optional[int] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get vulnerabilities with optional filtering"""
    try:
        service = RASPService(db)
        vulnerabilities = await service.get_vulnerabilities(
            skip=skip, limit=limit, agent_id=agent_id, status=status,
            severity=severity, vuln_type=vuln_type
        )
        return vulnerabilities
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific vulnerability by ID"""
    try:
        service = RASPService(db)
        vulnerability = await service.get_vulnerability(vuln_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vulnerability
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vulnerability {vuln_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(vuln_id: int, vuln_data: VulnerabilityUpdate, db: AsyncSession = Depends(get_db)):
    """Update vulnerability status and details"""
    try:
        service = RASPService(db)
        vulnerability = await service.update_vulnerability(vuln_id, vuln_data)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vulnerability
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating vulnerability {vuln_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Virtual Patching Endpoints
@router.get("/virtual-patches", response_model=List[VirtualPatchResponse])
async def get_virtual_patches(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    agent_id: Optional[int] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get virtual patches with optional filtering"""
    try:
        service = RASPService(db)
        patches = await service.get_virtual_patches(skip=skip, limit=limit, agent_id=agent_id, status=status)
        return patches
    except Exception as e:
        logger.error(f"Error getting virtual patches: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/virtual-patches", response_model=VirtualPatchResponse)
async def create_virtual_patch(patch_data: VirtualPatchCreate, db: AsyncSession = Depends(get_db)):
    """Create a new virtual patch"""
    try:
        service = RASPService(db)
        patch = await service.create_virtual_patch(patch_data)
        return patch
    except Exception as e:
        logger.error(f"Error creating virtual patch: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Alert Management Endpoints
@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    agent_id: Optional[int] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get alerts with optional filtering"""
    try:
        service = RASPService(db)
        alerts = await service.get_alerts(skip=skip, limit=limit, agent_id=agent_id, status=status, severity=severity)
        return alerts
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/alerts/{alert_id}", response_model=AlertResponse)
async def update_alert(alert_id: int, alert_data: AlertUpdate, db: AsyncSession = Depends(get_db)):
    """Update alert status (acknowledge, resolve, etc.)"""
    try:
        service = RASPService(db)
        alert = await service.update_alert(alert_id, alert_data)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Dashboard and Analytics Endpoints
@router.get("/dashboard/overview")
async def get_rasp_overview(db: AsyncSession = Depends(get_db)):
    """Get RASP dashboard overview with key metrics"""
    try:
        service = RASPService(db)
        overview = await service.get_dashboard_overview()
        return overview
    except Exception as e:
        logger.error(f"Error getting RASP overview: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/dashboard/attack-summary")
async def get_attack_summary(
    hours: int = Query(24, ge=1, le=168),
    agent_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get attack summary statistics"""
    try:
        service = RASPService(db)
        summary = await service.get_attack_summary(hours=hours, agent_id=agent_id)
        return summary
    except Exception as e:
        logger.error(f"Error getting attack summary: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/dashboard/agent-status")
async def get_agent_status(db: AsyncSession = Depends(get_db)):
    """Get agent status and health information"""
    try:
        service = RASPService(db)
        status = await service.get_agent_status()
        return status
    except Exception as e:
        logger.error(f"Error getting agent status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Integration Endpoints
@router.get("/integrations", response_model=List[IntegrationResponse])
async def get_integrations(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    integration_type: Optional[str] = None,
    enabled: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get SIEM/SOAR integrations"""
    try:
        service = RASPService(db)
        integrations = await service.get_integrations(skip=skip, limit=limit, integration_type=integration_type, enabled=enabled)
        return integrations
    except Exception as e:
        logger.error(f"Error getting integrations: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/integrations", response_model=IntegrationResponse)
async def create_integration(integration_data: IntegrationCreate, db: AsyncSession = Depends(get_db)):
    """Create a new SIEM/SOAR integration"""
    try:
        service = RASPService(db)
        integration = await service.create_integration(integration_data)
        return integration
    except Exception as e:
        logger.error(f"Error creating integration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Agent Heartbeat Endpoint
@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: int,
    heartbeat_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    """Update agent heartbeat and telemetry data"""
    try:
        service = RASPService(db)
        success = await service.update_agent_heartbeat(agent_id, heartbeat_data)
        if not success:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"message": "Heartbeat updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating agent heartbeat {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Webhook Endpoint for External Integrations
@router.post("/webhook")
async def rasp_webhook(
    webhook_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    """Webhook endpoint for external integrations (SIEM, SOAR, etc.)"""
    try:
        service = RASPService(db)
        result = await service.process_webhook(webhook_data)
        return result
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 