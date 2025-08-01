import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, text
from sqlalchemy.orm import joinedload
import json
from enum import Enum
from dataclasses import dataclass

from app.models.user import User
from app.models.incident import Incident
from app.services.notification_service import notification_service

logger = structlog.get_logger()

class WorkflowStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ESCALATED = "escalated"

class WorkflowType(Enum):
    INCIDENT_RESPONSE = "incident_response"
    ACCESS_REQUEST = "access_request"
    CHANGE_MANAGEMENT = "change_management"
    APPROVAL_PROCESS = "approval_process"
    ESCALATION = "escalation"
    REMEDIATION = "remediation"

class ActionType(Enum):
    ASSIGN = "assign"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    APPROVE = "approve"
    REJECT = "reject"
    COMPLETE = "complete"
    UPDATE_STATUS = "update_status"
    SEND_EMAIL = "send_email"
    CREATE_TICKET = "create_ticket"
    UPDATE_SLA = "update_sla"

@dataclass
class WorkflowStep:
    id: str
    name: str
    action_type: ActionType
    conditions: Dict[str, Any]
    actions: List[Dict[str, Any]]
    timeout_minutes: int
    required_approvers: List[int]
    auto_approve: bool = False
    escalation_rules: Optional[Dict[str, Any]] = None

@dataclass
class WorkflowDefinition:
    id: str
    name: str
    description: str
    workflow_type: WorkflowType
    steps: List[WorkflowStep]
    triggers: List[str]
    sla_hours: int
    auto_start: bool = True
    enabled: bool = True

class WorkflowService:
    def __init__(self):
        self.active_workflows: Dict[str, Dict[str, Any]] = {}
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        self.workflow_queue = asyncio.Queue()
        self.sla_monitor_task = None
    
    async def start_workflow_service(self):
        """Start the workflow service"""
        logger.info("Starting workflow service")
        self.sla_monitor_task = asyncio.create_task(self._monitor_sla())
        asyncio.create_task(self._process_workflow_queue())
        await self._load_workflow_definitions()
    
    async def _load_workflow_definitions(self):
        """Load workflow definitions from database or configuration"""
        try:
            # Incident Response Workflow
            incident_workflow = WorkflowDefinition(
                id="incident_response_v1",
                name="Incident Response Workflow",
                description="Automated incident response and escalation workflow",
                workflow_type=WorkflowType.INCIDENT_RESPONSE,
                sla_hours=4,
                auto_start=True,
                enabled=True,
                triggers=["incident_created", "incident_updated"],
                steps=[
                    WorkflowStep(
                        id="initial_assessment",
                        name="Initial Assessment",
                        action_type=ActionType.ASSIGN,
                        conditions={"severity": ["high", "critical"]},
                        actions=[
                            {"type": "assign_to_security_team", "team": "security_analysts"},
                            {"type": "notify_stakeholders", "roles": ["admin", "security_manager"]}
                        ],
                        timeout_minutes=30,
                        required_approvers=[],
                        auto_approve=True
                    ),
                    WorkflowStep(
                        id="investigation",
                        name="Investigation",
                        action_type=ActionType.UPDATE_STATUS,
                        conditions={"status": "investigating"},
                        actions=[
                            {"type": "start_investigation", "tools": ["siem", "edr", "network_monitoring"]},
                            {"type": "collect_evidence", "sources": ["logs", "artifacts", "witnesses"]}
                        ],
                        timeout_minutes=120,
                        required_approvers=[1, 2],  # Security analysts
                        auto_approve=False
                    ),
                    WorkflowStep(
                        id="remediation",
                        name="Remediation",
                        action_type=ActionType.REMEDIATION,
                        conditions={"investigation_complete": True},
                        actions=[
                            {"type": "apply_remediation", "actions": ["isolate_host", "block_ioc", "update_firewall"]},
                            {"type": "verify_remediation", "checks": ["malware_scan", "network_scan"]}
                        ],
                        timeout_minutes=60,
                        required_approvers=[1],
                        auto_approve=False
                    ),
                    WorkflowStep(
                        id="closure",
                        name="Incident Closure",
                        action_type=ActionType.COMPLETE,
                        conditions={"remediation_verified": True},
                        actions=[
                            {"type": "update_incident_status", "status": "resolved"},
                            {"type": "generate_report", "template": "incident_summary"},
                            {"type": "notify_completion", "stakeholders": ["reporter", "management"]}
                        ],
                        timeout_minutes=30,
                        required_approvers=[],
                        auto_approve=True
                    )
                ]
            )
            
            # Access Request Workflow
            access_workflow = WorkflowDefinition(
                id="access_request_v1",
                name="Access Request Workflow",
                description="Automated access request approval workflow",
                workflow_type=WorkflowType.ACCESS_REQUEST,
                sla_hours=24,
                auto_start=True,
                enabled=True,
                triggers=["access_request_created"],
                steps=[
                    WorkflowStep(
                        id="manager_approval",
                        name="Manager Approval",
                        action_type=ActionType.APPROVE,
                        conditions={"access_level": ["standard", "elevated"]},
                        actions=[
                            {"type": "notify_manager", "template": "access_request_manager"},
                            {"type": "set_approval_deadline", "hours": 24}
                        ],
                        timeout_minutes=1440,  # 24 hours
                        required_approvers=[],  # Will be set dynamically
                        auto_approve=False
                    ),
                    WorkflowStep(
                        id="security_review",
                        name="Security Review",
                        action_type=ActionType.APPROVE,
                        conditions={"access_level": ["admin", "privileged"]},
                        actions=[
                            {"type": "security_assessment", "checks": ["background_check", "compliance_check"]},
                            {"type": "notify_security_team", "template": "privileged_access_request"}
                        ],
                        timeout_minutes=480,  # 8 hours
                        required_approvers=[1, 2],  # Security team
                        auto_approve=False
                    ),
                    WorkflowStep(
                        id="provision_access",
                        name="Provision Access",
                        action_type=ActionType.ASSIGN,
                        conditions={"approved": True},
                        actions=[
                            {"type": "provision_user_access", "systems": ["active_directory", "vpn", "applications"]},
                            {"type": "send_access_credentials", "method": "secure_email"}
                        ],
                        timeout_minutes=60,
                        required_approvers=[],
                        auto_approve=True
                    )
                ]
            )
            
            self.workflow_definitions = {
                incident_workflow.id: incident_workflow,
                access_workflow.id: access_workflow
            }
            
            logger.info(f"Loaded {len(self.workflow_definitions)} workflow definitions")
            
        except Exception as e:
            logger.error("Failed to load workflow definitions", error=str(e))
    
    async def start_workflow(self, workflow_id: str, context: Dict[str, Any], db: AsyncSession) -> str:
        """Start a new workflow instance"""
        try:
            if workflow_id not in self.workflow_definitions:
                raise ValueError(f"Workflow definition {workflow_id} not found")
            
            workflow_def = self.workflow_definitions[workflow_id]
            if not workflow_def.enabled:
                raise ValueError(f"Workflow {workflow_id} is disabled")
            
            # Create workflow instance
            workflow_instance = {
                "id": f"{workflow_id}_{datetime.utcnow().timestamp()}",
                "workflow_id": workflow_id,
                "status": WorkflowStatus.PENDING.value,
                "context": context,
                "current_step": 0,
                "steps_completed": [],
                "started_at": datetime.utcnow(),
                "sla_deadline": datetime.utcnow() + timedelta(hours=workflow_def.sla_hours),
                "approvals": {},
                "history": []
            }
            
            self.active_workflows[workflow_instance["id"]] = workflow_instance
            
            # Add to processing queue
            await self.workflow_queue.put(workflow_instance)
            
            logger.info(f"Started workflow {workflow_instance['id']}", 
                       workflow_id=workflow_id, 
                       context=context)
            
            return workflow_instance["id"]
            
        except Exception as e:
            logger.error("Failed to start workflow", error=str(e))
            raise
    
    async def _process_workflow_queue(self):
        """Process workflow queue"""
        while True:
            try:
                workflow_instance = await self.workflow_queue.get()
                await self._execute_workflow_step(workflow_instance)
                self.workflow_queue.task_done()
            except Exception as e:
                logger.error("Error processing workflow", error=str(e))
    
    async def _execute_workflow_step(self, workflow_instance: Dict[str, Any]):
        """Execute the current workflow step"""
        try:
            workflow_id = workflow_instance["workflow_id"]
            workflow_def = self.workflow_definitions[workflow_id]
            current_step_index = workflow_instance["current_step"]
            
            if current_step_index >= len(workflow_def.steps):
                # Workflow completed
                workflow_instance["status"] = WorkflowStatus.COMPLETED.value
                workflow_instance["completed_at"] = datetime.utcnow()
                await self._notify_workflow_completion(workflow_instance)
                return
            
            current_step = workflow_def.steps[current_step_index]
            
            # Check if step conditions are met
            if not await self._evaluate_step_conditions(current_step, workflow_instance):
                logger.info(f"Step conditions not met for {current_step.name}", 
                           workflow_id=workflow_instance["id"])
                return
            
            # Execute step actions
            await self._execute_step_actions(current_step, workflow_instance)
            
            # Update workflow state
            workflow_instance["current_step"] += 1
            workflow_instance["steps_completed"].append({
                "step_id": current_step.id,
                "completed_at": datetime.utcnow(),
                "actions_executed": current_step.actions
            })
            
            # Check if step requires approval
            if current_step.required_approvers and not current_step.auto_approve:
                workflow_instance["status"] = WorkflowStatus.IN_PROGRESS.value
                await self._request_approvals(current_step, workflow_instance)
            else:
                # Auto-approve and continue
                await self._approve_step(current_step, workflow_instance)
            
            # Add to history
            workflow_instance["history"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "step_executed",
                "step": current_step.name,
                "status": workflow_instance["status"]
            })
            
        except Exception as e:
            logger.error("Failed to execute workflow step", error=str(e))
            workflow_instance["status"] = WorkflowStatus.CANCELLED.value
            workflow_instance["error"] = str(e)
    
    async def _evaluate_step_conditions(self, step: WorkflowStep, workflow_instance: Dict[str, Any]) -> bool:
        """Evaluate if step conditions are met"""
        try:
            context = workflow_instance["context"]
            
            for condition_key, expected_values in step.conditions.items():
                if condition_key in context:
                    actual_value = context[condition_key]
                    if isinstance(expected_values, list):
                        if actual_value not in expected_values:
                            return False
                    else:
                        if actual_value != expected_values:
                            return False
                else:
                    return False
            
            return True
            
        except Exception as e:
            logger.error("Failed to evaluate step conditions", error=str(e))
            return False
    
    async def _execute_step_actions(self, step: WorkflowStep, workflow_instance: Dict[str, Any]):
        """Execute step actions"""
        try:
            for action in step.actions:
                action_type = action.get("type")
                
                if action_type == "assign_to_security_team":
                    await self._assign_to_security_team(action, workflow_instance)
                elif action_type == "notify_stakeholders":
                    await self._notify_stakeholders(action, workflow_instance)
                elif action_type == "start_investigation":
                    await self._start_investigation(action, workflow_instance)
                elif action_type == "apply_remediation":
                    await self._apply_remediation(action, workflow_instance)
                elif action_type == "update_incident_status":
                    await self._update_incident_status(action, workflow_instance)
                elif action_type == "provision_user_access":
                    await self._provision_user_access(action, workflow_instance)
                else:
                    logger.warning(f"Unknown action type: {action_type}")
            
        except Exception as e:
            logger.error("Failed to execute step actions", error=str(e))
            raise
    
    async def _assign_to_security_team(self, action: Dict[str, Any], workflow_instance: Dict[str, Any]):
        """Assign incident to security team"""
        try:
            team = action.get("team", "security_analysts")
            incident_id = workflow_instance["context"].get("incident_id")
            
            # In a real implementation, this would query the database for team members
            team_members = [1, 2, 3]  # Mock team member IDs
            
            # Assign to first available team member
            assigned_to = team_members[0]
            
            # Update incident assignment
            workflow_instance["context"]["assigned_to"] = assigned_to
            
            # Send notification
            await notification_service.send_personal_message({
                "recipient_id": assigned_to,
                "type": "in_app",
                "notification_type": "incident",
                "priority": "high",
                "message": f"New incident assigned: {incident_id}",
                "action_url": f"/incidents/{incident_id}"
            })
            
            logger.info(f"Assigned incident {incident_id} to team member {assigned_to}")
            
        except Exception as e:
            logger.error("Failed to assign to security team", error=str(e))
    
    async def _notify_stakeholders(self, action: Dict[str, Any], workflow_instance: Dict[str, Any]):
        """Notify stakeholders about workflow progress"""
        try:
            roles = action.get("roles", [])
            incident_id = workflow_instance["context"].get("incident_id")
            
            # In a real implementation, this would query users by role
            for role in roles:
                # Mock user IDs for each role
                user_ids = {"admin": [1], "security_manager": [2]}.get(role, [])
                
                for user_id in user_ids:
                    await notification_service.send_personal_message({
                        "recipient_id": user_id,
                        "type": "in_app",
                        "notification_type": "workflow",
                        "priority": "medium",
                        "message": f"Workflow update for incident {incident_id}",
                        "action_url": f"/incidents/{incident_id}"
                    })
            
        except Exception as e:
            logger.error("Failed to notify stakeholders", error=str(e))
    
    async def _start_investigation(self, action: Dict[str, Any], workflow_instance: Dict[str, Any]):
        """Start incident investigation"""
        try:
            tools = action.get("tools", [])
            incident_id = workflow_instance["context"].get("incident_id")
            
            # In a real implementation, this would trigger investigation tools
            for tool in tools:
                logger.info(f"Starting {tool} investigation for incident {incident_id}")
            
            # Update context
            workflow_instance["context"]["investigation_started"] = True
            workflow_instance["context"]["investigation_tools"] = tools
            
        except Exception as e:
            logger.error("Failed to start investigation", error=str(e))
    
    async def _apply_remediation(self, action: Dict[str, Any], workflow_instance: Dict[str, Any]):
        """Apply remediation actions"""
        try:
            remediation_actions = action.get("actions", [])
            incident_id = workflow_instance["context"].get("incident_id")
            
            # In a real implementation, this would execute remediation actions
            for remediation_action in remediation_actions:
                logger.info(f"Applying {remediation_action} for incident {incident_id}")
            
            # Update context
            workflow_instance["context"]["remediation_applied"] = True
            workflow_instance["context"]["remediation_actions"] = remediation_actions
            
        except Exception as e:
            logger.error("Failed to apply remediation", error=str(e))
    
    async def _update_incident_status(self, action: Dict[str, Any], workflow_instance: Dict[str, Any]):
        """Update incident status"""
        try:
            new_status = action.get("status")
            incident_id = workflow_instance["context"].get("incident_id")
            
            # In a real implementation, this would update the database
            logger.info(f"Updating incident {incident_id} status to {new_status}")
            
            # Update context
            workflow_instance["context"]["incident_status"] = new_status
            
        except Exception as e:
            logger.error("Failed to update incident status", error=str(e))
    
    async def _provision_user_access(self, action: Dict[str, Any], workflow_instance: Dict[str, Any]):
        """Provision user access"""
        try:
            systems = action.get("systems", [])
            user_id = workflow_instance["context"].get("user_id")
            
            # In a real implementation, this would provision access in each system
            for system in systems:
                logger.info(f"Provisioning access for user {user_id} in {system}")
            
            # Update context
            workflow_instance["context"]["access_provisioned"] = True
            workflow_instance["context"]["provisioned_systems"] = systems
            
        except Exception as e:
            logger.error("Failed to provision user access", error=str(e))
    
    async def _request_approvals(self, step: WorkflowStep, workflow_instance: Dict[str, Any]):
        """Request approvals for workflow step"""
        try:
            for approver_id in step.required_approvers:
                await notification_service.send_personal_message({
                    "recipient_id": approver_id,
                    "type": "in_app",
                    "notification_type": "approval",
                    "priority": "high",
                    "message": f"Approval required for workflow step: {step.name}",
                    "action_url": f"/workflows/{workflow_instance['id']}/approve",
                    "metadata": {
                        "workflow_id": workflow_instance["id"],
                        "step_id": step.id,
                        "approval_type": "workflow_step"
                    }
                })
                
                # Track approval request
                workflow_instance["approvals"][step.id] = {
                    "requested_at": datetime.utcnow().isoformat(),
                    "approvers": step.required_approvers,
                    "approved_by": [],
                    "rejected_by": [],
                    "status": "pending"
                }
            
        except Exception as e:
            logger.error("Failed to request approvals", error=str(e))
    
    async def approve_workflow_step(self, workflow_id: str, step_id: str, approver_id: int, approved: bool):
        """Approve or reject a workflow step"""
        try:
            if workflow_id not in self.active_workflows:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            workflow_instance = self.active_workflows[workflow_id]
            workflow_def = self.workflow_definitions[workflow_instance["workflow_id"]]
            
            # Find the step
            current_step = None
            for step in workflow_def.steps:
                if step.id == step_id:
                    current_step = step
                    break
            
            if not current_step:
                raise ValueError(f"Step {step_id} not found in workflow")
            
            # Update approval status
            if step_id in workflow_instance["approvals"]:
                approval_info = workflow_instance["approvals"][step_id]
                
                if approved:
                    approval_info["approved_by"].append(approver_id)
                else:
                    approval_info["rejected_by"].append(approver_id)
                
                # Check if all approvals are complete
                if len(approval_info["approved_by"]) + len(approval_info["rejected_by"]) >= len(current_step.required_approvers):
                    if len(approval_info["rejected_by"]) > 0:
                        # Step rejected
                        workflow_instance["status"] = WorkflowStatus.REJECTED.value
                        await self._notify_workflow_rejection(workflow_instance, step_id)
                    else:
                        # Step approved
                        await self._approve_step(current_step, workflow_instance)
            
            # Add to history
            workflow_instance["history"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "step_approved" if approved else "step_rejected",
                "step": step_id,
                "approver": approver_id
            })
            
        except Exception as e:
            logger.error("Failed to approve workflow step", error=str(e))
            raise
    
    async def _approve_step(self, step: WorkflowStep, workflow_instance: Dict[str, Any]):
        """Approve a workflow step and continue"""
        try:
            workflow_instance["status"] = WorkflowStatus.IN_PROGRESS.value
            
            # Continue to next step
            await self.workflow_queue.put(workflow_instance)
            
            logger.info(f"Step {step.name} approved, continuing workflow", 
                       workflow_id=workflow_instance["id"])
            
        except Exception as e:
            logger.error("Failed to approve step", error=str(e))
    
    async def _monitor_sla(self):
        """Monitor SLA deadlines for active workflows"""
        while True:
            try:
                current_time = datetime.utcnow()
                workflows_to_escalate = []
                
                for workflow_id, workflow_instance in self.active_workflows.items():
                    if workflow_instance["status"] in [WorkflowStatus.PENDING.value, WorkflowStatus.IN_PROGRESS.value]:
                        if current_time > workflow_instance["sla_deadline"]:
                            workflows_to_escalate.append(workflow_id)
                
                for workflow_id in workflows_to_escalate:
                    await self._escalate_workflow(workflow_id)
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error("Error in SLA monitoring", error=str(e))
                await asyncio.sleep(300)
    
    async def _escalate_workflow(self, workflow_id: str):
        """Escalate workflow due to SLA breach"""
        try:
            workflow_instance = self.active_workflows[workflow_id]
            workflow_instance["status"] = WorkflowStatus.ESCALATED.value
            
            # Notify management
            await notification_service.send_personal_message({
                "recipient_id": 1,  # Management user ID
                "type": "in_app",
                "notification_type": "sla_breach",
                "priority": "critical",
                "message": f"Workflow {workflow_id} has exceeded SLA",
                "action_url": f"/workflows/{workflow_id}"
            })
            
            # Add to history
            workflow_instance["history"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "workflow_escalated",
                "reason": "SLA breach"
            })
            
            logger.warning(f"Workflow {workflow_id} escalated due to SLA breach")
            
        except Exception as e:
            logger.error("Failed to escalate workflow", error=str(e))
    
    async def _notify_workflow_completion(self, workflow_instance: Dict[str, Any]):
        """Notify stakeholders of workflow completion"""
        try:
            workflow_id = workflow_instance["id"]
            context = workflow_instance["context"]
            
            # Notify relevant stakeholders
            stakeholders = context.get("stakeholders", [])
            for stakeholder_id in stakeholders:
                await notification_service.send_personal_message({
                    "recipient_id": stakeholder_id,
                    "type": "in_app",
                    "notification_type": "workflow_completed",
                    "priority": "medium",
                    "message": f"Workflow {workflow_id} has been completed",
                    "action_url": f"/workflows/{workflow_id}"
                })
            
        except Exception as e:
            logger.error("Failed to notify workflow completion", error=str(e))
    
    async def _notify_workflow_rejection(self, workflow_instance: Dict[str, Any], step_id: str):
        """Notify stakeholders of workflow rejection"""
        try:
            workflow_id = workflow_instance["id"]
            context = workflow_instance["context"]
            
            # Notify relevant stakeholders
            stakeholders = context.get("stakeholders", [])
            for stakeholder_id in stakeholders:
                await notification_service.send_personal_message({
                    "recipient_id": stakeholder_id,
                    "type": "in_app",
                    "notification_type": "workflow_rejected",
                    "priority": "high",
                    "message": f"Workflow {workflow_id} was rejected at step {step_id}",
                    "action_url": f"/workflows/{workflow_id}"
                })
            
        except Exception as e:
            logger.error("Failed to notify workflow rejection", error=str(e))
    
    async def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status"""
        return self.active_workflows.get(workflow_id)
    
    async def get_user_workflows(self, user_id: int) -> List[Dict[str, Any]]:
        """Get workflows for a specific user"""
        try:
            user_workflows = []
            
            for workflow_instance in self.active_workflows.values():
                context = workflow_instance["context"]
                
                # Check if user is involved in this workflow
                if (context.get("assigned_to") == user_id or 
                    context.get("reported_by") == user_id or
                    user_id in context.get("stakeholders", [])):
                    user_workflows.append(workflow_instance)
            
            return user_workflows
            
        except Exception as e:
            logger.error("Failed to get user workflows", error=str(e))
            return []
    
    async def get_workflow_definitions(self) -> List[Dict[str, Any]]:
        """Get all workflow definitions"""
        try:
            definitions = []
            for workflow_def in self.workflow_definitions.values():
                definitions.append({
                    "id": workflow_def.id,
                    "name": workflow_def.name,
                    "description": workflow_def.description,
                    "workflow_type": workflow_def.workflow_type.value,
                    "sla_hours": workflow_def.sla_hours,
                    "enabled": workflow_def.enabled,
                    "steps_count": len(workflow_def.steps)
                })
            
            return definitions
            
        except Exception as e:
            logger.error("Failed to get workflow definitions", error=str(e))
            return []

# Global instance
workflow_service = WorkflowService() 