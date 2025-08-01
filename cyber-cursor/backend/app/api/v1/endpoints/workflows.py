from fastapi import APIRouter, Depends, HTTPException, Query, Body, Path
from typing import List, Dict, Any, Optional
import structlog
from datetime import datetime

from app.services.workflow_service import workflow_service
from app.models.user import User
from app.core.database import get_db

logger = structlog.get_logger()
router = APIRouter()

@router.get("/definitions")
async def get_workflow_definitions(
    current_user: User = Depends(get_db().get_current_user)
):
    """Get all available workflow definitions"""
    try:
        definitions = await workflow_service.get_workflow_definitions()
        return {
            "success": True,
            "data": definitions,
            "total": len(definitions)
        }
    except Exception as e:
        logger.error("Failed to get workflow definitions", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get workflow definitions")

@router.post("/start")
async def start_workflow(
    workflow_id: str = Body(..., embed=True),
    context: Dict[str, Any] = Body(..., embed=True),
    current_user: User = Depends(get_db().get_current_user)
):
    """Start a new workflow instance"""
    try:
        # Add user context
        context["user_id"] = current_user.id
        context["started_by"] = current_user.id
        context["started_at"] = datetime.utcnow().isoformat()
        
        workflow_instance_id = await workflow_service.start_workflow(workflow_id, context, get_db())
        
        return {
            "success": True,
            "workflow_instance_id": workflow_instance_id,
            "message": f"Workflow {workflow_id} started successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Failed to start workflow", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start workflow")

@router.get("/status/{workflow_id}")
async def get_workflow_status(
    workflow_id: str = Path(..., description="Workflow instance ID"),
    current_user: User = Depends(get_db().get_current_user)
):
    """Get workflow status"""
    try:
        workflow_status = await workflow_service.get_workflow_status(workflow_id)
        
        if not workflow_status:
            raise HTTPException(status_code=404, detail="Workflow not found")
        
        return {
            "success": True,
            "data": workflow_status
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get workflow status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get workflow status")

@router.get("/user")
async def get_user_workflows(
    current_user: User = Depends(get_db().get_current_user)
):
    """Get workflows for the current user"""
    try:
        user_workflows = await workflow_service.get_user_workflows(current_user.id)
        
        return {
            "success": True,
            "data": user_workflows,
            "total": len(user_workflows)
        }
    except Exception as e:
        logger.error("Failed to get user workflows", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get user workflows")

@router.post("/approve")
async def approve_workflow_step(
    workflow_id: str = Body(..., embed=True),
    step_id: str = Body(..., embed=True),
    approved: bool = Body(True, embed=True),
    current_user: User = Depends(get_db().get_current_user)
):
    """Approve or reject a workflow step"""
    try:
        await workflow_service.approve_workflow_step(workflow_id, step_id, current_user.id, approved)
        
        action = "approved" if approved else "rejected"
        return {
            "success": True,
            "message": f"Workflow step {step_id} {action} successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Failed to approve workflow step", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to approve workflow step")

@router.post("/incident-response")
async def start_incident_response_workflow(
    incident_id: int = Body(..., embed=True),
    severity: str = Body(..., embed=True),
    current_user: User = Depends(get_db().get_current_user)
):
    """Start incident response workflow"""
    try:
        context = {
            "incident_id": incident_id,
            "severity": severity,
            "workflow_type": "incident_response",
            "stakeholders": [current_user.id]
        }
        
        workflow_instance_id = await workflow_service.start_workflow("incident_response_v1", context, get_db())
        
        return {
            "success": True,
            "workflow_instance_id": workflow_instance_id,
            "message": "Incident response workflow started"
        }
    except Exception as e:
        logger.error("Failed to start incident response workflow", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start incident response workflow")

@router.post("/access-request")
async def start_access_request_workflow(
    user_id: int = Body(..., embed=True),
    access_level: str = Body(..., embed=True),
    systems: List[str] = Body(..., embed=True),
    reason: str = Body(..., embed=True),
    current_user: User = Depends(get_db().get_current_user)
):
    """Start access request workflow"""
    try:
        context = {
            "user_id": user_id,
            "access_level": access_level,
            "systems": systems,
            "reason": reason,
            "requested_by": current_user.id,
            "workflow_type": "access_request",
            "stakeholders": [user_id, current_user.id]
        }
        
        workflow_instance_id = await workflow_service.start_workflow("access_request_v1", context, get_db())
        
        return {
            "success": True,
            "workflow_instance_id": workflow_instance_id,
            "message": "Access request workflow started"
        }
    except Exception as e:
        logger.error("Failed to start access request workflow", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start access request workflow")

@router.get("/pending-approvals")
async def get_pending_approvals(
    current_user: User = Depends(get_db().get_current_user)
):
    """Get pending approvals for the current user"""
    try:
        user_workflows = await workflow_service.get_user_workflows(current_user.id)
        
        pending_approvals = []
        for workflow in user_workflows:
            if workflow["status"] == "in_progress":
                approvals = workflow.get("approvals", {})
                for step_id, approval_info in approvals.items():
                    if approval_info["status"] == "pending":
                        pending_approvals.append({
                            "workflow_id": workflow["id"],
                            "step_id": step_id,
                            "workflow_name": workflow.get("workflow_id", "Unknown"),
                            "requested_at": approval_info["requested_at"],
                            "context": workflow.get("context", {})
                        })
        
        return {
            "success": True,
            "data": pending_approvals,
            "total": len(pending_approvals)
        }
    except Exception as e:
        logger.error("Failed to get pending approvals", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get pending approvals")

@router.get("/history")
async def get_workflow_history(
    workflow_id: str = Query(..., description="Workflow instance ID"),
    current_user: User = Depends(get_db().get_current_user)
):
    """Get workflow history"""
    try:
        workflow_status = await workflow_service.get_workflow_status(workflow_id)
        
        if not workflow_status:
            raise HTTPException(status_code=404, detail="Workflow not found")
        
        history = workflow_status.get("history", [])
        
        return {
            "success": True,
            "data": history,
            "total": len(history)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get workflow history", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get workflow history")

@router.get("/metrics")
async def get_workflow_metrics(
    time_range: str = Query("30d", description="Time range for metrics"),
    current_user: User = Depends(get_db().get_current_user)
):
    """Get workflow metrics"""
    try:
        user_workflows = await workflow_service.get_user_workflows(current_user.id)
        
        # Calculate metrics
        total_workflows = len(user_workflows)
        completed_workflows = len([w for w in user_workflows if w["status"] == "completed"])
        in_progress_workflows = len([w for w in user_workflows if w["status"] == "in_progress"])
        failed_workflows = len([w for w in user_workflows if w["status"] in ["rejected", "cancelled"]])
        
        # Calculate average completion time
        completion_times = []
        for workflow in user_workflows:
            if workflow["status"] == "completed" and "completed_at" in workflow:
                started_at = datetime.fromisoformat(workflow["started_at"])
                completed_at = datetime.fromisoformat(workflow["completed_at"])
                completion_time = (completed_at - started_at).total_seconds() / 3600  # hours
                completion_times.append(completion_time)
        
        avg_completion_time = sum(completion_times) / len(completion_times) if completion_times else 0
        
        metrics = {
            "total_workflows": total_workflows,
            "completed_workflows": completed_workflows,
            "in_progress_workflows": in_progress_workflows,
            "failed_workflows": failed_workflows,
            "completion_rate": (completed_workflows / total_workflows * 100) if total_workflows > 0 else 0,
            "avg_completion_time_hours": round(avg_completion_time, 2)
        }
        
        return {
            "success": True,
            "data": metrics,
            "time_range": time_range
        }
    except Exception as e:
        logger.error("Failed to get workflow metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get workflow metrics") 