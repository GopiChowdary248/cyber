from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from typing import List, Optional
from datetime import datetime, timedelta
import uuid

from app.core.database import get_db
from app.models.user import User
from app.core.auth import get_current_user
from app.schemas.quality_goals import (
    QualityGoalCreate,
    QualityGoalUpdate,
    QualityGoalResponse,
    QualityGoalListResponse,
    QualityMetricsResponse
)

router = APIRouter()

# Mock data for quality goals (in a real implementation, this would be stored in the database)
MOCK_QUALITY_GOALS = [
    {
        "id": "1",
        "title": "Address Critical Vulnerabilities",
        "description": "Fix all critical security vulnerabilities identified in SAST scans",
        "category": "immediate",
        "priority": "high",
        "status": "in-progress",
        "progress": 65,
        "target_date": (datetime.utcnow() + timedelta(days=7)).isoformat(),
        "current_value": "5 critical",
        "target_value": "0 critical",
        "metric": "Critical Vulnerabilities",
        "impact": "security",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "2",
        "title": "Increase Test Coverage",
        "description": "Improve test coverage for projects with low coverage ratings",
        "category": "immediate",
        "priority": "high",
        "status": "in-progress",
        "progress": 40,
        "target_date": (datetime.utcnow() + timedelta(days=14)).isoformat(),
        "current_value": "75%",
        "target_value": "85%",
        "metric": "Test Coverage",
        "impact": "coverage",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "3",
        "title": "Reduce Technical Debt",
        "description": "Refactor code to reduce technical debt in high-debt projects",
        "category": "immediate",
        "priority": "medium",
        "status": "not-started",
        "progress": 0,
        "target_date": (datetime.utcnow() + timedelta(days=21)).isoformat(),
        "current_value": "45 hours",
        "target_value": "36 hours",
        "metric": "Technical Debt",
        "impact": "maintainability",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "4",
        "title": "Improve Security Rating to A",
        "description": "Achieve A rating for security by addressing all high-priority vulnerabilities",
        "category": "short-term",
        "priority": "high",
        "status": "in-progress",
        "progress": 75,
        "target_date": (datetime.utcnow() + timedelta(days=14)).isoformat(),
        "current_value": "B",
        "target_value": "A",
        "metric": "Security Rating",
        "impact": "security",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "5",
        "title": "Increase Coverage Rating to A",
        "description": "Achieve A rating for test coverage by improving test suite",
        "category": "short-term",
        "priority": "medium",
        "status": "in-progress",
        "progress": 60,
        "target_date": (datetime.utcnow() + timedelta(days=14)).isoformat(),
        "current_value": "B",
        "target_value": "A",
        "metric": "Coverage Rating",
        "impact": "coverage",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "6",
        "title": "Reduce Technical Debt by 20%",
        "description": "Reduce technical debt from 45 hours to 36 hours",
        "category": "short-term",
        "priority": "medium",
        "status": "not-started",
        "progress": 0,
        "target_date": (datetime.utcnow() + timedelta(days=14)).isoformat(),
        "current_value": "45 hours",
        "target_value": "36 hours",
        "metric": "Technical Debt",
        "impact": "maintainability",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "7",
        "title": "Achieve A Ratings Across All Metrics",
        "description": "Maintain A ratings for security, reliability, maintainability, and coverage",
        "category": "long-term",
        "priority": "high",
        "status": "not-started",
        "progress": 0,
        "target_date": (datetime.utcnow() + timedelta(days=60)).isoformat(),
        "current_value": "B (avg)",
        "target_value": "A (all)",
        "metric": "Overall Quality",
        "impact": "overall",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "8",
        "title": "Implement Automated Quality Gates",
        "description": "Set up automated quality gates in CI/CD pipeline",
        "category": "long-term",
        "priority": "medium",
        "status": "not-started",
        "progress": 0,
        "target_date": (datetime.utcnow() + timedelta(days=45)).isoformat(),
        "current_value": "Manual",
        "target_value": "Automated",
        "metric": "Quality Gates",
        "impact": "overall",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    },
    {
        "id": "9",
        "title": "Establish Quality Monitoring Dashboards",
        "description": "Create comprehensive quality monitoring and reporting system",
        "category": "long-term",
        "priority": "medium",
        "status": "not-started",
        "progress": 0,
        "target_date": (datetime.utcnow() + timedelta(days=60)).isoformat(),
        "current_value": "Basic",
        "target_value": "Comprehensive",
        "metric": "Monitoring",
        "impact": "overall",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
]

@router.get("/goals", response_model=QualityGoalListResponse)
async def get_quality_goals(
    category: Optional[str] = None,
    priority: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all quality goals with optional filtering"""
    goals = MOCK_QUALITY_GOALS.copy()
    
    # Apply filters
    if category:
        goals = [goal for goal in goals if goal["category"] == category]
    if priority:
        goals = [goal for goal in goals if goal["priority"] == priority]
    if status:
        goals = [goal for goal in goals if goal["status"] == status]
    
    return {
        "goals": goals,
        "total": len(goals),
        "categories": ["immediate", "short-term", "long-term"],
        "priorities": ["high", "medium", "low"],
        "statuses": ["not-started", "in-progress", "completed", "blocked"]
    }

@router.get("/goals/{goal_id}", response_model=QualityGoalResponse)
async def get_quality_goal(
    goal_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific quality goal by ID"""
    goal = next((goal for goal in MOCK_QUALITY_GOALS if goal["id"] == goal_id), None)
    if not goal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quality goal not found"
        )
    return goal

@router.post("/goals", response_model=QualityGoalResponse)
async def create_quality_goal(
    goal_data: QualityGoalCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new quality goal"""
    new_goal = {
        "id": str(uuid.uuid4()),
        **goal_data.dict(),
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    MOCK_QUALITY_GOALS.append(new_goal)
    return new_goal

@router.put("/goals/{goal_id}", response_model=QualityGoalResponse)
async def update_quality_goal(
    goal_id: str,
    goal_data: QualityGoalUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update a quality goal"""
    goal_index = next((i for i, goal in enumerate(MOCK_QUALITY_GOALS) if goal["id"] == goal_id), None)
    if goal_index is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quality goal not found"
        )
    
    # Update only provided fields
    update_data = goal_data.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow().isoformat()
    
    MOCK_QUALITY_GOALS[goal_index].update(update_data)
    return MOCK_QUALITY_GOALS[goal_index]

@router.delete("/goals/{goal_id}")
async def delete_quality_goal(
    goal_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a quality goal"""
    goal_index = next((i for i, goal in enumerate(MOCK_QUALITY_GOALS) if goal["id"] == goal_id), None)
    if goal_index is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quality goal not found"
        )
    
    MOCK_QUALITY_GOALS.pop(goal_index)
    return {"message": "Quality goal deleted successfully"}

@router.put("/goals/{goal_id}/progress")
async def update_goal_progress(
    goal_id: str,
    progress: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update the progress of a quality goal"""
    goal_index = next((i for i, goal in enumerate(MOCK_QUALITY_GOALS) if goal["id"] == goal_id), None)
    if goal_index is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quality goal not found"
        )
    
    # Ensure progress is between 0 and 100
    progress = max(0, min(100, progress))
    
    MOCK_QUALITY_GOALS[goal_index]["progress"] = progress
    MOCK_QUALITY_GOALS[goal_index]["updated_at"] = datetime.utcnow().isoformat()
    
    # Update status based on progress
    if progress == 100:
        MOCK_QUALITY_GOALS[goal_index]["status"] = "completed"
    elif progress > 0:
        MOCK_QUALITY_GOALS[goal_index]["status"] = "in-progress"
    else:
        MOCK_QUALITY_GOALS[goal_index]["status"] = "not-started"
    
    return MOCK_QUALITY_GOALS[goal_index]

@router.get("/metrics", response_model=QualityMetricsResponse)
async def get_quality_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current quality metrics for the dashboard"""
    # Calculate metrics from goals
    total_goals = len(MOCK_QUALITY_GOALS)
    completed_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["status"] == "completed"])
    in_progress_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["status"] == "in-progress"])
    not_started_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["status"] == "not-started"])
    
    # Calculate average progress
    total_progress = sum(goal["progress"] for goal in MOCK_QUALITY_GOALS)
    average_progress = total_progress / total_goals if total_goals > 0 else 0
    
    # Calculate goals by category
    immediate_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["category"] == "immediate"])
    short_term_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["category"] == "short-term"])
    long_term_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["category"] == "long-term"])
    
    # Calculate goals by priority
    high_priority_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["priority"] == "high"])
    medium_priority_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["priority"] == "medium"])
    low_priority_goals = len([goal for goal in MOCK_QUALITY_GOALS if goal["priority"] == "low"])
    
    return {
        "total_goals": total_goals,
        "completed_goals": completed_goals,
        "in_progress_goals": in_progress_goals,
        "not_started_goals": not_started_goals,
        "average_progress": round(average_progress, 1),
        "immediate_goals": immediate_goals,
        "short_term_goals": short_term_goals,
        "long_term_goals": long_term_goals,
        "high_priority_goals": high_priority_goals,
        "medium_priority_goals": medium_priority_goals,
        "low_priority_goals": low_priority_goals,
        "completion_rate": round((completed_goals / total_goals * 100), 1) if total_goals > 0 else 0,
        "on_track_goals": len([goal for goal in MOCK_QUALITY_GOALS if goal["progress"] >= 50]),
        "at_risk_goals": len([goal for goal in MOCK_QUALITY_GOALS if goal["progress"] < 25 and goal["status"] != "completed"])
    }

@router.get("/goals/category/{category}")
async def get_goals_by_category(
    category: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get goals filtered by category"""
    goals = [goal for goal in MOCK_QUALITY_GOALS if goal["category"] == category]
    return {
        "goals": goals,
        "total": len(goals),
        "category": category
    }

@router.get("/goals/priority/{priority}")
async def get_goals_by_priority(
    priority: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get goals filtered by priority"""
    goals = [goal for goal in MOCK_QUALITY_GOALS if goal["priority"] == priority]
    return {
        "goals": goals,
        "total": len(goals),
        "priority": priority
    } 