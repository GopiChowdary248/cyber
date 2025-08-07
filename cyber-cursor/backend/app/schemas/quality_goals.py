from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum

class GoalCategory(str, Enum):
    IMMEDIATE = "immediate"
    SHORT_TERM = "short-term"
    LONG_TERM = "long-term"

class GoalPriority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class GoalStatus(str, Enum):
    NOT_STARTED = "not-started"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"

class GoalImpact(str, Enum):
    SECURITY = "security"
    RELIABILITY = "reliability"
    MAINTAINABILITY = "maintainability"
    COVERAGE = "coverage"
    OVERALL = "overall"

class QualityGoalBase(BaseModel):
    title: str = Field(..., description="Goal title")
    description: str = Field(..., description="Goal description")
    category: GoalCategory = Field(..., description="Goal category")
    priority: GoalPriority = Field(..., description="Goal priority")
    target_date: str = Field(..., description="Target completion date")
    current_value: str = Field(..., description="Current metric value")
    target_value: str = Field(..., description="Target metric value")
    metric: str = Field(..., description="Metric being tracked")
    impact: GoalImpact = Field(..., description="Impact area")

class QualityGoalCreate(QualityGoalBase):
    pass

class QualityGoalUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Goal title")
    description: Optional[str] = Field(None, description="Goal description")
    category: Optional[GoalCategory] = Field(None, description="Goal category")
    priority: Optional[GoalPriority] = Field(None, description="Goal priority")
    status: Optional[GoalStatus] = Field(None, description="Goal status")
    progress: Optional[int] = Field(None, ge=0, le=100, description="Progress percentage")
    target_date: Optional[str] = Field(None, description="Target completion date")
    current_value: Optional[str] = Field(None, description="Current metric value")
    target_value: Optional[str] = Field(None, description="Target metric value")
    metric: Optional[str] = Field(None, description="Metric being tracked")
    impact: Optional[GoalImpact] = Field(None, description="Impact area")

class QualityGoalResponse(QualityGoalBase):
    id: str = Field(..., description="Goal ID")
    status: GoalStatus = Field(..., description="Goal status")
    progress: int = Field(..., ge=0, le=100, description="Progress percentage")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True

class QualityGoalListResponse(BaseModel):
    goals: List[QualityGoalResponse] = Field(..., description="List of quality goals")
    total: int = Field(..., description="Total number of goals")
    categories: List[str] = Field(..., description="Available categories")
    priorities: List[str] = Field(..., description="Available priorities")
    statuses: List[str] = Field(..., description="Available statuses")

class QualityMetricsResponse(BaseModel):
    total_goals: int = Field(..., description="Total number of goals")
    completed_goals: int = Field(..., description="Number of completed goals")
    in_progress_goals: int = Field(..., description="Number of in-progress goals")
    not_started_goals: int = Field(..., description="Number of not-started goals")
    average_progress: float = Field(..., description="Average progress across all goals")
    immediate_goals: int = Field(..., description="Number of immediate goals")
    short_term_goals: int = Field(..., description="Number of short-term goals")
    long_term_goals: int = Field(..., description="Number of long-term goals")
    high_priority_goals: int = Field(..., description="Number of high priority goals")
    medium_priority_goals: int = Field(..., description="Number of medium priority goals")
    low_priority_goals: int = Field(..., description="Number of low priority goals")
    completion_rate: float = Field(..., description="Completion rate percentage")
    on_track_goals: int = Field(..., description="Number of goals on track (>=50% progress)")
    at_risk_goals: int = Field(..., description="Number of goals at risk (<25% progress)")

class GoalProgressUpdate(BaseModel):
    progress: int = Field(..., ge=0, le=100, description="New progress percentage")

class GoalFilter(BaseModel):
    category: Optional[GoalCategory] = Field(None, description="Filter by category")
    priority: Optional[GoalPriority] = Field(None, description="Filter by priority")
    status: Optional[GoalStatus] = Field(None, description="Filter by status")
    impact: Optional[GoalImpact] = Field(None, description="Filter by impact")

class GoalAnalytics(BaseModel):
    category_distribution: dict = Field(..., description="Goals distribution by category")
    priority_distribution: dict = Field(..., description="Goals distribution by priority")
    status_distribution: dict = Field(..., description="Goals distribution by status")
    impact_distribution: dict = Field(..., description="Goals distribution by impact")
    progress_trends: dict = Field(..., description="Progress trends over time")
    completion_forecast: dict = Field(..., description="Completion forecast based on current progress") 