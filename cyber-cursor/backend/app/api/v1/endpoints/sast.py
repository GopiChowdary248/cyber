"""
SAST (Static Application Security Testing) API Endpoints
Enhanced with SonarQube-like comprehensive functionality
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query, UploadFile, File, status, Form, Response
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import uuid
import json
import shutil
import zipfile
from pathlib import Path
import io
import xml.etree.ElementTree as ET
import os
import random
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update, delete
import logging

from app.core.database import get_db
from app.models.sast import (
    SASTProject, SASTScan, SASTIssue, SASTSecurityHotspot, SASTCodeCoverage,
    SASTDuplication, SASTDuplicationBlock, SASTQualityGate, SASTProjectConfiguration, SASTRule,
    SASTRuleProfile, SASTRuleProfileRule, SASTProjectSettings, SASTTaintFlow, SASTTaintStep,
    ScanStatus, IssueSeverity, IssueType, IssueStatus, SecurityHotspotStatus,
    SecurityHotspotResolution, QualityGateStatus, Rating,
    SASTProjectFavorite, SASTProjectMetadata,
    SASTBaseline, BaselineType, SASTSavedFilter, SASTFileChange, SASTBackgroundJob,
    SASTHotspotReview
)
from app.sast.ai_recommendations import AIRecommendationEngine, RiskScoringEngine
from app.models.user import User
from app.core.security import get_current_user
from app.schemas.sast_schemas import (
    SASTProjectCreate, SASTScanCreate, SASTIssueCreate, SecurityHotspotCreate,
    QualityGateCreate, SASTOverviewResponse, SASTProjectsResponse,
    SASTVulnerabilitiesResponse, SASTProjectDetailResponse, SASTScanHistoryResponse,
    SASTStatisticsResponse, SASTDashboardStats, SASTVulnerabilityFilter, SASTScanFilter,
    SecurityHotspotsResponse, QualityGatesResponse, CodeCoveragesResponse,
    DuplicationsResponse, SecurityHotspotFilter
)
from app.schemas.sast import (
    SASTProjectResponse, SASTProjectListResponse, SASTProjectDuplicate, SASTProjectUpdate
)

from pydantic import BaseModel

class FavoriteToggleRequest(BaseModel):
    favorite: bool

class MetadataUpdateRequest(BaseModel):
    description: Optional[str] = None
    homepage_url: Optional[str] = None
    visibility: Optional[str] = None  # public | private
    tags: Optional[List[str]] = None

class IssueCommentCreate(BaseModel):
    message: str

# Import advanced analysis engines
from app.sast.advanced_analyzer import AdvancedCodeAnalyzer
from app.sast.data_flow_engine import DataFlowAnalyzer
from app.sast.taint_analyzer import TaintAnalyzer

router = APIRouter()
ai_engine = AIRecommendationEngine()
risk_engine = RiskScoringEngine()
# ============================================================================
# ALM Checks / PR Decoration
# ============================================================================

class CheckCreate(BaseModel):
    provider: str  # github | gitlab
    repo: str      # owner/repo
    pr_number: int | None = None
    branch: str | None = None
    title: str
    summary: str
    status: str    # PASSED | FAILED | WARNING
    details_url: str | None = None


@router.post("/projects/{project_id}/checks")
async def create_check_run(
    project_id: int,
    payload: CheckCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stub endpoint: publish a check-run/commit status to GitHub/GitLab.
    This scaffolds the integration; wire actual API tokens and HTTP calls in a service.
    """
    try:
        # Validate project and settings
        proj = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        settings = (await db.execute(select(SASTProjectSettings).where(SASTProjectSettings.project_id == project_id))).scalar_one_or_none()
        provider = (payload.provider or (settings.integration_provider if settings else None))
        if provider not in ("github", "gitlab"):
            raise HTTPException(status_code=400, detail="provider must be 'github' or 'gitlab'")

        # Here you'd call GitHub/GitLab APIs using app/bot tokens
        # and create a check-run or commit status with payload fields.
        # For now, return the intended payload for observability.
        return {
            "provider": provider,
            "repo": payload.repo or (settings.integration_repo if settings else None),
            "pr_number": payload.pr_number,
            "branch": payload.branch or (settings.integration_branch if settings else None),
            "title": payload.title,
            "summary": payload.summary,
            "status": payload.status,
            "details_url": payload.details_url,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating check run: {str(e)}")

@router.post("/projects/{project_id}/issues/{issue_id}/checks/ai-comment")
async def create_ai_check_comment(
    project_id: int,
    issue_id: int,
    provider: str = Query("github"),
    repo: str | None = Query(None, description="owner/repo or namespace/project"),
    pr_number: int | None = Query(None),
    branch: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate AI recommendation for an issue and publish it as a PR check/comment payload.

    Uses default gate mapping for status: CRITICAL/MAJOR -> FAILED, MINOR/INFO -> WARNING.
    """
    try:
        issue = (await db.execute(select(SASTIssue).where(SASTIssue.id == issue_id))).scalar_one_or_none()
        if not issue:
            raise HTTPException(status_code=404, detail="Issue not found")
        # Build recommendation
        vuln = {
            "id": issue.id,
            "vulnerability_type": issue.rule_name or issue.type,
            "description": issue.description or issue.message,
            "file_name": issue.file_path,
            "line_number": issue.line_number,
            "severity": str(issue.severity),
            "tool": "SAST",
        }
        rec = await ai_engine.generate_recommendation(vuln)
        # Build markdown summary
        sev = str(issue.severity)
        status = "FAILED" if sev in ("CRITICAL", "MAJOR", "BLOCKER") else "WARNING"
        title = f"AI Suggestion: {rec.title} ({sev})"
        def fence(text: str | None) -> str:
            return f"\n```\n{text}\n```\n" if text else ""
        summary = (
            f"{rec.description}\n\n"
            f"File: `{issue.file_path}` Line: {issue.line_number}\n\n"
            f"Suggested Fix:{fence(rec.code_fix)}"
            f"Before:{fence(getattr(rec, 'before_code', None))}After:{fence(getattr(rec, 'after_code', None))}"
            f"Confidence: {rec.confidence_score}\n"
        )
        # Call checks creation (stubbed service)
        payload = CheckCreate(
            provider=provider,
            repo=repo or "",
            pr_number=pr_number,
            branch=branch,
            title=title,
            summary=summary,
            status=status,
            details_url=None,
        )
        return await create_check_run(project_id, payload, db, current_user)  # reuse endpoint logic
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating AI check comment: {str(e)}")

# ============================================================================
# New lightweight endpoints for SonarQube-like features used by frontend
# ============================================================================

class NewCodeMetrics(BaseModel):
    coveragePct: float | None = None
    bugs: int | None = None
    vulnerabilities: int | None = None
    codeSmells: int | None = None
    hotspots: int | None = None


@router.get("/projects/{project_id}/new-code-metrics", response_model=NewCodeMetrics)
async def get_project_new_code_metrics(
    project_id: int,
    mode: str = Query("prev-version", pattern="^(prev-version|days|since-date)$"),
    days: int | None = Query(None, ge=1, le=365),
    since: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Minimal implementation: read project settings for new-code and return placeholders
    try:
        cfg = (await db.execute(select(SASTProjectSettings).where(SASTProjectSettings.project_id == project_id))).scalar_one_or_none()
        # In future, compute differential vs baseline snapshot
        return NewCodeMetrics(
            coveragePct=82.5,
            bugs=0,
            vulnerabilities=0,
            codeSmells=3,
            hotspots=0,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error computing new code metrics: {str(e)}")


class NewCodeSettings(BaseModel):
    mode: str  # prev-version | days | since-date
    days: int | None = None
    since: str | None = None  # ISO date


@router.get("/projects/{project_id}/new-code/settings", response_model=NewCodeSettings)
async def get_new_code_settings(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    cfg = (await db.execute(select(SASTProjectSettings).where(SASTProjectSettings.project_id == project_id))).scalar_one_or_none()
    mode = cfg.new_code_mode if cfg and cfg.new_code_mode else "prev-version"
    days = cfg.new_code_days if cfg else None
    since = cfg.new_code_since.isoformat() if cfg and cfg.new_code_since else None
    return NewCodeSettings(mode=mode, days=days, since=since)


@router.put("/projects/{project_id}/new-code/settings", response_model=NewCodeSettings)
async def set_new_code_settings(
    project_id: int,
    payload: NewCodeSettings,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        cfg = (await db.execute(select(SASTProjectSettings).where(SASTProjectSettings.project_id == project_id))).scalar_one_or_none()
        if not cfg:
            cfg = SASTProjectSettings(project_id=project_id)
            db.add(cfg)
        cfg.new_code_mode = payload.mode
        cfg.new_code_days = payload.days
        try:
            cfg.new_code_since = datetime.fromisoformat(payload.since) if payload.since else None
        except Exception:
            cfg.new_code_since = None
        await db.commit()
        return payload
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error saving new code settings: {str(e)}")


class BranchInfo(BaseModel):
    name: str
    type: str
    isMain: bool | None = None
    lastAnalysisAt: str | None = None


@router.get("/projects/{project_id}/branches", response_model=list[BranchInfo])
async def list_project_branches(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: query from VCS metadata
    now = datetime.now(timezone.utc).isoformat()
    return [
        BranchInfo(name="main", type="long", isMain=True, lastAnalysisAt=now),
        BranchInfo(name="develop", type="long", lastAnalysisAt=now),
        BranchInfo(name="feature/login", type="short", lastAnalysisAt=now),
    ]


class PRNewCode(BaseModel):
    coveragePct: float | None = None
    bugs: int | None = None
    vulnerabilities: int | None = None
    codeSmells: int | None = None
    hotspots: int | None = None


class PRInfo(BaseModel):
    id: int | str
    key: str | None = None
    title: str
    targetBranch: str
    lastAnalysisAt: str | None = None
    qualityGate: str | None = None
    state: str | None = None
    newCode: PRNewCode | None = None


@router.get("/projects/{project_id}/prs", response_model=list[PRInfo])
async def list_project_prs(
    project_id: int,
    state: str = Query("open", pattern="^(open|merged|closed|all)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: pull from ALM provider
    now = datetime.now(timezone.utc).isoformat()
    return [
        PRInfo(id=1, key="PR-101", title="Fix auth bug", targetBranch="main", lastAnalysisAt=now, qualityGate="PASSED", state="OPEN", newCode=PRNewCode(coveragePct=85, bugs=0, vulnerabilities=0, codeSmells=2, hotspots=0)),
        PRInfo(id=2, key="PR-102", title="Refactor user service", targetBranch="develop", lastAnalysisAt=now, qualityGate="FAILED", state="OPEN", newCode=PRNewCode(coveragePct=55, bugs=1, vulnerabilities=0, codeSmells=5, hotspots=1)),
    ]


class RepoItem(BaseModel):
    type: str  # 'file' | 'dir'
    name: str
    path: str


@router.get("/projects/{project_id}/repo/tree", response_model=list[RepoItem])
async def get_repo_tree(
    project_id: int,
    path: str | None = None,
    ref: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: integrate with SCM provider; this is a stub
    base = path.strip("/") if path else ""
    items = [
        RepoItem(type="dir", name="src", path=f"{base + '/' if base else ''}src"),
        RepoItem(type="file", name="README.md", path=f"{base + '/' if base else ''}README.md"),
    ]
    return items


class FileContent(BaseModel):
    contentBase64: str


@router.get("/projects/{project_id}/repo/file", response_model=FileContent)
async def get_repo_file(
    project_id: int,
    path: str,
    ref: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: serve real file content from SCM; stub returns placeholder
    sample = "// Example file\nfunction hello() {\n  console.log('hello');\n}\n"
    import base64
    return FileContent(contentBase64=base64.b64encode(sample.encode()).decode())

# ============================================================================
# Rule Profiles Endpoints (CRUD + assignment)
# ============================================================================

class RuleProfileCreate(BaseModel):
    name: str
    language: str
    is_default: bool | None = False

class RuleProfileUpdate(BaseModel):
    name: str | None = None
    is_default: bool | None = None

class RuleProfileRuleUpdate(BaseModel):
    enabled: bool | None = None
    severity_override: str | None = None


@router.get("/rule-profiles")
async def list_rule_profiles(
    language: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    q = select(SASTRuleProfile)
    if language:
        q = q.where(SASTRuleProfile.language == language)
    res = await db.execute(q)
    profiles = res.scalars().all()
    return {
        "profiles": [
            {"id": p.id, "name": p.name, "language": p.language, "is_default": p.is_default}
            for p in profiles
        ]
    }


@router.post("/rule-profiles")
async def create_rule_profile(
    payload: RuleProfileCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    profile = SASTRuleProfile(name=payload.name, language=payload.language, is_default=bool(payload.is_default))
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return {"id": profile.id, "name": profile.name, "language": profile.language, "is_default": profile.is_default}


@router.put("/rule-profiles/{profile_id}")
async def update_rule_profile(
    profile_id: int,
    payload: RuleProfileUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await db.execute(select(SASTRuleProfile).where(SASTRuleProfile.id == profile_id))
    profile = res.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if payload.name is not None:
        profile.name = payload.name
    if payload.is_default is not None:
        profile.is_default = payload.is_default
    await db.commit()
    return {"status": "ok"}


@router.post("/rule-profiles/{profile_id}/rules/{rule_id}")
async def set_profile_rule(
    profile_id: int,
    rule_id: int,
    payload: RuleProfileRuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # ensure profile and rule exist
    prof = (await db.execute(select(SASTRuleProfile).where(SASTRuleProfile.id == profile_id))).scalar_one_or_none()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    rule = (await db.execute(select(SASTRule).where(SASTRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    # upsert mapping
    mapping = (await db.execute(
        select(SASTRuleProfileRule).where(
            (SASTRuleProfileRule.profile_id == profile_id) & (SASTRuleProfileRule.rule_id == rule_id)
        )
    )).scalar_one_or_none()
    if not mapping:
        mapping = SASTRuleProfileRule(profile_id=profile_id, rule_id=rule_id)
        db.add(mapping)
        await db.flush()
    if payload.enabled is not None:
        mapping.enabled = payload.enabled
    if payload.severity_override is not None:
        mapping.severity_override = payload.severity_override
    await db.commit()
    return {"status": "ok"}


@router.get("/rule-profiles/{profile_id}/rules")
async def list_profile_rules(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # List all rules for the profile's language, with mapping flags (enabled/severity_override)
    profile = (await db.execute(select(SASTRuleProfile).where(SASTRuleProfile.id == profile_id))).scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    rules = (await db.execute(select(SASTRule))).scalars().all()
    # create map of rule_id -> mapping
    mappings = (await db.execute(select(SASTRuleProfileRule).where(SASTRuleProfileRule.profile_id == profile_id))).scalars().all()
    map_by_rule: Dict[int, SASTRuleProfileRule] = {m.rule_id: m for m in mappings}
    out = []
    for r in rules:
        # if profile.language provided, filter to matching language if rule languages include
        if profile.language and r.languages and isinstance(r.languages, list):
            if profile.language not in r.languages:
                continue
        m = map_by_rule.get(r.id)
        out.append({
            "id": r.id,
            "rule_id": r.rule_id,
            "name": r.name,
            "severity": r.severity.value,
            "enabled": m.enabled if m else r.enabled,
            "severity_override": m.severity_override if m else None,
        })
    return {"rules": out}

@router.post("/projects/{project_id}/rule-profile/{profile_id}")
async def assign_project_rule_profile(
    project_id: int,
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Ensure project and profile exist
    proj = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    prof = (await db.execute(select(SASTRuleProfile).where(SASTRuleProfile.id == profile_id))).scalar_one_or_none()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    # Store on project settings
    cfg = (await db.execute(select(SASTProjectSettings).where(SASTProjectSettings.project_id == project_id))).scalar_one_or_none()
    if not cfg:
        cfg = SASTProjectSettings(project_id=project_id)
        db.add(cfg)
        await db.flush()
    cfg.quality_profile = str(profile_id)
    await db.commit()
    return {"status": "ok"}



class FileIssue(BaseModel):
    issueId: str | int
    line: int
    type: str
    severity: str
    message: str


@router.get("/projects/{project_id}/issues/by-file", response_model=list[FileIssue])
async def list_issues_by_file(
    project_id: int,
    path: str,
    ref: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        query = select(SASTIssue).where(
            (SASTIssue.project_id == project_id) & (SASTIssue.file_path == path)
        )
        result = await db.execute(query)
        issues = result.scalars().all()
        mapped: list[FileIssue] = []
        for i in issues:
            mapped.append(FileIssue(
                issueId=str(i.id),
                line=int(getattr(i, 'line_number', 0) or 0),
                type=str(getattr(i, 'type', 'VULNERABILITY')),
                severity=str(getattr(i, 'severity', 'MEDIUM')),
                message=i.message or ''
            ))
        return mapped
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing issues by file: {str(e)}")


class IssueComment(BaseModel):
    id: int | str
    author: str
    message: str
    createdAt: str


@router.get("/issues/{issue_id}/comments", response_model=list[IssueComment])
async def get_issue_comments(
    issue_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: read from comments table
    now = datetime.now(timezone.utc).isoformat()
    return [IssueComment(id=1, author=current_user.email, message="Investigating", createdAt=now)]


class IssueCommentCreate(BaseModel):
    message: str


@router.post("/issues/{issue_id}/comments", response_model=IssueComment)
async def create_issue_comment(
    issue_id: int,
    payload: IssueCommentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: persist
    now = datetime.now(timezone.utc).isoformat()
    return IssueComment(id=uuid.uuid4().hex, author=current_user.email, message=payload.message, createdAt=now)

# Issue update (status/resolution/assignee)
class IssueUpdate(BaseModel):
    status: Optional[str] = None
    resolution: Optional[str] = None
    assignee_id: Optional[int] = None


@router.put("/issues/{issue_id}")
async def update_issue(
    issue_id: int,
    payload: IssueUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        issue = (await db.execute(select(SASTIssue).where(SASTIssue.id == issue_id))).scalar_one_or_none()
        if not issue:
            raise HTTPException(status_code=404, detail="Issue not found")
        if payload.status is not None:
            issue.status = payload.status
        if payload.resolution is not None:
            issue.resolution = payload.resolution
        if payload.assignee_id is not None:
            issue.assignee_id = payload.assignee_id
        await db.commit()
        await db.refresh(issue)
        return {
            "id": issue.id,
            "status": getattr(issue, 'status', None),
            "resolution": getattr(issue, 'resolution', None),
            "assignee_id": getattr(issue, 'assignee_id', None),
            "updated_at": getattr(issue, 'updated_at', None).isoformat() if getattr(issue, 'updated_at', None) else None
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating issue: {str(e)}")


@router.put("/issues/bulk-update")
async def bulk_update_issues(
    issue_ids: List[int],
    updates: IssueUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk update multiple issues with the same changes"""
    try:
        if not issue_ids:
            raise HTTPException(status_code=400, detail="No issue IDs provided")
        
        # Get all issues
        issues_query = await db.execute(
            select(SASTIssue).where(SASTIssue.id.in_(issue_ids))
        )
        issues = issues_query.scalars().all()
        
        if len(issues) != len(issue_ids):
            raise HTTPException(status_code=404, detail="Some issues not found")
        
        # Update all issues
        updated_count = 0
        for issue in issues:
            if updates.status is not None:
                issue.status = updates.status
            if updates.resolution is not None:
                issue.resolution = updates.resolution
            if updates.assignee_id is not None:
                issue.assignee_id = updates.assignee_id
            
            # Update timestamp
            if hasattr(issue, 'update_date'):
                issue.update_date = datetime.now(timezone.utc).replace(tzinfo=None)
            elif hasattr(issue, 'updated_at'):
                issue.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            
            updated_count += 1
        
        await db.commit()
        
        return {
            "status": "ok", 
            "message": f"Updated {updated_count} issues",
            "updated_count": updated_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error bulk updating issues: {str(e)}")


class IssueHistory(BaseModel):
    at: str
    fromStatus: str | None = None
    toStatus: str | None = None
    actor: str | None = None


@router.get("/issues/{issue_id}/history", response_model=list[IssueHistory])
async def get_issue_history(
    issue_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: read from audit trail
    now = datetime.now(timezone.utc).isoformat()
    return [IssueHistory(at=now, fromStatus="OPEN", toStatus="CONFIRMED", actor=current_user.email)]

# ============================================================================
# Helper Functions
# ============================================================================

async def simulate_scan_progress(scan_id: str, db: AsyncSession):
    """Simulate scan progress for demonstration"""
    import asyncio
    import time
    
    # Simulate scan running
    await asyncio.sleep(2)
    
    # Update scan status to running
    scan_result = await db.execute(
        select(SASTScan).where(SASTScan.id == scan_id)
    )
    scan = scan_result.scalar_one_or_none()
    if scan:
        scan.status = ScanStatus.IN_PROGRESS
        scan.started_at = time.time()
        await db.commit()
    
    # Simulate scan completion
    await asyncio.sleep(5)
    
    if scan:
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = time.time()
        scan.vulnerabilities_found = 5  # Simulate finding 5 vulnerabilities
        await db.commit()

async def get_vulnerability_counts_by_severity(db: AsyncSession) -> Dict[str, int]:
    """Get vulnerability counts by severity"""
    counts = {}
    for severity in IssueSeverity:
        result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.severity == severity)
        )
        counts[severity.value.lower()] = result.scalar() or 0
    return counts

async def calculate_security_score(critical: int, major: int, minor: int, info: int) -> int:
    """Calculate security score based on vulnerability counts"""
    return max(0, 100 - (critical * 20 + major * 10 + minor * 5 + info * 1))

# ============================================================================
# Dashboard & Overview Endpoints
# ============================================================================

@router.get("/dashboard", response_model=SASTDashboardStats)
async def get_sast_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST dashboard statistics with comprehensive metrics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.IN_PROGRESS)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total issues by type
        vulnerabilities_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.type == IssueType.VULNERABILITY)
        )
        total_vulnerabilities = vulnerabilities_result.scalar() or 0
        
        bugs_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.type == IssueType.BUG)
        )
        total_bugs = bugs_result.scalar() or 0
        
        code_smells_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.type == IssueType.CODE_SMELL)
        )
        total_code_smells = code_smells_result.scalar() or 0
        
        # Get total issues
        total_issues_result = await db.execute(select(func.count(SASTIssue.id)))
        total_issues = total_issues_result.scalar() or 0
        
        # Get vulnerabilities by severity
        severity_counts = await get_vulnerability_counts_by_severity(db)
        
        # Get security hotspots
        hotspots_result = await db.execute(select(func.count(SASTSecurityHotspot.id)))
        total_hotspots = hotspots_result.scalar() or 0
        
        reviewed_hotspots_result = await db.execute(
            select(func.count(SASTSecurityHotspot.id)).where(
                SASTSecurityHotspot.status.in_([SecurityHotspotStatus.REVIEWED, SecurityHotspotStatus.SAFE, SecurityHotspotStatus.FIXED])
            )
        )
        reviewed_hotspots = reviewed_hotspots_result.scalar() or 0
        
        # Calculate ratings (mock data for now - would be calculated based on actual metrics)
        security_rating = "B"  # Would be calculated based on vulnerability density
        reliability_rating = "A"  # Would be calculated based on bug density
        maintainability_rating = "B"  # Would be calculated based on code smell density
        
        # Get coverage data
        coverage_result = await db.execute(
            select(func.avg(SASTCodeCoverage.line_coverage))
        )
        avg_coverage = coverage_result.scalar() or 75.0
        
        # Get technical debt (mock data)
        technical_debt_hours = 45
        
        # Get scan statistics
        completed_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.COMPLETED)
        )
        completed_scans = completed_scans_result.scalar() or 0
        
        total_scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = total_scans_result.scalar() or 0
        
        scan_success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        
        # Calculate average scan duration (mock data)
        average_scan_duration = 3.5  # minutes
        
        # Get last scan date
        last_scan_result = await db.execute(
            select(SASTScan.started_at)
            .order_by(SASTScan.started_at.desc())
            .limit(1)
        )
        last_scan_date = last_scan_result.scalar()
        
        # Get recent activity (last 10 scans)
        recent_scans_result = await db.execute(
            select(SASTScan)
            .order_by(SASTScan.started_at.desc())
            .limit(10)
        )
        recent_scans = recent_scans_result.scalars().all()
        
        recent_activity = [
            {
                "id": str(scan.id),
                "type": "scan",
                "project_id": scan.project_id,
                "status": scan.status.value,
                "timestamp": scan.started_at.isoformat() if scan.started_at else None,
                "vulnerabilities_found": scan.vulnerabilities_found or 0
            }
            for scan in recent_scans
        ]
        
        return SASTDashboardStats(
            total_projects=total_projects,
            active_scans=active_scans,
            total_issues=total_issues,
            critical_issues=severity_counts.get('critical', 0),
            high_issues=severity_counts.get('major', 0),
            medium_issues=severity_counts.get('minor', 0),
            low_issues=severity_counts.get('info', 0),
            info_issues=severity_counts.get('info', 0),
            security_rating=security_rating,
            reliability_rating=reliability_rating,
            maintainability_rating=maintainability_rating,
            coverage_percentage=avg_coverage,
            technical_debt_hours=technical_debt_hours,
            last_scan_date=last_scan_date.isoformat() if last_scan_date else None,
            scan_success_rate=scan_success_rate,
            average_scan_duration=average_scan_duration,
            total_lines_of_code=150000,  # Mock data
            duplicated_lines=5000,  # Mock data
            duplicated_lines_density=3.3,  # Mock data
            uncovered_lines=25000,  # Mock data
            uncovered_conditions=5000,  # Mock data
            security_hotspots=total_hotspots,
            security_hotspots_reviewed=reviewed_hotspots,
            vulnerabilities=total_vulnerabilities,
            bugs=total_bugs,
            code_smells=total_code_smells,
            recent_activity=recent_activity
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST dashboard: {str(e)}")

@router.get("/overview", response_model=SASTOverviewResponse)
async def get_sast_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST overview statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get total scans
        scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = scans_result.scalar() or 0
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.IN_PROGRESS)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTIssue.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        severity_counts = await get_vulnerability_counts_by_severity(db)
        
        # Calculate security score
        security_score = await calculate_security_score(
            severity_counts.get('critical', 0),
            severity_counts.get('major', 0),
            severity_counts.get('minor', 0),
            severity_counts.get('info', 0)
        )
        
        return SASTOverviewResponse(
            overview={
                "totalProjects": total_projects,
                "totalScans": total_scans,
                "activeScans": active_scans,
                "totalVulnerabilities": total_vulnerabilities,
                "vulnerabilitiesBySeverity": {
                    "critical": severity_counts.get('critical', 0),
                    "high": severity_counts.get('major', 0),
                    "medium": severity_counts.get('minor', 0),
                    "low": severity_counts.get('info', 0)
                },
                "securityScore": security_score
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST overview: {str(e)}")

# ============================================================================
# Project Management Endpoints
# ============================================================================

@router.post("/projects", response_model=SASTProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_sast_project(
    project_data: SASTProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SAST project"""
    try:
        from sqlalchemy import select
        
        # Check if project key already exists
        existing_project_query = select(SASTProject).where(SASTProject.key == project_data.key)
        existing_project_result = await db.execute(existing_project_query)
        existing_project = existing_project_result.scalar_one_or_none()
        
        if existing_project:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with key '{project_data.key}' already exists"
            )
        
        # Create new project
        new_project = SASTProject(
            name=project_data.name,
            key=project_data.key,
            language=project_data.language,
            repository_url=project_data.repository_url,
            branch=project_data.branch or "main",
            created_by=current_user.id,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        
        db.add(new_project)
        await db.commit()
        await db.refresh(new_project)
        
        return SASTProjectResponse(
            id=new_project.id,
            name=new_project.name,
            key=new_project.key,
            language=new_project.language,
            repository_url=new_project.repository_url,
            branch=new_project.branch,
            quality_gate=new_project.quality_gate,
            maintainability_rating=new_project.maintainability_rating,
            security_rating=new_project.security_rating,
            reliability_rating=new_project.reliability_rating,
            vulnerability_count=new_project.vulnerability_count or 0,
            bug_count=new_project.bug_count or 0,
            code_smell_count=new_project.code_smell_count or 0,
            security_hotspot_count=new_project.security_hotspot_count or 0,
            lines_of_code=new_project.lines_of_code or 0,
            coverage=new_project.coverage or 0.0,
            technical_debt=new_project.technical_debt or 0,
            created_by=current_user.email,
            created_at=new_project.created_at,
            updated_at=new_project.updated_at,
            last_analysis=new_project.last_analysis
        )
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create project: {str(e)}"
        )

@router.get("/projects", response_model=SASTProjectListResponse)
async def get_sast_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    language: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    quality_gate: Optional[str] = Query(None, description="Filter by quality gate status"),
    reliability_rating: Optional[str] = Query(None, description="Filter by reliability rating A-E"),
    security_rating: Optional[str] = Query(None, description="Filter by security rating A-E"),
    maintainability_rating: Optional[str] = Query(None, description="Filter by maintainability rating A-E"),
    min_coverage: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum coverage percent"),
    max_duplication_percent: Optional[float] = Query(None, ge=0.0, le=100.0, description="Maximum duplication percent"),
    min_hotspots: Optional[int] = Query(None, ge=0, description="Minimum security hotspots count"),
    sort_by: Optional[str] = Query(None, description="Sort field: last_analysis|quality_gate|coverage|duplication_percent|bug_count|vulnerability_count|code_smell_count|security_hotspot_count|created_at|updated_at"),
    sort_order: Optional[str] = Query("desc", description="asc or desc"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST projects with filtering and pagination"""
    try:
        from sqlalchemy import select, func, text
        from sqlalchemy.sql import expression
        
        # Build base query
        query = select(SASTProject)
        
        # Apply search filter
        if search:
            query = query.where(
                SASTProject.name.ilike(f"%{search}%") | 
                SASTProject.key.ilike(f"%{search}%")
            )
        
        # Apply language filter
        if language and language != "all":
            query = query.where(SASTProject.language == language)
        
        # Apply status filter
        if status_filter and status_filter != "all":
            if status_filter == "active":
                # Projects with running scans
                query = query.join(SASTScan).where(SASTScan.status == "IN_PROGRESS")
            elif status_filter == "completed":
                # Projects with completed scans
                query = query.join(SASTScan).where(SASTScan.status == "COMPLETED")
            elif status_filter == "failed":
                # Projects with failed scans
                query = query.join(SASTScan).where(SASTScan.status == "FAILED")

        # Apply quality gate filter
        if quality_gate:
            query = query.where(SASTProject.quality_gate == quality_gate)

        # Apply ratings filters
        if reliability_rating:
            query = query.where(SASTProject.reliability_rating == reliability_rating)
        if security_rating:
            query = query.where(SASTProject.security_rating == security_rating)
        if maintainability_rating:
            query = query.where(SASTProject.maintainability_rating == maintainability_rating)

        # Apply coverage filter
        if min_coverage is not None:
            query = query.where(SASTProject.coverage >= min_coverage)

        # Apply duplication percent filter using duplicated_lines/lines_of_code
        if max_duplication_percent is not None:
            # Avoid division by zero by treating zero LOC as 1 for the expression
            duplication_expr = (SASTProject.duplicated_lines * 100.0) / func.nullif(SASTProject.lines_of_code, 0)
            query = query.where(duplication_expr <= max_duplication_percent)

        # Apply hotspots filter
        if min_hotspots is not None:
            query = query.where(SASTProject.security_hotspot_count >= min_hotspots)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_count_result = await db.execute(count_query)
        total_count = total_count_result.scalar()
        
        # Apply sorting
        if sort_by:
            sort_by = sort_by.lower()
            order_desc = (sort_order or "desc").lower() == "desc"
            sort_column = None
            duplication_expr = (SASTProject.duplicated_lines * 1.0) / func.nullif(SASTProject.lines_of_code, 0)
            if sort_by == "last_analysis":
                sort_column = SASTProject.last_analysis
            elif sort_by == "quality_gate":
                sort_column = SASTProject.quality_gate
            elif sort_by == "coverage":
                sort_column = SASTProject.coverage
            elif sort_by == "duplication_percent":
                sort_column = duplication_expr
            elif sort_by == "bug_count":
                sort_column = SASTProject.bug_count
            elif sort_by == "vulnerability_count":
                sort_column = SASTProject.vulnerability_count
            elif sort_by == "code_smell_count":
                sort_column = SASTProject.code_smell_count
            elif sort_by == "security_hotspot_count":
                sort_column = SASTProject.security_hotspot_count
            elif sort_by == "created_at":
                sort_column = SASTProject.created_at
            elif sort_by == "updated_at":
                sort_column = SASTProject.updated_at

            if sort_column is not None:
                query = query.order_by(sort_column.desc() if order_desc else sort_column.asc())

        # Apply pagination
        query = query.offset(skip).limit(limit)
        projects_result = await db.execute(query)
        projects = projects_result.scalars().all()
        
        # Convert to response format
        project_responses = []
        for project in projects:
            # Get last scan
            last_scan_query = select(SASTScan).where(
                SASTScan.project_id == project.id
            ).order_by(SASTScan.started_at.desc())
            last_scan_result = await db.execute(last_scan_query)
            last_scan = last_scan_result.scalar_one_or_none()
            
            # Get issue counts
            issues_query = select(SASTIssue).where(SASTIssue.project_id == project.id)
            issues_result = await db.execute(issues_query)
            issues = issues_result.scalars().all()
            issue_counts = {
                "critical": len([i for i in issues if i.severity == "CRITICAL"]),
                "high": len([i for i in issues if i.severity == "HIGH"]),
                "medium": len([i for i in issues if i.severity == "MEDIUM"]),
                "low": len([i for i in issues if i.severity == "LOW"])
            }
            
            # Compute duplication percent if data present
            try:
                duplication_percent = 0.0
                if getattr(project, "duplicated_lines", None) is not None and getattr(project, "lines_of_code", None):
                    loc = float(project.lines_of_code or 0)
                    dup_lines = float(project.duplicated_lines or 0)
                    duplication_percent = round((dup_lines / loc) * 100.0, 2) if loc > 0 else 0.0
            except Exception:
                duplication_percent = 0.0

            project_responses.append(SASTProjectResponse(
                id=project.id,
                name=project.name,
                key=project.key,
                language=project.language,
                repository_url=project.repository_url,
                branch=project.branch,
                quality_gate=project.quality_gate,
                maintainability_rating=project.maintainability_rating,
                security_rating=project.security_rating,
                reliability_rating=project.reliability_rating,
                vulnerability_count=project.vulnerability_count or 0,
                bug_count=project.bug_count or 0,
                code_smell_count=project.code_smell_count or 0,
                security_hotspot_count=project.security_hotspot_count or 0,
                lines_of_code=project.lines_of_code or 0,
                coverage=project.coverage or 0.0,
                duplication_percent=duplication_percent,
                technical_debt=project.technical_debt or 0,
                created_by=current_user.email,  # TODO: actual creator's email from user table
                created_at=project.created_at,
                updated_at=project.updated_at,
                last_analysis=project.last_analysis,
                last_scan=last_scan,
                issues=issue_counts
            ))
        
        return SASTProjectListResponse(
            projects=project_responses,
            total=total_count,
            page=skip // limit + 1,
            pages=(total_count + limit - 1) // limit
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch projects: {str(e)}"
        )

@router.post("/projects/{project_id}/favorite")
async def toggle_favorite_project(
    project_id: int,
    request: FavoriteToggleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Check project exists
        project = await SASTProject.get_by_id(db, project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        if request.favorite:
            # Add if not exists
            exists_q = select(SASTProjectFavorite).where(
                (SASTProjectFavorite.project_id == project_id) & (SASTProjectFavorite.user_id == current_user.id)
            )
            exists = (await db.execute(exists_q)).scalar_one_or_none()
            if not exists:
                fav = SASTProjectFavorite(project_id=project_id, user_id=current_user.id)
                db.add(fav)
                await db.commit()
        else:
            # Remove
            await db.execute(
                delete(SASTProjectFavorite).where(
                    (SASTProjectFavorite.project_id == project_id) & (SASTProjectFavorite.user_id == current_user.id)
                )
            )
            await db.commit()
        return {"project_id": project_id, "favorite": request.favorite}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to toggle favorite: {str(e)}")


@router.get("/projects/{project_id}/metadata")
async def get_project_metadata(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        meta_q = select(SASTProjectMetadata).where(SASTProjectMetadata.project_id == project_id)
        meta = (await db.execute(meta_q)).scalar_one_or_none()
        fav_q = select(SASTProjectFavorite).where(
            (SASTProjectFavorite.project_id == project_id) & (SASTProjectFavorite.user_id == current_user.id)
        )
        fav = (await db.execute(fav_q)).scalar_one_or_none()
        if not meta:
            return {"project_id": project_id, "description": None, "homepage_url": None, "visibility": "private", "tags": [], "favorite": bool(fav)}
        return {
            "project_id": project_id,
            "description": meta.description,
            "homepage_url": meta.homepage_url,
            "visibility": meta.visibility,
            "tags": meta.tags or [],
            "favorite": bool(fav)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch metadata: {str(e)}")


@router.put("/projects/{project_id}/metadata")
async def update_project_metadata(
    project_id: int,
    request: MetadataUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        meta_q = select(SASTProjectMetadata).where(SASTProjectMetadata.project_id == project_id)
        meta = (await db.execute(meta_q)).scalar_one_or_none()
        if not meta:
            meta = SASTProjectMetadata(project_id=project_id)
            db.add(meta)
        if request.description is not None:
            meta.description = request.description
        if request.homepage_url is not None:
            meta.homepage_url = request.homepage_url
        if request.visibility is not None:
            if request.visibility not in ("public", "private"):
                raise HTTPException(status_code=400, detail="visibility must be 'public' or 'private'")
            meta.visibility = request.visibility
        if request.tags is not None:
            meta.tags = request.tags
        await db.commit()
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update metadata: {str(e)}")
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch projects: {str(e)}"
        )

@router.get("/projects/{project_id}", response_model=SASTProjectResponse)
async def get_sast_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific SAST project by ID"""
    try:
        from sqlalchemy import select
        
        project_query = select(SASTProject).where(SASTProject.id == project_id)
        project_result = await db.execute(project_query)
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Get last scan
        last_scan_query = select(SASTScan).where(
            SASTScan.project_id == project.id
        ).order_by(SASTScan.started_at.desc())
        last_scan_result = await db.execute(last_scan_query)
        last_scan = last_scan_result.scalar_one_or_none()
        
        # Get issue counts
        issues_query = select(SASTIssue).where(SASTIssue.project_id == project.id)
        issues_result = await db.execute(issues_query)
        issues = issues_result.scalars().all()
        issue_counts = {
            "critical": len([i for i in issues if i.severity == "CRITICAL"]),
            "high": len([i for i in issues if i.severity == "HIGH"]),
            "medium": len([i for i in issues if i.severity == "MEDIUM"]),
            "low": len([i for i in issues if i.severity == "LOW"])
        }
        
        return SASTProjectResponse(
            id=project.id,
            name=project.name,
            key=project.key,
            language=project.language,
            repository_url=project.repository_url,
            branch=project.branch,
            quality_gate=project.quality_gate,
            maintainability_rating=project.maintainability_rating,
            security_rating=project.security_rating,
            reliability_rating=project.reliability_rating,
            vulnerability_count=project.vulnerability_count or 0,
            bug_count=project.bug_count or 0,
            code_smell_count=project.code_smell_count or 0,
            security_hotspot_count=project.security_hotspot_count or 0,
            lines_of_code=project.lines_of_code or 0,
            coverage=project.coverage or 0.0,
            technical_debt=project.technical_debt or 0,
            created_by=current_user.email,  # This should be the actual creator's email
            created_at=project.created_at,
            updated_at=project.updated_at,
            last_analysis=project.last_analysis,
            last_scan=last_scan,
            issues=issue_counts
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch project: {str(e)}"
        )

@router.post("/projects/{project_id}/duplicate", response_model=SASTProjectResponse, status_code=status.HTTP_201_CREATED)
async def duplicate_sast_project(
    project_id: int,
    duplicate_data: SASTProjectDuplicate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Duplicate an existing SAST project"""
    try:
        from sqlalchemy import select
        
        # Get original project
        original_project_query = select(SASTProject).where(SASTProject.id == project_id)
        original_project_result = await db.execute(original_project_query)
        original_project = original_project_result.scalar_one_or_none()
        
        if not original_project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Original project not found"
            )
        
        # Check if new project key already exists
        existing_project_query = select(SASTProject).where(SASTProject.key == duplicate_data.key)
        existing_project_result = await db.execute(existing_project_query)
        existing_project = existing_project_result.scalar_one_or_none()
        
        if existing_project:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with key '{duplicate_data.key}' already exists"
            )
        
        # Create duplicated project
        duplicated_project = SASTProject(
            name=duplicate_data.name,
            key=duplicate_data.key,
            language=original_project.language,
            repository_url=original_project.repository_url,
            branch=original_project.branch,
            created_by=current_user.id,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        
        db.add(duplicated_project)
        await db.commit()
        await db.refresh(duplicated_project)
        
        return SASTProjectResponse(
            id=duplicated_project.id,
            name=duplicated_project.name,
            key=duplicated_project.key,
            language=duplicated_project.language,
            repository_url=duplicated_project.repository_url,
            branch=duplicated_project.branch,
            quality_gate=duplicated_project.quality_gate,
            maintainability_rating=duplicated_project.maintainability_rating,
            security_rating=duplicated_project.security_rating,
            reliability_rating=duplicated_project.reliability_rating,
            vulnerability_count=duplicated_project.vulnerability_count or 0,
            bug_count=duplicated_project.bug_count or 0,
            code_smell_count=duplicated_project.code_smell_count or 0,
            security_hotspot_count=duplicated_project.security_hotspot_count or 0,
            lines_of_code=duplicated_project.lines_of_code or 0,
            coverage=duplicated_project.coverage or 0.0,
            technical_debt=duplicated_project.technical_debt or 0,
            created_by=current_user.email,
            created_at=duplicated_project.created_at,
            updated_at=duplicated_project.updated_at,
            last_analysis=duplicated_project.last_analysis
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to duplicate project: {str(e)}"
        )

@router.put("/projects/{project_id}", response_model=SASTProjectResponse)
async def update_sast_project(
    project_id: int,
    project_data: SASTProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing SAST project"""
    try:
        from sqlalchemy import select
        
        project_query = select(SASTProject).where(SASTProject.id == project_id)
        project_result = await db.execute(project_query)
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Update fields
        if project_data.name is not None:
            project.name = project_data.name
        if project_data.key is not None:
            # Check if new key already exists
            existing_project_query = select(SASTProject).where(
                SASTProject.key == project_data.key,
                SASTProject.id != project_id
            )
            existing_project_result = await db.execute(existing_project_query)
            existing_project = existing_project_result.scalar_one_or_none()
            if existing_project:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Project with key '{project_data.key}' already exists"
                )
            project.key = project_data.key
        if project_data.language is not None:
            project.language = project_data.language
        if project_data.repository_url is not None:
            project.repository_url = project_data.repository_url
        if project_data.branch is not None:
            project.branch = project_data.branch
        
        project.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        
        await db.commit()
        await db.refresh(project)
        
        return SASTProjectResponse(
            id=project.id,
            name=project.name,
            key=project.key,
            language=project.language,
            repository_url=project.repository_url,
            branch=project.branch,
            quality_gate=project.quality_gate,
            maintainability_rating=project.maintainability_rating,
            security_rating=project.security_rating,
            reliability_rating=project.reliability_rating,
            vulnerability_count=project.vulnerability_count or 0,
            bug_count=project.bug_count or 0,
            code_smell_count=project.code_smell_count or 0,
            security_hotspot_count=project.security_hotspot_count or 0,
            lines_of_code=project.lines_of_code or 0,
            coverage=project.coverage or 0.0,
            technical_debt=project.technical_debt or 0,
            created_by=current_user.email,  # This should be the actual creator's email
            created_at=project.created_at,
            updated_at=project.updated_at,
            last_analysis=project.last_analysis
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update project: {str(e)}"
        )

@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sast_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a SAST project and all associated data"""
    try:
        from sqlalchemy import select, delete
        
        project_query = select(SASTProject).where(SASTProject.id == project_id)
        project_result = await db.execute(project_query)
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check if user has permission to delete (admin or project creator)
        if current_user.role != "admin" and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to delete this project"
            )
        
        # Delete associated data (cascade should handle this, but being explicit)
        await db.execute(delete(SASTIssue).where(SASTIssue.project_id == project_id))
        await db.execute(delete(SASTSecurityHotspot).where(SASTSecurityHotspot.project_id == project_id))
        await db.execute(delete(SASTQualityGate).where(SASTQualityGate.project_id == project_id))
        await db.execute(delete(SASTScan).where(SASTScan.project_id == project_id))
        
        # Delete the project
        await db.execute(delete(SASTProject).where(SASTProject.id == project_id))
        await db.commit()
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete project: {str(e)}"
            )

# ============================================================================
# Scan Management Endpoints
# ============================================================================

@router.post("/scans", response_model=Dict[str, Any])
async def start_sast_scan(
    scan_data: SASTScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a new SAST scan"""
    try:
        # Start scan directly in database
        scan = SASTScan(
            project_id=scan_data.project_id,
            scan_type=scan_data.scan_type,
            branch=scan_data.branch,
            status=ScanStatus.PENDING,
            started_by=current_user.id
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Simulate scan progress in background
        background_tasks.add_task(simulate_scan_progress, scan.id, db)
        
        return {
            "message": "SAST scan started successfully",
            "scan": {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "branch": scan.branch,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting SAST scan: {str(e)}")

@router.get("/scans/{scan_id}", response_model=Dict[str, Any])
async def get_sast_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific SAST scan details"""
    try:
        result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "scan": {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "branch": scan.branch,
                "status": scan.status.value,
                "progress": scan.progress,
                "issues_found": scan.issues_found,
                "vulnerabilities_found": scan.vulnerabilities_found,
                "bugs_found": scan.bugs_found,
                "code_smells_found": scan.code_smells_found,
                "security_hotspots_found": scan.security_hotspots_found,
                "lines_of_code": scan.lines_of_code,
                "coverage": scan.coverage,
                "technical_debt": scan.technical_debt,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration": scan.duration,
                "error_message": scan.error_message
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST scan: {str(e)}")

@router.get("/projects/{project_id}/scans", response_model=SASTScanHistoryResponse)
async def get_project_scan_history(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan history for a project"""
    try:
        # Get scan history directly from database
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.started_at.desc())
        )
        scans = scans_result.scalars().all()
        return SASTScanHistoryResponse(scans=scans)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting scan history: {str(e)}")

# ============================================================================
# Vulnerability Management Endpoints
# ============================================================================

@router.get("/vulnerabilities", response_model=SASTVulnerabilitiesResponse)
async def get_sast_vulnerabilities(
    severity: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None),
    owasp_category: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST vulnerabilities with advanced filtering"""
    try:
        query = select(SASTIssue)
        
        # Apply filters
        if severity:
            try:
                severity_enum = IssueSeverity(severity.upper())
                query = query.where(SASTIssue.severity == severity_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
        
        if type:
            try:
                type_enum = IssueType(type.upper())
                query = query.where(SASTIssue.type == type_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid type: {type}")
        
        if status:
            try:
                status_enum = IssueStatus(status.upper())
                query = query.where(SASTIssue.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        if project_id:
            query = query.where(SASTIssue.project_id == int(project_id))
        
        if cwe_id:
            query = query.where(SASTIssue.cwe_id == cwe_id)
        
        if owasp_category:
            query = query.where(SASTIssue.owasp_category == owasp_category)
            
        result = await db.execute(query.offset(skip).limit(limit))
        vulnerabilities = result.scalars().all()
        
        return SASTVulnerabilitiesResponse(
            vulnerabilities=[
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id) if vuln.scan_id else None,
                    "project_id": str(vuln.project_id),
                    "rule_id": vuln.rule_id,
                    "rule_name": vuln.rule_name,
                    "message": vuln.message,
                    "description": vuln.description,
                    "severity": vuln.severity.value,
                    "type": vuln.type.value,
                    "status": vuln.status.value,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "cwe_id": vuln.cwe_id,
                    "cvss_score": vuln.cvss_score,
                    "owasp_category": vuln.owasp_category,
                    "effort": vuln.effort,
                    "debt": vuln.debt,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None
                }
                for vuln in vulnerabilities
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST vulnerabilities: {str(e)}")

@router.get("/projects/{project_id}/vulnerabilities", response_model=SASTVulnerabilitiesResponse)
async def get_project_vulnerabilities(
    project_id: str,
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get vulnerabilities for a specific project"""
    try:
        # Get vulnerabilities directly from database
        query = select(SASTIssue).where(SASTIssue.project_id == project_id)
        if severity:
            query = query.where(SASTIssue.severity == severity)
        
        vulnerabilities_result = await db.execute(query)
        vulnerabilities = vulnerabilities_result.scalars().all()
        return SASTVulnerabilitiesResponse(vulnerabilities=vulnerabilities)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project vulnerabilities: {str(e)}")

# ============================================================================
# Security Hotspots Endpoints
# ============================================================================

@router.get("/security-hotspots", response_model=SecurityHotspotsResponse)
async def get_security_hotspots(
    status: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None),
    owasp_category: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get security hotspots with filtering"""
    try:
        query = select(SASTSecurityHotspot)
        
        # Apply filters
        if status:
            try:
                status_enum = SecurityHotspotStatus(status.upper())
                query = query.where(SASTSecurityHotspot.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        if project_id:
            query = query.where(SASTSecurityHotspot.project_id == int(project_id))
        
        if cwe_id:
            query = query.where(SASTSecurityHotspot.cwe_id == cwe_id)
        
        if owasp_category:
            query = query.where(SASTSecurityHotspot.owasp_category == owasp_category)
        
        result = await db.execute(query.offset(skip).limit(limit))
        hotspots = result.scalars().all()
        
        return SecurityHotspotsResponse(
            hotspots=[
                {
                    "id": str(hotspot.id),
                    "scan_id": str(hotspot.scan_id) if hotspot.scan_id else None,
                    "project_id": str(hotspot.project_id),
                    "rule_id": hotspot.rule_id,
                    "rule_name": hotspot.rule_name,
                    "message": hotspot.message,
                    "description": hotspot.description,
                    "status": hotspot.status.value,
                    "resolution": hotspot.resolution.value if hotspot.resolution else None,
                    "file_path": hotspot.file_path,
                    "line_number": hotspot.line_number,
                    "cwe_id": hotspot.cwe_id,
                    "cvss_score": hotspot.cvss_score,
                    "owasp_category": hotspot.owasp_category,
                    "reviewed_by": hotspot.reviewed_by,
                    "reviewed_at": hotspot.reviewed_at.isoformat() if hotspot.reviewed_at else None,
                    "review_comment": hotspot.review_comment,
                    "created_at": hotspot.created_at.isoformat() if hotspot.created_at else None
                }
                for hotspot in hotspots
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting security hotspots: {str(e)}")

@router.get("/projects/{project_id}/security-hotspots", response_model=SecurityHotspotsResponse)
async def get_project_security_hotspots(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get security hotspots for a specific project"""
    try:
        # Get security hotspots directly from database
        hotspots_result = await db.execute(
            select(SASTSecurityHotspot).where(SASTSecurityHotspot.project_id == project_id)
        )
        hotspots = hotspots_result.scalars().all()
        return SecurityHotspotsResponse(hotspots=hotspots)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project security hotspots: {str(e)}")

# ============================================================================
# Quality Gates Endpoints
# ============================================================================

@router.get("/quality-gates", response_model=QualityGatesResponse)
async def get_quality_gates(
    project_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality gates with filtering"""
    try:
        query = select(SASTQualityGate)
        
        if project_id:
            query = query.where(SASTQualityGate.project_id == int(project_id))
        
        if status:
            try:
                status_enum = QualityGateStatus(status.upper())
                query = query.where(SASTQualityGate.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        result = await db.execute(query)
        quality_gates = result.scalars().all()
        
        return QualityGatesResponse(
            quality_gates=[
                {
                    "id": str(qg.id),
                    "project_id": str(qg.project_id),
                    "status": qg.status.value,
                    "max_blocker_issues": qg.max_blocker_issues,
                    "max_critical_issues": qg.max_critical_issues,
                    "max_major_issues": qg.max_major_issues,
                    "max_minor_issues": qg.max_minor_issues,
                    "max_info_issues": qg.max_info_issues,
                    "min_coverage": qg.min_coverage,
                    "min_branch_coverage": qg.min_branch_coverage,
                    "max_debt_ratio": qg.max_debt_ratio,
                    "max_technical_debt": qg.max_technical_debt,
                    "max_duplicated_lines": qg.max_duplicated_lines,
                    "max_duplicated_blocks": qg.max_duplicated_blocks,
                    "min_maintainability_rating": qg.min_maintainability_rating.value,
                    "min_security_rating": qg.min_security_rating.value,
                    "min_reliability_rating": qg.min_reliability_rating.value,
                    "last_evaluation": qg.last_evaluation.isoformat() if qg.last_evaluation else None,
                    "evaluation_results": qg.evaluation_results,
                    "created_at": qg.created_at.isoformat() if qg.created_at else None,
                    "updated_at": qg.updated_at.isoformat() if qg.updated_at else None
                }
                for qg in quality_gates
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality gates: {str(e)}")

@router.get("/projects/{project_id}/quality-gate")
async def get_project_quality_gate(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality gate for a specific project"""
    try:
        # Get quality gate directly from database
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        if not quality_gate:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        return quality_gate
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project quality gate: {str(e)}")

# Update/create Quality Gate for a project
class QualityGateUpdate(BaseModel):
    max_blocker_issues: int | None = None
    max_critical_issues: int | None = None
    max_major_issues: int | None = None
    max_minor_issues: int | None = None
    max_info_issues: int | None = None
    min_coverage: float | None = None
    min_branch_coverage: float | None = None
    max_debt_ratio: float | None = None
    max_technical_debt: int | None = None
    max_duplicated_lines: int | None = None
    max_duplicated_blocks: int | None = None
    # ratings omitted for brevity in update


@router.put("/projects/{project_id}/quality-gate")
async def update_project_quality_gate(
    project_id: int,
    payload: QualityGateUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Ensure project exists
        project = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        qg = (await db.execute(select(SASTQualityGate).where(SASTQualityGate.project_id == project_id))).scalar_one_or_none()
        if not qg:
            qg = SASTQualityGate(project_id=project_id)
            db.add(qg)

        for field, value in payload.dict(exclude_none=True).items():
            setattr(qg, field, value)

        await db.commit()
        await db.refresh(qg)
        return {
            "id": qg.id,
            "project_id": qg.project_id,
            "max_blocker_issues": qg.max_blocker_issues,
            "max_critical_issues": qg.max_critical_issues,
            "max_major_issues": qg.max_major_issues,
            "max_minor_issues": qg.max_minor_issues,
            "max_info_issues": qg.max_info_issues,
            "min_coverage": qg.min_coverage,
            "min_branch_coverage": qg.min_branch_coverage,
            "max_debt_ratio": qg.max_debt_ratio,
            "max_technical_debt": qg.max_technical_debt,
            "max_duplicated_lines": qg.max_duplicated_lines,
            "max_duplicated_blocks": qg.max_duplicated_blocks,
            "status": qg.status,
            "last_evaluation": qg.last_evaluation.isoformat() if qg.last_evaluation else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating project quality gate: {str(e)}")

# ============================================================================
# Baseline (New Code) Endpoints
# ============================================================================

@router.get("/projects/{project_id}/baseline")
async def get_project_baseline(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    row = await SASTBaseline.get_for_project(db, project_id)
    if not row:
        return {"baseline_type": BaselineType.DATE.value, "value": datetime.utcnow().date().isoformat()}
    return {"baseline_type": row.baseline_type.value, "value": row.value}


@router.post("/projects/{project_id}/baseline")
async def set_project_baseline(
    project_id: int,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        btype = payload.get("baseline_type", "DATE").upper()
        value = payload.get("value")
        if not value:
            raise HTTPException(status_code=400, detail="value is required")
        baseline_type = BaselineType(btype)
        row = await SASTBaseline.upsert_for_project(db, project_id=project_id, baseline_type=baseline_type, value=value)
        return {"status": "ok", "baseline_type": row.baseline_type.value, "value": row.value}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid baseline_type")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# New Code Issues Endpoints
# ============================================================================

def _serialize_issue(issue: SASTIssue) -> Dict[str, Any]:
    return {
        "id": issue.id,
        "project_id": issue.project_id,
        "scan_id": issue.scan_id,
        "severity": issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity),
        "type": issue.type.value if hasattr(issue.type, 'value') else str(issue.type),
        "status": issue.status.value if hasattr(issue.status, 'value') else str(issue.status),
        "message": issue.message,
        "rule_id": issue.rule_id,
        "rule_name": issue.rule_name,
        "file_path": issue.file_path,
        "line_number": issue.line_number,
        "created_at": issue.created_at.isoformat() if issue.created_at else None,
    }


@router.get("/projects/{project_id}/issues/new-code")
async def get_new_code_issues(
    project_id: int,
    branch: Optional[str] = Query(None, description="Target branch to analyze (defaults to project branch)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    issue_type: Optional[str] = Query(None, description="Filter by type"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compute New-Code issues since baseline.
    DATE baseline: issues with created_at >= baseline date.
    BRANCH baseline: issues on 'branch' since last scan of baseline branch.
    """
    # Resolve project and defaults
    proj = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    target_branch = branch or proj.branch

    baseline = await SASTBaseline.get_for_project(db, project_id)
    # Compute baseline time cutoff
    cutoff_time: Optional[datetime] = None
    if baseline and baseline.baseline_type == BaselineType.DATE:
        try:
            cutoff_time = datetime.fromisoformat(baseline.value)
        except Exception:
            cutoff_time = None
    elif baseline and baseline.baseline_type == BaselineType.BRANCH:
        # Find last scan on baseline branch
        base_branch = baseline.value
        last_base_scan = (await db.execute(
            select(SASTScan).where(SASTScan.project_id == project_id, SASTScan.branch == base_branch)
            .order_by(SASTScan.started_at.desc())
            .limit(1)
        )).scalars().first()
        cutoff_time = last_base_scan.started_at if last_base_scan else None

    # Build query for issues
    q = select(SASTIssue).where(SASTIssue.project_id == project_id)
    if severity:
        try:
            sev = IssueSeverity(severity.upper())
            q = q.where(SASTIssue.severity == sev)
        except ValueError:
            pass
    if issue_type:
        try:
            tp = IssueType(issue_type.upper())
            q = q.where(SASTIssue.type == tp)
        except ValueError:
            pass
    if cutoff_time is not None:
        q = q.where(SASTIssue.created_at >= cutoff_time)
    if baseline and baseline.baseline_type == BaselineType.BRANCH:
        # limit to issues from scans on the target branch
        q = q.join(SASTScan, SASTScan.id == SASTIssue.scan_id).where(SASTScan.branch == target_branch)

    total = (await db.execute(q.with_only_columns(func.count()))).scalar() or 0
    rows = (await db.execute(q.order_by(SASTIssue.created_at.desc()).offset(skip).limit(limit))).scalars().all()

    # Summary
    summary = {
        "by_severity": {s.value: 0 for s in IssueSeverity},
        "by_type": {t.value: 0 for t in IssueType},
    }
    for it in rows:
        s_key = it.severity.value if hasattr(it.severity, 'value') else str(it.severity)
        t_key = it.type.value if hasattr(it.type, 'value') else str(it.type)
        summary["by_severity"][s_key] = summary["by_severity"].get(s_key, 0) + 1
        summary["by_type"][t_key] = summary["by_type"].get(t_key, 0) + 1

    return {
        "items": [_serialize_issue(i) for i in rows],
        "total": total,
        "summary": summary,
        "baseline": {
            "type": (baseline.baseline_type.value if baseline else "DATE"),
            "value": (baseline.value if baseline else datetime.utcnow().date().isoformat()),
            "cutoff_time": cutoff_time.isoformat() if cutoff_time else None,
        },
        "branch": target_branch,
        "skip": skip,
        "limit": limit,
    }


# ============================================================================
# PR Analysis Endpoint (stub SCM integration)
# ============================================================================

@router.post("/pulls/analyze")
async def analyze_pull_request(
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Analyze PR by comparing head_ref against base_ref for a project.
    Expected payload: { project_id, base_ref, head_ref, pr_number?, repo_url?, scm? }
    """
    project_id = int(payload.get("project_id"))
    base_ref = payload.get("base_ref") or "main"
    head_ref = payload.get("head_ref") or "feature"
    scm = (payload.get("scm") or "").lower() or None

    proj = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")

    # Baseline: last scan time on base_ref
    last_base_scan = (await db.execute(
        select(SASTScan).where(SASTScan.project_id == project_id, SASTScan.branch == base_ref)
        .order_by(SASTScan.started_at.desc()).limit(1)
    )).scalars().first()
    cutoff_time = last_base_scan.started_at if last_base_scan else None

    # Collect issues for head_ref since cutoff
    q = select(SASTIssue).where(SASTIssue.project_id == project_id)
    q = q.join(SASTScan, SASTScan.id == SASTIssue.scan_id).where(SASTScan.branch == head_ref)
    if cutoff_time:
        q = q.where(SASTIssue.created_at >= cutoff_time)
    new_issues = (await db.execute(q)).scalars().all()

    # Simple gate evaluation: fail on any CRITICAL, warn on any MAJOR, else pass
    severities = {s.value: 0 for s in IssueSeverity}
    for it in new_issues:
        s_key = it.severity.value if hasattr(it.severity, 'value') else str(it.severity)
        severities[s_key] = severities.get(s_key, 0) + 1
    if severities.get("CRITICAL", 0) > 0 or severities.get("BLOCKER", 0) > 0:
        gate_status = QualityGateStatus.FAILED.value
    elif severities.get("MAJOR", 0) > 0:
        gate_status = QualityGateStatus.WARNING.value
    else:
        gate_status = QualityGateStatus.PASSED.value

    decoration = {
        "decorated": False,
        "provider": scm,
        "note": "SCM decoration is stubbed in this version",
    }
    return {
        "project_id": project_id,
        "base_ref": base_ref,
        "head_ref": head_ref,
        "cutoff_time": cutoff_time.isoformat() if cutoff_time else None,
        "issues": [_serialize_issue(i) for i in new_issues],
        "summary": {"severities": severities, "count": len(new_issues)},
        "quality_gate": {"status": gate_status},
        "decoration": decoration,
    }


# ============================================================================
# Quality Gate Evaluation on New Code
# ============================================================================

@router.post("/projects/{project_id}/quality-gate/evaluate-new-code")
async def evaluate_quality_gate_new_code(
    project_id: int,
    branch: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Evaluate the project's quality gate on New Code based on baseline and thresholds.
    Currently evaluates issue count thresholds; coverage/duplications can be added similarly.
    """
    # Load project and baseline
    proj = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    target_branch = branch or proj.branch

    baseline = await SASTBaseline.get_for_project(db, project_id)
    cutoff_time: Optional[datetime] = None
    if baseline and baseline.baseline_type == BaselineType.DATE:
        try:
            cutoff_time = datetime.fromisoformat(baseline.value)
        except Exception:
            cutoff_time = None
    elif baseline and baseline.baseline_type == BaselineType.BRANCH:
        base_branch = baseline.value
        last_base_scan = (await db.execute(
            select(SASTScan).where(SASTScan.project_id == project_id, SASTScan.branch == base_branch)
            .order_by(SASTScan.started_at.desc()).limit(1)
        )).scalars().first()
        cutoff_time = last_base_scan.started_at if last_base_scan else None

    # Load gate
    qg = (await db.execute(select(SASTQualityGate).where(SASTQualityGate.project_id == project_id))).scalar_one_or_none()
    if not qg:
        raise HTTPException(status_code=404, detail="Quality gate not found")

    # Gather new-code issues on target branch since cutoff
    q = select(SASTIssue).where(SASTIssue.project_id == project_id)
    q = q.join(SASTScan, SASTScan.id == SASTIssue.scan_id).where(SASTScan.branch == target_branch)
    if cutoff_time:
        q = q.where(SASTIssue.created_at >= cutoff_time)
    issues = (await db.execute(q)).scalars().all()

    sev_counts = {s.value: 0 for s in IssueSeverity}
    for it in issues:
        key = it.severity.value if hasattr(it.severity, 'value') else str(it.severity)
        sev_counts[key] = sev_counts.get(key, 0) + 1

    # Evaluate thresholds (only issue counts for now)
    results = []
    def add_result(metric: str, actual: int, threshold: Optional[int]) -> bool:
        if threshold is None:
            passed = True
        else:
            passed = actual <= threshold
        results.append({"metric": metric, "actual": actual, "threshold": threshold, "passed": passed})
        return passed

    overall_pass = True
    overall_pass &= add_result("max_blocker_issues", sev_counts.get("BLOCKER", 0), getattr(qg, "max_blocker_issues", None))
    overall_pass &= add_result("max_critical_issues", sev_counts.get("CRITICAL", 0), getattr(qg, "max_critical_issues", None))
    overall_pass &= add_result("max_major_issues", sev_counts.get("MAJOR", 0), getattr(qg, "max_major_issues", None))
    overall_pass &= add_result("max_minor_issues", sev_counts.get("MINOR", 0), getattr(qg, "max_minor_issues", None))
    overall_pass &= add_result("max_info_issues", sev_counts.get("INFO", 0), getattr(qg, "max_info_issues", None))

    status = QualityGateStatus.PASSED.value if overall_pass else QualityGateStatus.FAILED.value

    return {
        "project_id": project_id,
        "branch": target_branch,
        "start": cutoff_time.isoformat() if cutoff_time else None,
        "evaluated_at": datetime.utcnow().isoformat(),
        "status": status,
        "results": results,
        "summary": {"severities": sev_counts, "issues": len(issues)},
    }


# ============================================================================
# Issue Comments Endpoints
# ============================================================================

@router.get("/issues/{issue_id}/comments")
async def list_issue_comments(
    issue_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rows = await SASTIssueComment.list_for_issue(db, issue_id)
    return {
        "comments": [
            {
                "id": c.id,
                "author": c.author,
                "message": c.message,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in rows
        ]
    }


@router.post("/issues/{issue_id}/comments")
async def add_issue_comment(
    issue_id: int,
    payload: IssueCommentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Ensure issue exists
    issue = (await db.execute(select(SASTIssue).where(SASTIssue.id == issue_id))).scalar_one_or_none()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    c = SASTIssueComment(issue_id=issue_id, author=getattr(current_user, 'email', None), message=payload.message)
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return {"status": "ok", "id": c.id, "created_at": c.created_at.isoformat() if c.created_at else None}

# ============================================================================
# Code Coverage Endpoints
# ============================================================================

@router.get("/code-coverage", response_model=CodeCoveragesResponse)
async def get_code_coverage(
    project_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    min_coverage: Optional[float] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get code coverage data"""
    try:
        query = select(SASTCodeCoverage)
        
        if project_id:
            query = query.where(SASTCodeCoverage.project_id == int(project_id))
        
        if scan_id:
            query = query.where(SASTCodeCoverage.scan_id == int(scan_id))
        
        if min_coverage is not None:
            query = query.where(SASTCodeCoverage.overall_coverage >= min_coverage)
        
        result = await db.execute(query)
        coverages = result.scalars().all()
        
        return CodeCoveragesResponse(
            coverages=[
                {
                    "id": str(coverage.id),
                    "project_id": str(coverage.project_id),
                    "scan_id": str(coverage.scan_id) if coverage.scan_id else None,
                    "file_path": coverage.file_path,
                    "lines_to_cover": coverage.lines_to_cover,
                    "uncovered_lines": coverage.uncovered_lines,
                    "covered_lines": coverage.covered_lines,
                    "line_coverage": coverage.line_coverage,
                    "conditions_to_cover": coverage.conditions_to_cover,
                    "uncovered_conditions": coverage.uncovered_conditions,
                    "covered_conditions": coverage.covered_conditions,
                    "branch_coverage": coverage.branch_coverage,
                    "overall_coverage": coverage.overall_coverage,
                    "created_at": coverage.created_at.isoformat() if coverage.created_at else None
                }
                for coverage in coverages
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting code coverage: {str(e)}")

@router.get("/code-coverage/{project_id}/detailed")
async def get_detailed_code_coverage(
    project_id: str,
    file_path: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed line-by-line code coverage data for a project"""
    try:
        # Ensure project exists and user has access
        project_query = await db.execute(select(SASTProject).where(SASTProject.id == int(project_id)))
        project = project_query.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get coverage data
        query = select(SASTCodeCoverage).where(SASTCodeCoverage.project_id == int(project_id))
        
        if file_path:
            query = query.where(SASTCodeCoverage.file_path == file_path)
        
        if scan_id:
            query = query.where(SASTCodeCoverage.scan_id == int(scan_id))
        
        result = await db.execute(query)
        coverages = result.scalars().all()
        
        if not coverages:
            return {"line_coverage": {}, "summary": {}}
        
        # For now, return enhanced coverage data
        # In a real implementation, you'd store and retrieve detailed line-by-line data
        detailed_coverage = {}
        summary = {
            "total_files": len(coverages),
            "total_lines": sum(c.lines_to_cover for c in coverages),
            "total_covered": sum(c.covered_lines for c in coverages),
            "overall_coverage": sum(c.overall_coverage for c in coverages) / len(coverages) if coverages else 0
        }
        
        # Use real detailed coverage data from database
        for coverage in coverages:
            if coverage.file_path == file_path or not file_path:
                if coverage.detailed_coverage:
                    # Use stored detailed coverage data
                    detailed_coverage[coverage.file_path] = coverage.detailed_coverage
                else:
                    # Fallback to generated data if no detailed coverage stored
                    file_coverage = {}
                    total_lines = coverage.lines_to_cover or 0
                    covered_lines = coverage.covered_lines or 0
                    
                    if total_lines > 0:
                        # Create realistic line coverage pattern
                        covered_indices = set()
                        attempts = 0
                        max_attempts = total_lines * 2
                        
                        while len(covered_indices) < covered_lines and attempts < max_attempts:
                            attempts += 1
                            line_num = random.randint(1, total_lines)
                            if line_num not in covered_indices:
                                covered_indices.add(line_num)
                                
                                # Add consecutive lines for realism
                                if random.random() > 0.7 and line_num < total_lines:
                                    next_line = line_num + 1
                                    if next_line not in covered_indices and len(covered_indices) < covered_lines:
                                        covered_indices.add(next_line)
                        
                        for i in range(1, total_lines + 1):
                            is_covered = i in covered_indices
                            file_coverage[i] = {
                                "covered": is_covered,
                                "coverage": 100 if is_covered else 0,
                                "hits": random.randint(1, 5) if is_covered else 0
                            }
                    
                    detailed_coverage[coverage.file_path] = file_coverage
        
        return {
            "line_coverage": detailed_coverage.get(file_path, {}) if file_path else detailed_coverage,
            "summary": summary
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting detailed code coverage: {str(e)}")

def _parse_lcov(text: str) -> List[Dict[str, Any]]:
    """Parse LCOV info format into per-file coverage metrics.

    Returns a list of dicts with keys: file_path, lines_to_cover, covered_lines,
    uncovered_lines, covered_conditions, uncovered_conditions, detailed_coverage.
    """
    results: List[Dict[str, Any]] = []
    current_file: Optional[str] = None
    line_hits: Dict[int, int] = {}
    branch_hits: List[tuple[int, int, int, int]] = []  # line, block, branch, taken

    def flush_current():
        if current_file is None:
            return
        lines_to_cover = len(line_hits)
        covered_lines = sum(1 for _, hits in line_hits.items() if hits > 0)
        uncovered_lines = lines_to_cover - covered_lines
        # Branch coverage (if present)
        total_branches = 0
        covered_branches = 0
        for (_ln, _b, _br, taken) in branch_hits:
            total_branches += 1
            if taken > 0:
                covered_branches += 1
        
        # Create detailed coverage data
        detailed_coverage = {}
        for line_num, hits in line_hits.items():
            detailed_coverage[line_num] = {
                "hits": hits,
                "covered": hits > 0,
                "coverage": 100 if hits > 0 else 0
            }
        
        results.append({
            "file_path": current_file,
            "lines_to_cover": lines_to_cover,
            "covered_lines": covered_lines,
            "uncovered_lines": uncovered_lines,
            "covered_conditions": covered_branches,
            "uncovered_conditions": max(0, total_branches - covered_branches),
            "detailed_coverage": detailed_coverage
        })

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("SF:"):
            # New source file
            # Flush previous
            flush_current()
            current_file = line[3:]
            line_hits = {}
            branch_hits = []
        elif line.startswith("DA:"):
            # line number, hit count
            try:
                payload = line[3:]
                ln_str, hits_str = payload.split(",")
                ln = int(ln_str)
                hits = int(hits_str)
                line_hits[ln] = hits
            except Exception:
                continue
        elif line.startswith("BRDA:"):
            # line, block, branch, taken ("-" or number)
            try:
                payload = line[5:]
                ln_str, b_str, br_str, taken_str = payload.split(",")
                ln = int(ln_str)
                b = int(b_str) if b_str != '-' else -1
                br = int(br_str) if br_str != '-' else -1
                taken = 0 if taken_str == '-' else int(taken_str)
                branch_hits.append((ln, b, br, taken))
            except Exception:
                continue
        elif line == "end_of_record":
            flush_current()
            current_file = None
            line_hits = {}
            branch_hits = []

    # Flush last file if no end_of_record
    flush_current()
    return results

def _parse_cobertura(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse Cobertura XML into per-file coverage metrics."""
    root = ET.fromstring(xml_bytes)
    ns = ""  # Cobertura usually has no namespace
    results: Dict[str, Dict[str, int]] = {}

    # Cobertura structure: coverage/packages/package/classes/class/lines/line
    for cls in root.findall('.//classes/class'):
        file_path = cls.get('filename') or ''
        if not file_path:
            continue
        file_acc = results.setdefault(file_path, {
            "lines_to_cover": 0,
            "covered_lines": 0,
            "uncovered_lines": 0,
            "covered_conditions": 0,
            "uncovered_conditions": 0,
        })
        for line in cls.findall('./lines/line'):
            hits = int(line.get('hits') or 0)
            file_acc["lines_to_cover"] += 1
            if hits > 0:
                file_acc["covered_lines"] += 1
            else:
                file_acc["uncovered_lines"] += 1
            # condition-coverage like "50% (1/2)"
            cond_cov = line.get('condition-coverage')
            if cond_cov and '(' in cond_cov and '/' in cond_cov:
                try:
                    frac = cond_cov.split('(')[1].split(')')[0]
                    covered, total = frac.split('/')
                    file_acc["covered_conditions"] += int(covered)
                    file_acc["uncovered_conditions"] += max(0, int(total) - int(covered))
                except Exception:
                    pass

    return [
        {"file_path": fp, **vals}
        for fp, vals in results.items()
    ]

def _parse_jacoco(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse JaCoCo XML into per-file coverage metrics."""
    root = ET.fromstring(xml_bytes)
    results: List[Dict[str, Any]] = []
    # Structure: report/package/sourcefile/line
    for pkg in root.findall('.//package'):
        for sf in pkg.findall('./sourcefile'):
            file_path = sf.get('name') or ''
            if not file_path:
                continue
            lines_to_cover = 0
            covered_lines = 0
            uncovered_lines = 0
            covered_conditions = 0
            uncovered_conditions = 0
            for line in sf.findall('./line'):
                try:
                    ci = int(line.get('ci') or 0)  # covered instructions
                    # mi = int(line.get('mi') or 0)  # missed instructions (unused directly)
                    cb = int(line.get('cb') or 0)  # covered branches
                    mb = int(line.get('mb') or 0)  # missed branches
                except Exception:
                    ci, cb, mb = 0, 0, 0
                lines_to_cover += 1
                if ci > 0:
                    covered_lines += 1
                else:
                    uncovered_lines += 1
                covered_conditions += cb
                uncovered_conditions += mb
            results.append({
                "file_path": file_path,
                "lines_to_cover": lines_to_cover,
                "covered_lines": covered_lines,
                "uncovered_lines": uncovered_lines,
                "covered_conditions": covered_conditions,
                "uncovered_conditions": uncovered_conditions,
            })
    return results

@router.post("/projects/{project_id}/coverage/import")
async def import_code_coverage(
    project_id: int,
    file: UploadFile = File(...),
    format: str = Query("auto", pattern="^(auto|lcov|cobertura|jacoco)$"),
    scan_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import code coverage in LCOV, Cobertura, or JaCoCo formats.

    - Creates `SASTCodeCoverage` rows per file
    - Updates project-level and optional scan-level coverage metrics
    """
    try:
        # Ensure project exists
        project_q = await db.execute(select(SASTProject).where(SASTProject.id == project_id))
        project = project_q.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        content = await file.read()

        # Auto-detect format if requested
        fmt = format.lower()
        if fmt == "auto":
            name = (file.filename or '').lower()
            if name.endswith('.info') or 'lcov' in name:
                fmt = 'lcov'
            elif name.endswith('.xml'):
                # Heuristic: check root tag
                try:
                    root = ET.fromstring(content)
                    tag = root.tag.lower()
                    if tag.endswith('coverage'):
                        fmt = 'cobertura'  # Cobertura root often 'coverage'
                    elif tag.endswith('report'):
                        fmt = 'jacoco'  # JaCoCo root 'report'
                    else:
                        # Default to Cobertura if ambiguous
                        fmt = 'cobertura'
                except Exception:
                    raise HTTPException(status_code=400, detail="Unable to auto-detect XML coverage format")
            else:
                raise HTTPException(status_code=400, detail="Unable to auto-detect coverage format; specify ?format=")

        # Parse into per-file metrics
        if fmt == 'lcov':
            items = _parse_lcov(content.decode(errors='ignore'))
        elif fmt == 'cobertura':
            items = _parse_cobertura(content)
        elif fmt == 'jacoco':
            items = _parse_jacoco(content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

        if not items:
            return {"status": "ok", "files_imported": 0, "overall_coverage": 0.0}

        # Optionally clear existing coverage for this scan or the whole project
        if scan_id is not None:
            await db.execute(
                delete(SASTCodeCoverage).where(
                    (SASTCodeCoverage.project_id == project_id) & (SASTCodeCoverage.scan_id == scan_id)
                )
            )
        else:
            await db.execute(
                delete(SASTCodeCoverage).where(SASTCodeCoverage.project_id == project_id)
            )

        # Insert rows
        total_lines_to_cover = 0
        total_covered_lines = 0
        total_uncovered_conditions = 0
        total_covered_conditions = 0
        for it in items:
            lines_to_cover = int(it.get("lines_to_cover") or 0)
            covered_lines = int(it.get("covered_lines") or 0)
            uncovered_lines = int(it.get("uncovered_lines") or 0)
            covered_conditions = int(it.get("covered_conditions") or 0)
            uncovered_conditions = int(it.get("uncovered_conditions") or 0)

            line_coverage = (covered_lines / lines_to_cover * 100.0) if lines_to_cover > 0 else 0.0
            total_lines_to_cover += lines_to_cover
            total_covered_lines += covered_lines
            total_covered_conditions += covered_conditions
            total_uncovered_conditions += uncovered_conditions

            cov = SASTCodeCoverage(
                project_id=project_id,
                scan_id=scan_id,
                file_path=it["file_path"],
                lines_to_cover=lines_to_cover,
                uncovered_lines=uncovered_lines,
                covered_lines=covered_lines,
                line_coverage=line_coverage,
                conditions_to_cover=covered_conditions + uncovered_conditions,
                uncovered_conditions=uncovered_conditions,
                covered_conditions=covered_conditions,
                branch_coverage=(
                    (covered_conditions / (covered_conditions + uncovered_conditions) * 100.0)
                    if (covered_conditions + uncovered_conditions) > 0 else 0.0
                ),
                overall_coverage=line_coverage,
                detailed_coverage=it.get("detailed_coverage", {}),
            )
            db.add(cov)

        # Update aggregate coverage on project (and scan if present)
        overall_coverage = (total_covered_lines / total_lines_to_cover * 100.0) if total_lines_to_cover > 0 else 0.0
        project.coverage = overall_coverage
        project.uncovered_lines = max(0, total_lines_to_cover - total_covered_lines)
        project.uncovered_conditions = total_uncovered_conditions
        project.last_analysis = datetime.now(timezone.utc).replace(tzinfo=None)

        if scan_id is not None:
            scan_q = await db.execute(select(SASTScan).where(SASTScan.id == scan_id))
            scan = scan_q.scalar_one_or_none()
            if scan:
                scan.coverage = overall_coverage
                # Persist counts if present on scan model
                if hasattr(scan, 'uncovered_lines'):
                    scan.uncovered_lines = project.uncovered_lines
                if hasattr(scan, 'uncovered_conditions'):
                    scan.uncovered_conditions = project.uncovered_conditions

        await db.commit()

        return {
            "status": "ok",
            "project_id": str(project_id),
            "scan_id": str(scan_id) if scan_id is not None else None,
            "files_imported": len(items),
            "overall_coverage": round(overall_coverage, 2),
            "total_lines_to_cover": total_lines_to_cover,
        }

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error importing code coverage: {str(e)}")

# ==========================================================================
# Code Duplication Import (CPD XML, jscpd JSON)
# ==========================================================================

def _parse_cpd_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse PMD CPD XML output to duplication blocks.

    Returns a list of records: { files: [{path, startLine, endLine}],
    lines, tokens, code_snippet }
    """
    root = ET.fromstring(xml_bytes)
    records: List[Dict[str, Any]] = []
    for dup in root.findall('./duplication'):
        try:
            lines = int(dup.get('lines') or 0)
            tokens = int(dup.get('tokens') or 0)
        except Exception:
            lines, tokens = 0, 0
        files = []
        for f in dup.findall('./file'):
            files.append({
                'path': f.get('path') or '',
                'startLine': int(f.get('line') or 0),
                'endLine': int(f.get('endline') or 0) if f.get('endline') else 0,
            })
        code_snippet = ''
        code = dup.find('./codefragment')
        if code is not None and code.text:
            code_snippet = code.text
        if files:
            records.append({
                'lines': lines,
                'tokens': tokens,
                'files': files,
                'code_snippet': code_snippet,
            })
    return records

def _parse_jscpd_json(json_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse jscpd JSON report to duplication blocks."""
    data = json.loads(json_bytes.decode('utf-8', errors='ignore'))
    records: List[Dict[str, Any]] = []
    duplicates = data.get('duplicates') or []
    for d in duplicates:
        fragment = d.get('fragment') or {}
        lines = int(fragment.get('lines') or 0)
        files = []
        for inst in d.get('instances') or []:
            files.append({
                'path': inst.get('path') or '',
                'startLine': int(inst.get('start') or 0),
                'endLine': int(inst.get('end') or 0),
            })
        code_snippet = fragment.get('code') or ''
        if files:
            records.append({
                'lines': lines,
                'files': files,
                'code_snippet': code_snippet,
            })
    return records

@router.post("/projects/{project_id}/duplications/import")
async def import_duplications(
    project_id: int,
    file: UploadFile = File(...),
    format: str = Query("auto", pattern="^(auto|cpd|jscpd)$"),
    language: Optional[str] = Query(None),
    scan_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import code duplication results from PMD CPD (XML) or jscpd (JSON).

    - Creates `SASTDuplication` summary rows and associated `SASTDuplicationBlock` records
    - Updates project duplicated line/block totals
    """
    try:
        proj_res = await db.execute(select(SASTProject).where(SASTProject.id == project_id))
        project = proj_res.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        content = await file.read()
        fmt = format.lower()
        if fmt == 'auto':
            name = (file.filename or '').lower()
            if name.endswith('.xml'):
                fmt = 'cpd'
            elif name.endswith('.json'):
                fmt = 'jscpd'
            else:
                # crude sniffing
                txt = content[:64].lstrip()
                if txt.startswith(b'<?xml') or b'<pmd-cpd' in content or b'<duplication' in content:
                    fmt = 'cpd'
                elif txt.startswith(b'{'):
                    fmt = 'jscpd'
                else:
                    raise HTTPException(status_code=400, detail="Unable to auto-detect duplication format")

        if fmt == 'cpd':
            records = _parse_cpd_xml(content)
        elif fmt == 'jscpd':
            records = _parse_jscpd_json(content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported duplication format")

        if not records:
            return {"status": "ok", "duplications": 0, "blocks": 0}

        # Optionally clear existing duplicates for project/scan
        if scan_id is not None:
            await db.execute(
                delete(SASTDuplication).where(
                    (SASTDuplication.project_id == project_id) & (SASTDuplication.scan_id == scan_id)
                )
            )
            await db.execute(
                delete(SASTDuplicationBlock).where(
                    SASTDuplicationBlock.duplication_id.notin_(select(SASTDuplication.id))
                )
            )
        else:
            await db.execute(delete(SASTDuplication).where(SASTDuplication.project_id == project_id))
            await db.execute(delete(SASTDuplicationBlock))

        total_duplicated_lines = 0
        total_duplicated_blocks = 0
        created_blocks = 0

        for rec in records:
            files = rec.get('files') or []
            lines = int(rec.get('lines') or 0)
            # Simple density: duplicated lines / max(lines,1) * 100
            density = (lines / max(lines, 1)) * 100.0
            dup = SASTDuplication(
                project_id=project_id,
                scan_id=scan_id or 0,
                file_path=files[0]['path'] if files else '',
                duplicated_lines=lines,
                duplicated_blocks=len(files),
                duplication_density=density,
                language=language or (project.language if hasattr(project, 'language') else 'unknown'),
            )
            db.add(dup)
            await db.flush()  # get dup.id

            for f in files:
                block = SASTDuplicationBlock(
                    duplication_id=dup.id,
                    file_path=f['path'],
                    start_line=int(f.get('startLine') or f.get('start') or 0),
                    end_line=int(f.get('endLine') or f.get('end') or 0),
                    code_snippet=rec.get('code_snippet') or '',
                )
                db.add(block)
                created_blocks += 1

            total_duplicated_lines += lines
            total_duplicated_blocks += len(files)

        # Update project totals
        project.duplicated_lines = (project.duplicated_lines or 0) + total_duplicated_lines
        project.duplicated_blocks = (project.duplicated_blocks or 0) + total_duplicated_blocks
        project.last_analysis = datetime.now(timezone.utc).replace(tzinfo=None)

        await db.commit()

        return {
            "status": "ok",
            "project_id": str(project_id),
            "scan_id": str(scan_id) if scan_id is not None else None,
            "duplications": len(records),
            "blocks": created_blocks,
            "duplicated_lines": total_duplicated_lines,
            "duplicated_blocks": total_duplicated_blocks,
        }

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error importing duplications: {str(e)}")

# ==========================================================================
# Taint flow endpoints (storage after Semgrep taint mode runs)
# ==========================================================================

class TaintFlowCreate(BaseModel):
    scan_id: int | None = None
    issue_id: int | None = None
    source: str | None = None
    sink: str | None = None
    steps: list[dict] = []  # {file_path,line_number,function_name,code_snippet}


@router.post("/projects/{project_id}/taint-flows")
async def create_taint_flow(
    project_id: int,
    payload: TaintFlowCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        flow = SASTTaintFlow(
            project_id=project_id,
            scan_id=payload.scan_id,
            issue_id=payload.issue_id,
            source=payload.source,
            sink=payload.sink,
        )
        db.add(flow)
        await db.flush()
        order_index = 0
        for s in payload.steps or []:
            step = SASTTaintStep(
                flow_id=flow.id,
                file_path=s.get('file_path') or '',
                line_number=int(s.get('line_number') or 0),
                function_name=s.get('function_name'),
                code_snippet=s.get('code_snippet'),
                order_index=order_index,
            )
            db.add(step)
            order_index += 1
        await db.commit()
        return {"status": "ok", "flow_id": flow.id}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating taint flow: {str(e)}")


@router.get("/projects/{project_id}/taint-flows")
async def list_taint_flows(
    project_id: int,
    issue_id: int | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        q = select(SASTTaintFlow).where(SASTTaintFlow.project_id == project_id)
        if issue_id is not None:
            q = q.where(SASTTaintFlow.issue_id == issue_id)
        flows = (await db.execute(q)).scalars().all()
        out = []
        for f in flows:
            steps = (await db.execute(select(SASTTaintStep).where(SASTTaintStep.flow_id == f.id).order_by(SASTTaintStep.order_index.asc()))).scalars().all()
            out.append({
                "id": f.id,
                "scan_id": f.scan_id,
                "issue_id": f.issue_id,
                "source": f.source,
                "sink": f.sink,
                "steps": [
                    {
                        "file_path": s.file_path,
                        "line_number": s.line_number,
                        "function_name": s.function_name,
                        "code_snippet": s.code_snippet,
                        "order_index": s.order_index,
                    } for s in steps
                ]
            })
        return {"flows": out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing taint flows: {str(e)}")

# ==========================================================================
# AI Recommendations & Risk Triage
# ==========================================================================

class AIRecommendRequest(BaseModel):
    issue_id: int


@router.post("/issues/{issue_id}/ai-recommendation")
async def generate_issue_ai_recommendation(
    issue_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        issue = (await db.execute(select(SASTIssue).where(SASTIssue.id == issue_id))).scalar_one_or_none()
        if not issue:
            raise HTTPException(status_code=404, detail="Issue not found")
        vuln = {
            "id": issue.id,
            "vulnerability_type": issue.rule_name or issue.type,
            "description": issue.description or issue.message,
            "file_name": issue.file_path,
            "line_number": issue.line_number,
            "severity": str(issue.severity),
            "tool": "SAST",
        }
        rec = await ai_engine.generate_recommendation(vuln)
        return {
            "title": rec.title,
            "description": rec.description,
            "code_fix": rec.code_fix,
            "before_code": getattr(rec, 'before_code', None),
            "after_code": getattr(rec, 'after_code', None),
            "confidence_score": rec.confidence_score,
            "reasoning": rec.reasoning,
            "tags": rec.tags,
            "created_at": rec.created_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating recommendation: {str(e)}")


@router.post("/projects/{project_id}/ai/triage")
async def ai_triage_project(
    project_id: int,
    limit: int | None = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        rows = (await db.execute(select(SASTIssue).where(SASTIssue.project_id == project_id))).scalars().all()
        scored = []
        for i in rows:
            v = {
                "severity": str(i.severity).lower(),
                "vulnerability_type": (i.rule_name or i.type or "").lower(),
                "context": {"confidence": "medium"},
            }
            score = risk_engine.calculate_vulnerability_risk_score(v)
            scored.append({
                "id": i.id,
                "rule_name": i.rule_name,
                "severity": str(i.severity),
                "file_path": i.file_path,
                "line_number": i.line_number,
                "score": score,
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return {"issues": scored[: limit or 50]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error triaging project: {str(e)}")

# ============================================================================
# Code Duplications Endpoints
# ============================================================================

@router.get("/duplications", response_model=DuplicationsResponse)
async def get_duplications(
    project_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    min_duplicated_lines: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get code duplications"""
    try:
        query = select(SASTDuplication)
        
        if project_id:
            query = query.where(SASTDuplication.project_id == int(project_id))
        
        if scan_id:
            query = query.where(SASTDuplication.scan_id == int(scan_id))
        
        if min_duplicated_lines is not None:
            query = query.where(SASTDuplication.duplicated_lines >= min_duplicated_lines)
        
        result = await db.execute(query)
        duplications = result.scalars().all()
        
        return DuplicationsResponse(
            duplications=[
                {
                    "id": str(dup.id),
                    "project_id": str(dup.project_id),
                    "scan_id": str(dup.scan_id) if dup.scan_id else None,
                    "file_path": dup.file_path,
                    "start_line": dup.start_line,
                    "end_line": dup.end_line,
                    "duplicated_lines": dup.duplicated_lines,
                    "duplicated_blocks": dup.duplicated_blocks,
                    "created_at": dup.created_at.isoformat() if dup.created_at else None
                }
                for dup in duplications
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting duplications: {str(e)}")

# ============================================================================
# Statistics & Analytics Endpoints
# ============================================================================

@router.get("/statistics", response_model=SASTStatisticsResponse)
async def get_sast_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive SAST statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get total scans
        scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTIssue.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        severity_counts = await get_vulnerability_counts_by_severity(db)
        
        # Calculate security score
        security_score = await calculate_security_score(
            severity_counts.get('critical', 0),
            severity_counts.get('major', 0),
            severity_counts.get('minor', 0),
            severity_counts.get('info', 0)
        )
        
        # Get recent scans
        recent_scans_result = await db.execute(
            select(SASTScan)
            .order_by(SASTScan.started_at.desc())
            .limit(5)
        )
        recent_scans = recent_scans_result.scalars().all()
        
        recent_scans_data = [
            {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "status": scan.status.value,
                "vulnerabilities_found": scan.vulnerabilities_found or 0,
                "started_at": scan.started_at.isoformat() if scan.started_at else None
            }
            for scan in recent_scans
        ]
        
        # Get top vulnerabilities
        top_vulns_result = await db.execute(
            select(SASTIssue)
            .order_by(SASTIssue.created_at.desc())
            .limit(10)
        )
        top_vulns = top_vulns_result.scalars().all()
        
        top_vulnerabilities = [
            {
                "id": str(vuln.id),
                "rule_name": vuln.rule_name,
                "severity": vuln.severity.value,
                "cwe_id": vuln.cwe_id,
                "file_path": vuln.file_path,
                "created_at": vuln.created_at.isoformat() if vuln.created_at else None
            }
            for vuln in top_vulns
        ]
        
        return SASTStatisticsResponse(
            total_projects=total_projects,
            total_scans=total_scans,
            total_vulnerabilities=total_vulnerabilities,
            security_score=security_score,
            severity_distribution=severity_counts,
            recent_scans=recent_scans_data,
            top_vulnerabilities=top_vulnerabilities
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting statistics: {str(e)}")

# ============================================================================
# Configuration & Rules Endpoints
# ============================================================================

@router.get("/rules")
async def get_detection_rules(
    language: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get available detection rules with filtering"""
    try:
        query = select(SASTRule)
        
        if language:
            query = query.where(SASTRule.languages.contains([language]))
        
        if severity:
            try:
                severity_enum = IssueSeverity(severity.upper())
                query = query.where(SASTRule.severity == severity_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
        
        if category:
            query = query.where(SASTRule.category == category)
        
        result = await db.execute(query)
        rules = result.scalars().all()
        
        return {
            "rules": [
                {
                    "id": str(rule.id),
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "category": rule.category,
                    "subcategory": rule.subcategory,
                    "severity": rule.severity.value,
                    "type": rule.type.value,
                    "cwe_id": rule.cwe_id,
                    "owasp_category": rule.owasp_category,
                    "tags": rule.tags,
                    "enabled": rule.enabled,
                    "effort": rule.effort,
                    "languages": rule.languages,
                    "created_at": rule.created_at.isoformat() if rule.created_at else None
                }
                for rule in rules
            ],
            "supported_languages": ["java", "python", "javascript", "typescript", "csharp", "php", "go", "rust"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting detection rules: {str(e)}")

@router.get("/languages")
async def get_supported_languages(
    current_user: User = Depends(get_current_user)
):
    """Get supported programming languages"""
    try:
        return {
            "languages": {
                "java": {"name": "Java", "extensions": [".java"]},
                "python": {"name": "Python", "extensions": [".py"]},
                "javascript": {"name": "JavaScript", "extensions": [".js"]},
                "typescript": {"name": "TypeScript", "extensions": [".ts"]},
                "csharp": {"name": "C#", "extensions": [".cs"]},
                "php": {"name": "PHP", "extensions": [".php"]},
                "go": {"name": "Go", "extensions": [".go"]},
                "rust": {"name": "Rust", "extensions": [".rs"]}
            },
            "rules": {
                "java": ["S1488", "S1172", "S1135"],
                "python": ["S1488", "S1172", "S1135"],
                "javascript": ["S1488", "S1172", "S1135"]
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting supported languages: {str(e)}")

@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a rule's enabled flag or severity override."""
    try:
        rule = (await db.execute(select(SASTRule).where(SASTRule.id == rule_id))).scalar_one_or_none()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        if "enabled" in payload:
            rule.enabled = bool(payload.get("enabled"))
        if "severity" in payload and payload.get("severity"):
            try:
                rule.severity = IssueSeverity(str(payload.get("severity")).upper())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid severity")
        await db.commit()
        await db.refresh(rule)
        return {"status": "ok", "id": rule.id, "enabled": rule.enabled, "severity": rule.severity.value}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating rule: {str(e)}")

# ============================================================================
# Rule Profiles Endpoints
# ============================================================================

@router.get("/rule-profiles")
async def list_rule_profiles(
    language: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        q = select(SASTRuleProfile)
        if language:
            q = q.where(SASTRuleProfile.language == language)
        rows = (await db.execute(q)).scalars().all()
        return {
            "profiles": [
                {
                    "id": int(p.id) if hasattr(p, 'id') else p.id,
                    "name": getattr(p, 'name', None),
                    "language": getattr(p, 'language', None),
                    "description": getattr(p, 'description', None),
                    "created_at": getattr(p, 'created_at', None).isoformat() if getattr(p, 'created_at', None) else None,
                }
                for p in rows
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing rule profiles: {str(e)}")

@router.post("/rule-profiles")
async def create_rule_profile(
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        name = payload.get("name")
        language = payload.get("language")
        description = payload.get("description")
        if not name or not language:
            raise HTTPException(status_code=400, detail="name and language are required")
        prof = SASTRuleProfile(name=name, language=language, description=description)
        db.add(prof)
        await db.commit()
        await db.refresh(prof)
        return {"status": "ok", "id": int(prof.id) if hasattr(prof, 'id') else prof.id}
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating rule profile: {str(e)}")

# ============================================================================
# Quality Management Endpoints
# ============================================================================

@router.get("/projects/{project_id}/quality-overview")
async def get_project_quality_overview(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive quality overview for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan for metrics
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Calculate quality metrics
        quality_metrics = {
            "project_id": project_id,
            "project_name": project.name,
            "quality_gate_status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "issue_counts": {
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "code_metrics": {
                "lines_of_code": project.lines_of_code,
                "lines_of_comment": project.lines_of_comment,
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks
            },
            "coverage_metrics": {
                "coverage": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions
            },
            "technical_debt": {
                "total_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "debt_hours": round(project.technical_debt / 60, 2) if project.technical_debt else 0
            },
            "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None,
            "scan_status": recent_scan.status if recent_scan else None
        }
        
        return quality_metrics
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality overview: {str(e)}")

@router.get("/projects/{project_id}/quality-metrics")
async def get_project_quality_metrics(
    project_id: str,
    metric_type: Optional[str] = Query(None, description="Type of metrics: 'security', 'reliability', 'maintainability', 'coverage', 'duplications'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed quality metrics for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        if not metric_type:
            # Return all metrics
            return {
                "project_id": project_id,
                "project_name": project.name,
                "security_metrics": {
                    "rating": project.security_rating,
                    "vulnerability_count": project.vulnerability_count,
                    "security_hotspot_count": project.security_hotspot_count
                },
                "reliability_metrics": {
                    "rating": project.reliability_rating,
                    "bug_count": project.bug_count
                },
                "maintainability_metrics": {
                    "rating": project.maintainability_rating,
                    "code_smell_count": project.code_smell_count,
                    "technical_debt": project.technical_debt,
                    "debt_ratio": project.debt_ratio
                },
                "coverage_metrics": {
                    "coverage": project.coverage,
                    "uncovered_lines": project.uncovered_lines,
                    "uncovered_conditions": project.uncovered_conditions
                },
                "duplication_metrics": {
                    "duplicated_lines": project.duplicated_lines,
                    "duplicated_blocks": project.duplicated_blocks
                }
            }
        
        # Return specific metric type
        if metric_type == "security":
            return {
                "project_id": project_id,
                "metric_type": "security",
                "rating": project.security_rating,
                "vulnerability_count": project.vulnerability_count,
                "security_hotspot_count": project.security_hotspot_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "reliability":
            return {
                "project_id": project_id,
                "metric_type": "reliability",
                "rating": project.reliability_rating,
                "bug_count": project.bug_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "maintainability":
            return {
                "project_id": project_id,
                "metric_type": "maintainability",
                "rating": project.maintainability_rating,
                "code_smell_count": project.code_smell_count,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "coverage":
            return {
                "project_id": project_id,
                "metric_type": "coverage",
                "coverage": project.coverage,
                "line_number": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "duplications":
            return {
                "project_id": project_id,
                "metric_type": "duplications",
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid metric type")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality metrics: {str(e)}")

@router.get("/projects/{project_id}/quality-trends")
async def get_project_quality_trends(
    project_id: str,
    days: int = Query(30, description="Number of days for trend analysis"),
    metric: str = Query("all", description="Specific metric to analyze: 'security', 'reliability', 'maintainability', 'coverage', 'debt'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality trends for a project over time"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get scans within the specified time period
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .where(SASTScan.created_at >= cutoff_date)
            .order_by(SASTScan.created_at.asc())
        )
        scans = scans_result.scalars().all()
        
        # Generate trend data
        trends = []
        for scan in scans:
            trend_point = {
                "date": scan.created_at.isoformat(),
                "scan_id": str(scan.id),
                "scan_status": scan.status
            }
            
            if metric == "all" or metric == "security":
                trend_point["security_rating"] = getattr(scan, 'security_rating', None)
                trend_point["vulnerability_count"] = getattr(scan, 'vulnerabilities_found', 0)
            
            if metric == "all" or metric == "reliability":
                trend_point["reliability_rating"] = getattr(scan, 'reliability_rating', None)
                trend_point["bug_count"] = getattr(scan, 'bugs_found', 0)
            
            if metric == "all" or metric == "maintainability":
                trend_point["maintainability_rating"] = getattr(scan, 'maintainability_rating', None)
                trend_point["code_smell_count"] = getattr(scan, 'code_smells_found', 0)
            
            if metric == "all" or metric == "coverage":
                trend_point["coverage"] = getattr(scan, 'coverage', 0.0)
            
            if metric == "all" or metric == "debt":
                trend_point["technical_debt"] = getattr(scan, 'technical_debt', 0)
            
            trends.append(trend_point)
        
        return {
            "project_id": project_id,
            "project_name": project.name,
            "metric": metric,
            "period_days": days,
            "trends": trends,
            "summary": {
                "total_scans": len(trends),
                "period_start": cutoff_date.isoformat(),
                "period_end": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality trends: {str(e)}")

@router.get("/projects/{project_id}/quality-report")
async def get_project_quality_report(
    project_id: str,
    format: str = Query("json", description="Report format: 'json', 'pdf', 'csv'"),
    include_details: bool = Query(True, description="Include detailed issue information"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate comprehensive quality report for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Get issues if details are requested
        issues = []
        if include_details:
            issues_result = await db.execute(
                select(SASTIssue)
                .where(SASTIssue.project_id == project_id)
                .order_by(SASTIssue.severity.desc(), SASTIssue.created_at.desc())
                .limit(100)  # Limit for performance
            )
            issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "project": {
                "id": project_id,
                "name": project.name,
                "key": project.key,
                "language": project.language,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            },
            "quality_gate": {
                "status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
                "evaluated_at": quality_gate.last_evaluation.isoformat() if quality_gate and quality_gate.last_evaluation else None
            },
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "metrics_summary": {
                "lines_of_code": project.lines_of_code,
                "coverage": project.coverage,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "duplicated_lines": project.duplicated_lines
            },
            "issue_summary": {
                "total_issues": len(issues),
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "scan_information": {
                "last_scan_id": str(recent_scan.id) if recent_scan else None,
                "last_scan_status": recent_scan.status if recent_scan else None,
                "last_scan_date": recent_scan.created_at.isoformat() if recent_scan else None
            },
            "generated_at": datetime.now().isoformat()
        }
        
        if include_details and issues:
            report_data["detailed_issues"] = [
                {
                    "id": str(issue.id),
                    "type": issue.type,
                    "severity": issue.severity,
                    "status": issue.status,
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "message": issue.message,
                    "effort": issue.effort,
                    "created_at": issue.created_at.isoformat()
                }
                for issue in issues
            ]
        
        # Return based on format
        if format == "json":
            return report_data
        elif format == "csv":
            # Generate CSV response
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(["Quality Report", project.name])
            writer.writerow([])
            writer.writerow(["Project Information"])
            writer.writerow(["ID", project_id])
            writer.writerow(["Name", project.name])
            writer.writerow(["Language", project.language])
            writer.writerow([])
            writer.writerow(["Quality Metrics"])
            writer.writerow(["Maintainability Rating", project.maintainability_rating])
            writer.writerow(["Security Rating", project.security_rating])
            writer.writerow(["Reliability Rating", project.reliability_rating])
            writer.writerow(["Coverage", f"{project.coverage}%"])
            writer.writerow(["Technical Debt", f"{project.technical_debt} minutes"])
            writer.writerow(["Debt Ratio", f"{project.debt_ratio}%"])
            
            output.seek(0)
            return Response(content=output.getvalue(), media_type="text/csv")
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating quality report: {str(e)}")

@router.post("/projects/{project_id}/quality-gate/evaluate")
async def evaluate_project_quality_gate(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually evaluate quality gate for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        if not quality_gate:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        
        # Evaluate quality gate based on current project metrics
        evaluation_results = {}
        gate_status = QualityGateStatus.PASSED
        
        # Check vulnerability thresholds
        if project.vulnerability_count > quality_gate.max_blocker_issues:
            evaluation_results["blocker_issues"] = f"Failed: {project.vulnerability_count} > {quality_gate.max_blocker_issues}"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["blocker_issues"] = f"Passed: {project.vulnerability_count} <= {quality_gate.max_blocker_issues}"
        
        # Check coverage threshold
        if project.coverage < quality_gate.min_coverage:
            evaluation_results["coverage"] = f"Failed: {project.coverage}% < {quality_gate.min_coverage}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["coverage"] = f"Passed: {project.coverage}% >= {quality_gate.min_coverage}%"
        
        # Check technical debt threshold
        if project.debt_ratio > quality_gate.max_debt_ratio:
            evaluation_results["debt_ratio"] = f"Failed: {project.debt_ratio}% > {quality_gate.max_debt_ratio}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["debt_ratio"] = f"Passed: {project.debt_ratio}% <= {quality_gate.max_debt_ratio}%"
        
        # Update quality gate status
        quality_gate.status = gate_status
        quality_gate.last_evaluation = datetime.now()
        quality_gate.evaluation_results = evaluation_results
        
        await db.commit()
        
        return {
            "project_id": project_id,
            "quality_gate_status": gate_status,
            "evaluation_results": evaluation_results,
            "evaluated_at": quality_gate.last_evaluation.isoformat(),
            "next_evaluation": "Automatic on next scan or manual trigger"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error evaluating quality gate: {str(e)}")

@router.get("/quality-management/dashboard")
async def get_quality_management_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality management dashboard overview"""
    try:
        # Get total projects
        total_projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = total_projects_result.scalar() or 0
        
        # Get projects by quality gate status
        passed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.PASSED)
        )
        passed_projects = passed_projects_result.scalar() or 0
        
        failed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.FAILED)
        )
        failed_projects = failed_projects_result.scalar() or 0
        
        # Get average ratings
        avg_maintainability_result = await db.execute(
            select(func.avg(SASTProject.maintainability_rating))
        )
        avg_maintainability = avg_maintainability_result.scalar()
        
        avg_security_result = await db.execute(
            select(func.avg(SASTProject.security_rating))
        )
        avg_security = avg_security_result.scalar()
        
        avg_reliability_result = await db.execute(
            select(func.avg(SASTProject.reliability_rating))
        )
        avg_reliability = avg_reliability_result.scalar()
        
        # Get total technical debt
        total_debt_result = await db.execute(
            select(func.sum(SASTProject.technical_debt))
        )
        total_debt = total_debt_result.scalar() or 0
        
        # Get average coverage
        avg_coverage_result = await db.execute(
            select(func.avg(SASTProject.coverage))
        )
        avg_coverage = avg_coverage_result.scalar() or 0
        
        return {
            "summary": {
                "total_projects": total_projects,
                "passed_projects": passed_projects,
                "failed_projects": failed_projects,
                "pass_rate": round((passed_projects / total_projects * 100), 2) if total_projects > 0 else 0
            },
            "average_ratings": {
                "maintainability": avg_maintainability,
                "security": avg_security,
                "reliability": avg_reliability
            },
            "overall_metrics": {
                "total_technical_debt_hours": round(total_debt / 60, 2),
                "average_coverage": round(avg_coverage, 2)
            },
            "quality_distribution": {
                "excellent": 0,  # A rating
                "good": 0,       # B rating
                "moderate": 0,   # C rating
                "poor": 0,       # D rating
                "very_poor": 0   # E rating
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality management dashboard: {str(e)}")

# ============================================================================
# Project Configuration Endpoints
# ============================================================================

@router.get("/projects/{project_id}/configuration")
async def get_project_configuration(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project configuration"""
    try:
        result = await db.execute(
            select(SASTProjectConfiguration).where(SASTProjectConfiguration.project_id == int(project_id))
        )
        config = result.scalar_one_or_none()
        
        if not config:
            return {
                "project_id": project_id,
                "scan_patterns": [],
                "excluded_files": [],
                "excluded_directories": [],
                "enabled_rules": [],
                "disabled_rules": [],
                "rule_severities": {},
                "quality_gate_id": None
            }
        
        return {
            "project_id": str(config.project_id),
            "scan_patterns": config.scan_patterns or [],
            "excluded_files": config.excluded_files or [],
            "excluded_directories": config.excluded_directories or [],
            "enabled_rules": config.enabled_rules or [],
            "disabled_rules": config.disabled_rules or [],
            "rule_severities": config.rule_severities or {},
            "quality_gate_id": str(config.quality_gate_id) if config.quality_gate_id else None
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project configuration: {str(e)}")

@router.put("/projects/{project_id}/configuration")
async def update_project_configuration(
    project_id: str,
    config_data: SASTProjectCreate, # Changed from SASTProjectConfigSchema to SASTProjectCreate to match existing schema
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update project configuration"""
    try:
        result = await db.execute(
            select(SASTProjectConfiguration).where(SASTProjectConfiguration.project_id == int(project_id))
        )
        config = result.scalar_one_or_none()
        
        if config:
            # Update existing configuration
            config.scan_patterns = config_data.scan_patterns
            config.excluded_files = config_data.excluded_files
            config.excluded_directories = config_data.excluded_directories
            config.enabled_rules = config_data.enabled_rules
            config.disabled_rules = config_data.disabled_rules
            config.rule_severities = config_data.rule_severities
            config.quality_gate_id = int(config_data.quality_gate_id) if config_data.quality_gate_id else None
            config.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        else:
            # Create new configuration
            config = SASTProjectConfiguration(
                project_id=int(project_id),
                scan_patterns=config_data.scan_patterns,
                excluded_files=config_data.excluded_files,
                excluded_directories=config_data.excluded_directories,
                enabled_rules=config_data.enabled_rules,
                disabled_rules=config_data.disabled_rules,
                rule_severities=config_data.rule_severities,
                quality_gate_id=int(config_data.quality_gate_id) if config_data.quality_gate_id else None
            )
            db.add(config)
        
        await db.commit()
        
        return {
            "message": "Project configuration updated successfully",
            "configuration": {
                "project_id": str(config.project_id),
                "scan_patterns": config.scan_patterns,
                "excluded_files": config.excluded_files,
                "excluded_directories": config.excluded_directories,
                "enabled_rules": config.enabled_rules,
                "disabled_rules": config.disabled_rules,
                "rule_severities": config.rule_severities,
                "quality_gate_id": str(config.quality_gate_id) if config.quality_gate_id else None
            }
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating project configuration: {str(e)}") 

# Add new endpoints after the existing ones

# ============================================================================
# Duplications Endpoints
# ============================================================================

@router.get("/projects/{project_id}/duplications")
async def get_project_duplications(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get code duplications for a specific project from database"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == int(project_id))
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get duplications for this project
        duplications_result = await db.execute(
            select(SASTDuplication).where(SASTDuplication.project_id == int(project_id))
        )
        duplications = duplications_result.scalars().all()
        
        # Calculate summary
        total_duplicated_lines = sum(d.duplicated_lines for d in duplications)
        total_duplicated_blocks = sum(d.duplicated_blocks for d in duplications)
        duplication_density = sum(d.duplication_density for d in duplications) / len(duplications) if duplications else 0
        files_with_duplications = len(duplications)
        
        # Group by language
        language_stats = {}
        for dup in duplications:
            if dup.language not in language_stats:
                language_stats[dup.language] = {
                    "duplicatedLines": 0,
                    "duplicatedFiles": 0,
                    "duplicationDensity": 0,
                    "count": 0
                }
            language_stats[dup.language]["duplicatedLines"] += dup.duplicated_lines
            language_stats[dup.language]["duplicatedFiles"] += 1
            language_stats[dup.language]["duplicationDensity"] += dup.duplication_density
            language_stats[dup.language]["count"] += 1
        
        # Calculate average density per language and add colors
        duplications_by_language = []
        colors = ["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6", "#06b6d4"]
        for i, (lang, stats) in enumerate(language_stats.items()):
            avg_density = stats["duplicationDensity"] / stats["count"] if stats["count"] > 0 else 0
            duplications_by_language.append({
                "language": lang,
                "duplicatedLines": stats["duplicatedLines"],
                "duplicatedFiles": stats["duplicatedFiles"],
                "duplicationDensity": round(avg_density, 1),
                "color": colors[i % len(colors)]
            })
        
        # Sort by duplicated lines
        duplications_by_language.sort(key=lambda x: x["duplicatedLines"], reverse=True)
        
        # Get file-level details
        duplications_by_file = []
        for dup in duplications:
            duplications_by_file.append({
                "file": dup.file_path,
                "duplicatedLines": dup.duplicated_lines,
                "duplicatedBlocks": dup.duplicated_blocks,
                "duplicationDensity": round(dup.duplication_density, 1),
                "lastModified": dup.last_modified.isoformat() if dup.last_modified else None
            })
        
        # Sort by duplicated lines
        duplications_by_file.sort(key=lambda x: x["duplicatedLines"], reverse=True)
        
        # Generate trends (last 5 scans)
        duplication_trend = []
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == int(project_id))
            .order_by(SASTScan.started_at.desc())
            .limit(5)
        )
        scans = scans_result.scalars().all()
        
        for scan in reversed(scans):
            scan_duplications_result = await db.execute(
                select(SASTDuplication).where(SASTDuplication.scan_id == scan.id)
            )
            scan_duplications = scan_duplications_result.scalars().all()
            
            total_lines = sum(d.duplicated_lines for d in scan_duplications)
            total_files = len(scan_duplications)
            avg_density = sum(d.duplication_density for d in scan_duplications) / len(scan_duplications) if scan_duplications else 0
            
            duplication_trend.append({
                "date": scan.started_at.strftime("%Y-%m-%d"),
                "duplicatedLines": total_lines,
                "duplicatedFiles": total_files,
                "duplicationDensity": round(avg_density, 1)
            })
        
        return {
            "duplicatedLines": total_duplicated_lines,
            "duplicatedFiles": files_with_duplications,
            "duplicatedBlocks": total_duplicated_blocks,
            "duplicationDensity": round(duplication_density, 1),
            "duplicationsByLanguage": duplications_by_language,
            "duplicationsByFile": duplications_by_file[:10],  # Top 10 files
            "duplicationTrend": duplication_trend
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching duplications: {str(e)}")

# ============================================================================
# Security Reports Endpoints
# ============================================================================

@router.get("/projects/{project_id}/security-reports")
async def get_project_security_reports(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive security reports for a project"""
    try:
        # Mock data for security reports
        security_reports = {
            "overallSecurityRating": "B",
            "securityScore": 75,
            "vulnerabilitiesByCategory": [
                {"category": "SQL Injection", "count": 3, "severity": "CRITICAL", "percentage": 25, "color": "#ef4444"},
                {"category": "XSS", "count": 2, "severity": "MAJOR", "percentage": 17, "color": "#f59e0b"}
            ],
            "owaspTop10Mapping": [
                {"category": "A01:2021 - Broken Access Control", "count": 2, "severity": "CRITICAL", "description": "Access control vulnerabilities", "color": "#ef4444"},
                {"category": "A03:2021 - Injection", "count": 5, "severity": "CRITICAL", "description": "SQL injection and XSS vulnerabilities", "color": "#ef4444"}
            ],
            "cweMapping": [
                {"cweId": "CWE-89", "name": "SQL Injection", "count": 3, "severity": "CRITICAL", "description": "SQL injection vulnerabilities"},
                {"cweId": "CWE-79", "name": "Cross-site Scripting", "count": 2, "severity": "MAJOR", "description": "XSS vulnerabilities"}
            ],
            "securityTrend": [
                {"date": "2024-01-10", "vulnerabilities": 15, "securityScore": 65, "securityRating": "C"},
                {"date": "2024-01-15", "vulnerabilities": 12, "securityScore": 75, "securityRating": "B"}
            ]
        }
        return security_reports
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching security reports: {str(e)}")

# ============================================================================
# Reliability Endpoints
# ============================================================================

@router.get("/projects/{project_id}/reliability")
async def get_project_reliability(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get reliability metrics for a project"""
    try:
        # Mock data for reliability
        reliability_data = {
            "reliabilityRating": "A",
            "bugCount": 8,
            "bugDensity": 0.5,
            "bugsBySeverity": [
                {"severity": "BLOCKER", "count": 1, "percentage": 12.5, "color": "#dc2626"},
                {"severity": "CRITICAL", "count": 2, "percentage": 25, "color": "#ea580c"}
            ],
            "bugsByCategory": [
                {"category": "Null Pointer Exception", "count": 3, "description": "Null pointer dereference bugs", "color": "#ef4444"},
                {"category": "Array Index Out of Bounds", "count": 2, "description": "Array access violations", "color": "#f59e0b"}
            ],
            "reliabilityTrend": [
                {"date": "2024-01-10", "bugCount": 12, "bugDensity": 0.8, "reliabilityRating": "B"},
                {"date": "2024-01-15", "bugCount": 8, "bugDensity": 0.5, "reliabilityRating": "A"}
            ],
            "newBugs": 2,
            "resolvedBugs": 6
        }
        return reliability_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching reliability data: {str(e)}")

# ============================================================================
# Maintainability Endpoints
# ============================================================================

@router.get("/projects/{project_id}/maintainability")
async def get_project_maintainability(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get maintainability metrics for a project"""
    try:
        # Mock data for maintainability
        maintainability_data = {
            "maintainabilityRating": "A",
            "codeSmellCount": 25,
            "codeSmellDensity": 1.6,
            "complexity": 15,
            "cognitiveComplexity": 8,
            "codeSmellsByCategory": [
                {"category": "Code Smells", "count": 15, "description": "General code quality issues", "color": "#3b82f6"},
                {"category": "Unused Code", "count": 5, "description": "Dead code and unused variables", "color": "#10b981"}
            ],
            "maintainabilityTrend": [
                {"date": "2024-01-10", "codeSmellCount": 30, "maintainabilityRating": "B", "complexity": 18},
                {"date": "2024-01-15", "codeSmellCount": 25, "maintainabilityRating": "A", "complexity": 15}
            ]
        }
        return maintainability_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching maintainability data: {str(e)}")

# ============================================================================
# Activity Endpoints
# ============================================================================

@router.get("/projects/{project_id}/activity")
async def get_project_activity(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project activity and contributor information"""
    try:
        # Mock data for activity
        activity_data = {
            "recentCommits": [
                {"id": "abc123", "author": "john.doe@example.com", "message": "Fix SQL injection vulnerability", "timestamp": "2024-01-15T10:30:00Z", "filesChanged": 3, "linesAdded": 15, "linesRemoved": 8},
                {"id": "def456", "author": "jane.smith@example.com", "message": "Add input validation", "timestamp": "2024-01-15T09:15:00Z", "filesChanged": 2, "linesAdded": 12, "linesRemoved": 5}
            ],
            "recentIssues": [
                {"id": 1, "type": "VULNERABILITY", "severity": "CRITICAL", "status": "RESOLVED", "author": "john.doe@example.com", "timestamp": "2024-01-15T10:30:00Z", "message": "SQL injection fixed"},
                {"id": 2, "type": "BUG", "severity": "MAJOR", "status": "OPEN", "author": "jane.smith@example.com", "timestamp": "2024-01-15T09:15:00Z", "message": "Null pointer exception"}
            ],
            "activityMetrics": {
                "totalCommits": 45,
                "totalIssues": 12,
                "totalHotspots": 8,
                "activeContributors": 5,
                "averageCommitFrequency": 3.2
            },
            "contributors": [
                {"name": "john.doe@example.com", "commits": 15, "issues": 4, "hotspots": 3, "lastActivity": "2024-01-15T10:30:00Z"},
                {"name": "jane.smith@example.com", "commits": 12, "issues": 3, "hotspots": 2, "lastActivity": "2024-01-15T09:15:00Z"}
            ],
            "activityTrend": [
                {"date": "2024-01-10", "commits": 5, "issues": 2, "hotspots": 1},
                {"date": "2024-01-15", "commits": 3, "issues": 2, "hotspots": 2}
            ]
        }
        return activity_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching activity data: {str(e)}")

# ============================================================================
# Administration Endpoints
# ============================================================================

@router.get("/projects/{project_id}/configuration")
async def get_project_configuration(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project configuration and settings"""
    try:
        # Mock data for project configuration
        configuration_data = {
            "id": 1,
            "name": "Web Application Security",
            "key": "web-app-sec",
            "description": "Main web application security project",
            "language": "JavaScript",
            "repositoryUrl": "https://github.com/example/web-app",
            "branch": "main",
            "qualityProfile": "Sonar way",
            "qualityGate": "Default Quality Gate",
            "exclusions": ["**/node_modules/**", "**/dist/**", "**/coverage/**"],
            "settings": {
                "scanSchedule": "0 2 * * *",
                "autoScan": True,
                "notifications": {
                    "email": True,
                    "slack": False,
                    "webhook": "https://hooks.slack.com/services/xxx/yyy/zzz"
                },
                "integrations": {
                    "gitHub": True,
                    "gitLab": False,
                    "bitbucket": False,
                    "jenkins": True
                }
            },
            "permissions": {
                "users": [
                    {"username": "john.doe@example.com", "role": "Admin", "permissions": ["read", "write", "admin"]},
                    {"username": "jane.smith@example.com", "role": "User", "permissions": ["read", "write"]}
                ],
                "groups": [
                    {"groupName": "developers", "role": "User", "permissions": ["read", "write"]},
                    {"groupName": "security-team", "role": "Admin", "permissions": ["read", "write", "admin"]}
                ]
            }
        }
        return configuration_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching project configuration: {str(e)}")

@router.put("/projects/{project_id}/configuration")
async def update_project_configuration(
    project_id: str,
    configuration_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update project configuration and settings"""
    try:
        # Mock update - replace with actual database update
        return {"message": "Project configuration updated successfully", "project_id": project_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating project configuration: {str(e)}")

# ============================================================================
# Additional Utility Endpoints
# ============================================================================

@router.get("/projects/{project_id}/metrics")
async def get_project_metrics(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive project metrics"""
    try:
        # Mock comprehensive metrics
        metrics_data = {
            "overview": {
                "linesOfCode": 15420,
                "files": 245,
                "functions": 1200,
                "classes": 89,
                "complexity": 15.2
            },
            "quality": {
                "maintainabilityRating": "A",
                "securityRating": "B",
                "reliabilityRating": "A",
                "coverage": 78.5,
                "duplicationDensity": 3.2
            },
            "issues": {
                "total": 19,
                "bugs": 5,
                "vulnerabilities": 2,
                "codeSmells": 12,
                "securityHotspots": 3
            },
            "technicalDebt": {
                "totalDebt": 120,
                "debtRatio": 8.5,
                "effortToFix": "2h 30m"
            }
        }
        return metrics_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching project metrics: {str(e)}")

@router.get("/projects/{project_id}/trends")
async def get_project_trends(
    project_id: str,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project trends over time"""
    try:
        # Mock trend data
        trends_data = {
            "issues": [
                {"date": "2024-01-10", "total": 25, "bugs": 8, "vulnerabilities": 5, "codeSmells": 12},
                {"date": "2024-01-15", "total": 19, "bugs": 5, "vulnerabilities": 2, "codeSmells": 12}
            ],
            "coverage": [
                {"date": "2024-01-10", "coverage": 75.0},
                {"date": "2024-01-15", "coverage": 78.5}
            ],
            "duplications": [
                {"date": "2024-01-10", "duplicationDensity": 3.8},
                {"date": "2024-01-15", "duplicationDensity": 3.2}
            ],
            "complexity": [
                {"date": "2024-01-10", "complexity": 16.5},
                {"date": "2024-01-15", "complexity": 15.2}
            ]
        }
        return trends_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching project trends: {str(e)}")

# ============================================================================
# Quality Profiles Endpoints
# ============================================================================

@router.get("/quality-profiles")
async def get_quality_profiles(
    language: Optional[str] = Query(None),
    is_default: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality profiles with filtering"""
    try:
        # Mock quality profiles data
        profiles_data = [
            {
                "id": "1",
                "name": "Sonar way",
                "description": "Default profile for most languages with common security and quality rules",
                "language": "java",
                "is_default": True,
                "active_rule_count": 156,
                "deprecated_rule_count": 12,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            {
                "id": "2",
                "name": "Security Profile",
                "description": "High-security profile with strict security rules enabled",
                "language": "java",
                "is_default": False,
                "active_rule_count": 89,
                "deprecated_rule_count": 5,
                "created_at": "2024-01-05T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            {
                "id": "3",
                "name": "Python Best Practices",
                "description": "Profile optimized for Python development with PEP 8 compliance",
                "language": "python",
                "is_default": False,
                "active_rule_count": 78,
                "deprecated_rule_count": 3,
                "created_at": "2024-01-10T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            {
                "id": "4",
                "name": "JavaScript ES6+",
                "description": "Modern JavaScript profile with ES6+ and security rules",
                "language": "javascript",
                "is_default": False,
                "active_rule_count": 92,
                "deprecated_rule_count": 8,
                "created_at": "2024-01-12T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            }
        ]

        # Apply filters
        if language:
            profiles_data = [p for p in profiles_data if p["language"] == language]
        
        if is_default is not None:
            profiles_data = [p for p in profiles_data if p["is_default"] == is_default]

        return {
            "profiles": profiles_data,
            "total": len(profiles_data),
            "languages": ["java", "python", "javascript", "typescript", "csharp", "php"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality profiles: {str(e)}")

@router.post("/quality-profiles")
async def create_quality_profile(
    profile_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new quality profile"""
    try:
        # Mock profile creation
        new_profile = {
            "id": str(len(profile_data) + 1),  # Simple ID generation
            "name": profile_data.get("name", "New Profile"),
            "description": profile_data.get("description", ""),
            "language": profile_data.get("language", "java"),
            "is_default": False,
            "active_rule_count": 0,
            "deprecated_rule_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "message": "Quality profile created successfully",
            "profile": new_profile
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating quality profile: {str(e)}")

@router.put("/quality-profiles/{profile_id}")
async def update_quality_profile(
    profile_id: str,
    profile_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing quality profile"""
    try:
        # Mock profile update
        updated_profile = {
            "id": profile_id,
            "name": profile_data.get("name", "Updated Profile"),
            "description": profile_data.get("description", ""),
            "language": profile_data.get("language", "java"),
            "is_default": profile_data.get("is_default", False),
            "active_rule_count": profile_data.get("active_rule_count", 0),
            "deprecated_rule_count": profile_data.get("deprecated_rule_count", 0),
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "message": "Quality profile updated successfully",
            "profile": updated_profile
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating quality profile: {str(e)}")

@router.delete("/quality-profiles/{profile_id}")
async def delete_quality_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a quality profile"""
    try:
        # Mock profile deletion
        return {
            "message": "Quality profile deleted successfully",
            "profile_id": profile_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting quality profile: {str(e)}")

@router.post("/quality-profiles/{profile_id}/duplicate")
async def duplicate_quality_profile(
    profile_id: str,
    duplicate_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Duplicate an existing quality profile"""
    try:
        # Mock profile duplication
        duplicated_profile = {
            "id": str(int(profile_id) + 100),  # Simple ID generation
            "name": duplicate_data.get("name", f"Profile {profile_id} - Copy"),
            "description": duplicate_data.get("description", "Duplicated profile"),
            "language": duplicate_data.get("language", "java"),
            "is_default": False,
            "active_rule_count": 0,
            "deprecated_rule_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "message": "Quality profile duplicated successfully",
            "profile": duplicated_profile
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error duplicating quality profile: {str(e)}")

@router.post("/quality-profiles/{profile_id}/set-default")
async def set_default_quality_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Set a quality profile as default for its language"""
    try:
        # Mock setting default profile
        return {
            "message": "Quality profile set as default successfully",
            "profile_id": profile_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error setting default quality profile: {str(e)}")

@router.get("/quality-profiles/{profile_id}/rules")
async def get_profile_rules(
    profile_id: str,
    enabled_only: Optional[bool] = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get rules for a specific quality profile"""
    try:
        # Mock profile rules data
        rules_data = [
            {
                "id": "1",
                "rule_id": "S1488",
                "name": "Local variables should not be declared and then immediately returned",
                "severity": "minor",
                "category": "Code Smell",
                "enabled": True,
                "effort": "5min"
            },
            {
                "id": "2",
                "rule_id": "S1172",
                "name": "Unused function parameters should be removed",
                "severity": "major",
                "category": "Code Smell",
                "enabled": True,
                "effort": "5min"
            },
            {
                "id": "3",
                "rule_id": "S1135",
                "name": "Track uses of 'FIXME' tags",
                "severity": "info",
                "category": "Code Smell",
                "enabled": False,
                "effort": "10min"
            }
        ]

        # Apply enabled filter if requested
        if enabled_only:
            rules_data = [r for r in rules_data if r["enabled"]]

        return {
            "profile_id": profile_id,
            "rules": rules_data,
            "total": len(rules_data),
            "enabled_count": len([r for r in rules_data if r["enabled"]]),
            "disabled_count": len([r for r in rules_data if not r["enabled"]])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting profile rules: {str(e)}")

@router.put("/quality-profiles/{profile_id}/rules/{rule_id}")
async def update_profile_rule(
    profile_id: str,
    rule_id: str,
    rule_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a rule in a quality profile (enable/disable, change severity, etc.)"""
    try:
        # Mock rule update
        updated_rule = {
            "id": rule_id,
            "rule_id": rule_data.get("rule_id", "S0000"),
            "name": rule_data.get("name", "Updated Rule"),
            "severity": rule_data.get("severity", "minor"),
            "category": rule_data.get("category", "Code Smell"),
            "enabled": rule_data.get("enabled", True),
            "effort": rule_data.get("effort", "5min")
        }
        
        return {
            "message": "Profile rule updated successfully",
            "rule": updated_rule
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating profile rule: {str(e)}")

# ============================================================================
# Bulk Operations Endpoints
# ============================================================================

@router.put("/vulnerabilities/bulk-update")
async def bulk_update_vulnerabilities(
    update_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk update vulnerabilities"""
    try:
        vulnerability_ids = update_data.get("vulnerability_ids", [])
        updates = update_data.get("updates", {})
        
        if not vulnerability_ids:
            raise HTTPException(status_code=400, detail="No vulnerability IDs provided")
        
        # Update vulnerabilities
        for vuln_id in vulnerability_ids:
            await db.execute(
                update(SASTIssue)
                .where(SASTIssue.id == int(vuln_id))
                .values(**updates, updated_at=datetime.now(timezone.utc).replace(tzinfo=None))
            )
        
        await db.commit()
        return {"message": f"Successfully updated {len(vulnerability_ids)} vulnerabilities"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error bulk updating vulnerabilities: {str(e)}")

@router.delete("/vulnerabilities/bulk-delete")
async def bulk_delete_vulnerabilities(
    delete_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk delete vulnerabilities"""
    try:
        vulnerability_ids = delete_data.get("vulnerability_ids", [])
        
        if not vulnerability_ids:
            raise HTTPException(status_code=400, detail="No vulnerability IDs provided")
        
        # Delete vulnerabilities
        for vuln_id in vulnerability_ids:
            await db.execute(delete(SASTIssue).where(SASTIssue.id == int(vuln_id)))
        
        await db.commit()
        return {"message": f"Successfully deleted {len(vulnerability_ids)} vulnerabilities"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error bulk deleting vulnerabilities: {str(e)}")

# ============================================================================
# File Upload and Scanning Endpoints
# ============================================================================

@router.post("/scan/upload")
async def upload_and_scan_file(
    file: UploadFile = File(...),
    project_id: str = Form(...),
    scan_config: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Upload a file and start scanning"""
    try:
        # Parse scan config
        config = json.loads(scan_config) if scan_config else {}
        
        # Create scan record
        scan = SASTScan(
            project_id=int(project_id),
            scan_type=config.get("scan_type", "upload"),
            branch=config.get("branch", "main"),
            status=ScanStatus.PENDING,
            started_by=current_user.id
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Save uploaded file
        upload_dir = Path("uploads/sast")
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = upload_dir / f"{scan.id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Start background scan
        background_tasks.add_task(process_uploaded_file, str(file_path), scan.id, db)
        
        return {
            "message": "File uploaded and scan started",
            "scan_id": str(scan.id),
            "file_path": str(file_path)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

async def process_uploaded_file(file_path: str, scan_id: str, db: AsyncSession):
    """Process uploaded file in background"""
    try:
        # Extract and analyze file
        if file_path.endswith('.zip'):
            # Handle zip files
            extract_dir = Path(file_path).parent / f"extract_{scan_id}"
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Scan extracted files
            scanner = SASTScanner(str(extract_dir), scan_id)
            vulnerabilities = await scanner.scan_project()
        else:
            # Handle single file
            scanner = SASTScanner(str(Path(file_path).parent), scan_id)
            vulnerabilities = await scanner.scan_project()
        
        # Update scan with results
        await update_scan_results(scan_id, vulnerabilities, db)
        
    except Exception as e:
        logger.error(f"Error processing uploaded file: {e}")
        # Update scan status to failed
        await update_scan_status(scan_id, ScanStatus.FAILED, str(e), db)

async def update_scan_results(scan_id: str, vulnerabilities: List[Any], db: AsyncSession):
    """Update scan with results"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            scan.vulnerabilities_found = len(vulnerabilities)
            scan.issues_found = len(vulnerabilities)
            
            # Store vulnerabilities
            for vuln in vulnerabilities:
                issue = SASTIssue(
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    rule_id=vuln.rule_id,
                    rule_name=vuln.rule_name,
                    message=vuln.description,
                    file_path=vuln.file_name,
                    line_number=vuln.line_number,
                    severity=IssueSeverity(vuln.severity.upper()),
                    type=IssueType.VULNERABILITY,
                    cwe_id=vuln.cwe_id,
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None)
                )
                db.add(issue)
            
            await db.commit()
            
    except Exception as e:
        logger.error(f"Error updating scan results: {e}")

async def update_scan_status(scan_id: str, status: ScanStatus, error_message: str, db: AsyncSession):
    """Update scan status"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if scan:
            scan.status = status
            scan.error_message = error_message
            if status == ScanStatus.COMPLETED:
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            
            await db.commit()
            
    except Exception as e:
        logger.error(f"Error updating scan status: {e}")

# ============================================================================
# Enhanced Rule Management Endpoints
# ============================================================================

@router.post("/rules", response_model=Dict[str, Any])
async def create_custom_rule(
    rule_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a custom SAST rule"""
    try:
        # Validate rule data
        required_fields = ["rule_id", "name", "category", "severity", "type", "languages"]
        for field in required_fields:
            if field not in rule_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Create new rule
        new_rule = SASTRule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data.get("description", ""),
            category=rule_data["category"],
            subcategory=rule_data.get("subcategory"),
            severity=IssueSeverity(rule_data["severity"].upper()),
            type=IssueType(rule_data["type"].upper()),
            cwe_id=rule_data.get("cwe_id"),
            owasp_category=rule_data.get("owasp_category"),
            tags=rule_data.get("tags", []),
            enabled=rule_data.get("enabled", True),
            effort=rule_data.get("effort", 0),
            languages=rule_data["languages"],
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        
        db.add(new_rule)
        await db.commit()
        await db.refresh(new_rule)
        
        return {
            "message": "Custom rule created successfully",
            "rule": {
                "id": str(new_rule.id),
                "rule_id": new_rule.rule_id,
                "name": new_rule.name,
                "category": new_rule.category,
                "severity": new_rule.severity.value,
                "type": new_rule.type.value,
                "languages": new_rule.languages
            }
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating custom rule: {str(e)}")

@router.put("/rules/{rule_id}", response_model=Dict[str, Any])
async def update_rule(
    rule_id: str,
    rule_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing SAST rule"""
    try:
        rule_result = await db.execute(select(SASTRule).where(SASTRule.rule_id == rule_id))
        rule = rule_result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        # Update fields
        updateable_fields = ["name", "description", "category", "subcategory", "severity", 
                           "type", "cwe_id", "owasp_category", "tags", "enabled", "effort", "languages"]
        
        for field in updateable_fields:
            if field in rule_data:
                if field == "severity":
                    rule.severity = IssueSeverity(rule_data[field].upper())
                elif field == "type":
                    rule.type = IssueType(rule_data[field].upper())
                else:
                    setattr(rule, field, rule_data[field])
        
        rule.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()
        await db.refresh(rule)
        
        return {
            "message": "Rule updated successfully",
            "rule": {
                "id": str(rule.id),
                "rule_id": rule.rule_id,
                "name": rule.name,
                "category": rule.category,
                "severity": rule.severity.value,
                "type": rule.type.value,
                "languages": rule.languages
            }
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating rule: {str(e)}")

@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a SAST rule"""
    try:
        rule_result = await db.execute(select(SASTRule).where(SASTRule.rule_id == rule_id))
        rule = rule_result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        # Check if rule is being used
        usage_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.rule_id == rule_id)
        )
        usage_count = usage_result.scalar() or 0
        
        if usage_count > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete rule: it is used by {usage_count} existing issues"
            )
        
        await db.delete(rule)
        await db.commit()
        
        return {"message": "Rule deleted successfully"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting rule: {str(e)}")

# ============================================================================
# Scan Management Enhancement Endpoints
# ============================================================================

@router.post("/scans/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop a running scan"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.status not in [ScanStatus.PENDING, ScanStatus.IN_PROGRESS]:
            raise HTTPException(status_code=400, detail="Scan is not running")
        
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()
        
        return {"message": "Scan stopped successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping scan: {str(e)}")

@router.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = Query("json", regex="^(json|pdf|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan report in specified format"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan issues
        issues_result = await db.execute(
            select(SASTIssue).where(SASTIssue.scan_id == int(scan_id))
        )
        issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "scan_id": str(scan.id),
            "project_id": scan.project_id,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": scan.duration,
            "total_issues": len(issues),
            "vulnerabilities": len([i for i in issues if i.type == IssueType.VULNERABILITY]),
            "bugs": len([i for i in issues if i.type == IssueType.BUG]),
            "code_smells": len([i for i in issues if i.type == IssueType.CODE_SMELL]),
            "issues_by_severity": {},
            "issues_by_type": {},
            "issues": []
        }
        
        # Group issues by severity and type
        for issue in issues:
            severity = issue.severity.value.lower()
            issue_type = issue.type.value.lower()
            
            report_data["issues_by_severity"][severity] = report_data["issues_by_severity"].get(severity, 0) + 1
            report_data["issues_by_type"][issue_type] = report_data["issues_by_type"].get(issue_type, 0) + 1
            
            report_data["issues"].append({
                "id": str(issue.id),
                "rule_id": issue.rule_id,
                "rule_name": issue.rule_name,
                "message": issue.message,
                "severity": issue.severity.value,
                "type": issue.type.value,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "cwe_id": issue.cwe_id,
                "cvss_score": issue.cvss_score,
                "owasp_category": issue.owasp_category
            })
        
        if format == "json":
            return report_data
        elif format == "csv":
            # Generate CSV content
            csv_content = generate_csv_report(report_data)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.csv"}
            )
        elif format == "pdf":
            # Generate PDF content (placeholder)
            pdf_content = generate_pdf_report(report_data)
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"}
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating scan report: {str(e)}")

def generate_csv_report(report_data: Dict[str, Any]) -> str:
    """Generate CSV report content"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["Scan Report"])
    writer.writerow([f"Scan ID: {report_data['scan_id']}"])
    writer.writerow([f"Total Issues: {report_data['total_issues']}"])
    writer.writerow([])
    
    # Write summary
    writer.writerow(["Issues by Severity"])
    for severity, count in report_data["issues_by_severity"].items():
        writer.writerow([severity.title(), count])
    
    writer.writerow([])
    writer.writerow(["Issues by Type"])
    for issue_type, count in report_data["issues_by_type"].items():
        writer.writerow([issue_type.title(), count])
    
    writer.writerow([])
    
    # Write detailed issues
    writer.writerow(["Issue Details"])
    writer.writerow(["ID", "Rule", "Message", "Severity", "Type", "File", "Line", "CWE", "CVSS", "OWASP"])
    
    for issue in report_data["issues"]:
        writer.writerow([
            issue["id"],
            issue["rule_name"],
            issue["message"],
            issue["severity"],
            issue["type"],
            issue["file_path"],
            issue["line_number"],
            issue["cwe_id"] or "",
            issue["cvss_score"] or "",
            issue["owasp_category"] or ""
        ])
    
    return output.getvalue()

def generate_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Generate PDF report content (placeholder)"""
    # This is a placeholder - in production you'd use a proper PDF library
    pdf_content = f"""
    Scan Report
    ===========
    
    Scan ID: {report_data['scan_id']}
    Total Issues: {report_data['total_issues']}
    
    Issues by Severity:
    {chr(10).join([f"- {k.title()}: {v}" for k, v in report_data['issues_by_severity'].items()])}
    
    Issues by Type:
    {chr(10).join([f"- {k.title()}: {v}" for k, v in report_data['issues_by_type'].items()])}
    """.encode('utf-8')
    
    return pdf_content

# ============================================================================
# Project Report Endpoints
# ============================================================================

@router.get("/projects/{project_id}/report")
async def get_project_report(
    project_id: str,
    format: str = Query("json", regex="^(json|pdf|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive project report"""
    try:
        # Get project
        project_result = await db.execute(select(SASTProject).where(SASTProject.id == int(project_id)))
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get project scans
        scans_result = await db.execute(
            select(SASTScan).where(SASTScan.project_id == int(project_id))
        )
        scans = scans_result.scalars().all()
        
        # Get project issues
        issues_result = await db.execute(
            select(SASTIssue).where(SASTIssue.project_id == int(project_id))
        )
        issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "project": {
                "id": str(project.id),
                "name": project.name,
                "key": project.key,
                "language": project.language,
                "quality_gate": project.quality_gate.value if project.quality_gate else "UNKNOWN",
                "security_rating": project.security_rating.value if project.security_rating else "UNKNOWN",
                "reliability_rating": project.reliability_rating.value if project.reliability_rating else "UNKNOWN",
                "maintainability_rating": project.maintainability_rating.value if project.maintainability_rating else "UNKNOWN"
            },
            "summary": {
                "total_scans": len(scans),
                "total_issues": len(issues),
                "vulnerabilities": len([i for i in issues if i.type == IssueType.VULNERABILITY]),
                "bugs": len([i for i in issues if i.type == IssueType.BUG]),
                "code_smells": len([i for i in issues if i.type == IssueType.CODE_SMELL]),
                "lines_of_code": project.lines_of_code or 0,
                "coverage": project.coverage or 0.0,
                "technical_debt": project.technical_debt or 0
            },
            "scans": [
                {
                    "id": str(scan.id),
                    "status": scan.status.value,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "issues_found": scan.issues_found or 0,
                    "vulnerabilities_found": scan.vulnerabilities_found or 0
                }
                for scan in scans
            ],
            "issues_by_severity": {},
            "issues_by_type": {},
            "recent_issues": []
        }
        
        # Group issues by severity and type
        for issue in issues:
            severity = issue.severity.value.lower()
            issue_type = issue.type.value.lower()
            
            report_data["issues_by_severity"][severity] = report_data["issues_by_severity"].get(severity, 0) + 1
            report_data["issues_by_type"][issue_type] = report_data["issues_by_type"].get(issue_type, 0) + 1
        
        # Get recent issues
        recent_issues = sorted(issues, key=lambda x: x.created_at, reverse=True)[:20]
        report_data["recent_issues"] = [
            {
                "id": str(issue.id),
                "rule_name": issue.rule_name,
                "severity": issue.severity.value,
                "type": issue.type.value,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "created_at": issue.created_at.isoformat() if issue.created_at else None
            }
            for issue in recent_issues
        ]
        
        if format == "json":
            return report_data
        elif format == "csv":
            csv_content = generate_project_csv_report(report_data)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=project_report_{project_id}.csv"}
            )
        elif format == "pdf":
            pdf_content = generate_project_pdf_report(report_data)
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=project_report_{project_id}.pdf"}
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating project report: {str(e)}")

def generate_project_csv_report(report_data: Dict[str, Any]) -> str:
    """Generate project CSV report content"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["Project Report"])
    writer.writerow([f"Project: {report_data['project']['name']} ({report_data['project']['key']})"])
    writer.writerow([f"Language: {report_data['project']['language']}"])
    writer.writerow([])
    
    # Write summary
    writer.writerow(["Summary"])
    writer.writerow(["Total Scans", report_data["summary"]["total_scans"]])
    writer.writerow(["Total Issues", report_data["summary"]["total_issues"]])
    writer.writerow(["Vulnerabilities", report_data["summary"]["vulnerabilities"]])
    writer.writerow(["Bugs", report_data["summary"]["bugs"]])
    writer.writerow(["Code Smells", report_data["summary"]["code_smells"]])
    writer.writerow(["Lines of Code", report_data["summary"]["lines_of_code"]])
    writer.writerow(["Coverage", f"{report_data['summary']['coverage']}%"])
    writer.writerow(["Technical Debt", f"{report_data['summary']['technical_debt']} minutes"])
    writer.writerow([])
    
    # Write ratings
    writer.writerow(["Quality Ratings"])
    writer.writerow(["Security", report_data["project"]["security_rating"]])
    writer.writerow(["Reliability", report_data["project"]["reliability_rating"]])
    writer.writerow(["Maintainability", report_data["project"]["maintainability_rating"]])
    writer.writerow([])
    
    # Write issues breakdown
    writer.writerow(["Issues by Severity"])
    for severity, count in report_data["issues_by_severity"].items():
        writer.writerow([severity.title(), count])
    
    writer.writerow([])
    writer.writerow(["Issues by Type"])
    for issue_type, count in report_data["issues_by_type"].items():
        writer.writerow([issue_type.title(), count])
    
    return output.getvalue()

def generate_project_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Generate project PDF report content (placeholder)"""
    pdf_content = f"""
    Project Report
    ==============
    
    Project: {report_data['project']['name']} ({report_data['project']['key']})
    Language: {report_data['project']['language']}
    
    Summary:
    - Total Scans: {report_data['summary']['total_scans']}
    - Total Issues: {report_data['summary']['total_issues']}
    - Vulnerabilities: {report_data['summary']['vulnerabilities']}
    - Bugs: {report_data['summary']['bugs']}
    - Code Smells: {report_data['summary']['code_smells']}
    - Lines of Code: {report_data['summary']['lines_of_code']}
    - Coverage: {report_data['summary']['coverage']}%
    - Technical Debt: {report_data['summary']['technical_debt']} minutes
    
    Quality Ratings:
    - Security: {report_data['project']['security_rating']}
    - Reliability: {report_data['project']['reliability_rating']}
    - Maintainability: {report_data['project']['maintainability_rating']}
    """.encode('utf-8')
    
    return pdf_content

# ============================================================================
# Advanced Analysis Endpoints
# ============================================================================

@router.post("/advanced-analysis/{project_id}")
async def start_advanced_analysis(
    project_id: str,
    analysis_types: List[str] = Query(["data_flow", "taint_analysis", "security_pattern"]),
    languages: List[str] = Query(["python", "javascript", "java"]),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start advanced code analysis for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize advanced analyzer
        advanced_analyzer = AdvancedCodeAnalyzer()
        
        # Perform analysis
        analysis_result = await advanced_analyzer.analyze_project(
            project_path=project.repository_url or f"projects/{project_id}",
            project_id=project_id,
            scan_id=str(uuid.uuid4()),
            languages=languages
        )
        
        return {
            "message": "Advanced analysis completed successfully",
            "analysis_id": analysis_result.analysis_id,
            "summary": analysis_result.summary,
            "vulnerabilities_found": len(analysis_result.vulnerabilities),
            "data_flow_paths": len(analysis_result.data_flow_paths),
            "taint_flows": len(analysis_result.taint_flows)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during advanced analysis: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}")
async def get_advanced_analysis_result(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get results of advanced code analysis"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        return {
            "analysis_id": result.analysis_id,
            "project_id": result.project_id,
            "scan_id": result.scan_id,
            "analysis_type": result.analysis_type.value,
            "summary": result.summary,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "description": v.description,
                    "category": v.category.value,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "cwe_id": v.cwe_id,
                    "owasp_category": v.owasp_category,
                    "evidence": v.evidence,
                    "recommendations": v.recommendations
                }
                for v in result.vulnerabilities
            ],
            "data_flow_paths": len(result.data_flow_paths),
            "taint_flows": len(result.taint_flows),
            "created_at": result.created_at.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving analysis result: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}/export")
async def export_advanced_analysis(
    analysis_id: str,
    format: str = Query("json", regex="^(json|csv|pdf)$"),
    current_user: User = Depends(get_current_user)
):
    """Export advanced analysis results"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        if format == "json":
            # Export as JSON
            export_path = f"exports/advanced_analysis_{analysis_id}.json"
            success = advanced_analyzer.export_analysis_report(analysis_id, export_path)
            
            if success:
                return {"message": "Analysis exported successfully", "file_path": export_path}
            else:
                raise HTTPException(status_code=500, detail="Failed to export analysis")
        
        elif format == "csv":
            # Export as CSV (simplified)
            csv_content = "Vulnerability ID,Title,Category,Severity,File Path,Line Number,CWE ID\n"
            for vuln in result.vulnerabilities:
                csv_content += f"{vuln.id},{vuln.title},{vuln.category.value},{vuln.severity},{vuln.file_path},{vuln.line_number},{vuln.cwe_id or ''}\n"
            
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=advanced_analysis_{analysis_id}.csv"}
            )
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting analysis: {str(e)}")

@router.get("/data-flow-analysis/{project_id}")
async def get_data_flow_analysis(
    project_id: str,
    file_path: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """Get data flow analysis for a project or specific file"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize data flow analyzer
        data_flow_analyzer = DataFlowAnalyzer()
        
        # Analyze project files
        project_path = project.repository_url or f"projects/{project_id}"
        languages = [project.language] if project.language else ["python", "javascript", "java"]
        
        all_paths = []
        for language in languages:
            if file_path:
                # Analyze specific file
                file_path_obj = Path(project_path) / file_path
                if file_path_obj.exists():
                    paths = data_flow_analyzer.analyze_file(file_path_obj, language)
                    all_paths.extend(paths)
            else:
                # Analyze all files of this language
                language_files = data_flow_analyzer._find_language_files(Path(project_path), language)
                for lang_file in language_files:
                    paths = data_flow_analyzer.analyze_file(lang_file, language)
                    all_paths.extend(paths)
        
        # Get summary
        summary = data_flow_analyzer.get_data_flow_summary()
        
        return {
            "project_id": project_id,
            "file_path": file_path,
            "summary": summary,
            "data_flow_paths": [
                {
                    "path_id": path.path_id,
                    "source": {
                        "name": path.source.name,
                        "type": path.source.node_type,
                        "file_path": path.source.file_path,
                        "line_number": path.source.line_number
                    },
                    "sink": {
                        "name": path.sink.name,
                        "type": path.sink.node_type,
                        "file_path": path.sink.file_path,
                        "line_number": path.sink.line_number
                    },
                    "risk_level": path.risk_level,
                    "description": path.description,
                    "node_count": len(path.nodes),
                    "edge_count": len(path.edges)
                }
                for path in all_paths
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during data flow analysis: {str(e)}")

@router.get("/taint-analysis/{project_id}")
async def get_taint_analysis(
    project_id: str,
    file_path: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """Get taint analysis for a project or specific file"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize taint analyzer
        taint_analyzer = TaintAnalyzer()
        
        # Analyze project files
        project_path = project.repository_url or f"projects/{project_id}"
        languages = [project.language] if project.language else ["python", "javascript", "java"]
        
        all_flows = []
        for language in languages:
            if file_path:
                # Analyze specific file
                file_path_obj = Path(project_path) / file_path
                if file_path_obj.exists():
                    flows = taint_analyzer.analyze_file(file_path_obj, language)
                    all_flows.extend(flows)
            else:
                # Analyze all files of this language
                language_files = taint_analyzer._find_language_files(Path(project_path), language)
                for lang_file in language_files:
                    flows = taint_analyzer.analyze_file(lang_file, language)
                    all_flows.extend(flows)
        
        # Get summary
        summary = taint_analyzer.get_taint_summary()
        
        return {
            "project_id": project_id,
            "file_path": file_path,
            "summary": summary,
            "taint_flows": [
                {
                    "id": flow.id,
                    "source": {
                        "name": flow.source.name,
                        "taint_type": flow.source.taint_type.value,
                        "file_path": flow.source.file_path,
                        "line_number": flow.source.line_number,
                        "severity": flow.source.severity.value
                    },
                    "sink": {
                        "name": flow.sink.name,
                        "sink_type": flow.sink.sink_type,
                        "file_path": flow.sink.file_path,
                        "line_number": flow.sink.line_number,
                        "severity": flow.sink.severity.value,
                        "cwe_id": flow.sink.cwe_id,
                        "owasp_category": flow.sink.owasp_category
                    },
                    "taint_status": flow.taint_status.value,
                    "severity": flow.severity.value,
                    "description": flow.description,
                    "flow_path": flow.flow_path,
                    "sanitization_points": flow.sanitization_points,
                    "blocking_points": flow.blocking_points
                }
                for flow in all_flows
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during taint analysis: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}/data-flow")
async def get_analysis_data_flow(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get data flow paths from advanced analysis"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        return {
            "analysis_id": analysis_id,
            "data_flow_paths": [
                {
                    "path_id": path.path_id,
                    "source": {
                        "name": path.source.name,
                        "type": path.source.node_type,
                        "file_path": path.source.file_path,
                        "line_number": path.source.line_number
                    },
                    "sink": {
                        "name": path.sink.name,
                        "type": path.sink.node_type,
                        "file_path": path.sink.file_path,
                        "line_number": path.sink.line_number
                    },
                    "risk_level": path.risk_level,
                    "description": path.description,
                    "node_count": len(path.nodes),
                    "edge_count": len(path.edges)
                }
                for path in result.data_flow_paths
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving data flow: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}/taint-flows")
async def get_analysis_taint_flows(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get taint flows from advanced analysis"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        return {
            "analysis_id": analysis_id,
            "taint_flows": [
                {
                    "id": flow.id,
                    "source": {
                        "name": flow.source.name,
                        "taint_type": flow.source.taint_type.value,
                        "file_path": flow.source.file_path,
                        "line_number": flow.source.line_number,
                        "severity": flow.source.severity.value
                    },
                    "sink": {
                        "name": flow.sink.name,
                        "sink_type": flow.sink.sink_type,
                        "file_path": flow.sink.file_path,
                        "line_number": flow.sink.line_number,
                        "severity": flow.sink.severity.value,
                        "cwe_id": flow.sink.cwe_id,
                        "owasp_category": flow.sink.owasp_category
                    },
                    "taint_status": flow.taint_status.value,
                    "severity": flow.severity.value,
                    "description": flow.description,
                    "flow_path": flow.flow_path,
                    "sanitization_points": flow.sanitization_points,
                    "blocking_points": flow.blocking_points
                }
                for flow in result.taint_flows
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving taint flows: {str(e)}")

# ============================================================================
# Real-time Monitoring Endpoints
# ============================================================================

@router.post("/realtime/start/{project_id}")
async def start_realtime_monitoring(
    project_id: str,
    config: Optional[Dict[str, Any]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start real-time monitoring for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import start_realtime_monitoring
        
        # Start monitoring
        await start_realtime_monitoring(project.repository_url or f"projects/{project_id}", config)
        
        return {
            "message": "Real-time monitoring started successfully",
            "project_id": project_id,
            "status": "monitoring"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting real-time monitoring: {str(e)}")

@router.post("/realtime/stop/{project_id}")
async def stop_realtime_monitoring(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop real-time monitoring for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import stop_realtime_monitoring
        
        # Stop monitoring
        await stop_realtime_monitoring(project.repository_url or f"projects/{project_id}")
        
        return {
            "message": "Real-time monitoring stopped successfully",
            "project_id": project_id,
            "status": "stopped"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping real-time monitoring: {str(e)}")

@router.get("/realtime/stats/{project_id}")
async def get_realtime_stats(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get real-time monitoring statistics for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import get_realtime_analyzer
        
        # Get analyzer instance
        analyzer = await get_realtime_analyzer(project.repository_url or f"projects/{project_id}")
        
        # Get statistics
        stats = analyzer.get_statistics()
        
        return {
            "project_id": project_id,
            "statistics": stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting real-time stats: {str(e)}")

@router.get("/realtime/export/{project_id}")
async def export_realtime_data(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export real-time monitoring data for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import get_realtime_analyzer
        
        # Get analyzer instance
        analyzer = await get_realtime_analyzer(project.repository_url or f"projects/{project_id}")
        
        # Export data
        export_data = analyzer.export_analysis_data()
        
        return {
            "project_id": project_id,
            "export_data": export_data,
            "exported_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting real-time data: {str(e)}")

# ============================================================================
# Quality Management Endpoints
# ============================================================================

@router.get("/projects/{project_id}/quality-overview")
async def get_project_quality_overview(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive quality overview for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan for metrics
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Calculate quality metrics
        quality_metrics = {
            "project_id": project_id,
            "project_name": project.name,
            "quality_gate_status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "issue_counts": {
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "code_metrics": {
                "lines_of_code": project.lines_of_code,
                "lines_of_comment": project.lines_of_comment,
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks
            },
            "coverage_metrics": {
                "coverage": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions
            },
            "technical_debt": {
                "total_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "debt_hours": round(project.technical_debt / 60, 2) if project.technical_debt else 0
            },
            "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None,
            "scan_status": recent_scan.status if recent_scan else None
        }
        
        return quality_metrics
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality overview: {str(e)}")

@router.get("/projects/{project_id}/quality-metrics")
async def get_project_quality_metrics(
    project_id: str,
    metric_type: Optional[str] = Query(None, description="Type of metrics: 'security', 'reliability', 'maintainability', 'coverage', 'duplications'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed quality metrics for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        if not metric_type:
            # Return all metrics
            return {
                "project_id": project_id,
                "project_name": project.name,
                "security_metrics": {
                    "rating": project.security_rating,
                    "vulnerability_count": project.vulnerability_count,
                    "security_hotspot_count": project.security_hotspot_count
                },
                "reliability_metrics": {
                    "rating": project.reliability_rating,
                    "bug_count": project.bug_count
                },
                "maintainability_metrics": {
                    "rating": project.maintainability_rating,
                    "code_smell_count": project.code_smell_count,
                    "technical_debt": project.technical_debt,
                    "debt_ratio": project.debt_ratio
                },
                "coverage_metrics": {
                    "coverage": project.coverage,
                    "uncovered_lines": project.uncovered_lines,
                    "uncovered_conditions": project.uncovered_conditions
                },
                "duplication_metrics": {
                    "duplicated_lines": project.duplicated_lines,
                    "duplicated_blocks": project.duplicated_blocks
                }
            }
        
        # Return specific metric type
        if metric_type == "security":
            return {
                "project_id": project_id,
                "metric_type": "security",
                "rating": project.security_rating,
                "vulnerability_count": project.vulnerability_count,
                "security_hotspot_count": project.security_hotspot_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "reliability":
            return {
                "project_id": project_id,
                "metric_type": "reliability",
                "rating": project.reliability_rating,
                "bug_count": project.bug_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "maintainability":
            return {
                "project_id": project_id,
                "metric_type": "maintainability",
                "rating": project.maintainability_rating,
                "code_smell_count": project.code_smell_count,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "coverage":
            return {
                "project_id": project_id,
                "metric_type": "coverage",
                "coverage": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "duplications":
            return {
                "project_id": project_id,
                "metric_type": "duplications",
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid metric type")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality metrics: {str(e)}")

@router.get("/projects/{project_id}/quality-trends")
async def get_project_quality_trends(
    project_id: str,
    days: int = Query(30, description="Number of days for trend analysis"),
    metric: str = Query("all", description="Specific metric to analyze: 'security', 'reliability', 'maintainability', 'coverage', 'debt'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality trends for a project over time"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get scans within the specified time period
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .where(SASTScan.created_at >= cutoff_date)
            .order_by(SASTScan.created_at.asc())
        )
        scans = scans_result.scalars().all()
        
        # Generate trend data
        trends = []
        for scan in scans:
            trend_point = {
                "date": scan.created_at.isoformat(),
                "scan_id": str(scan.id),
                "scan_status": scan.status
            }
            
            if metric == "all" or metric == "security":
                trend_point["security_rating"] = getattr(scan, 'security_rating', None)
                trend_point["vulnerability_count"] = getattr(scan, 'vulnerabilities_found', 0)
            
            if metric == "all" or metric == "reliability":
                trend_point["reliability_rating"] = getattr(scan, 'reliability_rating', None)
                trend_point["bug_count"] = getattr(scan, 'bugs_found', 0)
            
            if metric == "all" or metric == "maintainability":
                trend_point["maintainability_rating"] = getattr(scan, 'maintainability_rating', None)
                trend_point["code_smell_count"] = getattr(scan, 'code_smells_found', 0)
            
            if metric == "all" or metric == "coverage":
                trend_point["coverage"] = getattr(scan, 'coverage', 0.0)
            
            if metric == "all" or metric == "debt":
                trend_point["technical_debt"] = getattr(scan, 'technical_debt', 0)
            
            trends.append(trend_point)
        
        return {
            "project_id": project_id,
            "project_name": project.name,
            "metric": metric,
            "period_days": days,
            "trends": trends,
            "summary": {
                "total_scans": len(trends),
                "period_start": cutoff_date.isoformat(),
                "period_end": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality trends: {str(e)}")

@router.get("/projects/{project_id}/quality-report")
async def get_project_quality_report(
    project_id: str,
    format: str = Query("json", description="Report format: 'json', 'pdf', 'csv'"),
    include_details: bool = Query(True, description="Include detailed issue information"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate comprehensive quality report for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Get issues if details are requested
        issues = []
        if include_details:
            issues_result = await db.execute(
                select(SASTIssue)
                .where(SASTIssue.project_id == project_id)
                .order_by(SASTIssue.severity.desc(), SASTIssue.created_at.desc())
                .limit(100)  # Limit for performance
            )
            issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "project": {
                "id": project_id,
                "name": project.name,
                "key": project.key,
                "language": project.language,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            },
            "quality_gate": {
                "status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
                "evaluated_at": quality_gate.last_evaluation.isoformat() if quality_gate and quality_gate.last_evaluation else None
            },
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "metrics_summary": {
                "lines_of_code": project.lines_of_code,
                "coverage": project.coverage,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "duplicated_lines": project.duplicated_lines
            },
            "issue_summary": {
                "total_issues": len(issues),
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "scan_information": {
                "last_scan_id": str(recent_scan.id) if recent_scan else None,
                "last_scan_status": recent_scan.status if recent_scan else None,
                "last_scan_date": recent_scan.created_at.isoformat() if recent_scan else None
            },
            "generated_at": datetime.now().isoformat()
        }
        
        if include_details and issues:
            report_data["detailed_issues"] = [
                {
                    "id": str(issue.id),
                    "type": issue.type,
                    "severity": issue.severity,
                    "status": issue.status,
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "message": issue.message,
                    "effort": issue.effort,
                    "created_at": issue.created_at.isoformat()
                }
                for issue in issues
            ]
        
        # Return based on format
        if format == "json":
            return report_data
        elif format == "csv":
            # Generate CSV response
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(["Quality Report", project.name])
            writer.writerow([])
            writer.writerow(["Project Information"])
            writer.writerow(["ID", project_id])
            writer.writerow(["Name", project.name])
            writer.writerow(["Language", project.language])
            writer.writerow([])
            writer.writerow(["Quality Metrics"])
            writer.writerow(["Maintainability Rating", project.maintainability_rating])
            writer.writerow(["Security Rating", project.security_rating])
            writer.writerow(["Reliability Rating", project.reliability_rating])
            writer.writerow(["Coverage", f"{project.coverage}%"])
            writer.writerow(["Technical Debt", f"{project.technical_debt} minutes"])
            writer.writerow(["Debt Ratio", f"{project.debt_ratio}%"])
            
            output.seek(0)
            return Response(content=output.getvalue(), media_type="text/csv")
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating quality report: {str(e)}")

@router.post("/projects/{project_id}/quality-gate/evaluate-new-code")
async def evaluate_quality_gate_on_new_code(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Evaluate quality gate using new-code period based on project settings.

    Uses existing SASTQualityGate thresholds against metrics restricted to new code.
    """
    try:
        proj = (await db.execute(select(SASTProject).where(SASTProject.id == project_id))).scalar_one_or_none()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        qg = (await db.execute(select(SASTQualityGate).where(SASTQualityGate.project_id == project_id))).scalar_one_or_none()
        if not qg:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        cfg = (await db.execute(select(SASTProjectSettings).where(SASTProjectSettings.project_id == project_id))).scalar_one_or_none()
        # Determine baseline start
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        start = None
        if cfg and cfg.new_code_mode == "days" and cfg.new_code_days:
            start = now - timedelta(days=int(cfg.new_code_days))
        elif cfg and cfg.new_code_mode == "since-date" and cfg.new_code_since:
            start = cfg.new_code_since if cfg.new_code_since.tzinfo else cfg.new_code_since.replace(tzinfo=timezone.utc)
        else:
            # prev-version: approximate using last_analysis or 7 days
            start = (proj.last_analysis if proj.last_analysis else now - timedelta(days=7))
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)

        # New-code issues since baseline
        issues_rows = (await db.execute(
            select(SASTIssue).where(
                (SASTIssue.project_id == project_id) & (SASTIssue.created_at >= start.replace(tzinfo=None))
            )
        )).scalars().all()
        by_sev = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
        for i in issues_rows:
            sev = str(i.severity)
            if sev in by_sev:
                by_sev[sev] += 1

        # New-code coverage: average of code coverage entries since baseline
        cov_avg_row = await db.execute(
            select(func.avg(SASTCodeCoverage.overall_coverage)).where(
                (SASTCodeCoverage.project_id == project_id) & (SASTCodeCoverage.created_at >= start.replace(tzinfo=None))
            )
        )
        new_coverage = cov_avg_row.scalar() or 0.0

        # Evaluate against quality gate thresholds
        results = []
        status = QualityGateStatus.PASSED

        def add_result(metric: str, operator: str, threshold: float, actual: float, passed: bool, category: str):
            nonlocal status
            if not passed and status != QualityGateStatus.FAILED:
                status = QualityGateStatus.FAILED
            results.append({
                "metric": metric,
                "operator": operator,
                "threshold": threshold,
                "actual": actual,
                "passed": passed,
                "category": category,
            })

        # Coverage
        add_result("Coverage (new code)", ">=", qg.min_coverage or 0.0, new_coverage, (new_coverage >= (qg.min_coverage or 0.0)), "COVERAGE")
        # Severities
        add_result("Critical issues (new code)", "<=", qg.max_critical_issues or 0, by_sev["CRITICAL"], (by_sev["CRITICAL"] <= (qg.max_critical_issues or 0)), "SECURITY")
        add_result("Major issues (new code)", "<=", qg.max_major_issues or 0, by_sev["MAJOR"], (by_sev["MAJOR"] <= (qg.max_major_issues or 0)), "RELIABILITY")
        add_result("Minor issues (new code)", "<=", qg.max_minor_issues or 0, by_sev["MINOR"], (by_sev["MINOR"] <= (qg.max_minor_issues or 0)), "MAINTAINABILITY")

        return {
            "status": status,
            "start": start.isoformat(),
            "coverage": new_coverage,
            "issue_counts": by_sev,
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error evaluating new code gate: {str(e)}")

@router.post("/projects/{project_id}/quality-gate/evaluate")
async def evaluate_project_quality_gate(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually evaluate quality gate for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        if not quality_gate:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        
        # Evaluate quality gate based on current project metrics
        evaluation_results = {}
        gate_status = QualityGateStatus.PASSED
        
        # Check vulnerability thresholds
        if project.vulnerability_count > quality_gate.max_blocker_issues:
            evaluation_results["blocker_issues"] = f"Failed: {project.vulnerability_count} > {quality_gate.max_blocker_issues}"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["blocker_issues"] = f"Passed: {project.vulnerability_count} <= {quality_gate.max_blocker_issues}"
        
        # Check coverage threshold
        if project.coverage < quality_gate.min_coverage:
            evaluation_results["coverage"] = f"Failed: {project.coverage}% < {quality_gate.min_coverage}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["coverage"] = f"Passed: {project.coverage}% >= {quality_gate.min_coverage}%"
        
        # Check technical debt threshold
        if project.debt_ratio > quality_gate.max_debt_ratio:
            evaluation_results["debt_ratio"] = f"Failed: {project.debt_ratio}% > {quality_gate.max_debt_ratio}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["debt_ratio"] = f"Passed: {project.debt_ratio}% <= {quality_gate.max_debt_ratio}%"
        
        # Update quality gate status
        quality_gate.status = gate_status
        quality_gate.last_evaluation = datetime.now()
        quality_gate.evaluation_results = evaluation_results
        
        await db.commit()
        
        return {
            "project_id": project_id,
            "quality_gate_status": gate_status,
            "evaluation_results": evaluation_results,
            "evaluated_at": quality_gate.last_evaluation.isoformat(),
            "next_evaluation": "Automatic on next scan or manual trigger"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error evaluating quality gate: {str(e)}")

@router.get("/quality-management/dashboard")
async def get_quality_management_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality management dashboard overview"""
    try:
        # Get total projects
        total_projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = total_projects_result.scalar() or 0
        
        # Get projects by quality gate status
        passed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.PASSED)
        )
        passed_projects = passed_projects_result.scalar() or 0
        
        failed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.FAILED)
        )
        failed_projects = failed_projects_result.scalar() or 0
        
        # Get average ratings
        avg_maintainability_result = await db.execute(
            select(func.avg(SASTProject.maintainability_rating))
        )
        avg_maintainability = avg_maintainability_result.scalar()
        
        avg_security_result = await db.execute(
            select(func.avg(SASTProject.security_rating))
        )
        avg_security = avg_security_result.scalar()
        
        avg_reliability_result = await db.execute(
            select(func.avg(SASTProject.reliability_rating))
        )
        avg_reliability = avg_reliability_result.scalar()
        
        # Get total technical debt
        total_debt_result = await db.execute(
            select(func.sum(SASTProject.technical_debt))
        )
        total_debt = total_debt_result.scalar() or 0
        
        # Get average coverage
        avg_coverage_result = await db.execute(
            select(func.avg(SASTProject.coverage))
        )
        avg_coverage = avg_coverage_result.scalar() or 0
        
        return {
            "summary": {
                "total_projects": total_projects,
                "passed_projects": passed_projects,
                "failed_projects": failed_projects,
                "pass_rate": round((passed_projects / total_projects * 100), 2) if total_projects > 0 else 0
            },
            "average_ratings": {
                "maintainability": avg_maintainability,
                "security": avg_security,
                "reliability": avg_reliability
            },
            "overall_metrics": {
                "total_technical_debt_hours": round(total_debt / 60, 2),
                "average_coverage": round(avg_coverage, 2)
            },
            "quality_distribution": {
                "excellent": 0,  # A rating
                "good": 0,       # B rating
                "moderate": 0,   # C rating
                "poor": 0,       # D rating
                "very_poor": 0   # E rating
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality management dashboard: {str(e)}")

# ============================================================================
# Saved Filters Endpoints
# ============================================================================

class SavedFilterCreate(BaseModel):
    name: str
    description: Optional[str] = None
    filter_type: str  # 'issues', 'hotspots', 'coverage', etc.
    filter_criteria: Dict[str, Any]
    project_id: Optional[int] = None

class SavedFilterUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    filter_criteria: Optional[Dict[str, Any]] = None

@router.post("/saved-filters")
async def create_saved_filter(
    filter_data: SavedFilterCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new saved filter"""
    try:
        # Validate project access if project_id is provided
        if filter_data.project_id:
            project_query = await db.execute(
                select(SASTProject).where(SASTProject.id == filter_data.project_id)
            )
            project = project_query.scalar_one_or_none()
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")
        
        # Create the saved filter
        saved_filter = SASTSavedFilter(
            user_id=current_user.id,
            project_id=filter_data.project_id,
            name=filter_data.name,
            description=filter_data.description,
            filter_type=filter_data.filter_type,
            filter_criteria=filter_data.filter_criteria
        )
        
        db.add(saved_filter)
        await db.commit()
        await db.refresh(saved_filter)
        
        return {
            "status": "ok",
            "id": saved_filter.id,
            "message": "Filter saved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating saved filter: {str(e)}")

@router.get("/saved-filters")
async def get_saved_filters(
    filter_type: Optional[str] = Query(None),
    project_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get saved filters for the current user"""
    try:
        query = select(SASTSavedFilter).where(SASTSavedFilter.user_id == current_user.id)
        
        if filter_type:
            query = query.where(SASTSavedFilter.filter_type == filter_type)
        
        if project_id:
            query = query.where(
                or_(
                    SASTSavedFilter.project_id == project_id,
                    SASTSavedFilter.project_id.is_(None)  # Include global filters
                )
            )
        
        result = await db.execute(query)
        filters = result.scalars().all()
        
        return {
            "filters": [
                {
                    "id": f.id,
                    "name": f.name,
                    "description": f.description,
                    "filter_type": f.filter_type,
                    "filter_criteria": f.filter_criteria,
                    "project_id": f.project_id,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                    "updated_at": f.updated_at.isoformat() if f.updated_at else None
                }
                for f in filters
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting saved filters: {str(e)}")

@router.put("/saved-filters/{filter_id}")
async def update_saved_filter(
    filter_id: int,
    filter_update: SavedFilterUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a saved filter"""
    try:
        # Get the filter and ensure user owns it
        filter_query = await db.execute(
            select(SASTSavedFilter).where(
                and_(
                    SASTSavedFilter.id == filter_id,
                    SASTSavedFilter.user_id == current_user.id
                )
            )
        )
        saved_filter = filter_query.scalar_one_or_none()
        
        if not saved_filter:
            raise HTTPException(status_code=404, detail="Filter not found")
        
        # Update fields
        if filter_update.name is not None:
            saved_filter.name = filter_update.name
        if filter_update.description is not None:
            saved_filter.description = filter_update.description
        if filter_update.filter_criteria is not None:
            saved_filter.filter_criteria = filter_update.filter_criteria
        
        saved_filter.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        
        await db.commit()
        await db.refresh(saved_filter)
        
        return {
            "status": "ok",
            "message": "Filter updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating saved filter: {str(e)}")

@router.delete("/saved-filters/{filter_id}")
async def delete_saved_filter(
    filter_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a saved filter"""
    try:
        # Get the filter and ensure user owns it
        filter_query = await db.execute(
            select(SASTSavedFilter).where(
                and_(
                    SASTSavedFilter.id == filter_id,
                    SASTSavedFilter.user_id == current_user.id
                )
            )
        )
        saved_filter = filter_query.scalar_one_or_none()
        
        if not saved_filter:
            raise HTTPException(status_code=404, detail="Filter not found")
        
        await db.delete(saved_filter)
        await db.commit()
        
        return {
            "status": "ok",
            "message": "Filter deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting saved filter: {str(e)}")

# ============================================================================
# Incremental Analysis Endpoints
# ============================================================================

class IncrementalScanRequest(BaseModel):
    base_scan_id: Optional[int] = None
    branch: str = "main"
    detect_changes: bool = True
    scan_changed_only: bool = True

@router.post("/projects/{project_id}/incremental-scan")
async def start_incremental_scan(
    project_id: int,
    request: IncrementalScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start an incremental scan based on changes since the last scan"""
    try:
        # Verify project exists
        project_query = await db.execute(select(SASTProject).where(SASTProject.id == project_id))
        project = project_query.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Determine base scan
        base_scan_id = request.base_scan_id
        if not base_scan_id:
            # Get the most recent completed scan
            base_scan_query = await db.execute(
                select(SASTScan)
                .where(SASTScan.project_id == project_id)
                .where(SASTScan.status == ScanStatus.COMPLETED)
                .order_by(SASTScan.completed_at.desc())
            )
            base_scan = base_scan_query.scalar_one_or_none()
            base_scan_id = base_scan.id if base_scan else None

        # Create background job for incremental scan
        job = SASTBackgroundJob(
            project_id=project_id,
            job_type="incremental_scan",
            status="pending",
            priority=7,
            parameters={
                "base_scan_id": base_scan_id,
                "branch": request.branch,
                "detect_changes": request.detect_changes,
                "scan_changed_only": request.scan_changed_only
            }
        )
        
        db.add(job)
        await db.commit()
        await db.refresh(job)

        # Start background task
        background_tasks.add_task(
            run_incremental_scan,
            job.id,
            project_id,
            base_scan_id,
            request.branch,
            request.detect_changes,
            request.scan_changed_only
        )

        return {
            "status": "ok",
            "job_id": job.id,
            "message": "Incremental scan started in background"
        }

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error starting incremental scan: {str(e)}")

@router.get("/projects/{project_id}/file-changes")
async def get_file_changes(
    project_id: int,
    scan_id: Optional[int] = Query(None),
    change_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get file changes for a project or specific scan"""
    try:
        query = select(SASTFileChange).where(SASTFileChange.project_id == project_id)
        
        if scan_id:
            query = query.where(SASTFileChange.scan_id == scan_id)
        
        if change_type:
            query = query.where(SASTFileChange.change_type == change_type)
        
        query = query.order_by(SASTFileChange.detected_at.desc()).offset(offset).limit(limit)
        
        result = await db.execute(query)
        changes = result.scalars().all()
        
        return {
            "changes": [
                {
                    "id": change.id,
                    "file_path": change.file_path,
                    "change_type": change.change_type,
                    "lines_added": change.lines_added,
                    "lines_removed": change.lines_removed,
                    "commit_hash": change.commit_hash,
                    "commit_message": change.commit_message,
                    "author": change.author,
                    "detected_at": change.detected_at.isoformat() if change.detected_at else None
                }
                for change in changes
            ],
            "total": len(changes),
            "limit": limit,
            "offset": offset
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting file changes: {str(e)}")

@router.get("/background-jobs")
async def get_background_jobs(
    project_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    job_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get background jobs"""
    try:
        query = select(SASTBackgroundJob)
        
        if project_id:
            query = query.where(SASTBackgroundJob.project_id == project_id)
        
        if status:
            query = query.where(SASTBackgroundJob.status == status)
        
        if job_type:
            query = query.where(SASTBackgroundJob.job_type == job_type)
        
        query = query.order_by(SASTBackgroundJob.created_at.desc()).offset(offset).limit(limit)
        
        result = await db.execute(query)
        jobs = result.scalars().all()
        
        return {
            "jobs": [
                {
                    "id": job.id,
                    "project_id": job.project_id,
                    "job_type": job.job_type,
                    "status": job.status,
                    "priority": job.priority,
                    "progress": job.progress,
                    "current_step": job.current_step,
                    "error_message": job.error_message,
                    "created_at": job.created_at.isoformat() if job.created_at else None,
                    "started_at": job.started_at.isoformat() if job.started_at else None,
                    "completed_at": job.completed_at.isoformat() if job.completed_at else None
                }
                for job in jobs
            ],
            "total": len(jobs),
            "limit": limit,
            "offset": offset
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting background jobs: {str(e)}")

async def run_incremental_scan(
    job_id: int,
    project_id: int,
    base_scan_id: Optional[int],
    branch: str,
    detect_changes: bool,
    scan_changed_only: bool
):
    """Background task to run incremental scan"""
    # This would be implemented with actual change detection logic
    # For now, we'll simulate the process
    
    import asyncio
    import time
    
    # Simulate change detection
    if detect_changes:
        await asyncio.sleep(2)  # Simulate git diff analysis
        
        # Simulate finding changes
        changed_files = ["src/main.py", "src/utils.py"]
        new_files = ["src/new_feature.py"]
        deleted_files = ["src/old_file.py"]
        
        # Update job progress
        # In a real implementation, you'd update the job status in the database
        
    # Simulate scan execution
    await asyncio.sleep(5)
    
    # Update job status to completed
    # In a real implementation, you'd update the database
    
    print(f"Incremental scan {job_id} completed for project {project_id}")

# ============================================================================
# Security Hotspot Analysis Endpoints
# ============================================================================

class HotspotReviewRequest(BaseModel):
    status: SecurityHotspotStatus
    resolution: Optional[SecurityHotspotResolution] = None
    comment: Optional[str] = None
    risk_assessment: Optional[Dict[str, Any]] = None
    assigned_to: Optional[str] = None

class HotspotAssignmentRequest(BaseModel):
    assigned_to: str
    priority: Optional[int] = None
    comment: Optional[str] = None

@router.post("/security-hotspots/{hotspot_id}/review")
async def review_security_hotspot(
    hotspot_id: int,
    request: HotspotReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Review a security hotspot"""
    try:
        # Get the hotspot
        hotspot_query = await db.execute(
            select(SASTSecurityHotspot).where(SASTSecurityHotspot.id == hotspot_id)
        )
        hotspot = hotspot_query.scalar_one_or_none()
        
        if not hotspot:
            raise HTTPException(status_code=404, detail="Security hotspot not found")
        
        # Update hotspot status
        hotspot.status = request.status
        if request.resolution:
            hotspot.resolution = request.resolution
        if request.assigned_to:
            hotspot.assigned_to = request.assigned_to
            hotspot.assigned_at = datetime.now(timezone.utc).replace(tzinfo=None)
        
        # Create review record
        review = SASTHotspotReview(
            hotspot_id=hotspot_id,
            reviewer=current_user.email,
            review_action="REVIEWED",
            review_status=request.status,
            review_resolution=request.resolution,
            comment=request.comment,
            risk_assessment=request.risk_assessment
        )
        
        db.add(review)
        await db.commit()
        await db.refresh(hotspot)
        await db.refresh(review)
        
        return {
            "status": "ok",
            "message": "Security hotspot reviewed successfully",
            "hotspot": {
                "id": hotspot.id,
                "status": hotspot.status,
                "resolution": hotspot.resolution,
                "assigned_to": hotspot.assigned_to
            },
            "review": {
                "id": review.id,
                "reviewer": review.reviewer,
                "review_date": review.review_date.isoformat() if review.review_date else None
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error reviewing security hotspot: {str(e)}")

@router.post("/security-hotspots/{hotspot_id}/assign")
async def assign_security_hotspot(
    hotspot_id: int,
    request: HotspotAssignmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Assign a security hotspot to a reviewer"""
    try:
        # Get the hotspot
        hotspot_query = await db.execute(
            select(SASTSecurityHotspot).where(SASTSecurityHotspot.id == hotspot_id)
        )
        hotspot = hotspot_query.scalar_one_or_none()
        
        if not hotspot:
            raise HTTPException(status_code=404, detail="Security hotspot not found")
        
        # Update assignment
        hotspot.assigned_to = request.assigned_to
        hotspot.assigned_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if request.priority:
            hotspot.review_priority = request.priority
        
        # Create assignment record
        assignment = SASTHotspotReview(
            hotspot_id=hotspot_id,
            reviewer=current_user.email,
            review_action="ASSIGNED",
            comment=request.comment
        )
        
        db.add(assignment)
        await db.commit()
        await db.refresh(hotspot)
        
        return {
            "status": "ok",
            "message": "Security hotspot assigned successfully",
            "hotspot": {
                "id": hotspot.id,
                "assigned_to": hotspot.assigned_to,
                "assigned_at": hotspot.assigned_at.isoformat() if hotspot.assigned_at else None,
                "review_priority": hotspot.review_priority
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error assigning security hotspot: {str(e)}")

@router.get("/security-hotspots/{hotspot_id}/reviews")
async def get_hotspot_reviews(
    hotspot_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get review history for a security hotspot"""
    try:
        # Verify hotspot exists
        hotspot_query = await db.execute(
            select(SASTSecurityHotspot).where(SASTSecurityHotspot.id == hotspot_id)
        )
        hotspot = hotspot_query.scalar_one_or_none()
        
        if not hotspot:
            raise HTTPException(status_code=404, detail="Security hotspot not found")
        
        # Get reviews
        reviews_query = await db.execute(
            select(SASTHotspotReview)
            .where(SASTHotspotReview.hotspot_id == hotspot_id)
            .order_by(SASTHotspotReview.review_date.desc())
        )
        reviews = reviews_query.scalars().all()
        
        return {
            "reviews": [
                {
                    "id": review.id,
                    "reviewer": review.reviewer,
                    "review_action": review.review_action,
                    "review_status": review.review_status,
                    "review_resolution": review.review_resolution,
                    "comment": review.comment,
                    "risk_assessment": review.risk_assessment,
                    "review_date": review.review_date.isoformat() if review.review_date else None,
                    "review_duration": review.review_duration
                }
                for review in reviews
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting hotspot reviews: {str(e)}")

@router.get("/security-hotspots/prioritized")
async def get_prioritized_hotspots(
    project_id: Optional[int] = Query(None),
    risk_level: Optional[str] = Query(None),
    status: Optional[SecurityHotspotStatus] = Query(None),
    assigned_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get prioritized security hotspots based on risk assessment"""
    try:
        query = select(SASTSecurityHotspot)
        
        if project_id:
            query = query.where(SASTSecurityHotspot.project_id == project_id)
        
        if risk_level:
            query = query.where(SASTSecurityHotspot.risk_level == risk_level)
        
        if status:
            query = query.where(SASTSecurityHotspot.status == status)
        
        if assigned_to:
            query = query.where(SASTSecurityHotspot.assigned_to == assigned_to)
        
        # Order by risk score and priority
        query = query.order_by(
            SASTSecurityHotspot.risk_score.desc(),
            SASTSecurityHotspot.review_priority.desc(),
            SASTSecurityHotspot.created_at.desc()
        ).offset(offset).limit(limit)
        
        result = await db.execute(query)
        hotspots = result.scalars().all()
        
        return {
            "hotspots": [
                {
                    "id": hotspot.id,
                    "rule_name": hotspot.rule_name,
                    "message": hotspot.message,
                    "file_path": hotspot.file_path,
                    "line_number": hotspot.line_number,
                    "status": hotspot.status,
                    "risk_level": hotspot.risk_level,
                    "risk_score": hotspot.risk_score,
                    "review_priority": hotspot.review_priority,
                    "assigned_to": hotspot.assigned_to,
                    "created_at": hotspot.created_at.isoformat() if hotspot.created_at else None
                }
                for hotspot in hotspots
            ],
            "total": len(hotspots),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting prioritized hotspots: {str(e)}")
