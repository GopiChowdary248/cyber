from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status, Request
from fastapi.responses import StreamingResponse
from typing import Any, Dict, List, Optional
from datetime import datetime
import asyncio
import base64
import re
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, cast, String

from app.core.database import get_db
from app.core.security import get_current_user, verify_token
from app.models.dast_tools import DASTProxyEntry, DASTLogEntry, DASTTargetNode, DASTRepeaterEntry, DASTProjectMember, DASTIntercept, DASTProxySettings, DASTCAConfig, DASTWSFrame, DASTAuditEvent, DASTLock, DASTProxyCorrelation, DASTIngestToken, DASTMatchReplaceRule
from app.models.user import User
from app.models.dast import DASTScan, DASTVulnerability, DASTProject
from app.models.project import Project
import os
from app.services.proxy_engine import proxy_engine_manager
from app.services.scanner_engine import scanner_engine
from app.services.crawler_engine import crawler_engine
from app.schemas.dast_tools import (
    DashboardActivityResponse,
    IssueSummaryResponse,
    DashboardEventsResponse,
    TargetMapResponse,
    RepeaterSendRequest,
    RepeaterSendResponse,
    RepeaterHistoryResponse,
    LoggerEntriesResponse,
    LoggerEntryDetail,
    LoggerBookmarkRequest,
    LoggerNoteRequest,
    SequencerStartResponse,
    SequencerResultsResponse,
    DecoderTransformRequest,
    DecoderTransformResponse,
    ComparerRequest,
    ComparerResponse,
    ExtenderListResponse,
    ExtenderInstallRequest,
    ExtenderActionResponse,
    ScannerStartResponse,
    ScannerStatusResponse,
    ScannerIssuesResponse,
    SettingsResponse,
    UpdateSettingsResponse,
    WSFramesResponse,
    WSFramePinRequest,
    WSFrameNoteRequest,
    AuditEventsResponse,
    AcquireLockRequest,
    LocksResponse,
    DASTIngestTokenCreate,
    DASTIngestToken,
    DASTMatchReplaceRuleCreate,
    DASTMatchReplaceRule,
    DASTMatchReplaceRuleUpdate,
)

router = APIRouter()

@router.get("/")
async def get_dast_overview():
    """Get DAST overview"""
    return {
        "module": "DAST",
        "description": "Dynamic Application Security Testing",
        "status": "active",
        "features": [
            "Scanner Engine",
            "Crawler Engine", 
            "Proxy Engine",
            "Intruder Tool",
            "Repeater Tool",
            "HTTP History",
            "Match/Replace Rules",
            "WebSocket Support"
        ],
        "endpoints": {
            "scanner": "/scanner",
            "crawler": "/crawler", 
            "proxy": "/proxy",
            "intruder": "/intruder",
            "repeater": "/repeater",
            "history": "/history",
            "rules": "/rules",
            "websocket": "/ws"
        }
    }

@router.get("/projects")
async def get_dast_projects():
    """Get DAST projects"""
    return {
        "projects": [
            {
                "id": 1,
                "name": "E-commerce Web App",
                "status": "active",
                "lastScan": "2025-08-16T10:00:00Z",
                "vulnerabilities": 3
            },
            {
                "id": 2,
                "name": "Admin Portal",
                "status": "active",
                "lastScan": "2025-08-16T09:30:00Z",
                "vulnerabilities": 1
            }
        ]
    }

@router.get("/scans")
async def get_dast_scans():
    """Get DAST scans"""
    return {
        "scans": [
            {
                "id": "scan-001",
                "projectName": "E-commerce Web App",
                "status": "completed",
                "vulnerabilities": 3,
                "duration": "3m 45s",
                "timestamp": "2025-08-16T10:00:00Z"
            }
        ]
    }

# In-memory scanner WS connections per project
SCANNER_CONNECTIONS: Dict[str, List[WebSocket]] = {}

async def _broadcast_scanner_log(project_id: str, level: str, message: str) -> None:
    conns = SCANNER_CONNECTIONS.get(project_id) or []
    stale: List[WebSocket] = []
    for ws in conns:
        try:
            await ws.send_json({
                "type": "log",
                "level": level,
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception:
            stale.append(ws)
    if stale:
        SCANNER_CONNECTIONS[project_id] = [w for w in conns if w not in stale]


# -------------------------------
# Helpers - Map/Replace
# -------------------------------

def _apply_match_replace(rules: list, request_obj: dict) -> dict:
    """Apply map/replace rules to the outgoing request object.
    Supported scopes: request-url, request-header, request-body.
    Match is treated as regex if it looks like a regex (best-effort), otherwise substring replacement.
    """
    if not request_obj:
        return request_obj
    if not isinstance(rules, list) or not rules:
        return request_obj
    method = request_obj.get("method") or "GET"
    url = request_obj.get("url") or ""
    headers = request_obj.get("headers") or {}
    body = request_obj.get("body")

    for rule in rules:
        if not rule or not rule.get("enabled", True):
            continue
        scope = rule.get("scope", "request-url")
        match = rule.get("match") or ""
        replace = rule.get("replace") or ""
        if not match:
            continue
        try:
            # Decide regex vs simple
            is_regex = bool(rule.get("regex")) or any(ch in match for ch in [".*", "?", "[", "]", "(", ")", "|", "+", "^", "$"])
            if scope == "request-url":
                if is_regex:
                    import re
                    url = re.sub(match, replace, url)
                else:
                    url = url.replace(match, replace)
            elif scope == "request-header":
                # Apply to header keys and values
                new_headers = {}
                for k, v in headers.items():
                    nk, nv = k, v
                    if is_regex:
                        import re
                        nk = re.sub(match, replace, k)
                        if isinstance(v, str):
                            nv = re.sub(match, replace, v)
                    else:
                        nk = k.replace(match, replace)
                        if isinstance(v, str):
                            nv = v.replace(match, replace)
                    new_headers[nk] = nv
                headers = new_headers
            elif scope == "request-body":
                if isinstance(body, str):
                    if is_regex:
                        import re
                        body = re.sub(match, replace, body)
                    else:
                        body = body.replace(match, replace)
        except Exception:
            # best effort: ignore failing rule
            continue

    request_obj["method"] = method
    request_obj["url"] = url
    request_obj["headers"] = headers
    if body is not None:
        request_obj["body"] = body
    return request_obj


# Response-side match/replace for headers/body
def _apply_response_match_replace(rules: list, response_obj: dict) -> dict:
    if not response_obj:
        return response_obj
    if not isinstance(rules, list) or not rules:
        return response_obj
    status = response_obj.get("status")
    headers = response_obj.get("headers") or {}
    body = response_obj.get("body")
    for rule in rules:
        if not rule or not rule.get("enabled", True):
            continue
        scope = rule.get("scope", "")
        match = rule.get("match") or ""
        replace = rule.get("replace") or ""
        if not match:
            continue
        try:
            is_regex = bool(rule.get("regex")) or any(ch in match for ch in [".*", "?", "[", "]", "(", ")", "|", "+", "^", "$"])
            if scope == "response-header":
                new_headers = {}
                for k, v in headers.items():
                    nk, nv = k, v
                    if is_regex:
                        import re
                        nk = re.sub(match, replace, k)
                        if isinstance(v, str):
                            nv = re.sub(match, replace, v)
                    else:
                        nk = k.replace(match, replace)
                        if isinstance(v, str):
                            nv = v.replace(match, replace)
                    new_headers[nk] = nv
                headers = new_headers
            elif scope == "response-body" and isinstance(body, str):
                if is_regex:
                    import re
                    body = re.sub(match, replace, body)
                else:
                    body = body.replace(match, replace)
        except Exception:
            continue
    response_obj["headers"] = headers
    if body is not None:
        response_obj["body"] = body
    if status is not None:
        response_obj["status"] = status
    return response_obj


# Scope checking against DASTProject.scope_config
def _is_url_in_scope(url: str, scope: Optional[dict]) -> bool:
    if not scope:
        return True
    try:
        include = scope.get("include") or []
        exclude = scope.get("exclude") or []
        text = url or ""
        # If include rules exist, require at least one match
        if include:
            inc_match = False
            for rule in include:
                try:
                    import re
                    if re.search(rule, text, flags=re.IGNORECASE):
                        inc_match = True
                        break
                except Exception:
                    # fallback to substring
                    if rule.lower() in text.lower():
                        inc_match = True
                        break
            if not inc_match:
                return False
        # Exclude overrides include
        for rule in exclude:
            try:
                import re
                if re.search(rule, text, flags=re.IGNORECASE):
                    return False
            except Exception:
                if rule.lower() in text.lower():
                    return False
        return True
    except Exception:
        return True

def _apply_response_match_replace(rules: list, response_obj: dict) -> dict:
    if not response_obj:
        return response_obj
    if not isinstance(rules, list) or not rules:
        return response_obj
    headers = response_obj.get("headers") or {}
    body = response_obj.get("body")
    for rule in rules:
        if not rule or not rule.get("enabled", True):
            continue
        scope = rule.get("scope", "")
        if not scope.startswith("response-"):
            continue
        match = rule.get("match") or ""
        replace = rule.get("replace") or ""
        if not match:
            continue
        try:
            is_regex = bool(rule.get("regex")) or any(ch in match for ch in [".*", "?", "[", "]", "(", ")", "|", "+", "^", "$"])
            if scope == "response-header":
                new_headers = {}
                for k, v in headers.items():
                    nk, nv = k, v
                    if is_regex:
                        import re
                        nk = re.sub(match, replace, k)
                        if isinstance(v, str):
                            nv = re.sub(match, replace, v)
                    else:
                        nk = k.replace(match, replace)
                        if isinstance(v, str):
                            nv = v.replace(match, replace)
                    new_headers[nk] = nv
                headers = new_headers
            elif scope == "response-body" and isinstance(body, str):
                if is_regex:
                    import re
                    body = re.sub(match, replace, body)
                else:
                    body = body.replace(match, replace)
        except Exception:
            continue
    response_obj["headers"] = headers
    if body is not None:
        response_obj["body"] = body
    return response_obj

# -------------------------------
# Helpers / RBAC
# -------------------------------

def _require_role(current_user: User, allowed_roles: List[str]):
    role = getattr(current_user, "role", None)
    if role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def _require_project_access(db: AsyncSession, project_id: str, current_user: User):
    # Allow if user owns or created the project in general projects table (if integer IDs used there)
    try:
        # try integer project id
        int_id = int(project_id)
        p = await Project.get_by_id(db, int_id)
        if p and (p.owner_id == current_user.id or p.created_by == current_user.id):
            return
    except Exception:
        # UUID project: check membership in dast_project_members
        try:
            if await DASTProjectMember.is_member(db, project_id, current_user.id):
                return
        except Exception:
            pass
    # If we reach here and found a non-owned project, deny
    if 'int_id' in locals():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to project")


# -------------------------------
# 1. Dashboard
# -------------------------------

@router.get("/{project_id}/dashboard/activity", response_model=DashboardActivityResponse)
async def get_dashboard_activity(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _require_project_access(db, project_id, current_user)
    # Active: queued/running scans
    active_q = select(DASTScan).where(DASTScan.project_id == project_id, DASTScan.status.in_(["queued", "running"]))
    active_scans = (await db.execute(active_q)).scalars().all()
    active_tasks = [
        {
            "id": str(s.id),
            "name": f"{s.scan_type.capitalize()} scan",
            "progress": 0 if s.status == "queued" else 50,
            "status": s.status,
            "updated_at": (s.updated_at.isoformat() if s.updated_at else datetime.utcnow().isoformat()),
        }
        for s in active_scans
    ]
    # Completed: recently completed scans
    completed_q = select(DASTScan).where(DASTScan.project_id == project_id, DASTScan.status.in_(["completed", "failed", "cancelled"]))\
        .order_by(DASTScan.completed_at.desc()).limit(10)
    completed_scans = (await db.execute(completed_q)).scalars().all()
    completed_tasks = [
        {
            "id": str(s.id),
            "name": f"{s.scan_type.capitalize()} scan",
            "progress": 100,
            "status": s.status,
            "updated_at": (s.completed_at.isoformat() if s.completed_at else s.updated_at.isoformat() if s.updated_at else datetime.utcnow().isoformat()),
        }
        for s in completed_scans
    ]
    return {"active_tasks": active_tasks, "completed_tasks": completed_tasks}


@router.get("/{project_id}/dashboard/issues", response_model=IssueSummaryResponse)
async def get_dashboard_issues(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _require_project_access(db, project_id, current_user)
    # Count vulnerabilities by severity
    sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rows = (await db.execute(select(DASTVulnerability.severity, func.count(DASTVulnerability.id)).where(DASTVulnerability.project_id == project_id).group_by(DASTVulnerability.severity))).all()
    for sev, cnt in rows:
        s = (sev or "").lower()
        if s in sev_map:
            sev_map[s] = cnt
    # Map to expected fields
    return {"high": sev_map["high"], "medium": sev_map["medium"], "low": sev_map["low"]}


@router.get("/{project_id}/dashboard/events", response_model=DashboardEventsResponse)
async def get_dashboard_events(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
):
    await _require_project_access(db, project_id, current_user)
    # Use recent log entries as events (can be extended to scans, etc.)
    logs = await DASTLogEntry.get_latest_by_project(db, project_id, limit=limit)
    events = [
        {"id": str(l.id), "type": "log", "message": f"{l.method or ''} {l.url}", "timestamp": (l.created_at.isoformat() if l.created_at else datetime.utcnow().isoformat())}
        for l in logs
    ]
    return {"events": events}


@router.websocket("/ws/{project_id}/dashboard")
async def ws_dashboard(websocket: WebSocket, project_id: str):
    token = websocket.query_params.get("token")
    try:
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        _ = verify_token(token)
        await websocket.accept()
        # Send recent events from DB
        try:
            from app.core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                logs = await DASTLogEntry.get_latest_by_project(db, project_id, limit=20)
                for l in logs[::-1]:
                    await websocket.send_json({
                        "type": "event",
                        "project_id": project_id,
                        "message": f"{l.method or ''} {l.url}",
                        "timestamp": (l.created_at.isoformat() if l.created_at else datetime.utcnow().isoformat()),
                    })
        except Exception:
            pass
        # Heartbeat loop
        while True:
            _ = await websocket.receive_text()
            await websocket.send_json({"type": "heartbeat", "timestamp": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        pass


# -------------------------------
# 2. Target
# -------------------------------

@router.post("/{project_id}/target/add")
async def add_target(project_id: str, body: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    label = body.get("label") or body.get("url") or ""
    node_type = body.get("type", "path")
    parent_id = body.get("parent_id")
    node = await DASTTargetNode.add_node(db, project_id=project_id, label=label, node_type=node_type, parent_id=parent_id, metadata=body, in_scope=True)
    return {"status": "ok", "id": str(node.id)}


@router.get("/{project_id}/target/map", response_model=TargetMapResponse)
async def get_site_map(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    nodes = await DASTTargetNode.list_by_project(db, project_id)
    return {"nodes": [
        {
            "id": str(n.id),
            "parent_id": str(n.parent_id) if n.parent_id else None,
            "type": n.node_type,
            "label": n.label,
            "in_scope": n.in_scope,
            "metadata": getattr(n, "node_metadata", None),
        }
        for n in nodes
    ]}


@router.put("/{project_id}/target/scope")
async def update_scope(project_id: str, rules: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "updated", "project_id": project_id, "rules": rules}


@router.delete("/{project_id}/target/remove/{item_id}")
async def remove_target_item(project_id: str, item_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "removed", "project_id": project_id, "item_id": item_id}


@router.put("/{project_id}/target/nodes/scope")
async def bulk_update_nodes_scope(
    project_id: str,
    payload: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    ids = payload.get("ids", [])
    in_scope = bool(payload.get("in_scope", True))
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="ids array required")
    updated = 0
    for node_id in ids:
        try:
            result = await db.execute(select(DASTTargetNode).where(DASTTargetNode.id == node_id, DASTTargetNode.project_id == project_id))
            node = result.scalar_one_or_none()
            if node:
                node.in_scope = in_scope
                updated += 1
        except Exception:
            continue
    await db.commit()
    return {"status": "updated", "updated": updated}


@router.put("/{project_id}/target/node/{node_id}/scope")
async def update_target_node_scope(
    project_id: str,
    node_id: str,
    payload: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    in_scope = bool(payload.get("in_scope", True))
    result = await db.execute(select(DASTTargetNode).where(DASTTargetNode.id == node_id, DASTTargetNode.project_id == project_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    node.in_scope = in_scope
    await db.commit()
    return {"status": "updated", "id": node_id, "in_scope": in_scope}


# -------------------------------
# 3. Proxy
# -------------------------------

@router.get("/{project_id}/proxy/http-history")
async def get_http_history(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    status: Optional[int] = Query(None, description="Filter by HTTP status code"),
    host: Optional[str] = Query(None, description="Filter by host (substring)"),
    url_regex: Optional[str] = Query(None, description="Regex on full URL (Postgres ~*)"),
    mime: Optional[str] = Query(None, description="Match response content type (substring)"),
    start_time: Optional[str] = Query(None, description="ISO start time"),
    end_time: Optional[str] = Query(None, description="ISO end time"),
):
    await _require_project_access(db, project_id, current_user)

    # Build query
    q = select(DASTProxyEntry).where(DASTProxyEntry.project_id == project_id)
    if method:
        q = q.where(DASTProxyEntry.method == method)
    if status is not None:
        q = q.where(DASTProxyEntry.status == status)
    if host:
        # simple host contains on URL
        q = q.where(DASTProxyEntry.url.ilike(f"%{host}%"))
    if url_regex:
        # Postgres case-insensitive regex ~*
        q = q.where(DASTProxyEntry.url.op("~*")(url_regex))
    if mime:
        # naive search in response JSON text for content-type
        q = q.where(cast(DASTProxyEntry.response, String).ilike(f"%{mime}%"))
    # time range on created_at if available, else 'time'
    if start_time:
        try:
            q = q.where((DASTProxyEntry.created_at >= start_time) | ((DASTProxyEntry.created_at.is_(None)) & (DASTProxyEntry.time >= start_time)))
        except Exception:
            pass
    if end_time:
        try:
            q = q.where((DASTProxyEntry.created_at <= end_time) | ((DASTProxyEntry.created_at.is_(None)) & (DASTProxyEntry.time <= end_time)))
        except Exception:
            pass

    # Count
    cq = select(func.count(DASTProxyEntry.id)).where(DASTProxyEntry.project_id == project_id)
    if method:
        cq = cq.where(DASTProxyEntry.method == method)
    if status is not None:
        cq = cq.where(DASTProxyEntry.status == status)
    if host:
        cq = cq.where(DASTProxyEntry.url.ilike(f"%{host}%"))
    if url_regex:
        cq = cq.where(DASTProxyEntry.url.op("~*")(url_regex))
    if mime:
        cq = cq.where(cast(DASTProxyEntry.response, String).ilike(f"%{mime}%"))
    if start_time:
        try:
            cq = cq.where((DASTProxyEntry.created_at >= start_time) | ((DASTProxyEntry.created_at.is_(None)) & (DASTProxyEntry.time >= start_time)))
        except Exception:
            pass
    if end_time:
        try:
            cq = cq.where((DASTProxyEntry.created_at <= end_time) | ((DASTProxyEntry.created_at.is_(None)) & (DASTProxyEntry.time <= end_time)))
        except Exception:
            pass

    total = (await db.execute(cq)).scalar() or 0
    offset = (page - 1) * page_size
    rows = (await db.execute(q.order_by(DASTProxyEntry.created_at.desc()).offset(offset).limit(page_size))).scalars().all()

    items = [
        {
            "id": str(e.id),
            "method": e.method,
            "url": e.url,
            "status": e.status,
            "size": e.size,
            "time": e.time.isoformat() if getattr(e, 'time', None) and hasattr(getattr(e, 'time'), 'isoformat') else None,
        }
        for e in rows
    ]

    return {"entries": items, "items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{project_id}/proxy/http-history/{entry_id}")
async def get_http_history_entry(
    project_id: str,
    entry_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    entry = await DASTProxyEntry.get_by_id(db, entry_id)
    if not entry or str(entry.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Entry not found")
    return {
        "id": str(entry.id),
        "method": entry.method,
        "url": entry.url,
        "status": entry.status,
        "size": entry.size,
        "time": entry.time.isoformat() if getattr(entry, 'time', None) and hasattr(getattr(entry, 'time'), 'isoformat') else None,
        "request": entry.request,
        "response": entry.response,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@router.get("/{project_id}/proxy/http-history/{entry_id}/payload")
async def get_http_history_payload(
    project_id: str,
    entry_id: str,
    part: str = Query("response", regex="^(request|response)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    entry = await DASTProxyEntry.get_by_id(db, entry_id)
    if not entry or str(entry.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Entry not found")
    data = entry.request if part == "request" else entry.response
    body = (data or {}).get("body", "")
    headers = (data or {}).get("headers", {})
    return {"headers": headers, "body": body}


@router.post("/{project_id}/proxy/intercept/toggle")
async def toggle_intercept(project_id: str, enabled: bool = Query(True), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "ok", "project_id": project_id, "intercept_enabled": enabled}


@router.get("/{project_id}/proxy/settings")
async def get_proxy_settings(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    row = await DASTProxySettings.get_by_project(db, project_id)
    return {"settings": row.settings if row else {"listeners": [], "matchReplace": []}}


@router.get("/{project_id}/proxy/ws-frames", response_model=WSFramesResponse)
async def list_ws_frames(project_id: str, limit: int = Query(200, ge=1, le=2000), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    rows = await DASTWSFrame.list_by_project(db, project_id, limit=limit)
    return {"frames": [
        {
            "id": str(r.id),
            "direction": r.direction,
            "opcode": r.opcode,
            "text": r.text,
            "payload_base64": r.payload_base64,
            "entry_id": (str(r.entry_id) if getattr(r, 'entry_id', None) else None),
            "pinned": bool(r.pinned),
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]}


@router.post("/{project_id}/proxy/engine/start")
async def proxy_engine_start(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # Spawn mitmproxy with default listener; API base inferred from env FRONTEND/REACT_APP_API_URL or local
    api_base = (os.environ.get("PUBLIC_API_BASE") or "http://localhost:8000").rstrip("/")
    token = getattr(current_user, "access_token", None) or None
    try:
        proxy_engine_manager.start(project_id=project_id, api_base=api_base, api_token=token)
    except Exception:
        pass
    await DASTAuditEvent.log(db, project_id=project_id, user_id=current_user.id, action="proxy_engine_start", object_type="proxy", object_id=project_id)
    return {"status": "starting"}


@router.post("/{project_id}/proxy/engine/stop")
async def proxy_engine_stop(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    try:
        proxy_engine_manager.stop(project_id=project_id)
    except Exception:
        pass
    await DASTAuditEvent.log(db, project_id=project_id, user_id=current_user.id, action="proxy_engine_stop", object_type="proxy", object_id=project_id)
    return {"status": "stopping"}


@router.post("/{project_id}/proxy/ingest/flow")
async def ingest_flow(project_id: str, payload: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # This endpoint can be secured with a dedicated token; for now reuse user auth
    await _require_project_access(db, project_id, current_user)
    corr = payload.get("correlation_id")
    req = payload.get("request") or {}
    resp = payload.get("response") or {}
    # TODO: apply match/replace pipelines
    entry = await DASTProxyEntry.create(db, project_id=project_id, method=req.get("method", "GET"), url=req.get("url", ""), status=resp.get("status"), size=(len((resp.get("body") or "")) or 0), time=datetime.utcnow().isoformat(), request=req, response=resp)
    if corr:
        try:
            await DASTProxyCorrelation.upsert(db, project_id=project_id, correlation_id=corr, entry_id=str(entry.id))
        except Exception:
            pass
    # Passive scan hook example: missing security headers
    try:
        headers = (resp.get("headers") or {})
        csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
        if not csp:
            await DASTLogEntry.create(db, project_id=project_id, method=req.get("method"), url=req.get("url", ""), status=resp.get("status"), details={"passive_issue": "Missing CSP", "entry_id": str(entry.id)})
    except Exception:
        pass
    return {"status": "ok", "entry_id": str(entry.id), "correlation_id": corr}


@router.post("/{project_id}/proxy/ingest/ws")
async def ingest_ws(project_id: str, payload: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    frame = payload.get("frame") or {}
    entry_correlation_id = payload.get("entry_correlation_id")
    entry_id = None
    if entry_correlation_id:
        try:
            corr = await DASTProxyCorrelation.get_latest(db, project_id=project_id, correlation_id=entry_correlation_id)
            if corr:
                entry_id = str(corr.entry_id)
        except Exception:
            pass
    saved = await DASTWSFrame.create(db, project_id=project_id, direction=frame.get("direction", "in"), opcode=int(frame.get("opcode", 1)), text=frame.get("text"), payload_base64=frame.get("payload_base64"), entry_id=entry_id)
    return {"status": "ok", "frame_id": str(saved.id), "entry_id": entry_id, "entry_correlation_id": entry_correlation_id}


@router.put("/{project_id}/proxy/ws-frames/{frame_id}/pin")
async def pin_ws_frame(project_id: str, frame_id: str, body: WSFramePinRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    row = await DASTWSFrame.get_by_id(db, frame_id)
    if not row or str(row.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Frame not found")
    await DASTWSFrame.set_pinned(db, frame_id=frame_id, pinned=body.pinned)
    return {"status": "ok"}


@router.put("/{project_id}/proxy/ws-frames/{frame_id}/note")
async def note_ws_frame(project_id: str, frame_id: str, body: WSFrameNoteRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    row = await DASTWSFrame.get_by_id(db, frame_id)
    if not row or str(row.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Frame not found")
    await DASTWSFrame.set_note(db, frame_id=frame_id, note=body.note)
    return {"status": "ok"}


@router.put("/{project_id}/proxy/settings")
async def update_proxy_settings(project_id: str, settings: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    row = await DASTProxySettings.set_for_project(db, project_id=project_id, settings=settings)
    return {"status": "saved", "project_id": project_id, "settings": row.settings}


@router.post("/{project_id}/proxy/intercept/forward")
async def proxy_intercept_forward(project_id: str, payload: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # Identify intercept if provided
    intercept_id = payload.get("intercept_id")
    req = payload.get("request", {}) or {}
    # If no request was supplied but intercept_id is provided, use the queued request
    if intercept_id and not req:
        row = await DASTIntercept.get_by_id(db, intercept_id)
        if row and str(row.project_id) == project_id:
            req = row.request or {}
    # Apply map/replace rules from settings
    settings_row = await DASTProxySettings.get_by_project(db, project_id)
    rules = (settings_row.settings or {}).get("matchReplace", []) if settings_row else []
    req = _apply_match_replace(rules, req)

    method = req.get("method", "GET")
    url = req.get("url", "")
    headers = req.get("headers", {})
    body = req.get("body")
    # Simulate execution and persist to history (respect project scope)
    history_id: Optional[str] = None
    try:
        # scope check
        proj = await DASTProject.get_by_id(db, project_id)
        if proj and not _is_url_in_scope(url, (proj.scope_config or {})):
            raise HTTPException(status_code=400, detail="URL out of scope")
        # apply response side rules as a last step to simulate replacement in body/headers
        simulated_response = {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": "OK"}
        simulated_response = _apply_response_match_replace(rules, simulated_response)
        entry = await DASTProxyEntry.create(
            db,
            project_id=project_id,
            method=method,
            url=url,
            status=200,
            size=len((body or "").encode("utf-8")) if isinstance(body, str) else 0,
            time=datetime.utcnow().isoformat(),
            request={"method": method, "url": url, "headers": headers, "body": body},
            response=simulated_response,
        )
        history_id = str(entry.id)
    except Exception:
        pass
    # If intercept exists, mark it forwarded
    if intercept_id:
        row = await DASTIntercept.get_by_id(db, intercept_id)
        if row and str(row.project_id) == project_id:
            row.status = "forwarded"
            await db.commit()
    return {"status": "forwarded", "entry_id": payload.get("entry_id"), "intercept_id": intercept_id, "history_id": history_id}


@router.post("/{project_id}/proxy/intercept/drop")
async def proxy_intercept_drop(project_id: str, payload: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # Support dropping by intercept_id to remove from queue
    intercept_id = payload.get("intercept_id")
    if intercept_id:
        row = await DASTIntercept.get_by_id(db, intercept_id)
        if row and str(row.project_id) == project_id:
            row.status = "dropped"
            await db.commit()
            return {"status": "dropped", "intercept_id": intercept_id}
    return {"status": "dropped", "entry_id": payload.get("entry_id")}


@router.get("/{project_id}/proxy/intercepts")
async def list_proxy_intercepts(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    rows = await DASTIntercept.list_pending(db, project_id, limit=100)
    return {
        "intercepts": [
            {
                "id": str(r.id),
                "request": r.request,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }


@router.websocket("/ws/{project_id}/proxy")
async def ws_proxy(websocket: WebSocket, project_id: str):
    token = websocket.query_params.get("token")
    try:
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        _ = verify_token(token)
        await websocket.accept()
        await websocket.send_json({"type": "connected", "message": "Proxy intercept stream connected", "project_id": project_id})
        while True:
            _ = await websocket.receive_text()
            # In a real implementation, this would come from the proxy engine
            sample_request = {"method": "GET", "url": "https://example.com/health", "headers": {"User-Agent": "CyberShield"}, "body": ""}

            # Persist to DB (best-effort, ignore failures)
            entry_id_value = None
            try:
                from app.core.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    await DASTIntercept.enqueue(db, project_id=project_id, request=sample_request)
                    try:
                        await DASTTargetNode.ensure_url_nodes(db, project_id=project_id, url=sample_request.get("url", ""))
                    except Exception:
                        pass
                    entry = await DASTProxyEntry.create(
                        db,
                        project_id=project_id,
                        method=sample_request.get("method", "GET"),
                        url=sample_request.get("url", ""),
                        status=200,
                        size=0,
                        time=datetime.utcnow().isoformat(),
                        request=sample_request,
                        response={"status": 200, "headers": {}, "body": ""},
                    )
                    entry_id_value = str(entry.id)
                    try:
                        await DASTWSFrame.create(db, project_id=project_id, direction="in", opcode=1, text="hello from server", entry_id=entry_id_value)
                        import base64 as _b64
                        await DASTWSFrame.create(db, project_id=project_id, direction="out", opcode=2, payload_base64=_b64.b64encode(b"\x00\x01\x02demo").decode("ascii"), entry_id=entry_id_value)
                    except Exception:
                        pass
            except Exception:
                pass

            await websocket.send_json({
                "type": "intercepted",
                "request": sample_request,
                "timestamp": datetime.utcnow().isoformat(),
            })
            # Demo WebSocket frames (text and binary) including entry_id for UI quick-linking
            await websocket.send_json({
                "type": "ws_message",
                "message": {"direction": "in", "opcode": 1, "text": "hello from server", "entry_id": entry_id_value},
                "timestamp": datetime.utcnow().isoformat(),
            })
            await websocket.send_json({
                "type": "ws_message",
                "message": {"direction": "out", "opcode": 2, "payload_base64": base64.b64encode(b"\x00\x01\x02demo").decode("ascii"), "entry_id": entry_id_value},
                "timestamp": datetime.utcnow().isoformat(),
            })
    except WebSocketDisconnect:
        pass


# -------------------------------
# 4. Intruder
# -------------------------------

@router.post("/{project_id}/intruder/start")
async def intruder_start(project_id: str, attack: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"attack_id": "atk-1", "status": "started", "project_id": project_id}


@router.get("/{project_id}/intruder/status/{attack_id}")
async def intruder_status(project_id: str, attack_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    return {"attack_id": attack_id, "status": "running", "progress": 37}


@router.get("/{project_id}/intruder/results/{attack_id}")
async def intruder_results(project_id: str, attack_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    return {
        "attack_id": attack_id,
        "results": [
            {"payload": "admin'--", "status": 200, "length": 2048, "snippet": "<html>..."},
        ],
    }


@router.put("/{project_id}/intruder/stop/{attack_id}")
async def intruder_stop(project_id: str, attack_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"attack_id": attack_id, "status": "stopped"}


# -------------------------------
# 5. Repeater
# -------------------------------

@router.post("/{project_id}/repeater/send", response_model=RepeaterSendResponse)
async def repeater_send(project_id: str, request_data: RepeaterSendRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst", "user"])  # Allow all authenticated to use
    await _require_project_access(db, project_id, current_user)
    # Echo a fake response
    response = {
        "status": 200,
        "headers": {"Content-Type": "application/json"},
        "body": {"echo": request_data},
        "size": 1234,
        "time_ms": 87,
    }
    try:
        await DASTRepeaterEntry.create(
            db,
            project_id=project_id,
            method=request_data.method or "GET",
            url=request_data.url or "",
            headers=request_data.headers,
            body=request_data.body,
            response=response,
        )
    except Exception:
        pass
    return {"status": "ok", "response": response}


@router.get("/{project_id}/repeater/history", response_model=RepeaterHistoryResponse)
async def repeater_history(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    rows = await DASTRepeaterEntry.list_by_project(db, project_id, limit=100)
    return {"sessions": [
        {
            "id": str(r.id),
            "method": r.method,
            "url": r.url,
            "status": (r.response or {}).get("status"),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]}


@router.delete("/{project_id}/repeater/session/{session_id}")
async def repeater_close_session(project_id: str, session_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "closed", "session_id": session_id}


# -------------------------------
# 6. Sequencer
# -------------------------------

@router.post("/{project_id}/sequencer/start", response_model=SequencerStartResponse)
async def sequencer_start(project_id: str, body: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"sequence_id": "seq-1", "status": "capturing"}


@router.get("/{project_id}/sequencer/results/{sequence_id}", response_model=SequencerResultsResponse)
async def sequencer_results(project_id: str, sequence_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    return {
        "sequence_id": sequence_id,
        "entropy": 4.72,
        "histogram": {"A": 10, "B": 12, "C": 9},
        "recommendations": ["Increase randomness", "Avoid predictable prefixes"],
    }


# -------------------------------
# 7. Decoder
# -------------------------------

@router.post("/{project_id}/decoder/transform", response_model=DecoderTransformResponse)
async def decoder_transform(project_id: str, body: DecoderTransformRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    mode = body.mode
    text = body.text
    if mode == "encode":
        out = text.encode("utf-8").hex()
    elif mode == "decode":
        try:
            out = bytes.fromhex(text).decode("utf-8")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid hex input for decode")
    else:
        out = text
    return {"output": out}


# -------------------------------
# 8. Comparer
# -------------------------------

@router.post("/{project_id}/comparer/compare", response_model=ComparerResponse)
async def comparer_compare(project_id: str, body: ComparerRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    left = body.left
    right = body.right
    mode = body.mode or "words"
    # Simple diff stub
    return {"mode": mode, "differences": [] if left == right else [{"index": 0, "left": left, "right": right}]}


# -------------------------------
# 9. Extender
# -------------------------------

@router.get("/{project_id}/extender/list", response_model=ExtenderListResponse)
async def extender_list(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    return {"installed": [{"name": "SampleExtension", "author": "CyberShield", "status": "enabled"}]}


@router.post("/{project_id}/extender/install", response_model=ExtenderActionResponse)
async def extender_install(project_id: str, body: ExtenderInstallRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "installed", "extension": body.name}


@router.delete("/{project_id}/extender/remove/{extension_id}", response_model=ExtenderActionResponse)
async def extender_remove(project_id: str, extension_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "removed", "extension_id": extension_id}


# -------------------------------
# 10. Scanner
# -------------------------------

@router.post("/{project_id}/scanner/start", response_model=ScannerStartResponse)
async def scanner_start(project_id: str, config: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # TODO: call external orchestrator here; for now, simulate and broadcast
    scan_id = "scan-" + datetime.utcnow().strftime("%H%M%S")
    asyncio.create_task(_broadcast_scanner_log(project_id, "info", f"Scan {scan_id} started"))
    return {"scan_id": scan_id, "status": "started"}


@router.get("/{project_id}/scanner/status/{scan_id}", response_model=ScannerStatusResponse)
async def scanner_status(project_id: str, scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    # TODO: query orchestrator; demo values for now
    return {"scan_id": scan_id, "status": "running", "progress": 42}


@router.get("/{project_id}/scanner/issues", response_model=ScannerIssuesResponse)
async def scanner_issues(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    return {
        "issues": [
            {"severity": "high", "description": "SQL Injection", "confidence": "firm"},
            {"severity": "medium", "description": "Missing CSP", "confidence": "tentative"},
        ]
    }


@router.put("/{project_id}/scanner/stop/{scan_id}", response_model=ScannerStatusResponse)
async def scanner_stop(project_id: str, scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    asyncio.create_task(_broadcast_scanner_log(project_id, "info", f"Scan {scan_id} stopped"))
    return {"scan_id": scan_id, "status": "stopped"}


# Live scanner logs via WebSocket
@router.websocket("/ws/{project_id}/scanner")
async def ws_scanner(websocket: WebSocket, project_id: str):
    token = websocket.query_params.get("token")
    try:
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        _ = verify_token(token)
        await websocket.accept()
        SCANNER_CONNECTIONS.setdefault(project_id, []).append(websocket)
        await websocket.send_json({
            "type": "connected",
            "message": "Scanner log stream connected",
            "project_id": project_id,
            "timestamp": datetime.utcnow().isoformat(),
        })
        while True:
            _ = await websocket.receive_text()
            await _broadcast_scanner_log(project_id, "info", "Scanner heartbeat...")
    except WebSocketDisconnect:
        try:
            if project_id in SCANNER_CONNECTIONS and websocket in SCANNER_CONNECTIONS[project_id]:
                SCANNER_CONNECTIONS[project_id].remove(websocket)
        except Exception:
            pass

# -------------------------------
# 11. Logger
# -------------------------------

@router.get("/{project_id}/logger/entries", response_model=LoggerEntriesResponse)
async def logger_entries(
    project_id: str,
    current_user: User = Depends(get_current_user),
    q: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[int] = None,
    host: Optional[str] = None,
    mime: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    query = select(DASTLogEntry).where(DASTLogEntry.project_id == project_id)
    if q:
        query = query.where(DASTLogEntry.url.ilike(f"%{q}%"))
    if method:
        query = query.where(DASTLogEntry.method == method)
    if status is not None:
        query = query.where(DASTLogEntry.status == status)
    if host:
        query = query.where(DASTLogEntry.url.ilike(f"%{host}%"))
    if mime:
        query = query.where(cast(DASTLogEntry.details, String).ilike(f"%{mime}%"))
    # Optional bookmark-only filter via q='is:bookmarked'
    if q and 'is:bookmarked' in q:
        query = query.where(DASTLogEntry.bookmarked.is_(True))
    rows = (await db.execute(query.order_by(DASTLogEntry.created_at.desc()).offset((page-1)*page_size).limit(page_size))).scalars().all()
    total = (await db.execute(select(func.count(DASTLogEntry.id)).where(DASTLogEntry.project_id == project_id))).scalar() or 0
    return {
        "entries": [{"id": str(r.id), "method": r.method, "url": r.url, "status": r.status, "bookmarked": bool(r.bookmarked)} for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{project_id}/logger/entries/{entry_id}")
async def logger_entry_detail(
    project_id: str,
    entry_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    row = await DASTLogEntry.get_by_id(db, entry_id)
    if not row or str(row.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Entry not found")
    return {
        "id": str(row.id),
        "method": row.method,
        "url": row.url,
        "status": row.status,
        "details": row.details,
        "bookmarked": bool(row.bookmarked),
        "note": row.note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.put("/{project_id}/logger/entries/{entry_id}/bookmark")
async def logger_bookmark(
    project_id: str,
    entry_id: str,
    body: LoggerBookmarkRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    row = await DASTLogEntry.get_by_id(db, entry_id)
    if not row or str(row.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Entry not found")
    await DASTLogEntry.set_bookmarked(db, entry_id=entry_id, bookmarked=body.bookmarked)
    return {"status": "ok"}


@router.put("/{project_id}/logger/entries/{entry_id}/note")
async def logger_note(
    project_id: str,
    entry_id: str,
    body: LoggerNoteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    row = await DASTLogEntry.get_by_id(db, entry_id)
    if not row or str(row.project_id) != project_id:
        raise HTTPException(status_code=404, detail="Entry not found")
    await DASTLogEntry.set_note(db, entry_id=entry_id, note=body.note)
    return {"status": "ok"}


@router.get("/{project_id}/logger/export")
async def logger_export(
    project_id: str,
    format: str = Query("har"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    rows = await DASTLogEntry.get_latest_by_project(db, project_id, limit=2000)
    if format == "har":
        har = {"log": {"version": "1.2", "creator": {"name": "CyberShield", "version": "dev"}, "entries": []}}
        for r in rows:
            details = r.details or {}
            started = r.created_at.isoformat() if r.created_at else datetime.utcnow().isoformat()
            har["log"]["entries"].append({
                "startedDateTime": started,
                "time": 0,
                "request": {"method": r.method, "url": r.url, "httpVersion": "HTTP/1.1", "headers": [], "cookies": [], "queryString": [], "headersSize": -1, "bodySize": 0},
                "response": {"status": r.status or 0, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [], "cookies": [], "content": {"size": 0, "mimeType": (details.get("response", {}).get("headers", {}) or {}).get("Content-Type", "")}, "redirectURL": "", "headersSize": -1, "bodySize": 0},
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            })
        import json
        return StreamingResponse(iter([json.dumps(har, indent=2)]), media_type="application/json")
    def generate():
        yield "id,method,url,status,created_at\n"
        for r in rows:
            created = r.created_at.isoformat() if r.created_at else ""
            url = (r.url or '').replace('"', '""')
            yield f"{r.id},{r.method or ''},\"{url}\",{r.status or ''},{created}\n"
    return StreamingResponse(generate(), media_type="text/csv")


@router.websocket("/ws/{project_id}/logger")
async def ws_logger(websocket: WebSocket, project_id: str):
    token = websocket.query_params.get("token")
    try:
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        _ = verify_token(token)
        await websocket.accept()
        await websocket.send_json({"type": "connected", "message": "Logger stream connected", "project_id": project_id})
        while True:
            _ = await websocket.receive_text()
            entry = {"method": "GET", "url": "https://example.com/ping", "status": 200, "time": datetime.utcnow().isoformat()}
            await websocket.send_json({
                "type": "log",
                "entry": entry,
            })
            # Persist to DB (best-effort)
            try:
                from app.core.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    await DASTLogEntry.create(
                        db,
                        project_id=project_id,
                        method=entry.get("method"),
                        url=entry.get("url"),
                        status=entry.get("status"),
                        details=entry,
                    )
            except Exception:
                pass
    except WebSocketDisconnect:
        pass


# -------------------------------
# 12. Settings
# -------------------------------

@router.get("/{project_id}/settings", response_model=SettingsResponse)
async def get_settings(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    proj = await DASTProject.get_by_id(db, project_id)
    scope = (proj.scope_config if proj else None) or {"include": ["example.com"], "exclude": ["/admin"], "ports": [], "filetypes": []}
    return {
        "project": {"scope": scope, "scan_defaults": {"speed": "normal"}},
        "user": {"theme": "dark", "shortcuts": {}, "globals": {}},
    }


@router.put("/{project_id}/settings", response_model=UpdateSettingsResponse)
async def update_settings(project_id: str, settings: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # Persist scope into project.scope_config if provided
    try:
        proj = await DASTProject.get_by_id(db, project_id)
        if proj is not None:
            scope = ((settings or {}).get("project") or {}).get("scope")
            if scope is not None:
                proj.scope_config = scope
                await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass
    return {"status": "updated", "project_id": project_id, "settings": settings}


# -------------------------------
# 12b. HTTPS Interception (CA Management)
# -------------------------------

@router.get("/{project_id}/proxy/ca")
async def get_ca_config(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    cfg = await DASTCAConfig.get_by_project(db, project_id)
    return {
        "enabled": bool(cfg.enabled) if cfg else False,
        "has_cert": bool((cfg and cfg.ca_cert_pem)),
        "has_key": bool((cfg and cfg.ca_key_pem)),
    }


@router.post("/{project_id}/proxy/ca")
async def upsert_ca_config(
    project_id: str,
    payload: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    ca_cert_pem = payload.get("ca_cert_pem")
    ca_key_pem = payload.get("ca_key_pem")
    enabled = bool(payload.get("enabled", False))
    cfg = await DASTCAConfig.upsert(db, project_id=project_id, ca_cert_pem=ca_cert_pem, ca_key_pem=ca_key_pem, enabled=enabled)
    return {"status": "saved", "enabled": cfg.enabled}


@router.get("/{project_id}/proxy/ca/cert")
async def download_ca_cert(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    cfg = await DASTCAConfig.get_by_project(db, project_id)
    if not cfg or not cfg.ca_cert_pem:
        raise HTTPException(status_code=404, detail="No CA certificate configured")
    # Return raw PEM
    return StreamingResponse(iter([cfg.ca_cert_pem]), media_type="text/plain")


# -------------------------------
# 14. Audit Trail & Locks
# -------------------------------

@router.get("/{project_id}/audit", response_model=AuditEventsResponse)
async def list_audit_events(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    rows = (await db.execute(select(DASTAuditEvent).where(DASTAuditEvent.project_id == project_id).order_by(DASTAuditEvent.created_at.desc()).limit(200))).scalars().all()
    return {"events": [
        {
            "id": str(r.id),
            "project_id": str(r.project_id),
            "user_id": r.user_id,
            "action": r.action,
            "object_type": r.object_type,
            "object_id": r.object_id,
            "metadata": r.audit_metadata,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows
    ]}


@router.post("/{project_id}/locks", response_model=LocksResponse)
async def acquire_lock(project_id: str, body: AcquireLockRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    lock = await DASTLock.acquire(db, project_id=project_id, resource_type=body.resource_type, resource_id=body.resource_id, user_id=current_user.id)
    locks = await DASTLock.list_for_resource(db, project_id=project_id, resource_type=body.resource_type, resource_id=body.resource_id)
    return {"locks": [{
        "id": str(l.id), "project_id": str(l.project_id), "resource_type": l.resource_type, "resource_id": l.resource_id,
        "user_id": l.user_id, "created_at": l.created_at.isoformat() if l.created_at else None, "expires_at": l.expires_at.isoformat() if l.expires_at else None
    } for l in locks]}


@router.delete("/{project_id}/locks/{lock_id}")
async def release_lock(project_id: str, lock_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    ok = await DASTLock.release(db, lock_id=lock_id, project_id=project_id)
    return {"status": "released" if ok else "not_found"}


# -------------------------------
# 13. Membership Management
# -------------------------------

@router.get("/{project_id}/members")
async def list_members(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    # simple fetch
    from sqlalchemy.future import select
    rows = (await db.execute(select(DASTProjectMember).where(DASTProjectMember.project_id == project_id))).scalars().all()
    return {
        "members": [
            {"user_id": r.user_id, "role": r.role, "created_at": r.created_at.isoformat() if r.created_at else None}
            for r in rows
        ]
    }

@router.post("/{project_id}/members")
async def add_member(
    project_id: str,
    body: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_role(current_user, ["admin", "analyst"])  # restrict who can add
    await _require_project_access(db, project_id, current_user)
    user_id = int(body.get("user_id"))
    role = body.get("role", "member")
    await DASTProjectMember.add_member(db, project_id=project_id, user_id=user_id, role=role)
    return {"status": "added"}


@router.put("/{project_id}/members/{user_id}")
async def update_member(
    project_id: str,
    user_id: int,
    body: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_role(current_user, ["admin", "analyst"])  # restrict who can update
    await _require_project_access(db, project_id, current_user)
    new_role = body.get("role")
    if not new_role:
        raise HTTPException(status_code=400, detail="role is required")
    row = (await db.execute(select(DASTProjectMember).where(DASTProjectMember.project_id == project_id, DASTProjectMember.user_id == user_id))).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Member not found")
    row.role = new_role
    await db.commit()
    return {"status": "updated"}


@router.delete("/{project_id}/members/{user_id}")
async def remove_member(
    project_id: str,
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_role(current_user, ["admin", "analyst"])  # restrict who can remove
    await _require_project_access(db, project_id, current_user)
    # Simple delete
    row = (await db.execute(select(DASTProjectMember).where(DASTProjectMember.project_id == project_id, DASTProjectMember.user_id == user_id))).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(row)
    await db.commit()
    return {"status": "removed"}


# -------- Ingest Token Management --------

@router.post("/{project_id}/ingest-tokens", response_model=DASTIngestToken)
async def create_ingest_token(
    project_id: str,
    request: DASTIngestTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new ingest token for the project."""
    await _require_project_access(db, project_id, current_user.id)
    
    token = await DASTIngestToken.create_for_project(
        db, 
        project_id=project_id, 
        name=request.name, 
        expires_in_days=request.expires_in_days
    )
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="create_ingest_token", 
        object_type="ingest_token", 
        object_id=str(token.id)
    )
    
    return token


@router.get("/{project_id}/ingest-tokens", response_model=List[DASTIngestToken])
async def list_ingest_tokens(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all ingest tokens for the project."""
    await _require_project_access(db, project_id, current_user.id)
    
    result = await db.execute(
        select(DASTIngestToken).where(DASTIngestToken.project_id == project_id)
    )
    return result.scalars().all()


# -------- Match/Replace Rules --------

@router.post("/{project_id}/match-replace-rules", response_model=DASTMatchReplaceRule)
async def create_match_replace_rule(
    project_id: str,
    request: DASTMatchReplaceRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new match/replace rule."""
    await _require_project_access(db, project_id, current_user.id)
    
    rule = DASTMatchReplaceRule(
        project_id=project_id,
        name=request.name,
        description=request.description,
        enabled=request.enabled,
        order_index=request.order_index,
        match_type=request.match_type,
        match_pattern=request.match_pattern,
        match_case_sensitive=request.match_case_sensitive,
        replace_type=request.replace_type,
        replace_pattern=request.replace_pattern,
        replace_value=request.replace_value
    )
    
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="create_match_replace_rule", 
        object_type="match_replace_rule", 
        object_id=str(rule.id)
    )
    
    return rule


@router.get("/{project_id}/match-replace-rules", response_model=List[DASTMatchReplaceRule])
async def list_match_replace_rules(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all match/replace rules for the project."""
    await _require_project_access(db, project_id, current_user.id)
    
    return await DASTMatchReplaceRule.get_active_rules(db, project_id=project_id)


@router.put("/{project_id}/match-replace-rules/{rule_id}", response_model=DASTMatchReplaceRule)
async def update_match_replace_rule(
    project_id: str,
    rule_id: str,
    request: DASTMatchReplaceRuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a match/replace rule."""
    await _require_project_access(db, project_id, current_user.id)
    
    result = await db.execute(
        select(DASTMatchReplaceRule).where(
            DASTMatchReplaceRule.id == rule_id,
            DASTMatchReplaceRule.project_id == project_id
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    # Update fields
    for field, value in request.dict(exclude_unset=True).items():
        setattr(rule, field, value)
    
    await db.commit()
    await db.refresh(rule)
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="update_match_replace_rule", 
        object_type="match_replace_rule", 
        object_id=str(rule.id)
    )
    
    return rule


@router.delete("/{project_id}/match-replace-rules/{rule_id}")
async def delete_match_replace_rule(
    project_id: str,
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a match/replace rule."""
    await _require_project_access(db, project_id, current_user.id)
    
    result = await db.execute(
        select(DASTMatchReplaceRule).where(
            DASTMatchReplaceRule.id == rule_id,
            DASTMatchReplaceRule.project_id == project_id
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    await db.delete(rule)
    await db.commit()
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="delete_match_replace_rule", 
        object_type="match_replace_rule", 
        object_id=str(rule.id)
    )
    
    return {"status": "deleted"}


# -------- Enhanced Scanner Engine --------

@router.post("/{project_id}/scanner/start")
async def start_scanner(
    project_id: str,
    request: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a new vulnerability scan."""
    await _require_project_access(db, project_id, current_user.id)
    
    target_urls = request.get("target_urls", [])
    scan_config = request.get("scan_config", {})
    
    if not target_urls:
        raise HTTPException(status_code=400, detail="No target URLs provided")
    
    scan_id = await scanner_engine.start_scan(project_id, target_urls, scan_config)
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="start_scanner", 
        object_type="scan", 
        object_id=scan_id
    )
    
    return {"scan_id": scan_id, "status": "started"}


@router.post("/{project_id}/scanner/{scan_id}/stop")
async def stop_scanner(
    project_id: str,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop a running scan."""
    await _require_project_access(db, project_id, current_user.id)
    
    success = await scanner_engine.stop_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="stop_scanner", 
        object_type="scan", 
        object_id=scan_id
    )
    
    return {"status": "stopped"}


@router.get("/{project_id}/scanner/{scan_id}/status")
async def get_scanner_status(
    project_id: str,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan status and progress."""
    await _require_project_access(db, project_id, current_user.id)
    
    status = await scanner_engine.get_scan_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return status


@router.get("/{project_id}/scanner/{scan_id}/issues")
async def get_scan_issues(
    project_id: str,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all issues from a scan."""
    await _require_project_access(db, project_id, current_user.id)
    
    issues = await scanner_engine.get_scan_issues(scan_id)
    return {"issues": [issue.__dict__ for issue in issues]}


@router.get("/{project_id}/scanner/issues")
async def get_all_scanner_issues(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all issues from all scans in the project."""
    await _require_project_access(db, project_id, current_user.id)
    
    issues = await scanner_engine.get_all_issues(project_id)
    return {"issues": [issue.__dict__ for issue in issues]}


# -------- Crawler Engine --------

@router.post("/{project_id}/crawler/start")
async def start_crawler(
    project_id: str,
    request: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a new web crawl."""
    await _require_project_access(db, project_id, current_user.id)
    
    start_url = request.get("start_url")
    scope_config = request.get("scope_config", {})
    crawl_config = request.get("crawl_config", {})
    
    if not start_url:
        raise HTTPException(status_code=400, detail="Start URL required")
    
    crawl_id = await crawler_engine.start_crawl(project_id, start_url, scope_config, crawl_config)
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="start_crawler", 
        object_type="crawl", 
        object_id=crawl_id
    )
    
    return {"crawl_id": crawl_id, "status": "started"}


@router.post("/{project_id}/crawler/{crawl_id}/stop")
async def stop_crawler(
    project_id: str,
    crawl_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop a running crawl."""
    await _require_project_access(db, project_id, current_user.id)
    
    success = await crawler_engine.stop_crawl(crawl_id)
    if not success:
        raise HTTPException(status_code=404, detail="Crawl not found")
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="stop_crawler", 
        object_type="crawl", 
        object_id=crawl_id
    )
    
    return {"status": "stopped"}


@router.get("/{project_id}/crawler/{crawl_id}/status")
async def get_crawler_status(
    project_id: str,
    crawl_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get crawl status and progress."""
    await _require_project_access(db, project_id, current_user.id)
    
    status = await crawler_engine.get_crawl_status(crawl_id)
    if not status:
        raise HTTPException(status_code=404, detail="Crawl not found")
    
    return status


@router.get("/{project_id}/crawler/{crawl_id}/results")
async def get_crawl_results(
    project_id: str,
    crawl_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all results from a crawl."""
    await _require_project_access(db, project_id, current_user.id)
    
    results = await crawler_engine.get_crawl_results(crawl_id)
    return {"results": [result.__dict__ for result in results]}


@router.get("/{project_id}/crawler/results")
async def get_all_crawler_results(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all results from all crawls in the project."""
    await _require_project_access(db, project_id, current_user.id)
    
    results = await crawler_engine.get_all_results(project_id)
    return {"results": [result.__dict__ for result in results]}


# -------- Enhanced Proxy Engine --------

@router.post("/{project_id}/proxy/engine/start")
async def start_proxy_engine(
    project_id: str,
    request: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start the proxy engine with ingest token authentication."""
    await _require_project_access(db, project_id, current_user.id)
    
    # Get or create ingest token
    result = await db.execute(
        select(DASTIngestToken).where(
            DASTIngestToken.project_id == project_id,
            DASTIngestToken.name == "Proxy Engine"
        )
    )
    ingest_token = result.scalar_one_or_none()
    
    if not ingest_token:
        ingest_token = await DASTIngestToken.create_for_project(
            db, project_id=project_id, name="Proxy Engine"
        )
    
    # Start proxy engine
    listen_host = request.get("listen_host", "127.0.0.1")
    listen_port = request.get("listen_port", 8080)
    
    proxy_engine_manager.start(
        project_id=project_id,
        api_base=request.get("api_base", "http://localhost:8000"),
        ingest_token=ingest_token.token,
        listen_host=listen_host,
        listen_port=listen_port
    )
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="start_proxy_engine", 
        object_type="proxy_engine", 
        metadata={"host": listen_host, "port": listen_port}
    )
    
    return {"status": "started", "ingest_token": ingest_token.token}


@router.post("/{project_id}/proxy/engine/stop")
async def stop_proxy_engine(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop the proxy engine."""
    await _require_project_access(db, project_id, current_user.id)
    
    proxy_engine_manager.stop(project_id=project_id)
    
    await DASTAuditEvent.log(
        db, 
        project_id=project_id, 
        user_id=current_user.id, 
        action="stop_proxy_engine", 
        object_type="proxy_engine"
    )
    
    return {"status": "stopped"}


@router.get("/{project_id}/proxy/engine/status")
async def get_proxy_engine_status(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get proxy engine status."""
    await _require_project_access(db, project_id, current_user.id)
    
    is_running = proxy_engine_manager.is_running(project_id)
    ingest_token = proxy_engine_manager.get_ingest_token(project_id)
    
    return {
        "running": is_running,
        "has_ingest_token": bool(ingest_token),
        "ingest_token": ingest_token if ingest_token else None
    }


# -------- Enhanced Ingest Endpoints --------

@router.post("/{project_id}/proxy/ingest/flow")
async def ingest_proxy_flow(
    project_id: str,
    payload: dict,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Ingest HTTP flow from proxy engine with token authentication."""
    # Validate ingest token
    ingest_token = request.headers.get("X-Ingest-Token")
    if not ingest_token:
        raise HTTPException(status_code=401, detail="Missing ingest token")
    
    token = await DASTIngestToken.validate(db, token=ingest_token, project_id=project_id)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid ingest token")
    
    # Process flow with match/replace rules
    req = payload.get("request", {})
    resp = payload.get("response", {})
    corr = payload.get("correlation_id")
    
    # Apply match/replace rules
    rules = await DASTMatchReplaceRule.get_active_rules(db, project_id=project_id)
    
    # Apply request rules
    for rule in rules:
        if rule.match_type in ['url', 'header', 'body']:
            req = rule.apply_to_request(req)
    
    # Apply response rules
    for rule in rules:
        if rule.match_type == 'response':
            resp = rule.apply_to_response(resp)
    
    # Save entry
    entry = await DASTProxyEntry.create(
        db, 
        project_id=project_id, 
        method=req.get("method", "GET"), 
        url=req.get("url", ""), 
        status=resp.get("status"), 
        size=(len((resp.get("body") or "")) or 0), 
        time=datetime.utcnow().isoformat(), 
        request=req, 
        response=resp
    )
    
    # Save correlation
    if corr:
        try:
            await DASTProxyCorrelation.upsert(db, project_id=project_id, correlation_id=corr, entry_id=str(entry.id))
        except Exception:
            pass
    
    # Passive scanning
    await _run_passive_scanning(db, project_id, req, resp)
    
    # Update target nodes
    await DASTTargetNode.ensure_url_nodes(db, project_id=project_id, url=req.get("url", ""))
    
    return {"status": "ok", "entry_id": str(entry.id)}


async def _run_passive_scanning(db: AsyncSession, project_id: str, request: Dict, response: Dict):
    """Run passive scanning on ingested traffic."""
    try:
        # Check for missing security headers
        security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
        missing_headers = [h for h in security_headers if h not in response.get('headers', {})]
        
        if missing_headers:
            await DASTLogEntry.create(
                db,
                project_id=project_id,
                method=request.get('method'),
                url=request.get('url', ''),
                status=response.get('status'),
                details={
                    "type": "security_header_missing",
                    "missing_headers": missing_headers,
                    "severity": "medium"
                }
            )
        
        # Check for sensitive information exposure
        body = response.get('body', '')
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'api_key["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'secret["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'<input[^>]*type=["\']password["\'][^>]*>'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                await DASTLogEntry.create(
                    db,
                    project_id=project_id,
                    method=request.get('method'),
                    url=request.get('url', ''),
                    status=response.get('status'),
                    details={
                        "type": "sensitive_info_exposure",
                        "pattern": pattern,
                        "severity": "high"
                    }
                )
                break
    
    except Exception as e:
        logging.error(f"Passive scanning error: {e}")

