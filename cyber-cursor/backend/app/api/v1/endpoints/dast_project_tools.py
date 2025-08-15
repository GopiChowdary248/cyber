from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.responses import StreamingResponse
from typing import Any, Dict, List, Optional
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.database import get_db
from app.core.security import get_current_user, verify_token
from app.models.dast_tools import DASTProxyEntry, DASTLogEntry, DASTTargetNode, DASTRepeaterEntry, DASTProjectMember
from app.models.user import User
from app.models.project import Project
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
)

router = APIRouter()


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
    # Stubbed activity payload
    now = datetime.utcnow().isoformat()
    return {
        "active_tasks": [
            {"id": "task-1", "name": "Crawl", "progress": 42, "status": "running", "updated_at": now},
            {"id": "task-2", "name": "Scan", "progress": 18, "status": "queued", "updated_at": now},
        ],
        "completed_tasks": [
            {"id": "task-0", "name": "Passive analysis", "progress": 100, "status": "completed", "updated_at": now}
        ],
    }


@router.get("/{project_id}/dashboard/issues", response_model=IssueSummaryResponse)
async def get_dashboard_issues(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Stubbed vulnerability counts
    return {"high": 3, "medium": 7, "low": 11}


@router.get("/{project_id}/dashboard/events", response_model=DashboardEventsResponse)
async def get_dashboard_events(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
):
    now = datetime.utcnow().isoformat()
    return {
        "events": [
            {"id": "evt-1", "type": "info", "message": "Project opened", "timestamp": now},
            {"id": "evt-2", "type": "scan", "message": "Scan queued", "timestamp": now},
        ][:limit]
    }


@router.websocket("/ws/{project_id}/dashboard")
async def ws_dashboard(websocket: WebSocket, project_id: str):
    token = websocket.query_params.get("token")
    try:
        if not token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        _ = verify_token(token)
        await websocket.accept()
        await websocket.send_json({
            "type": "hello",
            "project_id": project_id,
            "message": "Dashboard stream connected",
            "timestamp": datetime.utcnow().isoformat(),
        })
        while True:
            # Keepalive/echo loop
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
            "metadata": n.metadata,
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
async def get_http_history(project_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    entries = await DASTProxyEntry.get_latest_by_project(db, project_id, limit=200)
    return {"entries": [
        {
            "id": str(e.id),
            "method": e.method,
            "url": e.url,
            "status": e.status,
            "size": e.size,
            "time": e.time.isoformat() if getattr(e, 'time', None) and hasattr(getattr(e, 'time'), 'isoformat') else None,
        }
        for e in entries
    ]}


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


@router.post("/{project_id}/proxy/intercept/toggle")
async def toggle_intercept(project_id: str, enabled: bool = Query(True), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "ok", "project_id": project_id, "intercept_enabled": enabled}


@router.put("/{project_id}/proxy/settings")
async def update_proxy_settings(project_id: str, settings: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "saved", "project_id": project_id, "settings": settings}


@router.post("/{project_id}/proxy/intercept/forward")
async def proxy_intercept_forward(project_id: str, payload: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # Accept optional modified request
    req = payload.get("request", {}) or {}
    method = req.get("method", "GET")
    url = req.get("url", "")
    headers = req.get("headers", {})
    body = req.get("body")
    # Simulate execution and persist to history
    try:
        entry = await DASTProxyEntry.create(
            db,
            project_id=project_id,
            method=method,
            url=url,
            status=200,
            size=len((body or "").encode("utf-8")) if isinstance(body, str) else 0,
            time=datetime.utcnow().isoformat(),
            request={"method": method, "url": url, "headers": headers, "body": body},
            response={"status": 200, "headers": {"Content-Type": "text/plain"}, "body": "OK"},
        )
        return {"status": "forwarded", "entry_id": payload.get("entry_id"), "history_id": str(entry.id)}
    except Exception:
        return {"status": "forwarded", "entry_id": payload.get("entry_id")}


@router.post("/{project_id}/proxy/intercept/drop")
async def proxy_intercept_drop(project_id: str, payload: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin", "analyst"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    # In a full implementation, this would drop the request from the intercept queue
    return {"status": "dropped", "entry_id": payload.get("entry_id")}


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
            sample_request = {"method": "GET", "url": "https://example.com/", "headers": {"User-Agent": "CyberShield"}, "body": ""}

            await websocket.send_json({
                "type": "intercepted",
                "request": sample_request,
                "timestamp": datetime.utcnow().isoformat(),
            })
            # Persist to DB (best-effort, ignore failures)
            try:
                from app.core.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    await DASTProxyEntry.create(
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
            except Exception:
                pass
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
    return {"scan_id": "scan-1", "status": "started"}


@router.get("/{project_id}/scanner/status/{scan_id}", response_model=ScannerStatusResponse)
async def scanner_status(project_id: str, scan_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    return {"scan_id": scan_id, "status": "running", "progress": 21}


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
    return {"scan_id": scan_id, "status": "stopped"}


# -------------------------------
# 11. Logger
# -------------------------------

@router.get("/{project_id}/logger/entries", response_model=LoggerEntriesResponse)
async def logger_entries(project_id: str, current_user: User = Depends(get_current_user), q: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    await _require_project_access(db, project_id, current_user)
    rows = await DASTLogEntry.get_latest_by_project(db, project_id, limit=500, q=q)
    return {"entries": [
        {"id": str(r.id), "method": r.method, "url": r.url, "status": r.status}
        for r in rows
    ]}


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
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/{project_id}/logger/export")
async def logger_export(
    project_id: str,
    format: str = Query("csv"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_project_access(db, project_id, current_user)
    rows = await DASTLogEntry.get_latest_by_project(db, project_id, limit=500)
    if format == "csv":
        def generate():
            yield "id,method,url,status,created_at\n"
            for r in rows:
                created = r.created_at.isoformat() if r.created_at else ""
                # naive CSV escaping
                url = (r.url or '').replace('"', '""')
                yield f"{r.id},{r.method or ''},\"{url}\",{r.status or ''},{created}\n"
        return StreamingResponse(generate(), media_type="text/csv")
    # default JSON
    return {"entries": [
        {"id": str(r.id), "method": r.method, "url": r.url, "status": r.status, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]}


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
    return {
        "project": {"scope": {"include": ["example.com"], "exclude": ["/admin"]}, "scan_defaults": {"speed": "normal"}},
        "user": {"theme": "dark", "shortcuts": {}, "globals": {}},
    }


@router.put("/{project_id}/settings", response_model=UpdateSettingsResponse)
async def update_settings(project_id: str, settings: Dict[str, Any], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _require_role(current_user, ["admin"])  # RBAC
    await _require_project_access(db, project_id, current_user)
    return {"status": "updated", "project_id": project_id, "settings": settings}


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

