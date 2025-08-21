from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import json
import asyncio
from datetime import datetime, timedelta

from ....database import get_db
from ....models.dast_models import (
    DASTProject, DASTScan, DASTScanIssue, DASTHttpEntry, 
    DASTCrawlResult, DASTMatchReplaceRule, DASTScanProfile,
    DASTIntruderAttack, DASTRepeaterRequest
)
from ....schemas.dast_schemas import (
    ScanCreate, ScanUpdate, ScanResponse, IssueResponse,
    HttpHistoryResponse, CrawlResultResponse, RuleCreate,
    RuleUpdate, RuleResponse, ProfileCreate, ProfileResponse,
    IntruderAttackCreate, IntruderAttackResponse,
    RepeaterRequestCreate, RepeaterRequestResponse
)
from ....core.security import get_current_user
from ....services.dast_service import DASTService
from ....core.websocket_manager import WebSocketManager

router = APIRouter(prefix="/dast/projects", tags=["DAST"])

# WebSocket manager for real-time updates
websocket_manager = WebSocketManager()

# DAST Service
dast_service = DASTService()

# ============================================================================
# PROJECT MANAGEMENT
# ============================================================================

@router.get("/{project_id}/status")
async def get_project_status(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get overall DAST project status"""
    try:
        status = await dast_service.get_project_status(db, project_id, current_user.id)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# HTTP HISTORY & TRAFFIC ANALYSIS
# ============================================================================

@router.get("/{project_id}/http-history")
async def get_http_history(
    project_id: str,
    page: int = 1,
    page_size: int = 100,
    method: Optional[str] = None,
    status: Optional[int] = None,
    host: Optional[str] = None,
    url_regex: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get HTTP traffic history with filtering and pagination"""
    try:
        filters = {
            "method": method,
            "status": status,
            "host": host,
            "url_regex": url_regex,
            "start_time": start_time,
            "end_time": end_time
        }
        
        history = await dast_service.get_http_history(
            db, project_id, current_user.id, page, page_size, filters
        )
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/http-history/{entry_id}")
async def get_http_entry_detail(
    project_id: str,
    entry_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get detailed HTTP entry information"""
    try:
        entry = await dast_service.get_http_entry_detail(
            db, project_id, entry_id, current_user.id
        )
        return entry
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/http-history/export")
async def export_http_history(
    project_id: str,
    format: str = "json",
    filters: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Export HTTP history in specified format"""
    try:
        if format not in ["json", "csv", "xml"]:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        export_data = await dast_service.export_http_history(
            db, project_id, current_user.id, format, filters
        )
        
        if format == "json":
            return export_data
        else:
            return StreamingResponse(
                iter([export_data]),
                media_type=f"text/{format}",
                headers={"Content-Disposition": f"attachment; filename=http_history.{format}"}
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# SCANNER & VULNERABILITY SCANNING
# ============================================================================

@router.get("/{project_id}/scanner/profiles")
async def get_scan_profiles(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get available scan profiles"""
    try:
        profiles = await dast_service.get_scan_profiles(db, project_id, current_user.id)
        return profiles
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/scanner/profiles")
async def create_scan_profile(
    project_id: str,
    profile: ProfileCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create new scan profile"""
    try:
        new_profile = await dast_service.create_scan_profile(
            db, project_id, profile, current_user.id
        )
        return new_profile
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/scanner/scans")
async def get_active_scans(
    project_id: str,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get active scans for project"""
    try:
        scans = await dast_service.get_active_scans(
            db, project_id, current_user.id, status
        )
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/scanner/scans")
async def create_scan(
    project_id: str,
    scan: ScanCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create and start new security scan"""
    try:
        new_scan = await dast_service.create_scan(
            db, project_id, scan, current_user.id
        )
        return new_scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/scanner/scans/{scan_id}")
async def get_scan_details(
    project_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get detailed scan information"""
    try:
        scan = await dast_service.get_scan_details(
            db, project_id, scan_id, current_user.id
        )
        return scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/scanner/scans/{scan_id}/start")
async def start_scan(
    project_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Start a scan"""
    try:
        result = await dast_service.start_scan(
            db, project_id, scan_id, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/scanner/scans/{scan_id}/stop")
async def stop_scan(
    project_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Stop a running scan"""
    try:
        result = await dast_service.stop_scan(
            db, project_id, scan_id, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{project_id}/scanner/scans/{scan_id}")
async def delete_scan(
    project_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete a scan"""
    try:
        await dast_service.delete_scan(
            db, project_id, scan_id, current_user.id
        )
        return {"message": "Scan deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/scanner/issues")
async def get_scan_issues(
    project_id: str,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get scan issues with filtering"""
    try:
        filters = {
            "scan_id": scan_id,
            "severity": severity,
            "status": status
        }
        
        issues = await dast_service.get_scan_issues(
            db, project_id, current_user.id, filters, page, page_size
        )
        return issues
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/{project_id}/scanner/issues/{issue_id}")
async def update_issue_status(
    project_id: str,
    issue_id: str,
    status_update: Dict[str, str],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update issue status"""
    try:
        updated_issue = await dast_service.update_issue_status(
            db, project_id, issue_id, status_update, current_user.id
        )
        return updated_issue
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# CRAWLER & SITE MAPPING
# ============================================================================

@router.post("/{project_id}/crawler/start")
async def start_crawler(
    project_id: str,
    crawl_config: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Start web crawler"""
    try:
        result = await dast_service.start_crawler(
            db, project_id, crawl_config, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/crawler/stop")
async def stop_crawler(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Stop web crawler"""
    try:
        result = await dast_service.stop_crawler(
            db, project_id, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/crawler/status")
async def get_crawler_status(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get crawler status"""
    try:
        status = await dast_service.get_crawler_status(
            db, project_id, current_user.id
        )
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/crawler/results")
async def get_crawl_results(
    project_id: str,
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get crawl results"""
    try:
        results = await dast_service.get_crawl_results(
            db, project_id, current_user.id, page, page_size
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# TARGET & SCOPE MANAGEMENT
# ============================================================================

@router.get("/{project_id}/target/sitemap")
async def get_site_map(
    project_id: str,
    view_mode: str = "tree",
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get site map for project"""
    try:
        sitemap = await dast_service.get_site_map(
            db, project_id, current_user.id, view_mode
        )
        return sitemap
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{project_id}/target/scope")
async def update_scope(
    project_id: str,
    scope_config: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update project scope configuration"""
    try:
        updated_scope = await dast_service.update_scope(
            db, project_id, scope_config, current_user.id
        )
        return updated_scope
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# INTRUDER TOOL
# ============================================================================

@router.post("/{project_id}/intruder/start")
async def start_intruder_attack(
    project_id: str,
    attack: IntruderAttackCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Start intruder attack"""
    try:
        result = await dast_service.start_intruder_attack(
            db, project_id, attack, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/intruder/{attack_id}/stop")
async def stop_intruder_attack(
    project_id: str,
    attack_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Stop intruder attack"""
    try:
        result = await dast_service.stop_intruder_attack(
            db, project_id, attack_id, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/intruder/{attack_id}/results")
async def get_intruder_results(
    project_id: str,
    attack_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get intruder attack results"""
    try:
        results = await dast_service.get_intruder_results(
            db, project_id, attack_id, current_user.id
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# REPEATER TOOL
# ============================================================================

@router.post("/{project_id}/repeater/send")
async def send_repeater_request(
    project_id: str,
    request: RepeaterRequestCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Send request via repeater tool"""
    try:
        result = await dast_service.send_repeater_request(
            db, project_id, request, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{project_id}/repeater/history")
async def get_repeater_history(
    project_id: str,
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get repeater request history"""
    try:
        history = await dast_service.get_repeater_history(
            db, project_id, current_user.id, page, page_size
        )
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# MATCH & REPLACE RULES
# ============================================================================

@router.get("/{project_id}/rules")
async def get_match_replace_rules(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get match/replace rules"""
    try:
        rules = await dast_service.get_match_replace_rules(
            db, project_id, current_user.id
        )
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/rules")
async def create_match_replace_rule(
    project_id: str,
    rule: RuleCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create new match/replace rule"""
    try:
        new_rule = await dast_service.create_match_replace_rule(
            db, project_id, rule, current_user.id
        )
        return new_rule
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{project_id}/rules/{rule_id}")
async def update_match_replace_rule(
    project_id: str,
    rule_id: str,
    rule: RuleUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update match/replace rule"""
    try:
        updated_rule = await dast_service.update_match_replace_rule(
            db, project_id, rule_id, rule, current_user.id
        )
        return updated_rule
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{project_id}/rules/{rule_id}")
async def delete_match_replace_rule(
    project_id: str,
    rule_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete match/replace rule"""
    try:
        await dast_service.delete_match_replace_rule(
            db, project_id, rule_id, current_user.id
        )
        return {"message": "Rule deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# PROXY ENGINE
# ============================================================================

@router.get("/{project_id}/proxy/status")
async def get_proxy_status(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get proxy engine status"""
    try:
        status = await dast_service.get_proxy_status(
            db, project_id, current_user.id
        )
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/proxy/start")
async def start_proxy(
    project_id: str,
    config: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Start proxy engine"""
    try:
        result = await dast_service.start_proxy(
            db, project_id, config, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/proxy/stop")
async def stop_proxy(
    project_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Stop proxy engine"""
    try:
        result = await dast_service.stop_proxy(
            db, project_id, current_user.id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# WEBSOCKET ENDPOINTS FOR REAL-TIME UPDATES
# ============================================================================

@router.websocket("/{project_id}/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    project_id: str,
    token: str
):
    """WebSocket endpoint for real-time updates"""
    try:
        # Validate token and get user
        user = await dast_service.validate_websocket_token(token)
        if not user:
            await websocket.close(code=4001, reason="Invalid token")
            return
        
        # Connect to WebSocket manager
        await websocket_manager.connect(websocket, project_id, user.id)
        
        try:
            while True:
                # Send real-time updates
                data = await websocket_manager.get_updates(project_id, user.id)
                if data:
                    await websocket.send_text(json.dumps(data))
                
                await asyncio.sleep(1)  # Update frequency
                
        except WebSocketDisconnect:
            websocket_manager.disconnect(websocket, project_id, user.id)
            
    except Exception as e:
        await websocket.close(code=4000, reason="Internal error")

# ============================================================================
# EXPORT & REPORTING
# ============================================================================

@router.post("/{project_id}/export/scan-results")
async def export_scan_results(
    project_id: str,
    scan_id: str,
    format: str = "json",
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Export scan results"""
    try:
        if format not in ["json", "csv", "xml", "pdf"]:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        export_data = await dast_service.export_scan_results(
            db, project_id, scan_id, format, current_user.id
        )
        
        if format == "json":
            return export_data
        else:
            return StreamingResponse(
                iter([export_data]),
                media_type=f"text/{format}",
                headers={"Content-Disposition": f"attachment; filename=scan_results_{scan_id}.{format}"}
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{project_id}/export/project-report")
async def export_project_report(
    project_id: str,
    format: str = "pdf",
    include_issues: bool = True,
    include_traffic: bool = False,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Export comprehensive project report"""
    try:
        if format not in ["pdf", "html", "docx"]:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        report_data = await dast_service.generate_project_report(
            db, project_id, format, include_issues, include_traffic, current_user.id
        )
        
        return StreamingResponse(
            iter([report_data]),
            media_type=f"application/{format}",
            headers={"Content-Disposition": f"attachment; filename=project_report_{project_id}.{format}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
