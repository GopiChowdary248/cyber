"""
DAST (Dynamic Application Security Testing) Service
Provides comprehensive DAST functionality including:
- Scan orchestration and management
- Project management
- Vulnerability analysis
- Report generation
- CI/CD integration
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from ..models.dast_models import (
    DASTProject, DASTScan, DASTScanIssue, DASTHttpEntry, 
    DASTCrawlResult, DASTMatchReplaceRule, DASTScanProfile,
    DASTIntruderAttack, DASTRepeaterRequest
)
from ..schemas.dast_schemas import (
    ScanCreate, IssueUpdate, ProfileCreate, RuleCreate,
    IntruderAttackCreate, RepeaterRequestCreate
)
from ..core.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)

class DASTService:
    """Service layer for DAST operations"""
    
    def __init__(self):
        self.scan_engines = {}
        self.crawler_engines = {}
        self.proxy_engines = {}
    
    # Project Management
    async def get_project_status(self, db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Get overall project status"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            project = db.query(DASTProject).filter(DASTProject.id == project_id).first()
            if not project:
                raise ValueError("Project not found")
            
            scans = db.query(DASTScan).filter(DASTScan.project_id == project_id).all()
            total_scans = len(scans)
            active_scans = len([s for s in scans if s.status == "running"])
            completed_scans = len([s for s in scans if s.status == "completed"])
            
            issues = db.query(DASTScanIssue).join(DASTScan).filter(DASTScan.project_id == project_id).all()
            total_issues = len(issues)
            issues_by_severity = {}
            for issue in issues:
                severity = issue.severity
                issues_by_severity[severity] = issues_by_severity.get(severity, 0) + 1
            
            return {
                "project_id": project_id,
                "total_scans": total_scans,
                "active_scans": active_scans,
                "completed_scans": completed_scans,
                "total_issues": total_issues,
                "issues_by_severity": issues_by_severity,
                "last_scan_date": None,
                "proxy_status": "stopped",
                "crawler_status": "idle"
            }
        except Exception as e:
            logger.error(f"Error getting project status: {e}")
            raise
    
    # HTTP History
    async def get_http_history(self, db: Session, project_id: str, user_id: str, page: int, page_size: int, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Get HTTP traffic history"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            query = db.query(DASTHttpEntry).filter(DASTHttpEntry.project_id == project_id)
            
            if filters.get("method"):
                query = query.filter(DASTHttpEntry.method == filters["method"])
            if filters.get("status"):
                query = query.filter(DASTHttpEntry.status_code == filters["status"])
            
            total = query.count()
            offset = (page - 1) * page_size
            entries = query.order_by(desc(DASTHttpEntry.timestamp)).offset(offset).limit(page_size).all()
            
            history_entries = []
            for entry in entries:
                history_entries.append({
                    "id": str(entry.id),
                    "method": entry.method,
                    "url": entry.url,
                    "host": entry.host,
                    "status_code": entry.status_code,
                    "timestamp": entry.timestamp,
                    "tags": entry.tags,
                    "highlighted": entry.highlighted
                })
            
            total_pages = (total + page_size - 1) // page_size
            
            return {
                "entries": history_entries,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages
            }
        except Exception as e:
            logger.error(f"Error getting HTTP history: {e}")
            raise
    
    # Scanner
    async def get_scan_profiles(self, db: Session, project_id: str, user_id: str) -> List[Dict[str, Any]]:
        """Get scan profiles"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            profiles = db.query(DASTScanProfile).filter(DASTScanProfile.project_id == project_id).all()
            
            return [
                {
                    "id": str(profile.id),
                    "name": profile.name,
                    "description": profile.description,
                    "modules": profile.modules,
                    "settings": profile.settings,
                    "is_default": profile.is_default
                }
                for profile in profiles
            ]
        except Exception as e:
            logger.error(f"Error getting scan profiles: {e}")
            raise
    
    async def create_scan(self, db: Session, project_id: str, scan_data: ScanCreate, user_id: str) -> Dict[str, Any]:
        """Create scan"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            scan = DASTScan(
                project_id=project_id,
                profile_id=scan_data.profile_id,
                name=scan_data.name,
                target_urls=scan_data.target_urls,
                scan_config=scan_data.scan_config,
                created_by=user_id
            )
            
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            return {
                "id": str(scan.id),
                "name": scan.name,
                "status": scan.status,
                "progress": scan.progress
            }
        except Exception as e:
            logger.error(f"Error creating scan: {e}")
            db.rollback()
            raise
    
    # Crawler
    async def start_crawler(self, db: Session, project_id: str, crawl_config: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Start crawler"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            # Create crawler engine instance
            crawler_id = f"{project_id}_{user_id}"
            if crawler_id not in self.crawler_engines:
                self.crawler_engines[crawler_id] = {
                    "status": "running",
                    "started_at": datetime.utcnow(),
                    "config": crawl_config,
                    "progress": 0.0,
                    "total_urls": 0,
                    "discovered_urls": 0
                }
            
            # Notify WebSocket clients
            await websocket_manager.send_crawler_update(project_id, {
                "status": "running",
                "progress": 0.0,
                "started_at": datetime.utcnow().isoformat()
            })
            
            return {"message": "Crawler started", "status": "running"}
        except Exception as e:
            logger.error(f"Error starting crawler: {e}")
            raise
    
    # Rules
    async def get_match_replace_rules(self, db: Session, project_id: str, user_id: str) -> List[Dict[str, Any]]:
        """Get rules"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            rules = db.query(DASTMatchReplaceRule).filter(
                DASTMatchReplaceRule.project_id == project_id
            ).order_by(DASTMatchReplaceRule.priority).all()
            
            return [
                {
                    "id": str(rule.id),
                    "name": rule.name,
                    "match_pattern": rule.match_pattern,
                    "replace_pattern": rule.replace_pattern,
                    "enabled": rule.enabled
                }
                for rule in rules
            ]
        except Exception as e:
            logger.error(f"Error getting rules: {e}")
            raise
    
    # Intruder
    async def start_intruder_attack(self, db: Session, project_id: str, attack_data: IntruderAttackCreate, user_id: str) -> Dict[str, Any]:
        """Start intruder attack"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            attack = DASTIntruderAttack(
                project_id=project_id,
                name=attack_data.name,
                target_url=attack_data.target_url,
                attack_type=attack_data.attack_type,
                payload_sets=attack_data.payload_sets,
                positions=attack_data.positions,
                created_by=user_id
            )
            
            db.add(attack)
            db.commit()
            db.refresh(attack)
            
            return {
                "id": str(attack.id),
                "name": attack.name,
                "status": attack.status
            }
        except Exception as e:
            logger.error(f"Error starting intruder attack: {e}")
            db.rollback()
            raise
    
    # Repeater
    async def send_repeater_request(self, db: Session, project_id: str, request_data: RepeaterRequestCreate, user_id: str) -> Dict[str, Any]:
        """Send repeater request"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            return {"message": "Request sent", "status": "success"}
        except Exception as e:
            logger.error(f"Error sending repeater request: {e}")
            raise
    
    # Additional Scanner Methods
    async def create_scan_profile(self, db: Session, project_id: str, profile_data: ProfileCreate, user_id: str) -> Dict[str, Any]:
        """Create scan profile"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            profile = DASTScanProfile(
                project_id=project_id,
                name=profile_data.name,
                description=profile_data.description,
                modules=profile_data.modules,
                settings=profile_data.settings,
                is_default=profile_data.is_default,
                created_by=user_id
            )
            
            db.add(profile)
            db.commit()
            db.refresh(profile)
            
            return {
                "id": str(profile.id),
                "name": profile.name,
                "description": profile.description,
                "modules": profile.modules,
                "settings": profile.settings,
                "is_default": profile.is_default
            }
        except Exception as e:
            logger.error(f"Error creating scan profile: {e}")
            db.rollback()
            raise

    async def start_scan(self, db: Session, project_id: str, scan_id: str, user_id: str) -> Dict[str, Any]:
        """Start a scan"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            scan = db.query(DASTScan).filter(DASTScan.id == scan_id).first()
            if not scan:
                raise ValueError("Scan not found")
            
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            scan.progress = 0.0
            
            db.commit()
            
            # Create scan engine instance
            scan_engine_id = f"{scan_id}_{user_id}"
            self.scan_engines[scan_engine_id] = {
                "status": "running",
                "started_at": datetime.utcnow(),
                "progress": 0.0
            }
            
            # Notify WebSocket clients
            await websocket_manager.send_scan_update(project_id, {
                "id": str(scan.id),
                "status": "running",
                "progress": 0.0,
                "started_at": scan.started_at.isoformat()
            })
            
            return {"message": "Scan started", "status": "running"}
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            db.rollback()
            raise

    async def stop_scan(self, db: Session, project_id: str, scan_id: str, user_id: str) -> Dict[str, Any]:
        """Stop a running scan"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            scan = db.query(DASTScan).filter(DASTScan.id == scan_id).first()
            if not scan:
                raise ValueError("Scan not found")
            
            scan.status = "paused"
            scan.progress = scan.progress or 0.0
            
            db.commit()
            
            # Stop scan engine
            scan_engine_id = f"{scan_id}_{user_id}"
            if scan_engine_id in self.scan_engines:
                self.scan_engines[scan_engine_id]["status"] = "paused"
            
            # Notify WebSocket clients
            await websocket_manager.send_scan_update(project_id, {
                "id": str(scan.id),
                "status": "paused",
                "progress": scan.progress
            })
            
            return {"message": "Scan stopped", "status": "paused"}
        except Exception as e:
            logger.error(f"Error stopping scan: {e}")
            db.rollback()
            raise

    async def get_scan_issues(self, db: Session, project_id: str, user_id: str, filters: Dict[str, Any], page: int, page_size: int) -> Dict[str, Any]:
        """Get scan issues with filtering"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            query = db.query(DASTScanIssue).join(DASTScan).filter(DASTScan.project_id == project_id)
            
            if filters.get("scan_id"):
                query = query.filter(DASTScanIssue.scan_id == filters["scan_id"])
            if filters.get("severity"):
                query = query.filter(DASTScanIssue.severity == filters["severity"])
            if filters.get("status"):
                query = query.filter(DASTScanIssue.status == filters["status"])
            
            total = query.count()
            offset = (page - 1) * page_size
            issues = query.order_by(desc(DASTScanIssue.discovered_at)).offset(offset).limit(page_size).all()
            
            return {
                "issues": [
                    {
                        "id": str(issue.id),
                        "type": issue.type,
                        "severity": issue.severity,
                        "title": issue.title,
                        "description": issue.description,
                        "url": issue.url,
                        "status": issue.status,
                        "confidence": issue.confidence,
                        "discovered_at": issue.discovered_at
                    }
                    for issue in issues
                ],
                "total": total,
                "page": page,
                "page_size": page_size
            }
        except Exception as e:
            logger.error(f"Error getting scan issues: {e}")
            raise

    # Additional Crawler Methods
    async def stop_crawler(self, db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Stop web crawler"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            crawler_id = f"{project_id}_{user_id}"
            if crawler_id in self.crawler_engines:
                self.crawler_engines[crawler_id]["status"] = "stopped"
            
            # Notify WebSocket clients
            await websocket_manager.send_crawler_update(project_id, {
                "status": "stopped",
                "progress": 0.0
            })
            
            return {"message": "Crawler stopped", "status": "stopped"}
        except Exception as e:
            logger.error(f"Error stopping crawler: {e}")
            raise

    async def get_crawler_status(self, db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Get crawler status"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            crawler_id = f"{project_id}_{user_id}"
            if crawler_id in self.crawler_engines:
                engine = self.crawler_engines[crawler_id]
                return {
                    "status": engine["status"],
                    "progress": engine["progress"],
                    "started_at": engine["started_at"].isoformat() if engine["started_at"] else None
                }
            
            return {"status": "idle", "progress": 0.0}
        except Exception as e:
            logger.error(f"Error getting crawler status: {e}")
            raise

    async def get_crawl_results(self, db: Session, project_id: str, user_id: str, page: int, page_size: int) -> Dict[str, Any]:
        """Get crawl results"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            query = db.query(DASTCrawlResult).filter(DASTCrawlResult.project_id == project_id)
            total = query.count()
            offset = (page - 1) * page_size
            results = query.order_by(desc(DASTCrawlResult.discovered_at)).offset(offset).limit(page_size).all()
            
            return {
                "results": [
                    {
                        "id": str(result.id),
                        "url": result.url,
                        "method": result.method,
                        "status_code": result.status_code,
                        "depth": result.depth,
                        "in_scope": result.in_scope,
                        "discovered_at": result.discovered_at
                    }
                    for result in results
                ],
                "total": total,
                "page": page,
                "page_size": page_size
            }
        except Exception as e:
            logger.error(f"Error getting crawl results: {e}")
            raise

    # Additional Rules Methods
    async def create_match_replace_rule(self, db: Session, project_id: str, rule_data: RuleCreate, user_id: str) -> Dict[str, Any]:
        """Create new match/replace rule"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            rule = DASTMatchReplaceRule(
                project_id=project_id,
                name=rule_data.name,
                description=rule_data.description,
                match_pattern=rule_data.match_pattern,
                replace_pattern=rule_data.replace_pattern,
                match_type=rule_data.match_type,
                apply_to=rule_data.apply_to,
                enabled=rule_data.enabled,
                priority=rule_data.priority,
                created_by=user_id
            )
            
            db.add(rule)
            db.commit()
            db.refresh(rule)
            
            return {
                "id": str(rule.id),
                "name": rule.name,
                "description": rule.description,
                "match_pattern": rule.match_pattern,
                "replace_pattern": rule.replace_pattern,
                "match_type": rule.match_type,
                "apply_to": rule.apply_to,
                "enabled": rule.enabled,
                "priority": rule.priority
            }
        except Exception as e:
            logger.error(f"Error creating rule: {e}")
            db.rollback()
            raise

    async def update_match_replace_rule(self, db: Session, project_id: str, rule_id: str, rule_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Update match/replace rule"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            rule = db.query(DASTMatchReplaceRule).filter(
                DASTMatchReplaceRule.id == rule_id,
                DASTMatchReplaceRule.project_id == project_id
            ).first()
            
            if not rule:
                raise ValueError("Rule not found")
            
            for field, value in rule_data.items():
                if hasattr(rule, field):
                    setattr(rule, field, value)
            
            db.commit()
            db.refresh(rule)
            
            return {
                "id": str(rule.id),
                "name": rule.name,
                "enabled": rule.enabled,
                "priority": rule.priority
            }
        except Exception as e:
            logger.error(f"Error updating rule: {e}")
            db.rollback()
            raise

    async def delete_match_replace_rule(self, db: Session, project_id: str, rule_id: str, user_id: str) -> bool:
        """Delete match/replace rule"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            rule = db.query(DASTMatchReplaceRule).filter(
                DASTMatchReplaceRule.id == rule_id,
                DASTMatchReplaceRule.project_id == project_id
            ).first()
            
            if not rule:
                raise ValueError("Rule not found")
            
            db.delete(rule)
            db.commit()
            
            return True
        except Exception as e:
            logger.error(f"Error deleting rule: {e}")
            db.rollback()
            raise

    # Additional Intruder Methods
    async def stop_intruder_attack(self, db: Session, project_id: str, attack_id: str, user_id: str) -> Dict[str, Any]:
        """Stop intruder attack"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            attack = db.query(DASTIntruderAttack).filter(
                DASTIntruderAttack.id == attack_id,
                DASTIntruderAttack.project_id == project_id
            ).first()
            
            if not attack:
                raise ValueError("Attack not found")
            
            attack.status = "stopped"
            attack.completed_at = datetime.utcnow()
            
            db.commit()
            
            return {"message": "Attack stopped", "status": "stopped"}
        except Exception as e:
            logger.error(f"Error stopping intruder attack: {e}")
            db.rollback()
            raise

    async def get_intruder_results(self, db: Session, project_id: str, attack_id: str, user_id: str) -> List[Dict[str, Any]]:
        """Get intruder attack results"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            # This would typically query DASTIntruderResult table
            # For now, return mock data
            return [
                {
                    "id": "mock_result_id",
                    "payload": "test_payload",
                    "status_code": 200,
                    "response_time": 150,
                    "highlighted": False
                }
            ]
        except Exception as e:
            logger.error(f"Error getting intruder results: {e}")
            raise

    # Additional Repeater Methods
    async def get_repeater_history(self, db: Session, project_id: str, user_id: str, page: int, page_size: int) -> Dict[str, Any]:
        """Get repeater request history"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            query = db.query(DASTRepeaterRequest).filter(DASTRepeaterRequest.project_id == project_id)
            total = query.count()
            offset = (page - 1) * page_size
            requests = query.order_by(desc(DASTRepeaterRequest.created_at)).offset(offset).limit(page_size).all()
            
            return {
                "requests": [
                    {
                        "id": str(req.id),
                        "name": req.name,
                        "method": req.method,
                        "url": req.url,
                        "created_at": req.created_at
                    }
                    for req in requests
                ],
                "total": total,
                "page": page,
                "page_size": page_size
            }
        except Exception as e:
            logger.error(f"Error getting repeater history: {e}")
            raise

    # Additional HTTP History Methods
    async def get_http_entry_detail(self, db: Session, project_id: str, entry_id: str, user_id: str) -> Dict[str, Any]:
        """Get detailed HTTP entry information"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            entry = db.query(DASTHttpEntry).filter(
                DASTHttpEntry.id == entry_id,
                DASTHttpEntry.project_id == project_id
            ).first()
            
            if not entry:
                raise ValueError("HTTP entry not found")
            
            return {
                "id": str(entry.id),
                "method": entry.method,
                "url": entry.url,
                "host": entry.host,
                "port": entry.port,
                "protocol": entry.protocol,
                "request_headers": entry.request_headers,
                "request_body": entry.request_body,
                "response_headers": entry.response_headers,
                "response_body": entry.response_body,
                "status_code": entry.status_code,
                "duration": entry.duration,
                "timestamp": entry.timestamp
            }
        except Exception as e:
            logger.error(f"Error getting HTTP entry detail: {e}")
            raise

    # Additional Target/Site Map Methods
    async def get_site_map(self, db: Session, project_id: str, user_id: str, view_mode: str = "tree") -> Dict[str, Any]:
        """Get site map for project"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            results = db.query(DASTCrawlResult).filter(DASTCrawlResult.project_id == project_id).all()
            
            # Build tree structure
            nodes = []
            for result in results:
                nodes.append({
                    "url": result.url,
                    "method": result.method,
                    "status_code": result.status_code,
                    "depth": result.depth,
                    "in_scope": result.in_scope,
                    "children": []
                })
            
            return {
                "nodes": nodes,
                "total_nodes": len(nodes),
                "in_scope_nodes": len([n for n in nodes if n["in_scope"]]),
                "out_of_scope_nodes": len([n for n in nodes if not n["in_scope"]]),
                "view_mode": view_mode
            }
        except Exception as e:
            logger.error(f"Error getting site map: {e}")
            raise

    async def update_scope(self, db: Session, project_id: str, scope_config: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Update project scope configuration"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            project = db.query(DASTProject).filter(DASTProject.id == project_id).first()
            if not project:
                raise ValueError("Project not found")
            
            project.scope_config = scope_config
            db.commit()
            
            return {"message": "Scope updated successfully", "scope_config": scope_config}
        except Exception as e:
            logger.error(f"Error updating scope: {e}")
            db.rollback()
            raise

    # Additional Proxy Methods
    async def get_proxy_status(self, db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Get proxy engine status"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            proxy_id = f"{project_id}_{user_id}"
            if proxy_id in self.proxy_engines:
                engine = self.proxy_engines[proxy_id]
                return {
                    "status": engine["status"],
                    "host": engine.get("host", "127.0.0.1"),
                    "port": engine.get("port", 8080),
                    "started_at": engine["started_at"].isoformat() if engine.get("started_at") else None
                }
            
            return {"status": "stopped", "host": "127.0.0.1", "port": 8080}
        except Exception as e:
            logger.error(f"Error getting proxy status: {e}")
            raise

    async def start_proxy(self, db: Session, project_id: str, config: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Start proxy engine"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            proxy_id = f"{project_id}_{user_id}"
            self.proxy_engines[proxy_id] = {
                "status": "running",
                "host": config.get("host", "127.0.0.1"),
                "port": config.get("port", 8080),
                "started_at": datetime.utcnow()
            }
            
            return {"message": "Proxy started", "status": "running"}
        except Exception as e:
            logger.error(f"Error starting proxy: {e}")
            raise

    async def stop_proxy(self, db: Session, project_id: str, user_id: str) -> Dict[str, Any]:
        """Stop proxy engine"""
        try:
            if not await self._verify_project_access(db, project_id, user_id):
                raise ValueError("Access denied to project")
            
            proxy_id = f"{project_id}_{user_id}"
            if proxy_id in self.proxy_engines:
                self.proxy_engines[proxy_id]["status"] = "stopped"
            
            return {"message": "Proxy stopped", "status": "stopped"}
        except Exception as e:
            logger.error(f"Error stopping proxy: {e}")
            raise

    # Utility methods
    async def _verify_project_access(self, db: Session, project_id: str, user_id: str, required_role: str = "user") -> bool:
        """Verify user access to project"""
        try:
            project = db.query(DASTProject).filter(
                DASTProject.id == project_id,
                DASTProject.created_by == user_id
            ).first()
            
            if project:
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error verifying project access: {e}")
            return False
    
    async def validate_websocket_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate WebSocket token"""
        try:
            # In a real implementation, this would validate JWT tokens
            # For now, return mock data
            return {"id": "mock_user_id", "username": "mock_user"}
        except Exception as e:
            logger.error(f"Error validating WebSocket token: {e}")
            return None 