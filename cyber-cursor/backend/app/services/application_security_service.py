"""
Application Security Service
Provides comprehensive application security testing and protection including:
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- SCA (Software Composition Analysis)
- WAF (Web Application Firewall)
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import structlog

logger = structlog.get_logger()

class ScanType(Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    WAF = "waf"

class ScanStatus(Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class WAFRuleAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"
    LOG = "log"

@dataclass
class Vulnerability:
    id: str
    scan_id: str
    scan_type: ScanType
    title: str
    description: str
    severity: VulnerabilitySeverity
    cve_id: Optional[str]
    cvss_score: Optional[float]
    file_path: Optional[str]
    line_number: Optional[int]
    component_name: Optional[str]
    component_version: Optional[str]
    remediation: str
    discovered_at: datetime
    status: str
    false_positive: bool = False

@dataclass
class SASTScan:
    id: str
    project_name: str
    repository_url: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    files_scanned: int
    vulnerabilities_found: int
    scan_duration: int
    engine_version: str

@dataclass
class DASTScan:
    id: str
    target_url: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    pages_scanned: int
    vulnerabilities_found: int
    scan_duration: int
    engine_version: str

@dataclass
class SCAScan:
    id: str
    project_name: str
    manifest_files: List[str]
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    dependencies_scanned: int
    vulnerabilities_found: int
    scan_duration: int
    engine_version: str

@dataclass
class WAFRule:
    id: str
    name: str
    description: str
    action: WAFRuleAction
    conditions: Dict[str, Any]
    priority: int
    enabled: bool
    created_at: datetime
    hit_count: int = 0

@dataclass
class Application:
    id: str
    name: str
    description: str
    repository_url: str
    deployment_url: str
    technology_stack: List[str]
    security_score: int
    last_scan: Optional[datetime]
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    created_at: datetime
    updated_at: datetime

class ApplicationSecurityService:
    def __init__(self):
        self.applications: Dict[str, Application] = {}
        self.sast_scans: Dict[str, SASTScan] = {}
        self.dast_scans: Dict[str, DASTScan] = {}
        self.sca_scans: Dict[str, SCAScan] = {}
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.waf_rules: Dict[str, WAFRule] = {}
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.is_running = False
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize with sample data"""
        # Sample applications
        apps_data = [
            {
                "id": "app-001",
                "name": "CyberShield Web Portal",
                "description": "Main web application for cybersecurity management",
                "repository_url": "https://github.com/company/cybershield-web",
                "deployment_url": "https://cybershield.company.com",
                "technology_stack": ["React", "Node.js", "PostgreSQL"],
                "security_score": 85,
                "last_scan": datetime.now() - timedelta(days=2),
                "total_vulnerabilities": 3,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 1,
                "created_at": datetime.now() - timedelta(days=30),
                "updated_at": datetime.now() - timedelta(days=2)
            }
        ]
        
        for app_data in apps_data:
            self.applications[app_data["id"]] = Application(**app_data)
        
        # Sample WAF rules
        waf_rules_data = [
            {
                "id": "waf-001",
                "name": "SQL Injection Protection",
                "description": "Blocks common SQL injection patterns",
                "action": WAFRuleAction.BLOCK,
                "conditions": {"patterns": ["' OR '1'='1", "DROP TABLE"]},
                "priority": 100,
                "enabled": True,
                "created_at": datetime.now() - timedelta(days=30),
                "hit_count": 15
            }
        ]
        
        for rule_data in waf_rules_data:
            self.waf_rules[rule_data["id"]] = WAFRule(**rule_data)
    
    async def start_application_security_service(self):
        """Start the service"""
        if self.is_running:
            return
        self.is_running = True
        asyncio.create_task(self._scan_worker())
        logger.info("Application security service started")
    
    async def stop_application_security_service(self):
        """Stop the service"""
        self.is_running = False
        logger.info("Application security service stopped")
    
    async def _scan_worker(self):
        """Background scan worker"""
        while self.is_running:
            try:
                scan_request = await asyncio.wait_for(self.scan_queue.get(), timeout=1.0)
                await self._process_scan(scan_request)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Error in scan worker", error=str(e))
    
    async def _process_scan(self, scan_request: Dict[str, Any]):
        """Process scan request"""
        scan_type = scan_request.get("scan_type")
        scan_id = scan_request.get("scan_id")
        
        await asyncio.sleep(3)  # Simulate scan time
        
        if scan_type == ScanType.SAST:
            await self._process_sast_scan(scan_request)
        elif scan_type == ScanType.DAST:
            await self._process_dast_scan(scan_request)
        elif scan_type == ScanType.SCA:
            await self._process_sca_scan(scan_request)
    
    async def _process_sast_scan(self, scan_request: Dict[str, Any]):
        """Process SAST scan"""
        scan_id = scan_request.get("scan_id")
        if scan_id in self.sast_scans:
            scan = self.sast_scans[scan_id]
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now()
            scan.files_scanned = 1250
            scan.vulnerabilities_found = 3
            scan.scan_duration = 180
            logger.info("SAST scan completed", scan_id=scan_id)
    
    async def _process_dast_scan(self, scan_request: Dict[str, Any]):
        """Process DAST scan"""
        scan_id = scan_request.get("scan_id")
        if scan_id in self.dast_scans:
            scan = self.dast_scans[scan_id]
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now()
            scan.pages_scanned = 45
            scan.vulnerabilities_found = 2
            scan.scan_duration = 300
            logger.info("DAST scan completed", scan_id=scan_id)
    
    async def _process_sca_scan(self, scan_request: Dict[str, Any]):
        """Process SCA scan"""
        scan_id = scan_request.get("scan_id")
        if scan_id in self.sca_scans:
            scan = self.sca_scans[scan_id]
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now()
            scan.dependencies_scanned = 156
            scan.vulnerabilities_found = 1
            scan.scan_duration = 90
            logger.info("SCA scan completed", scan_id=scan_id)
    
    # Application Management
    async def register_application(self, app_data: Dict[str, Any]) -> str:
        """Register new application"""
        app_id = f"app-{uuid.uuid4().hex[:8]}"
        app = Application(
            id=app_id,
            name=app_data.get("name", ""),
            description=app_data.get("description", ""),
            repository_url=app_data.get("repository_url", ""),
            deployment_url=app_data.get("deployment_url", ""),
            technology_stack=app_data.get("technology_stack", []),
            security_score=100,
            last_scan=None,
            total_vulnerabilities=0,
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        self.applications[app_id] = app
        return app_id
    
    async def get_applications(self) -> List[Dict[str, Any]]:
        """Get all applications"""
        return [asdict(app) for app in self.applications.values()]
    
    # SAST Methods
    async def start_sast_scan(self, app_id: str, scan_config: Dict[str, Any]) -> str:
        """Start SAST scan"""
        if app_id not in self.applications:
            raise ValueError("Application not found")
        
        scan_id = f"sast-{uuid.uuid4().hex[:8]}"
        scan = SASTScan(
            id=scan_id,
            project_name=self.applications[app_id].name,
            repository_url=self.applications[app_id].repository_url,
            status=ScanStatus.PENDING,
            started_at=datetime.now(),
            completed_at=None,
            files_scanned=0,
            vulnerabilities_found=0,
            scan_duration=0,
            engine_version="SonarQube 9.9"
        )
        
        self.sast_scans[scan_id] = scan
        await self.scan_queue.put({"scan_id": scan_id, "scan_type": ScanType.SAST})
        return scan_id
    
    async def get_sast_scans(self) -> List[Dict[str, Any]]:
        """Get SAST scans"""
        return [asdict(scan) for scan in self.sast_scans.values()]
    
    # DAST Methods
    async def start_dast_scan(self, target_url: str, scan_config: Dict[str, Any]) -> str:
        """Start DAST scan"""
        scan_id = f"dast-{uuid.uuid4().hex[:8]}"
        scan = DASTScan(
            id=scan_id,
            target_url=target_url,
            status=ScanStatus.PENDING,
            started_at=datetime.now(),
            completed_at=None,
            pages_scanned=0,
            vulnerabilities_found=0,
            scan_duration=0,
            engine_version="OWASP ZAP 2.14"
        )
        
        self.dast_scans[scan_id] = scan
        await self.scan_queue.put({"scan_id": scan_id, "scan_type": ScanType.DAST})
        return scan_id
    
    async def get_dast_scans(self) -> List[Dict[str, Any]]:
        """Get DAST scans"""
        return [asdict(scan) for scan in self.dast_scans.values()]
    
    # SCA Methods
    async def start_sca_scan(self, app_id: str, manifest_files: List[str]) -> str:
        """Start SCA scan"""
        if app_id not in self.applications:
            raise ValueError("Application not found")
        
        scan_id = f"sca-{uuid.uuid4().hex[:8]}"
        scan = SCAScan(
            id=scan_id,
            project_name=self.applications[app_id].name,
            manifest_files=manifest_files,
            status=ScanStatus.PENDING,
            started_at=datetime.now(),
            completed_at=None,
            dependencies_scanned=0,
            vulnerabilities_found=0,
            scan_duration=0,
            engine_version="Snyk 1.1200"
        )
        
        self.sca_scans[scan_id] = scan
        await self.scan_queue.put({"scan_id": scan_id, "scan_type": ScanType.SCA})
        return scan_id
    
    async def get_sca_scans(self) -> List[Dict[str, Any]]:
        """Get SCA scans"""
        return [asdict(scan) for scan in self.sca_scans.values()]
    
    # WAF Methods
    async def create_waf_rule(self, rule_data: Dict[str, Any]) -> str:
        """Create WAF rule"""
        rule_id = f"waf-{uuid.uuid4().hex[:8]}"
        rule = WAFRule(
            id=rule_id,
            name=rule_data.get("name", ""),
            description=rule_data.get("description", ""),
            action=WAFRuleAction(rule_data.get("action", "block")),
            conditions=rule_data.get("conditions", {}),
            priority=rule_data.get("priority", 100),
            enabled=rule_data.get("enabled", True),
            created_at=datetime.now()
        )
        self.waf_rules[rule_id] = rule
        return rule_id
    
    async def get_waf_rules(self) -> List[Dict[str, Any]]:
        """Get WAF rules"""
        return [asdict(rule) for rule in self.waf_rules.values()]
    
    # Vulnerability Management
    async def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get vulnerabilities"""
        return [asdict(vuln) for vuln in self.vulnerabilities.values()]
    
    async def update_vulnerability_status(self, vuln_id: str, status: str) -> bool:
        """Update vulnerability status"""
        if vuln_id in self.vulnerabilities:
            self.vulnerabilities[vuln_id].status = status
            return True
        return False
    
    # Reporting
    async def get_application_security_summary(self) -> Dict[str, Any]:
        """Get security summary"""
        total_apps = len(self.applications)
        total_vulns = len(self.vulnerabilities)
        critical_vulns = len([v for v in self.vulnerabilities.values() if v.severity == VulnerabilitySeverity.CRITICAL])
        high_vulns = len([v for v in self.vulnerabilities.values() if v.severity == VulnerabilitySeverity.HIGH])
        
        return {
            "total_applications": total_apps,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "active_waf_rules": len([r for r in self.waf_rules.values() if r.enabled]),
            "avg_security_score": sum(app.security_score for app in self.applications.values()) / total_apps if total_apps > 0 else 0
        }

# Global instance
application_security_service = ApplicationSecurityService() 