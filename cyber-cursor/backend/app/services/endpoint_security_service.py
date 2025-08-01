"""
Endpoint Security Service
Provides comprehensive endpoint protection including:
- Antivirus scanning and management
- EDR (Endpoint Detection and Response)
- Application whitelisting and blacklisting
- Endpoint monitoring and compliance
- Threat detection and response
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import structlog
from pathlib import Path

logger = structlog.get_logger()

class ScanStatus(Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EndpointStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    COMPROMISED = "compromised"

class WhitelistAction(Enum):
    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"

@dataclass
class AntivirusScan:
    id: str
    endpoint_id: str
    scan_type: str  # quick, full, custom
    status: ScanStatus
    files_scanned: int
    threats_found: int
    scan_duration: int  # seconds
    started_at: datetime
    completed_at: Optional[datetime]
    scan_path: str
    results: Dict[str, Any]

@dataclass
class EDRAlert:
    id: str
    endpoint_id: str
    alert_type: str
    severity: ThreatLevel
    title: str
    description: str
    timestamp: datetime
    process_name: str
    process_path: str
    parent_process: str
    command_line: str
    network_connections: List[str]
    file_operations: List[str]
    registry_changes: List[str]
    status: str  # new, investigating, resolved, false_positive
    ioc_indicators: List[str]

@dataclass
class WhitelistEntry:
    id: str
    name: str
    path: str
    hash: str
    publisher: str
    action: WhitelistAction
    created_at: datetime
    created_by: str
    is_active: bool
    description: str

@dataclass
class Endpoint:
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    os_type: str
    os_version: str
    status: EndpointStatus
    last_seen: datetime
    antivirus_version: str
    edr_version: str
    compliance_score: int
    risk_score: int
    installed_apps: List[str]
    running_processes: List[str]
    network_connections: List[str]

class EndpointSecurityService:
    def __init__(self):
        self.endpoints: Dict[str, Endpoint] = {}
        self.scans: Dict[str, AntivirusScan] = {}
        self.alerts: Dict[str, EDRAlert] = {}
        self.whitelist: Dict[str, WhitelistEntry] = {}
        self.blacklist: Set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.alert_queue: asyncio.Queue = asyncio.Queue()
        self.is_running = False
        
        # Initialize with sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize service with sample data for demonstration"""
        # Sample endpoints
        endpoints_data = [
            {
                "id": "ep-001",
                "hostname": "DESKTOP-ABC123",
                "ip_address": "192.168.1.100",
                "mac_address": "00:1B:44:11:3A:B7",
                "os_type": "Windows",
                "os_version": "Windows 10 Pro",
                "status": EndpointStatus.ONLINE,
                "last_seen": datetime.now(),
                "antivirus_version": "v2.1.0",
                "edr_version": "v1.5.2",
                "compliance_score": 85,
                "risk_score": 15,
                "installed_apps": ["Chrome", "Firefox", "Office 365", "Slack"],
                "running_processes": ["chrome.exe", "slack.exe", "antivirus.exe"],
                "network_connections": ["192.168.1.1:80", "8.8.8.8:53"]
            },
            {
                "id": "ep-002",
                "hostname": "LAPTOP-XYZ789",
                "ip_address": "192.168.1.101",
                "mac_address": "00:1B:44:11:3A:B8",
                "os_type": "Windows",
                "os_version": "Windows 11 Pro",
                "status": EndpointStatus.ONLINE,
                "last_seen": datetime.now() - timedelta(minutes=5),
                "antivirus_version": "v2.1.0",
                "edr_version": "v1.5.2",
                "compliance_score": 92,
                "risk_score": 8,
                "installed_apps": ["Chrome", "Teams", "Visual Studio Code"],
                "running_processes": ["chrome.exe", "teams.exe", "code.exe"],
                "network_connections": ["192.168.1.1:80", "8.8.8.8:53"]
            }
        ]
        
        for ep_data in endpoints_data:
            self.endpoints[ep_data["id"]] = Endpoint(**ep_data)
        
        # Sample whitelist entries
        whitelist_data = [
            {
                "id": "wl-001",
                "name": "Google Chrome",
                "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "hash": "a1b2c3d4e5f6...",
                "publisher": "Google LLC",
                "action": WhitelistAction.ALLOW,
                "created_at": datetime.now() - timedelta(days=30),
                "created_by": "admin@company.com",
                "is_active": True,
                "description": "Standard browser application"
            },
            {
                "id": "wl-002",
                "name": "Microsoft Office",
                "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "hash": "b2c3d4e5f6g7...",
                "publisher": "Microsoft Corporation",
                "action": WhitelistAction.ALLOW,
                "created_at": datetime.now() - timedelta(days=45),
                "created_by": "admin@company.com",
                "is_active": True,
                "description": "Office productivity suite"
            }
        ]
        
        for wl_data in whitelist_data:
            self.whitelist[wl_data["id"]] = WhitelistEntry(**wl_data)
        
        # Sample blacklist
        self.blacklist = {
            "malware.exe",
            "keylogger.dll",
            "ransomware.bat"
        }
        
        # Sample scans
        scan_data = {
            "id": "scan-001",
            "endpoint_id": "ep-001",
            "scan_type": "full",
            "status": ScanStatus.COMPLETED,
            "files_scanned": 125000,
            "threats_found": 0,
            "scan_duration": 1800,
            "started_at": datetime.now() - timedelta(hours=2),
            "completed_at": datetime.now() - timedelta(hours=1, minutes=30),
            "scan_path": "C:\\",
            "results": {
                "clean": True,
                "quarantined_files": [],
                "scan_summary": "No threats detected"
            }
        }
        
        self.scans[scan_data["id"]] = AntivirusScan(**scan_data)
        
        # Sample EDR alerts
        alert_data = {
            "id": "alert-001",
            "endpoint_id": "ep-001",
            "alert_type": "suspicious_process",
            "severity": ThreatLevel.MEDIUM,
            "title": "Suspicious PowerShell Execution",
            "description": "PowerShell executed with encoded command",
            "timestamp": datetime.now() - timedelta(hours=1),
            "process_name": "powershell.exe",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell -enc JABw...",
            "network_connections": ["192.168.1.100:443"],
            "file_operations": ["C:\\temp\\script.ps1"],
            "registry_changes": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
            "status": "investigating",
            "ioc_indicators": ["encoded_powershell", "suspicious_registry"]
        }
        
        self.alerts[alert_data["id"]] = EDRAlert(**alert_data)
    
    async def start_endpoint_security_service(self):
        """Start the endpoint security service"""
        if self.is_running:
            return
        
        self.is_running = True
        logger.info("Starting endpoint security service")
        
        # Start background tasks
        asyncio.create_task(self._scan_worker())
        asyncio.create_task(self._alert_processor())
        asyncio.create_task(self._endpoint_monitor())
        
        logger.info("Endpoint security service started successfully")
    
    async def stop_endpoint_security_service(self):
        """Stop the endpoint security service"""
        self.is_running = False
        logger.info("Stopping endpoint security service")
    
    async def _scan_worker(self):
        """Background worker for processing scan requests"""
        while self.is_running:
            try:
                scan_request = await asyncio.wait_for(self.scan_queue.get(), timeout=1.0)
                await self._process_scan(scan_request)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Error in scan worker", error=str(e))
    
    async def _alert_processor(self):
        """Background worker for processing EDR alerts"""
        while self.is_running:
            try:
                alert = await asyncio.wait_for(self.alert_queue.get(), timeout=1.0)
                await self._process_alert(alert)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Error in alert processor", error=str(e))
    
    async def _endpoint_monitor(self):
        """Monitor endpoint status and health"""
        while self.is_running:
            try:
                await self._check_endpoint_health()
                await asyncio.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error("Error in endpoint monitor", error=str(e))
    
    async def _process_scan(self, scan_request: Dict[str, Any]):
        """Process an antivirus scan request"""
        scan_id = scan_request.get("scan_id")
        endpoint_id = scan_request.get("endpoint_id")
        
        if scan_id not in self.scans:
            return
        
        scan = self.scans[scan_id]
        scan.status = ScanStatus.SCANNING
        
        # Simulate scan process
        await asyncio.sleep(2)  # Simulate scan time
        
        # Update scan results
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now()
        scan.files_scanned = 125000
        scan.threats_found = 0
        scan.scan_duration = 120
        
        logger.info("Scan completed", scan_id=scan_id, endpoint_id=endpoint_id)
    
    async def _process_alert(self, alert: EDRAlert):
        """Process an EDR alert"""
        logger.info("Processing EDR alert", alert_id=alert.id, severity=alert.severity.value)
        
        # Update endpoint risk score based on alert
        if alert.endpoint_id in self.endpoints:
            endpoint = self.endpoints[alert.endpoint_id]
            if alert.severity == ThreatLevel.CRITICAL:
                endpoint.risk_score = min(100, endpoint.risk_score + 20)
            elif alert.severity == ThreatLevel.HIGH:
                endpoint.risk_score = min(100, endpoint.risk_score + 15)
            elif alert.severity == ThreatLevel.MEDIUM:
                endpoint.risk_score = min(100, endpoint.risk_score + 10)
            else:
                endpoint.risk_score = min(100, endpoint.risk_score + 5)
    
    async def _check_endpoint_health(self):
        """Check health of all endpoints"""
        current_time = datetime.now()
        
        for endpoint in self.endpoints.values():
            # Simulate endpoint health check
            if (current_time - endpoint.last_seen).seconds > 300:  # 5 minutes
                endpoint.status = EndpointStatus.OFFLINE
            else:
                endpoint.status = EndpointStatus.ONLINE
    
    # Antivirus Management Methods
    async def start_antivirus_scan(self, endpoint_id: str, scan_type: str = "quick", scan_path: str = "C:\\") -> str:
        """Start an antivirus scan on an endpoint"""
        if endpoint_id not in self.endpoints:
            raise ValueError("Endpoint not found")
        
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        scan = AntivirusScan(
            id=scan_id,
            endpoint_id=endpoint_id,
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            files_scanned=0,
            threats_found=0,
            scan_duration=0,
            started_at=datetime.now(),
            completed_at=None,
            scan_path=scan_path,
            results={}
        )
        
        self.scans[scan_id] = scan
        
        # Queue scan for processing
        await self.scan_queue.put({
            "scan_id": scan_id,
            "endpoint_id": endpoint_id,
            "scan_type": scan_type,
            "scan_path": scan_path
        })
        
        logger.info("Antivirus scan started", scan_id=scan_id, endpoint_id=endpoint_id, scan_type=scan_type)
        return scan_id
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of an antivirus scan"""
        if scan_id not in self.scans:
            return None
        
        scan = self.scans[scan_id]
        return asdict(scan)
    
    async def get_endpoint_scans(self, endpoint_id: str) -> List[Dict[str, Any]]:
        """Get all scans for an endpoint"""
        scans = [asdict(scan) for scan in self.scans.values() if scan.endpoint_id == endpoint_id]
        return sorted(scans, key=lambda x: x["started_at"], reverse=True)
    
    # EDR Management Methods
    async def create_edr_alert(self, endpoint_id: str, alert_data: Dict[str, Any]) -> str:
        """Create a new EDR alert"""
        alert_id = f"alert-{uuid.uuid4().hex[:8]}"
        
        alert = EDRAlert(
            id=alert_id,
            endpoint_id=endpoint_id,
            alert_type=alert_data.get("alert_type", "unknown"),
            severity=ThreatLevel(alert_data.get("severity", "medium")),
            title=alert_data.get("title", ""),
            description=alert_data.get("description", ""),
            timestamp=datetime.now(),
            process_name=alert_data.get("process_name", ""),
            process_path=alert_data.get("process_path", ""),
            parent_process=alert_data.get("parent_process", ""),
            command_line=alert_data.get("command_line", ""),
            network_connections=alert_data.get("network_connections", []),
            file_operations=alert_data.get("file_operations", []),
            registry_changes=alert_data.get("registry_changes", []),
            status="new",
            ioc_indicators=alert_data.get("ioc_indicators", [])
        )
        
        self.alerts[alert_id] = alert
        
        # Queue alert for processing
        await self.alert_queue.put(alert)
        
        logger.info("EDR alert created", alert_id=alert_id, endpoint_id=endpoint_id, severity=alert.severity.value)
        return alert_id
    
    async def get_edr_alerts(self, endpoint_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get EDR alerts with optional filtering"""
        alerts = []
        
        for alert in self.alerts.values():
            if endpoint_id and alert.endpoint_id != endpoint_id:
                continue
            if status and alert.status != status:
                continue
            
            alerts.append(asdict(alert))
        
        return sorted(alerts, key=lambda x: x["timestamp"], reverse=True)
    
    async def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update the status of an EDR alert"""
        if alert_id not in self.alerts:
            return False
        
        self.alerts[alert_id].status = status
        logger.info("Alert status updated", alert_id=alert_id, status=status)
        return True
    
    # Application Whitelisting Methods
    async def add_whitelist_entry(self, entry_data: Dict[str, Any]) -> str:
        """Add a new application to the whitelist"""
        entry_id = f"wl-{uuid.uuid4().hex[:8]}"
        
        entry = WhitelistEntry(
            id=entry_id,
            name=entry_data.get("name", ""),
            path=entry_data.get("path", ""),
            hash=entry_data.get("hash", ""),
            publisher=entry_data.get("publisher", ""),
            action=WhitelistAction(entry_data.get("action", "allow")),
            created_at=datetime.now(),
            created_by=entry_data.get("created_by", "system"),
            is_active=True,
            description=entry_data.get("description", "")
        )
        
        self.whitelist[entry_id] = entry
        logger.info("Whitelist entry added", entry_id=entry_id, name=entry.name)
        return entry_id
    
    async def remove_whitelist_entry(self, entry_id: str) -> bool:
        """Remove an application from the whitelist"""
        if entry_id not in self.whitelist:
            return False
        
        del self.whitelist[entry_id]
        logger.info("Whitelist entry removed", entry_id=entry_id)
        return True
    
    async def get_whitelist_entries(self) -> List[Dict[str, Any]]:
        """Get all whitelist entries"""
        entries = [asdict(entry) for entry in self.whitelist.values()]
        return sorted(entries, key=lambda x: x["created_at"], reverse=True)
    
    async def check_application_whitelist(self, app_path: str, app_hash: str) -> WhitelistAction:
        """Check if an application is whitelisted"""
        for entry in self.whitelist.values():
            if not entry.is_active:
                continue
            
            if entry.path == app_path or entry.hash == app_hash:
                return entry.action
        
        return WhitelistAction.DENY
    
    # Endpoint Management Methods
    async def register_endpoint(self, endpoint_data: Dict[str, Any]) -> str:
        """Register a new endpoint"""
        endpoint_id = f"ep-{uuid.uuid4().hex[:8]}"
        
        endpoint = Endpoint(
            id=endpoint_id,
            hostname=endpoint_data.get("hostname", ""),
            ip_address=endpoint_data.get("ip_address", ""),
            mac_address=endpoint_data.get("mac_address", ""),
            os_type=endpoint_data.get("os_type", ""),
            os_version=endpoint_data.get("os_version", ""),
            status=EndpointStatus.ONLINE,
            last_seen=datetime.now(),
            antivirus_version=endpoint_data.get("antivirus_version", ""),
            edr_version=endpoint_data.get("edr_version", ""),
            compliance_score=100,
            risk_score=0,
            installed_apps=endpoint_data.get("installed_apps", []),
            running_processes=endpoint_data.get("running_processes", []),
            network_connections=endpoint_data.get("network_connections", [])
        )
        
        self.endpoints[endpoint_id] = endpoint
        logger.info("Endpoint registered", endpoint_id=endpoint_id, hostname=endpoint.hostname)
        return endpoint_id
    
    async def get_endpoints(self) -> List[Dict[str, Any]]:
        """Get all registered endpoints"""
        endpoints = [asdict(endpoint) for endpoint in self.endpoints.values()]
        return sorted(endpoints, key=lambda x: x["last_seen"], reverse=True)
    
    async def get_endpoint_details(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about an endpoint"""
        if endpoint_id not in self.endpoints:
            return None
        
        return asdict(self.endpoints[endpoint_id])
    
    async def update_endpoint_status(self, endpoint_id: str, status: EndpointStatus) -> bool:
        """Update endpoint status"""
        if endpoint_id not in self.endpoints:
            return False
        
        self.endpoints[endpoint_id].status = status
        logger.info("Endpoint status updated", endpoint_id=endpoint_id, status=status.value)
        return True
    
    # Reporting Methods
    async def get_endpoint_security_summary(self) -> Dict[str, Any]:
        """Get a summary of endpoint security status"""
        total_endpoints = len(self.endpoints)
        online_endpoints = len([ep for ep in self.endpoints.values() if ep.status == EndpointStatus.ONLINE])
        quarantined_endpoints = len([ep for ep in self.endpoints.values() if ep.status == EndpointStatus.QUARANTINED])
        
        total_scans = len(self.scans)
        completed_scans = len([s for s in self.scans.values() if s.status == ScanStatus.COMPLETED])
        
        total_alerts = len(self.alerts)
        new_alerts = len([a for a in self.alerts.values() if a.status == "new"])
        critical_alerts = len([a for a in self.alerts.values() if a.severity == ThreatLevel.CRITICAL])
        
        avg_compliance_score = sum(ep.compliance_score for ep in self.endpoints.values()) / total_endpoints if total_endpoints > 0 else 0
        avg_risk_score = sum(ep.risk_score for ep in self.endpoints.values()) / total_endpoints if total_endpoints > 0 else 0
        
        return {
            "total_endpoints": total_endpoints,
            "online_endpoints": online_endpoints,
            "quarantined_endpoints": quarantined_endpoints,
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_alerts": total_alerts,
            "new_alerts": new_alerts,
            "critical_alerts": critical_alerts,
            "avg_compliance_score": round(avg_compliance_score, 1),
            "avg_risk_score": round(avg_risk_score, 1),
            "whitelist_entries": len(self.whitelist),
            "blacklist_entries": len(self.blacklist)
        }
    
    async def get_threat_analysis(self, days: int = 7) -> Dict[str, Any]:
        """Get threat analysis for the specified period"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_alerts = [a for a in self.alerts.values() if a.timestamp >= cutoff_date]
        recent_scans = [s for s in self.scans.values() if s.started_at >= cutoff_date]
        
        # Threat distribution by severity
        severity_distribution = {}
        for alert in recent_alerts:
            severity = alert.severity.value
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        # Threat distribution by type
        alert_type_distribution = {}
        for alert in recent_alerts:
            alert_type = alert.alert_type
            alert_type_distribution[alert_type] = alert_type_distribution.get(alert_type, 0) + 1
        
        # Scan results
        total_threats_found = sum(scan.threats_found for scan in recent_scans)
        
        return {
            "period_days": days,
            "total_alerts": len(recent_alerts),
            "total_scans": len(recent_scans),
            "total_threats_found": total_threats_found,
            "severity_distribution": severity_distribution,
            "alert_type_distribution": alert_type_distribution,
            "top_threat_indicators": [
                "suspicious_process",
                "network_anomaly",
                "file_operation",
                "registry_change"
            ]
        }

# Global instance
endpoint_security_service = EndpointSecurityService() 