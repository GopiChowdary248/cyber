import asyncio
import re
import hashlib
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class IssueSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueConfidence(Enum):
    FALSE_POSITIVE = "false_positive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ScanIssue:
    id: str
    title: str
    description: str
    severity: IssueSeverity
    confidence: IssueConfidence
    url: str
    method: str
    evidence: Dict
    cwe_id: Optional[str] = None
    references: List[str] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.created_at is None:
            self.created_at = datetime.utcnow()


class ScannerModule:
    """Base class for scanner modules."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.enabled = True
    
    async def scan_request(self, request: Dict, response: Dict, context: Dict) -> List[ScanIssue]:
        """Scan a single request/response pair."""
        raise NotImplementedError
    
    async def scan_response(self, response: Dict, context: Dict) -> List[ScanIssue]:
        """Scan a single response."""
        raise NotImplementedError


class SQLInjectionModule(ScannerModule):
    """SQL Injection detection module."""
    
    def __init__(self):
        super().__init__("sql_injection", "Detects SQL injection vulnerabilities")
        self.payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
        self.error_patterns = [
            r"sql syntax.*mysql",
            r"oracle.*error",
            r"postgresql.*error",
            r"microsoft.*database.*error",
            r"sqlite.*syntax",
            r"warning.*mysql",
            r"unclosed quotation mark after the char string",
            r"quoted string not properly terminated"
        ]
    
    async def scan_request(self, request: Dict, response: Dict, context: Dict) -> List[ScanIssue]:
        issues = []
        
        # Check URL parameters
        if '?' in request.get('url', ''):
            for payload in self.payloads:
                if payload in request.get('url', ''):
                    issues.append(ScanIssue(
                        id=f"sql_inj_url_{hashlib.md5(payload.encode()).hexdigest()[:8]}",
                        title="Potential SQL Injection in URL",
                        description=f"URL contains SQL injection payload: {payload}",
                        severity=IssueSeverity.HIGH,
                        confidence=IssueConfidence.MEDIUM,
                        url=request.get('url', ''),
                        method=request.get('method', 'GET'),
                        evidence={"payload": payload, "location": "url"},
                        cwe_id="CWE-89"
                    ))
        
        # Check request body
        body = request.get('body', '')
        if body:
            for payload in self.payloads:
                if payload in body:
                    issues.append(ScanIssue(
                        id=f"sql_inj_body_{hashlib.md5(payload.encode()).hexdigest()[:8]}",
                        title="Potential SQL Injection in Request Body",
                        description=f"Request body contains SQL injection payload: {payload}",
                        severity=IssueSeverity.HIGH,
                        confidence=IssueConfidence.MEDIUM,
                        url=request.get('url', ''),
                        method=request.get('method', 'POST'),
                        evidence={"payload": payload, "location": "body"},
                        cwe_id="CWE-89"
                    ))
        
        return issues
    
    async def scan_response(self, response: Dict, context: Dict) -> List[ScanIssue]:
        issues = []
        body = response.get('body', '')
        
        if body:
            for pattern in self.error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    issues.append(ScanIssue(
                        id=f"sql_error_{hashlib.md5(pattern.encode()).hexdigest()[:8]}",
                        title="SQL Error in Response",
                        description=f"Response contains SQL error pattern: {pattern}",
                        severity=IssueSeverity.MEDIUM,
                        confidence=IssueConfidence.HIGH,
                        url=context.get('url', ''),
                        method=context.get('method', ''),
                        evidence={"pattern": pattern, "response_body": body[:200]},
                        cwe_id="CWE-209"
                    ))
        
        return issues


class XSSModule(ScannerModule):
    """Cross-Site Scripting detection module."""
    
    def __init__(self):
        super().__init__("xss", "Detects Cross-Site Scripting vulnerabilities")
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        self.reflection_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<img[^>]*on\w+\s*=",
            r"javascript:",
            r"on\w+\s*="
        ]
    
    async def scan_request(self, request: Dict, response: Dict, context: Dict) -> List[ScanIssue]:
        issues = []
        
        # Check if XSS payloads are reflected in response
        for payload in self.payloads:
            if payload in request.get('body', '') or payload in request.get('url', ''):
                # Check if payload is reflected in response
                if payload in response.get('body', ''):
                    issues.append(ScanIssue(
                        id=f"xss_reflected_{hashlib.md5(payload.encode()).hexdigest()[:8]}",
                        title="Reflected Cross-Site Scripting",
                        description=f"XSS payload is reflected in response: {payload}",
                        severity=IssueSeverity.HIGH,
                        confidence=IssueConfidence.HIGH,
                        url=request.get('url', ''),
                        method=request.get('method', ''),
                        evidence={"payload": payload, "reflected": True},
                        cwe_id="CWE-79"
                    ))
        
        return issues
    
    async def scan_response(self, response: Dict, context: Dict) -> List[ScanIssue]:
        issues = []
        body = response.get('body', '')
        
        if body:
            for pattern in self.reflection_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    issues.append(ScanIssue(
                        id=f"xss_stored_{hashlib.md5(pattern.encode()).hexdigest()[:8]}",
                        title="Stored Cross-Site Scripting",
                        description=f"Response contains potentially dangerous XSS pattern: {pattern}",
                        severity=IssueSeverity.MEDIUM,
                        confidence=IssueConfidence.LOW,
                        url=context.get('url', ''),
                        method=context.get('method', ''),
                        evidence={"pattern": pattern, "response_body": body[:200]},
                        cwe_id="CWE-79"
                    ))
        
        return issues


class CSRFModule(ScannerModule):
    """CSRF detection module."""
    
    def __init__(self):
        super().__init__("csrf", "Detects CSRF vulnerabilities")
    
    async def scan_request(self, request: Dict, response: Dict, context: Dict) -> List[ScanIssue]:
        issues = []
        method = request.get('method', '').upper()
        
        # Check for state-changing operations without CSRF protection
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            headers = request.get('headers', {})
            body = request.get('body', '')
            
            # Check for CSRF tokens
            has_csrf_token = any(
                re.search(r'csrf|xsrf|_token', key.lower()) 
                for key in headers.keys()
            ) or re.search(r'csrf|xsrf|_token', body.lower())
            
            if not has_csrf_token:
                issues.append(ScanIssue(
                    id=f"csrf_missing_{hashlib.md5(request.get('url', '').encode()).hexdigest()[:8]}",
                    title="Missing CSRF Protection",
                    description=f"State-changing {method} request lacks CSRF protection",
                    severity=IssueSeverity.MEDIUM,
                    confidence=IssueConfidence.MEDIUM,
                    url=request.get('url', ''),
                    method=method,
                    evidence={"method": method, "has_csrf_token": False},
                    cwe_id="CWE-352"
                ))
        
        return issues
    
    async def scan_response(self, response: Dict, context: Dict) -> List[ScanIssue]:
        return []


class ScannerEngine:
    """Main scanner engine that orchestrates vulnerability scanning."""
    
    def __init__(self):
        self.modules: List[ScannerModule] = [
            SQLInjectionModule(),
            XSSModule(),
            CSRFModule()
        ]
        self.active_scans: Dict[str, Dict] = {}
        self.rate_limiters: Dict[str, Dict] = {}
        self.issue_cache: Set[str] = set()  # Simple deduplication cache
    
    async def start_scan(self, project_id: str, target_urls: List[str], scan_config: Dict) -> str:
        """Start a new scan."""
        scan_id = f"scan_{project_id}_{int(datetime.utcnow().timestamp())}"
        
        self.active_scans[scan_id] = {
            "project_id": project_id,
            "target_urls": target_urls,
            "config": scan_config,
            "status": ScanStatus.RUNNING,
            "started_at": datetime.utcnow(),
            "issues": [],
            "progress": 0,
            "total_requests": len(target_urls) * len(self.modules)
        }
        
        # Start scan in background
        asyncio.create_task(self._run_scan(scan_id))
        
        return scan_id
    
    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["status"] = ScanStatus.PAUSED
            return True
        return False
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get current scan status."""
        return self.active_scans.get(scan_id)
    
    async def _run_scan(self, scan_id: str):
        """Run the actual scan."""
        scan = self.active_scans[scan_id]
        
        try:
            for i, url in enumerate(scan["target_urls"]):
                if scan["status"] != ScanStatus.RUNNING:
                    break
                
                # Simulate scanning each URL with each module
                for module in self.modules:
                    if not module.enabled:
                        continue
                    
                    # Simulate request/response (in real implementation, this would be actual HTTP requests)
                    mock_request = {
                        "method": "GET",
                        "url": url,
                        "headers": {"User-Agent": "CyberShield Scanner"},
                        "body": ""
                    }
                    
                    mock_response = {
                        "status": 200,
                        "headers": {"Content-Type": "text/html"},
                        "body": f"<html><body>Response from {url}</body></html>"
                    }
                    
                    # Run module scans
                    request_issues = await module.scan_request(mock_request, mock_response, {"url": url})
                    response_issues = await module.scan_response(mock_response, {"url": url, "method": "GET"})
                    
                    # Deduplicate and add issues
                    all_issues = request_issues + response_issues
                    for issue in all_issues:
                        issue_hash = self._generate_issue_hash(issue)
                        if issue_hash not in self.issue_cache:
                            self.issue_cache.add(issue_hash)
                            scan["issues"].append(issue)
                    
                    # Update progress
                    scan["progress"] += 1
                    
                    # Rate limiting
                    await asyncio.sleep(0.1)  # 100ms delay between requests
                
                # Update progress percentage
                scan["progress"] = int((i + 1) / len(scan["target_urls"]) * 100)
            
            scan["status"] = ScanStatus.COMPLETED
            scan["completed_at"] = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan["status"] = ScanStatus.FAILED
            scan["error"] = str(e)
    
    def _generate_issue_hash(self, issue: ScanIssue) -> str:
        """Generate a hash for issue deduplication."""
        content = f"{issue.title}:{issue.url}:{issue.method}:{issue.evidence}"
        return hashlib.md5(content.encode()).hexdigest()
    
    async def get_scan_issues(self, scan_id: str) -> List[ScanIssue]:
        """Get all issues from a scan."""
        scan = self.active_scans.get(scan_id)
        if scan:
            return scan.get("issues", [])
        return []
    
    async def get_all_issues(self, project_id: str) -> List[ScanIssue]:
        """Get all issues from all scans in a project."""
        all_issues = []
        for scan in self.active_scans.values():
            if scan["project_id"] == project_id:
                all_issues.extend(scan.get("issues", []))
        return all_issues


# Global scanner engine instance
scanner_engine = ScannerEngine()
