"""
DAST Scanner Core Implementation
Provides the main scanning engine for dynamic application security testing
"""

import asyncio
import aiohttp
import json
import re
import time
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dast import (
    DASTProject, DASTScan, DASTVulnerability, DASTPayload,
    ScanStatus, VulnerabilitySeverity, VulnerabilityStatus, AuthType, ScanType
)

logger = logging.getLogger(__name__)

class ScanPhase(str, Enum):
    INITIALIZATION = "initialization"
    SPIDERING = "spidering"
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"
    REPORTING = "reporting"
    COMPLETED = "completed"

@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    params: Dict[str, Any] = None
    headers: Dict[str, str] = None
    data: Dict[str, Any] = None
    auth_required: bool = False

@dataclass
class Vulnerability:
    title: str
    description: str
    severity: VulnerabilitySeverity
    url: str
    http_method: str
    param_name: Optional[str] = None
    vuln_type: str = None
    payload: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    evidence: Dict[str, Any] = None
    response_code: Optional[int] = None
    response_time: Optional[float] = None

class DASTScanner:
    """Main DAST scanner class"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.scan_id: Optional[str] = None
        self.project_id: Optional[str] = None
        self.target_url: Optional[str] = None
        self.scan_config: Dict[str, Any] = {}
        self.auth_config: Dict[str, Any] = {}
        self.discovered_urls: Set[str] = set()
        self.vulnerabilities: List[Vulnerability] = []
        self.session_cookies: Dict[str, str] = {}
        self.auth_headers: Dict[str, str] = {}
        
    async def initialize_scan(self, scan_id: str, project_id: str, scan_config: Dict[str, Any] = None):
        """Initialize the scan with configuration"""
        self.scan_id = scan_id
        self.project_id = project_id
        self.scan_config = scan_config or {}
        
        # Get project details
        project = await DASTProject.get_by_id(self.session, project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")
        
        self.target_url = project.target_url
        self.auth_config = project.auth_config or {}
        
        # Update scan status
        scan = await DASTScan.get_by_id(self.session, scan_id)
        if scan:
            scan.status = ScanStatus.IN_PROGRESS
            scan.started_at = datetime.utcnow()
            await self.session.commit()
        
        logger.info(f"Initialized DAST scan {scan_id} for project {project_id}")
    
    async def run_scan(self) -> Dict[str, Any]:
        """Run the complete DAST scan workflow"""
        try:
            logger.info(f"Starting DAST scan {self.scan_id}")
            
            # Phase 1: Spidering and crawling
            await self._update_scan_phase(ScanPhase.SPIDERING)
            discovered_targets = await self._spider_target()
            
            # Phase 2: Passive scanning
            await self._update_scan_phase(ScanPhase.PASSIVE_SCAN)
            passive_vulns = await self._passive_scan(discovered_targets)
            self.vulnerabilities.extend(passive_vulns)
            
            # Phase 3: Active scanning
            await self._update_scan_phase(ScanPhase.ACTIVE_SCAN)
            active_vulns = await self._active_scan(discovered_targets)
            self.vulnerabilities.extend(active_vulns)
            
            # Phase 4: Reporting
            await self._update_scan_phase(ScanPhase.REPORTING)
            scan_results = await self._generate_scan_report()
            
            # Phase 5: Complete
            await self._update_scan_phase(ScanPhase.COMPLETED)
            await self._save_vulnerabilities()
            await self._finalize_scan(scan_results)
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Scan {self.scan_id} failed: {str(e)}")
            await self._mark_scan_failed(str(e))
            raise
    
    async def _update_scan_phase(self, phase: ScanPhase):
        """Update scan phase in database"""
        scan = await DASTScan.get_by_id(self.session, self.scan_id)
        if scan:
            scan.scan_summary = scan.scan_summary or {}
            scan.scan_summary["current_phase"] = phase
            scan.scan_summary["phase_started"] = datetime.utcnow().isoformat()
            await self.session.commit()
    
    async def _spider_target(self) -> List[ScanTarget]:
        """Spider the target application to discover URLs and endpoints"""
        logger.info(f"Starting spidering for {self.target_url}")
        
        discovered_targets = []
        urls_to_scan = [self.target_url]
        scanned_urls = set()
        
        max_urls = self.scan_config.get("max_urls", 100)
        max_depth = self.scan_config.get("max_depth", 3)
        
        async with aiohttp.ClientSession() as session:
            for depth in range(max_depth):
                if len(scanned_urls) >= max_urls:
                    break
                
                current_level_urls = urls_to_scan.copy()
                urls_to_scan = []
                
                for url in current_level_urls:
                    if url in scanned_urls or len(scanned_urls) >= max_urls:
                        continue
                    
                    try:
                        # Add authentication headers if configured
                        headers = self.auth_headers.copy()
                        
                        response = await session.get(url, headers=headers, timeout=30)
                        scanned_urls.add(url)
                        
                        # Create scan target for this URL
                        target = ScanTarget(
                            url=url,
                            method="GET",
                            headers=dict(response.request_info.headers)
                        )
                        discovered_targets.append(target)
                        
                        # Extract links from response
                        if response.content_type and "text/html" in response.content_type:
                            content = await response.text()
                            new_urls = self._extract_urls(content, url)
                            urls_to_scan.extend(new_urls)
                        
                        # Extract forms
                        if response.content_type and "text/html" in response.content_type:
                            content = await response.text()
                            form_targets = self._extract_forms(content, url)
                            discovered_targets.extend(form_targets)
                        
                        await response.release()
                        
                    except Exception as e:
                        logger.warning(f"Failed to spider {url}: {str(e)}")
                        continue
        
        logger.info(f"Spidering completed. Discovered {len(discovered_targets)} targets")
        return discovered_targets
    
    def _extract_urls(self, html_content: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content"""
        urls = []
        
        # Extract href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.findall(href_pattern, html_content):
            if match.startswith(('http://', 'https://')):
                urls.append(match)
            elif match.startswith('/'):
                urls.append(urljoin(base_url, match))
            elif not match.startswith(('#', 'javascript:', 'mailto:')):
                urls.append(urljoin(base_url, match))
        
        # Extract src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.findall(src_pattern, html_content):
            if match.startswith(('http://', 'https://')):
                urls.append(match)
            elif match.startswith('/'):
                urls.append(urljoin(base_url, match))
            elif not match.startswith(('data:', 'javascript:')):
                urls.append(urljoin(base_url, match))
        
        return list(set(urls))
    
    def _extract_forms(self, html_content: str, base_url: str) -> List[ScanTarget]:
        """Extract forms from HTML content"""
        targets = []
        
        # Simple form extraction (in production, use BeautifulSoup)
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
        method_pattern = r'method=["\']([^"\']*)["\']'
        
        for match in re.finditer(form_pattern, html_content):
            action = match.group(1)
            if not action:
                action = base_url
            
            # Extract method
            method_match = re.search(method_pattern, match.group(0))
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract form fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            params = {}
            for input_match in re.findall(input_pattern, match.group(0)):
                params[input_match] = ""
            
            target = ScanTarget(
                url=urljoin(base_url, action),
                method=method,
                params=params if method == "GET" else None,
                data=params if method == "POST" else None
            )
            targets.append(target)
        
        return targets
    
    async def _passive_scan(self, targets: List[ScanTarget]) -> List[Vulnerability]:
        """Perform passive scanning (no payload injection)"""
        logger.info("Starting passive scan")
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for target in targets:
                try:
                    headers = self.auth_headers.copy()
                    
                    response = await session.request(
                        target.method,
                        target.url,
                        headers=headers,
                        params=target.params,
                        data=target.data,
                        timeout=30
                    )
                    
                    # Check for security headers
                    security_vulns = self._check_security_headers(response, target.url)
                    vulnerabilities.extend(security_vulns)
                    
                    # Check for information disclosure
                    info_vulns = self._check_information_disclosure(response, target.url)
                    vulnerabilities.extend(info_vulns)
                    
                    await response.release()
                    
                except Exception as e:
                    logger.warning(f"Passive scan failed for {target.url}: {str(e)}")
                    continue
        
        logger.info(f"Passive scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _check_security_headers(self, response: aiohttp.ClientResponse, url: str) -> List[Vulnerability]:
        """Check for missing or misconfigured security headers"""
        vulnerabilities = []
        
        security_headers = {
            "X-Frame-Options": "Missing X-Frame-Options header (clickjacking protection)",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header (MIME sniffing protection)",
            "X-XSS-Protection": "Missing X-XSS-Protection header (XSS protection)",
            "Strict-Transport-Security": "Missing HSTS header (HTTPS enforcement)",
            "Content-Security-Policy": "Missing CSP header (XSS and injection protection)",
            "Referrer-Policy": "Missing Referrer-Policy header (referrer information control)"
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                vuln = Vulnerability(
                    title=f"Missing Security Header: {header}",
                    description=description,
                    severity=VulnerabilitySeverity.MEDIUM,
                    url=url,
                    http_method=response.method,
                    vuln_type="security_headers",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    evidence={"missing_header": header}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_information_disclosure(self, response: aiohttp.ClientResponse, url: str) -> List[Vulnerability]:
        """Check for information disclosure in responses"""
        vulnerabilities = []
        
        # Check for server information in headers
        server_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in server_headers:
            if header in response.headers:
                vuln = Vulnerability(
                    title=f"Information Disclosure: {header} Header",
                    description=f"Server information exposed via {header} header",
                    severity=VulnerabilitySeverity.LOW,
                    url=url,
                    http_method=response.method,
                    vuln_type="information_disclosure",
                    cwe_id="CWE-200",
                    owasp_category="A01:2021-Broken Access Control",
                    evidence={"exposed_header": header, "value": response.headers[header]}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _active_scan(self, targets: List[ScanTarget]) -> List[Vulnerability]:
        """Perform active scanning with payload injection"""
        logger.info("Starting active scan")
        
        vulnerabilities = []
        payloads = await self._get_payloads()
        
        async with aiohttp.ClientSession() as session:
            for target in targets:
                # Skip non-injectable targets
                if not self._is_injectable(target):
                    continue
                
                for payload in payloads:
                    try:
                        vuln = await self._test_payload(session, target, payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                    
                    except Exception as e:
                        logger.warning(f"Payload test failed for {target.url}: {str(e)}")
                        continue
        
        logger.info(f"Active scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _is_injectable(self, target: ScanTarget) -> bool:
        """Check if target is suitable for payload injection"""
        # Check for parameters in GET requests
        if target.method == "GET" and target.params:
            return True
        
        # Check for form data in POST requests
        if target.method == "POST" and target.data:
            return True
        
        # Check for query parameters in URL
        if "?" in target.url:
            return True
        
        return False
    
    async def _get_payloads(self) -> List[DASTPayload]:
        """Get payloads for active scanning"""
        payloads = await DASTPayload.get_active_payloads(self.session)
        return payloads
    
    async def _test_payload(self, session: aiohttp.ClientSession, target: ScanTarget, payload: DASTPayload) -> Optional[Vulnerability]:
        """Test a specific payload against a target"""
        start_time = time.time()
        
        try:
            # Prepare request with payload
            test_url = target.url
            test_params = target.params.copy() if target.params else {}
            test_data = target.data.copy() if target.data else {}
            test_headers = self.auth_headers.copy()
            
            # Inject payload into parameters
            if target.method == "GET" and test_params:
                for param_name in test_params:
                    test_params[param_name] = payload.payload
            
            elif target.method == "POST" and test_data:
                for param_name in test_data:
                    test_data[param_name] = payload.payload
            
            # Make request
            response = await session.request(
                target.method,
                test_url,
                headers=test_headers,
                params=test_params,
                data=test_data,
                timeout=30
            )
            
            response_time = time.time() - start_time
            content = await response.text()
            
            # Analyze response for vulnerability indicators
            is_vulnerable = self._analyze_response_for_vulnerability(
                response, content, payload, response_time
            )
            
            if is_vulnerable:
                vuln = Vulnerability(
                    title=f"{payload.vuln_type.upper()} Vulnerability",
                    description=f"Detected {payload.vuln_type} vulnerability using payload: {payload.payload}",
                    severity=payload.severity,
                    url=test_url,
                    http_method=target.method,
                    param_name=list(test_params.keys())[0] if test_params else list(test_data.keys())[0] if test_data else None,
                    vuln_type=payload.vuln_type,
                    payload=payload.payload,
                    cwe_id=payload.cwe_id,
                    owasp_category=payload.owasp_category,
                    evidence={
                        "payload": payload.payload,
                        "response_code": response.status,
                        "response_time": response_time,
                        "response_size": len(content)
                    },
                    response_code=response.status,
                    response_time=response_time
                )
                return vuln
            
            await response.release()
            return None
            
        except Exception as e:
            logger.warning(f"Payload test failed: {str(e)}")
            return None
    
    def _analyze_response_for_vulnerability(self, response: aiohttp.ClientResponse, content: str, payload: DASTPayload, response_time: float) -> bool:
        """Analyze response to determine if vulnerability exists"""
        
        # SQL Injection detection
        if payload.vuln_type == "sqli":
            sql_error_patterns = [
                r"sql syntax.*mysql",
                r"warning.*mysql",
                r"mysql.*error",
                r"sql syntax.*mariadb",
                r"oracle.*error",
                r"postgresql.*error",
                r"sql server.*error",
                r"sqlite.*error"
            ]
            
            for pattern in sql_error_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            # Time-based detection
            if response_time > 5.0:  # Suspicious delay
                return True
        
        # XSS detection
        elif payload.vuln_type == "xss":
            # Check if payload is reflected in response
            if payload.payload in content:
                return True
        
        # Command Injection detection
        elif payload.vuln_type == "cmdi":
            # Check for command output in response
            cmd_output_patterns = [
                r"root:.*:0:0:",
                r"uid=\d+",
                r"gid=\d+",
                r"total \d+",
                r"drwx"
            ]
            
            for pattern in cmd_output_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            # Time-based detection
            if response_time > 3.0:
                return True
        
        return False
    
    async def _generate_scan_report(self) -> Dict[str, Any]:
        """Generate scan report"""
        logger.info("Generating scan report")
        
        # Calculate statistics
        total_vulns = len(self.vulnerabilities)
        critical_vulns = len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL])
        high_vulns = len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH])
        medium_vulns = len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM])
        low_vulns = len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.LOW])
        
        # Calculate security score
        security_score = max(0, 100 - (critical_vulns * 20 + high_vulns * 10 + medium_vulns * 5 + low_vulns * 2))
        
        report = {
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "target_url": self.target_url,
            "scan_duration": time.time(),  # This should be calculated from start time
            "urls_scanned": len(self.discovered_urls),
            "vulnerabilities_found": total_vulns,
            "security_score": security_score,
            "vulnerabilities_by_severity": {
                "critical": critical_vulns,
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns
            },
            "vulnerabilities_by_type": self._group_vulnerabilities_by_type(),
            "recommendations": self._generate_recommendations(),
            "generated_at": datetime.utcnow().isoformat()
        }
        
        return report
    
    def _group_vulnerabilities_by_type(self) -> Dict[str, int]:
        """Group vulnerabilities by type"""
        grouped = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vuln_type or "unknown"
            grouped[vuln_type] = grouped.get(vuln_type, 0) + 1
        return grouped
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]
        if critical_vulns:
            recommendations.append("Immediately address all critical vulnerabilities")
        
        # Check for SQL injection
        sqli_vulns = [v for v in self.vulnerabilities if v.vuln_type == "sqli"]
        if sqli_vulns:
            recommendations.append("Implement parameterized queries to prevent SQL injection")
        
        # Check for XSS
        xss_vulns = [v for v in self.vulnerabilities if v.vuln_type == "xss"]
        if xss_vulns:
            recommendations.append("Implement proper input validation and output encoding")
        
        # Check for missing security headers
        header_vulns = [v for v in self.vulnerabilities if v.vuln_type == "security_headers"]
        if header_vulns:
            recommendations.append("Implement security headers (CSP, HSTS, X-Frame-Options, etc.)")
        
        return recommendations
    
    async def _save_vulnerabilities(self):
        """Save vulnerabilities to database"""
        logger.info(f"Saving {len(self.vulnerabilities)} vulnerabilities to database")
        
        for vuln in self.vulnerabilities:
            db_vuln = DASTVulnerability(
                scan_id=self.scan_id,
                project_id=self.project_id,
                title=vuln.title,
                description=vuln.description,
                severity=vuln.severity,
                url=vuln.url,
                http_method=vuln.http_method,
                param_name=vuln.param_name,
                vuln_type=vuln.vuln_type,
                payload=vuln.payload,
                cwe_id=vuln.cwe_id,
                owasp_category=vuln.owasp_category,
                evidence=vuln.evidence,
                response_code=vuln.response_code,
                response_time=vuln.response_time
            )
            self.session.add(db_vuln)
        
        await self.session.commit()
    
    async def _finalize_scan(self, scan_results: Dict[str, Any]):
        """Finalize the scan and update database"""
        scan = await DASTScan.get_by_id(self.session, self.scan_id)
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.vulnerabilities_found = scan_results["vulnerabilities_found"]
            scan.urls_scanned = scan_results["urls_scanned"]
            scan.scan_duration = scan_results["scan_duration"]
            scan.scan_summary = scan_results
            
            await self.session.commit()
        
        logger.info(f"Scan {self.scan_id} completed successfully")
    
    async def _mark_scan_failed(self, error_message: str):
        """Mark scan as failed"""
        scan = await DASTScan.get_by_id(self.session, self.scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            scan.scan_summary = {"error": error_message}
            await self.session.commit() 