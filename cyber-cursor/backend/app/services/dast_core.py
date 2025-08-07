"""
Core DAST Scanner Engine
Essential scanning capabilities for DAST tool
"""

import asyncio
import aiohttp
import json
import re
import time
import uuid
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ScanPhase(str, Enum):
    SPIDER = "spider"
    PASSIVE = "passive"
    ACTIVE = "active"
    FUZZER = "fuzzer"

class VulnerabilityType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    LFI = "lfi"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"

@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    data: Dict[str, Any] = None
    cookies: Dict[str, str] = None

@dataclass
class ScanResult:
    target: ScanTarget
    response_code: int
    response_headers: Dict[str, str]
    response_body: str
    response_time: float
    vulnerabilities: List[Dict[str, Any]]
    scan_phase: ScanPhase
    timestamp: float

class DASTScanner:
    """Core DAST Scanner with essential capabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
        self.discovered_urls: Set[str] = set()
        self.scan_results: List[ScanResult] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.payloads = self._load_payloads()
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'DAST-Scanner/1.0'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load essential payload library"""
        return {
            VulnerabilityType.SQL_INJECTION: [
                "' OR 1=1 --",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR '1'='1"
            ],
            VulnerabilityType.XSS: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "; sleep 5 #",
                "| sleep 5",
                "& sleep 5"
            ],
            VulnerabilityType.LFI: [
                "../../../../../etc/passwd",
                "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ],
            VulnerabilityType.SSRF: [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:22"
            ]
        }
    
    async def scan_target(self, target_url: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Main scanning method"""
        logger.info(f"Starting DAST scan for: {target_url}")
        
        scan_start_time = time.time()
        scan_results = {
            "target_url": target_url,
            "scan_id": str(uuid.uuid4()),
            "start_time": scan_start_time,
            "phases": {},
            "vulnerabilities": [],
            "statistics": {
                "urls_discovered": 0,
                "requests_made": 0,
                "vulnerabilities_found": 0,
                "scan_duration": 0
            }
        }
        
        try:
            # Phase 1: Spider
            logger.info("Starting Spider phase...")
            spider_results = await self._spider_phase(target_url, scan_config)
            scan_results["phases"]["spider"] = spider_results
            scan_results["statistics"]["urls_discovered"] = len(self.discovered_urls)
            
            # Phase 2: Passive Scanner
            logger.info("Starting Passive Scanner phase...")
            passive_results = await self._passive_scan_phase()
            scan_results["phases"]["passive"] = passive_results
            
            # Phase 3: Active Scanner
            logger.info("Starting Active Scanner phase...")
            active_results = await self._active_scan_phase(scan_config)
            scan_results["phases"]["active"] = active_results
            
            # Compile results
            scan_results["vulnerabilities"] = self.vulnerabilities
            scan_results["statistics"]["vulnerabilities_found"] = len(self.vulnerabilities)
            scan_results["statistics"]["requests_made"] = len(self.scan_results)
            scan_results["statistics"]["scan_duration"] = time.time() - scan_start_time
            scan_results["end_time"] = time.time()
            
            logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
            return scan_results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            scan_results["error"] = str(e)
            return scan_results
    
    async def _spider_phase(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Spider phase to discover URLs"""
        spider_results = {
            "urls_discovered": [],
            "forms_discovered": [],
            "errors": []
        }
        
        try:
            await self._crawl_url(target_url, depth=0, max_depth=config.get("max_depth", 3))
            spider_results["urls_discovered"] = list(self.discovered_urls)
            
        except Exception as e:
            logger.error(f"Spider phase failed: {str(e)}")
            spider_results["errors"].append({"phase": "spider", "error": str(e)})
        
        return spider_results
    
    async def _crawl_url(self, url: str, depth: int, max_depth: int):
        """Recursively crawl URLs"""
        if depth > max_depth or url in self.discovered_urls:
            return
        
        self.discovered_urls.add(url)
        
        try:
            target = ScanTarget(url=url)
            result = await self._make_request(target)
            
            if result and result.response_code == 200:
                links = self._extract_links(result.response_body, url)
                
                for link in links:
                    if self._is_in_scope(link, url):
                        await self._crawl_url(link, depth + 1, max_depth)
                        
        except Exception as e:
            logger.warning(f"Failed to crawl {url}: {str(e)}")
    
    async def _passive_scan_phase(self) -> Dict[str, Any]:
        """Passive scanning phase"""
        passive_results = {
            "security_headers": [],
            "information_disclosure": [],
            "errors": []
        }
        
        for result in self.scan_results:
            try:
                security_headers = self._check_security_headers(result.response_headers)
                passive_results["security_headers"].extend(security_headers)
                
                info_disclosure = self._check_information_disclosure(result.response_body, result.target.url)
                passive_results["information_disclosure"].extend(info_disclosure)
                
            except Exception as e:
                passive_results["errors"].append({"url": result.target.url, "error": str(e)})
        
        return passive_results
    
    async def _active_scan_phase(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Active scanning phase"""
        active_results = {
            "vulnerabilities_found": [],
            "tests_performed": 0,
            "errors": []
        }
        
        targets = self._get_active_scan_targets()
        
        for target in targets:
            try:
                sqli_vulns = await self._test_sql_injection(target)
                active_results["vulnerabilities_found"].extend(sqli_vulns)
                
                xss_vulns = await self._test_xss(target)
                active_results["vulnerabilities_found"].extend(xss_vulns)
                
                active_results["tests_performed"] += 1
                
            except Exception as e:
                active_results["errors"].append({"target": target.url, "error": str(e)})
        
        return active_results
    
    async def _make_request(self, target: ScanTarget) -> Optional[ScanResult]:
        """Make HTTP request"""
        try:
            start_time = time.time()
            
            async with self.session.request(
                method=target.method,
                url=target.url,
                headers=target.headers,
                data=target.data,
                cookies=target.cookies
            ) as response:
                
                response_time = time.time() - start_time
                response_body = await response.text()
                
                result = ScanResult(
                    target=target,
                    response_code=response.status,
                    response_headers=dict(response.headers),
                    response_body=response_body,
                    response_time=response_time,
                    vulnerabilities=[],
                    scan_phase=ScanPhase.PASSIVE,
                    timestamp=time.time()
                )
                
                self.scan_results.append(result)
                return result
                
        except Exception as e:
            logger.error(f"Request failed for {target.url}: {str(e)}")
            return None
    
    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        href_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            absolute_url = urljoin(base_url, match)
            if self._is_valid_url(absolute_url):
                links.append(absolute_url)
        
        return links
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_in_scope(self, url: str, base_url: str) -> bool:
        """Check if URL is in scope"""
        try:
            base_domain = urlparse(base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain
        except:
            return False
    
    def _check_security_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check security headers"""
        issues = []
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        for header in required_headers:
            if header not in headers:
                issues.append({
                    "type": "missing_security_header",
                    "header": header,
                    "severity": "medium",
                    "description": f"Missing security header: {header}"
                })
        
        return issues
    
    def _check_information_disclosure(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """Check for information disclosure"""
        issues = []
        
        sensitive_patterns = [
            (r'error in your sql syntax', 'SQL Error'),
            (r'stack trace:', 'Stack Trace'),
            (r'debug.*mode', 'Debug Mode'),
            (r'version.*\d+\.\d+\.\d+', 'Version Information')
        ]
        
        for pattern, description in sensitive_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                issues.append({
                    "type": "information_disclosure",
                    "description": f"Potential {description} disclosure",
                    "severity": "medium",
                    "url": url
                })
        
        return issues
    
    async def _test_sql_injection(self, target: ScanTarget) -> List[Dict[str, Any]]:
        """Test for SQL injection"""
        vulnerabilities = []
        
        for payload in self.payloads[VulnerabilityType.SQL_INJECTION]:
            try:
                fuzzed_target = self._inject_payload(target, payload)
                result = await self._make_request(fuzzed_target)
                
                if result and self._detect_sql_injection(result, payload):
                    vulnerabilities.append({
                        "type": VulnerabilityType.SQL_INJECTION,
                        "url": target.url,
                        "payload": payload,
                        "severity": "critical",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021-Injection"
                    })
                    
            except Exception as e:
                logger.warning(f"SQL injection test failed: {str(e)}")
        
        return vulnerabilities
    
    async def _test_xss(self, target: ScanTarget) -> List[Dict[str, Any]]:
        """Test for XSS"""
        vulnerabilities = []
        
        for payload in self.payloads[VulnerabilityType.XSS]:
            try:
                fuzzed_target = self._inject_payload(target, payload)
                result = await self._make_request(fuzzed_target)
                
                if result and self._detect_xss(result, payload):
                    vulnerabilities.append({
                        "type": VulnerabilityType.XSS,
                        "url": target.url,
                        "payload": payload,
                        "severity": "high",
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021-Injection"
                    })
                    
            except Exception as e:
                logger.warning(f"XSS test failed: {str(e)}")
        
        return vulnerabilities
    
    def _detect_sql_injection(self, result: ScanResult, payload: str) -> bool:
        """Detect SQL injection"""
        sql_errors = [
            "sql syntax",
            "mysql_fetch_array",
            "ora-",
            "postgresql",
            "sqlite"
        ]
        
        response_lower = result.response_body.lower()
        return any(error in response_lower for error in sql_errors)
    
    def _detect_xss(self, result: ScanResult, payload: str) -> bool:
        """Detect XSS"""
        return payload in result.response_body
    
    def _inject_payload(self, target: ScanTarget, payload: str) -> ScanTarget:
        """Inject payload"""
        if target.data:
            fuzzed_data = target.data.copy()
            for key in fuzzed_data:
                if isinstance(fuzzed_data[key], str):
                    fuzzed_data[key] = payload
            return ScanTarget(
                url=target.url,
                method=target.method,
                headers=target.headers,
                data=fuzzed_data,
                cookies=target.cookies
            )
        else:
            parsed_url = urlparse(target.url)
            params = parse_qs(parsed_url.query)
            fuzzed_params = {}
            for key, values in params.items():
                fuzzed_params[key] = [payload]
            
            from urllib.parse import urlencode
            fuzzed_query = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{fuzzed_query}"
            
            return ScanTarget(
                url=fuzzed_url,
                method=target.method,
                headers=target.headers,
                cookies=target.cookies
            )
    
    def _get_active_scan_targets(self) -> List[ScanTarget]:
        """Get targets for active scanning"""
        targets = []
        for url in self.discovered_urls:
            targets.append(ScanTarget(url=url))
        return targets 