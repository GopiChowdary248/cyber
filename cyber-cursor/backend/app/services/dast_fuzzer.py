"""
DAST Fuzzer Module
Parameter fuzzing and mutation testing capabilities
"""

import asyncio
import random
import string
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging
import re

logger = logging.getLogger(__name__)

class FuzzerType(str, Enum):
    PARAMETER = "parameter"
    HEADER = "header"
    COOKIE = "cookie"
    JSON = "json"
    XML = "xml"

@dataclass
class FuzzTarget:
    url: str
    method: str
    parameters: Dict[str, Any]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: Optional[str] = None

@dataclass
class FuzzResult:
    target: FuzzTarget
    mutation: Dict[str, Any]
    response_code: int
    response_time: float
    response_size: int
    anomalies: List[Dict[str, Any]]
    timestamp: float

class DASTFuzzer:
    """DAST Fuzzer for parameter testing and mutation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mutation_patterns = self._load_mutation_patterns()
        self.anomaly_detectors = self._load_anomaly_detectors()
        
    def _load_mutation_patterns(self) -> Dict[str, List[str]]:
        """Load mutation patterns for fuzzing"""
        return {
            "empty_values": ["", "null", "undefined", "None"],
            "numeric_values": ["0", "-1", "999999999", "1.1", "-1.1", "0.0"],
            "boolean_values": ["true", "false", "True", "False", "1", "0"],
            "special_characters": ["'", '"', "\\", "<", ">", "&", "|", ";", "`"],
            "path_traversal": ["../", "..\\", "....//", "%2e%2e%2f", "..%252F"],
            "encoding": ["%00", "%0a", "%0d", "%20", "%3c", "%3e"],
            "long_strings": ["a" * 1000, "a" * 10000, "a" * 100000],
            "unicode": ["\u0000", "\u0001", "\u00ff", "\uffff"],
            "sql_injection": ["' OR 1=1 --", "'; DROP TABLE users--", "' UNION SELECT NULL--"],
            "xss": ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"],
            "command_injection": ["; sleep 5 #", "| sleep 5", "& sleep 5"],
            "ssrf": ["http://169.254.169.254/", "http://127.0.0.1:22"],
            "open_redirect": ["https://evil.com", "//evil.com", "javascript:alert('redirect')"],
            "json_injection": ['{"key": "value"}', '{"key": null}', '{"key": []}'],
            "xml_injection": ["<xml>test</xml>", "<?xml version='1.0'?>", "<!DOCTYPE test>"]
        }
    
    def _load_anomaly_detectors(self) -> Dict[str, callable]:
        """Load anomaly detection functions"""
        return {
            "response_code": self._detect_response_code_anomaly,
            "response_time": self._detect_response_time_anomaly,
            "response_size": self._detect_response_size_anomaly,
            "error_patterns": self._detect_error_patterns,
            "information_disclosure": self._detect_information_disclosure
        }
    
    async def fuzz_target(self, target: FuzzTarget, session) -> List[FuzzResult]:
        """Main fuzzing method"""
        logger.info(f"Starting fuzzing for target: {target.url}")
        
        results = []
        mutations = self._generate_mutations(target)
        
        for mutation in mutations:
            try:
                result = await self._apply_mutation(target, mutation, session)
                if result:
                    results.append(result)
                    
                # Rate limiting
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.warning(f"Fuzzing mutation failed: {str(e)}")
        
        return results
    
    def _generate_mutations(self, target: FuzzTarget) -> List[Dict[str, Any]]:
        """Generate mutations for the target"""
        mutations = []
        
        # Parameter mutations
        if target.parameters:
            for param_name, param_value in target.parameters.items():
                param_mutations = self._generate_parameter_mutations(param_name, param_value)
                mutations.extend(param_mutations)
        
        # Header mutations
        if target.headers:
            for header_name, header_value in target.headers.items():
                header_mutations = self._generate_header_mutations(header_name, header_value)
                mutations.extend(header_mutations)
        
        # Cookie mutations
        if target.cookies:
            for cookie_name, cookie_value in target.cookies.items():
                cookie_mutations = self._generate_cookie_mutations(cookie_name, cookie_value)
                mutations.extend(cookie_mutations)
        
        # Body mutations
        if target.body:
            body_mutations = self._generate_body_mutations(target.body)
            mutations.extend(body_mutations)
        
        return mutations
    
    def _generate_parameter_mutations(self, param_name: str, param_value: Any) -> List[Dict[str, Any]]:
        """Generate parameter mutations"""
        mutations = []
        
        # Basic value mutations
        for pattern_name, patterns in self.mutation_patterns.items():
            for pattern in patterns:
                mutations.append({
                    "type": FuzzerType.PARAMETER,
                    "target": param_name,
                    "original_value": str(param_value),
                    "mutation": pattern,
                    "description": f"Parameter {param_name}: {pattern_name} mutation"
                })
        
        # Type-specific mutations
        if isinstance(param_value, (int, float)):
            mutations.extend(self._generate_numeric_mutations(param_name, param_value))
        elif isinstance(param_value, str):
            mutations.extend(self._generate_string_mutations(param_name, param_value))
        elif isinstance(param_value, bool):
            mutations.extend(self._generate_boolean_mutations(param_name, param_value))
        
        return mutations
    
    def _generate_numeric_mutations(self, param_name: str, value: Any) -> List[Dict[str, Any]]:
        """Generate numeric-specific mutations"""
        mutations = []
        
        numeric_mutations = [
            str(value + 1),
            str(value - 1),
            str(value * 2),
            str(value / 2),
            str(-value),
            str(float('inf')),
            str(float('-inf')),
            "NaN"
        ]
        
        for mutation in numeric_mutations:
            mutations.append({
                "type": FuzzerType.PARAMETER,
                "target": param_name,
                "original_value": str(value),
                "mutation": mutation,
                "description": f"Parameter {param_name}: numeric mutation"
            })
        
        return mutations
    
    def _generate_string_mutations(self, param_name: str, value: str) -> List[Dict[str, Any]]:
        """Generate string-specific mutations"""
        mutations = []
        
        string_mutations = [
            value.upper(),
            value.lower(),
            value[::-1],  # Reverse
            value * 2,  # Duplicate
            value.replace("a", "A"),
            value.replace("e", "3"),
            value.replace("i", "1"),
            value.replace("o", "0"),
            value.replace("s", "5"),
            value + "'; DROP TABLE users--",
            value + "<script>alert('xss')</script>",
            value + "../../../etc/passwd"
        ]
        
        for mutation in string_mutations:
            mutations.append({
                "type": FuzzerType.PARAMETER,
                "target": param_name,
                "original_value": value,
                "mutation": mutation,
                "description": f"Parameter {param_name}: string mutation"
            })
        
        return mutations
    
    def _generate_boolean_mutations(self, param_name: str, value: bool) -> List[Dict[str, Any]]:
        """Generate boolean-specific mutations"""
        mutations = []
        
        boolean_mutations = [
            not value,
            str(value).lower(),
            str(value).upper(),
            "1" if value else "0",
            "true" if value else "false",
            "yes" if value else "no",
            "on" if value else "off"
        ]
        
        for mutation in boolean_mutations:
            mutations.append({
                "type": FuzzerType.PARAMETER,
                "target": param_name,
                "original_value": str(value),
                "mutation": str(mutation),
                "description": f"Parameter {param_name}: boolean mutation"
            })
        
        return mutations
    
    def _generate_header_mutations(self, header_name: str, header_value: str) -> List[Dict[str, Any]]:
        """Generate header mutations"""
        mutations = []
        
        # Common header injection patterns
        header_mutations = [
            header_value + "\r\nX-Forwarded-For: 127.0.0.1",
            header_value + "\r\nX-Forwarded-Host: evil.com",
            header_value + "\r\nX-Original-URL: /admin",
            header_value + "\r\nX-Rewrite-URL: /admin",
            header_value + "\r\nX-Custom-IP-Authorization: 127.0.0.1"
        ]
        
        for mutation in header_mutations:
            mutations.append({
                "type": FuzzerType.HEADER,
                "target": header_name,
                "original_value": header_value,
                "mutation": mutation,
                "description": f"Header {header_name}: injection mutation"
            })
        
        return mutations
    
    def _generate_cookie_mutations(self, cookie_name: str, cookie_value: str) -> List[Dict[str, Any]]:
        """Generate cookie mutations"""
        mutations = []
        
        cookie_mutations = [
            cookie_value + "; Path=/admin",
            cookie_value + "; Domain=evil.com",
            cookie_value + "; HttpOnly=false",
            cookie_value + "; Secure=false",
            cookie_value + "; SameSite=None"
        ]
        
        for mutation in cookie_mutations:
            mutations.append({
                "type": FuzzerType.COOKIE,
                "target": cookie_name,
                "original_value": cookie_value,
                "mutation": mutation,
                "description": f"Cookie {cookie_name}: attribute mutation"
            })
        
        return mutations
    
    def _generate_body_mutations(self, body: str) -> List[Dict[str, Any]]:
        """Generate body mutations"""
        mutations = []
        
        # JSON body mutations
        if body.strip().startswith('{'):
            json_mutations = self._generate_json_mutations(body)
            mutations.extend(json_mutations)
        
        # XML body mutations
        elif body.strip().startswith('<'):
            xml_mutations = self._generate_xml_mutations(body)
            mutations.extend(xml_mutations)
        
        # Form data mutations
        else:
            form_mutations = self._generate_form_mutations(body)
            mutations.extend(form_mutations)
        
        return mutations
    
    def _generate_json_mutations(self, json_body: str) -> List[Dict[str, Any]]:
        """Generate JSON body mutations"""
        mutations = []
        
        try:
            import json
            data = json.loads(json_body)
            
            # Type mutations for JSON values
            for key, value in data.items():
                if isinstance(value, str):
                    mutations.append({
                        "type": FuzzerType.JSON,
                        "target": key,
                        "original_value": value,
                        "mutation": value + "<script>alert('xss')</script>",
                        "description": f"JSON field {key}: XSS injection"
                    })
                elif isinstance(value, (int, float)):
                    mutations.append({
                        "type": FuzzerType.JSON,
                        "target": key,
                        "original_value": str(value),
                        "mutation": str(value) + "' OR 1=1 --",
                        "description": f"JSON field {key}: SQL injection"
                    })
        
        except json.JSONDecodeError:
            pass
        
        return mutations
    
    def _generate_xml_mutations(self, xml_body: str) -> List[Dict[str, Any]]:
        """Generate XML body mutations"""
        mutations = []
        
        # XXE injection patterns
        xxe_patterns = [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]><foo>&xxe;</foo>'
        ]
        
        for pattern in xxe_patterns:
            mutations.append({
                "type": FuzzerType.XML,
                "target": "xml_body",
                "original_value": xml_body,
                "mutation": pattern,
                "description": "XML body: XXE injection"
            })
        
        return mutations
    
    def _generate_form_mutations(self, form_body: str) -> List[Dict[str, Any]]:
        """Generate form data mutations"""
        mutations = []
        
        # Form injection patterns
        form_patterns = [
            form_body + "&injected=test",
            form_body + "&admin=true",
            form_body + "&debug=1"
        ]
        
        for pattern in form_patterns:
            mutations.append({
                "type": FuzzerType.PARAMETER,
                "target": "form_body",
                "original_value": form_body,
                "mutation": pattern,
                "description": "Form body: parameter injection"
            })
        
        return mutations
    
    async def _apply_mutation(self, target: FuzzTarget, mutation: Dict[str, Any], session) -> Optional[FuzzResult]:
        """Apply mutation to target and make request"""
        try:
            import time
            
            # Create mutated target
            mutated_target = self._create_mutated_target(target, mutation)
            
            # Make request
            start_time = time.time()
            
            async with session.request(
                method=mutated_target.method,
                url=mutated_target.url,
                headers=mutated_target.headers,
                data=mutated_target.body, # Changed from mutated_target.data to mutated_target.body
                cookies=mutated_target.cookies
            ) as response:
                
                response_time = time.time() - start_time
                response_body = await response.text()
                response_size = len(response_body)
                
                # Detect anomalies
                anomalies = self._detect_anomalies(
                    response.status,
                    response_time,
                    response_size,
                    response_body,
                    mutation
                )
                
                result = FuzzResult(
                    target=target,
                    mutation=mutation,
                    response_code=response.status,
                    response_time=response_time,
                    response_size=response_size,
                    anomalies=anomalies,
                    timestamp=time.time()
                )
                
                return result
                
        except Exception as e:
            logger.error(f"Failed to apply mutation: {str(e)}")
            return None
    
    def _create_mutated_target(self, target: FuzzTarget, mutation: Dict[str, Any]) -> FuzzTarget:
        """Create mutated target based on mutation"""
        import copy
        from urllib.parse import urlencode, parse_qs, urlparse
        
        mutated_target = copy.deepcopy(target)
        
        if mutation["type"] == FuzzerType.PARAMETER:
            # Mutate URL parameters
            if target.parameters:
                mutated_params = target.parameters.copy()
                mutated_params[mutation["target"]] = mutation["mutation"]
                
                # Reconstruct URL with mutated parameters
                parsed_url = urlparse(target.url)
                query_params = parse_qs(parsed_url.query)
                
                # Update query parameters
                for key, value in mutated_params.items():
                    if isinstance(value, (list, tuple)):
                        query_params[key] = value
                    else:
                        query_params[key] = [str(value)]
                
                new_query = urlencode(query_params, doseq=True)
                mutated_target.url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        elif mutation["type"] == FuzzerType.HEADER:
            # Mutate headers
            if target.headers:
                mutated_target.headers = target.headers.copy()
                mutated_target.headers[mutation["target"]] = mutation["mutation"]
        
        elif mutation["type"] == FuzzerType.COOKIE:
            # Mutate cookies
            if target.cookies:
                mutated_target.cookies = target.cookies.copy()
                mutated_target.cookies[mutation["target"]] = mutation["mutation"]
        
        elif mutation["type"] in [FuzzerType.JSON, FuzzerType.XML]:
            # Mutate request body
            mutated_target.body = mutation["mutation"]
        
        return mutated_target
    
    def _detect_anomalies(self, response_code: int, response_time: float, 
                         response_size: int, response_body: str, 
                         mutation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in response"""
        anomalies = []
        
        # Check each anomaly detector
        for detector_name, detector_func in self.anomaly_detectors.items():
            try:
                detector_anomalies = detector_func(
                    response_code, response_time, response_size, 
                    response_body, mutation
                )
                anomalies.extend(detector_anomalies)
            except Exception as e:
                logger.warning(f"Anomaly detector {detector_name} failed: {str(e)}")
        
        return anomalies
    
    def _detect_response_code_anomaly(self, response_code: int, response_time: float,
                                    response_size: int, response_body: str,
                                    mutation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect response code anomalies"""
        anomalies = []
        
        # Server errors
        if response_code >= 500:
            anomalies.append({
                "type": "server_error",
                "severity": "medium",
                "description": f"Server error (5xx) for mutation: {mutation.get('description', 'Unknown')}",
                "response_code": response_code
            })
        
        # Client errors (but not 404 which might be expected)
        elif response_code >= 400 and response_code != 404:
            anomalies.append({
                "type": "client_error",
                "severity": "low",
                "description": f"Client error (4xx) for mutation: {mutation.get('description', 'Unknown')}",
                "response_code": response_code
            })
        
        return anomalies
    
    def _detect_response_time_anomaly(self, response_code: int, response_time: float,
                                    response_size: int, response_body: str,
                                    mutation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect response time anomalies"""
        anomalies = []
        
        # Slow response (potential DoS or processing issue)
        if response_time > 5.0:
            anomalies.append({
                "type": "slow_response",
                "severity": "medium",
                "description": f"Slow response time ({response_time:.2f}s) for mutation: {mutation.get('description', 'Unknown')}",
                "response_time": response_time
            })
        
        # Very fast response (potential caching or bypass)
        elif response_time < 0.1:
            anomalies.append({
                "type": "fast_response",
                "severity": "low",
                "description": f"Very fast response time ({response_time:.3f}s) for mutation: {mutation.get('description', 'Unknown')}",
                "response_time": response_time
            })
        
        return anomalies
    
    def _detect_response_size_anomaly(self, response_code: int, response_time: float,
                                    response_size: int, response_body: str,
                                    mutation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect response size anomalies"""
        anomalies = []
        
        # Large response (potential information disclosure)
        if response_size > 1000000:  # 1MB
            anomalies.append({
                "type": "large_response",
                "severity": "medium",
                "description": f"Large response size ({response_size} bytes) for mutation: {mutation.get('description', 'Unknown')}",
                "response_size": response_size
            })
        
        # Very small response (potential error or bypass)
        elif response_size < 100:
            anomalies.append({
                "type": "small_response",
                "severity": "low",
                "description": f"Very small response size ({response_size} bytes) for mutation: {mutation.get('description', 'Unknown')}",
                "response_size": response_size
            })
        
        return anomalies
    
    def _detect_error_patterns(self, response_code: int, response_time: float,
                             response_size: int, response_body: str,
                             mutation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect error patterns in response"""
        anomalies = []
        
        error_patterns = [
            (r'error in your sql syntax', 'SQL Error'),
            (r'stack trace:', 'Stack Trace'),
            (r'debug.*mode', 'Debug Mode'),
            (r'fatal error', 'Fatal Error'),
            (r'exception.*occurred', 'Exception'),
            (r'warning.*mysql', 'MySQL Warning'),
            (r'oracle.*error', 'Oracle Error'),
            (r'postgresql.*error', 'PostgreSQL Error'),
            (r'asp\.net.*error', 'ASP.NET Error'),
            (r'php.*fatal error', 'PHP Fatal Error')
        ]
        
        for pattern, error_type in error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                anomalies.append({
                    "type": "error_pattern",
                    "severity": "high",
                    "description": f"{error_type} detected for mutation: {mutation.get('description', 'Unknown')}",
                    "error_type": error_type,
                    "pattern": pattern
                })
        
        return anomalies
    
    def _detect_information_disclosure(self, response_code: int, response_time: float,
                                     response_size: int, response_body: str,
                                     mutation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect information disclosure"""
        anomalies = []
        
        disclosure_patterns = [
            (r'version.*\d+\.\d+\.\d+', 'Version Information'),
            (r'build.*\d+', 'Build Information'),
            (r'config.*file', 'Configuration File'),
            (r'database.*connection', 'Database Connection'),
            (r'password.*=.*["\'][^"\']+["\']', 'Hardcoded Password'),
            (r'api.*key.*=.*["\'][^"\']+["\']', 'API Key'),
            (r'secret.*=.*["\'][^"\']+["\']', 'Secret Key'),
            (r'private.*key', 'Private Key'),
            (r'aws.*access.*key', 'AWS Access Key'),
            (r'google.*api.*key', 'Google API Key')
        ]
        
        for pattern, disclosure_type in disclosure_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                anomalies.append({
                    "type": "information_disclosure",
                    "severity": "high",
                    "description": f"{disclosure_type} disclosure for mutation: {mutation.get('description', 'Unknown')}",
                    "disclosure_type": disclosure_type,
                    "pattern": pattern
                })
        
        return anomalies 