import subprocess
import json
import os
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class Vulnerability:
    def __init__(self, file_path: str, line_no: int, column_no: Optional[int], 
                 vulnerability: str, severity: str, recommendation: str, 
                 tool_name: str, cwe_id: Optional[str] = None, confidence: str = "medium"):
        self.file_path = file_path
        self.line_no = line_no
        self.column_no = column_no
        self.vulnerability = vulnerability
        self.severity = severity
        self.recommendation = recommendation
        self.tool_name = tool_name
        self.cwe_id = cwe_id
        self.confidence = confidence

class SASTScanner:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.temp_dir = None
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def detect_languages(self) -> List[str]:
        """Detect programming languages in the project"""
        languages = []
        
        # Check for Python files
        if list(self.project_path.rglob("*.py")):
            languages.append("python")
            
        # Check for JavaScript/TypeScript files
        if (list(self.project_path.rglob("*.js")) or 
            list(self.project_path.rglob("*.jsx")) or
            list(self.project_path.rglob("*.ts")) or
            list(self.project_path.rglob("*.tsx"))):
            languages.append("javascript")
            
        # Check for package.json for Node.js projects
        if (self.project_path / "package.json").exists():
            languages.append("javascript")
            
        return languages
    
    def scan_project(self, scan_type: str = "full") -> List[Vulnerability]:
        """Run comprehensive SAST scan on the project"""
        vulnerabilities = []
        languages = self.detect_languages()
        
        logger.info(f"Detected languages: {languages}")
        logger.info(f"Starting {scan_type} scan on {self.project_path}")
        
        # Run appropriate tools based on detected languages
        if "python" in languages:
            logger.info("Running Python security tools...")
            vulnerabilities.extend(self._run_bandit_scan())
            vulnerabilities.extend(self._run_semgrep_scan())
            vulnerabilities.extend(self._run_pylint_scan())
            
        if "javascript" in languages:
            logger.info("Running JavaScript security tools...")
            vulnerabilities.extend(self._run_eslint_scan())
            vulnerabilities.extend(self._run_semgrep_js_scan())
            
        # Remove duplicates and sort by severity
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        vulnerabilities.sort(key=lambda x: self._severity_score(x.severity), reverse=True)
        
        logger.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_bandit_scan(self) -> List[Vulnerability]:
        """Run Bandit security scan for Python"""
        vulnerabilities = []
        try:
            result = subprocess.run(
                ["bandit", "-r", str(self.project_path), "-f", "json", "-q"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.returncode == 1:  # Bandit returns 1 when issues found
                data = json.loads(result.stdout)
                for issue in data.get("results", []):
                    vuln = Vulnerability(
                        file_path=issue.get("filename", ""),
                        line_no=issue.get("line_number"),
                        column_no=None,
                        vulnerability=issue.get("issue_text", ""),
                        severity=self._map_bandit_severity(issue.get("issue_severity", "medium")),
                        recommendation=issue.get("more_info", ""),
                        tool_name="bandit",
                        cwe_id=issue.get("cwe", {}).get("id") if issue.get("cwe") else None,
                        confidence="high"
                    )
                    vulnerabilities.append(vuln)
                    
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
        except Exception as e:
            logger.error(f"Error running Bandit scan: {e}")
            
        return vulnerabilities
    
    def _run_semgrep_scan(self) -> List[Vulnerability]:
        """Run Semgrep scan for Python"""
        vulnerabilities = []
        try:
            result = subprocess.run(
                ["semgrep", "--config=p/owasp-top-ten", str(self.project_path), "--json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.returncode == 1:  # Semgrep returns 1 when issues found
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    vuln = Vulnerability(
                        file_path=finding.get("path", ""),
                        line_no=finding.get("start", {}).get("line"),
                        column_no=finding.get("start", {}).get("col"),
                        vulnerability=finding.get("message", ""),
                        severity=self._map_semgrep_severity(finding.get("extra", {}).get("severity", "medium")),
                        recommendation=finding.get("extra", {}).get("message", ""),
                        tool_name="semgrep",
                        cwe_id=finding.get("extra", {}).get("metadata", {}).get("cwe_id"),
                        confidence="high"
                    )
                    vulnerabilities.append(vuln)
                    
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
        except Exception as e:
            logger.error(f"Error running Semgrep scan: {e}")
            
        return vulnerabilities
    
    def _run_pylint_scan(self) -> List[Vulnerability]:
        """Run Pylint scan for Python code quality and security"""
        vulnerabilities = []
        try:
            result = subprocess.run(
                ["pylint", "--output-format=json", str(self.project_path)],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.returncode == 1:  # Pylint returns 1 when issues found
                data = json.loads(result.stdout)
                for issue in data:
                    # Focus on security-related issues
                    if self._is_security_related_pylint(issue.get("message-id", "")):
                        vuln = Vulnerability(
                            file_path=issue.get("path", ""),
                            line_no=issue.get("line"),
                            column_no=issue.get("column"),
                            vulnerability=issue.get("message", ""),
                            severity=self._map_pylint_severity(issue.get("type", "convention")),
                            recommendation=issue.get("message", ""),
                            tool_name="pylint",
                            cwe_id=None,
                            confidence="medium"
                        )
                        vulnerabilities.append(vuln)
                        
        except subprocess.TimeoutExpired:
            logger.error("Pylint scan timed out")
        except Exception as e:
            logger.error(f"Error running Pylint scan: {e}")
            
        return vulnerabilities
    
    def _run_eslint_scan(self) -> List[Vulnerability]:
        """Run ESLint scan for JavaScript/TypeScript"""
        vulnerabilities = []
        try:
            # Check if ESLint is available
            result = subprocess.run(
                ["npx", "eslint", "--version"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.warning("ESLint not available, skipping JavaScript scan")
                return vulnerabilities
            
            # Run ESLint with security rules
            result = subprocess.run(
                ["npx", "eslint", str(self.project_path), "--format=json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.returncode == 1:  # ESLint returns 1 when issues found
                data = json.loads(result.stdout)
                for file_issues in data:
                    for issue in file_issues.get("messages", []):
                        if self._is_security_related_eslint(issue.get("ruleId", "")):
                            vuln = Vulnerability(
                                file_path=file_issues.get("filePath", ""),
                                line_no=issue.get("line"),
                                column_no=issue.get("column"),
                                vulnerability=issue.get("message", ""),
                                severity=self._map_eslint_severity(issue.get("severity", 1)),
                                recommendation=issue.get("message", ""),
                                tool_name="eslint",
                                cwe_id=None,
                                confidence="medium"
                            )
                            vulnerabilities.append(vuln)
                            
        except subprocess.TimeoutExpired:
            logger.error("ESLint scan timed out")
        except Exception as e:
            logger.error(f"Error running ESLint scan: {e}")
            
        return vulnerabilities
    
    def _run_semgrep_js_scan(self) -> List[Vulnerability]:
        """Run Semgrep scan specifically for JavaScript/TypeScript"""
        vulnerabilities = []
        try:
            result = subprocess.run(
                ["semgrep", "--config=p/owasp-top-ten", "--config=p/javascript", str(self.project_path), "--json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 or result.returncode == 1:
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    vuln = Vulnerability(
                        file_path=finding.get("path", ""),
                        line_no=finding.get("start", {}).get("line"),
                        column_no=finding.get("start", {}).get("col"),
                        vulnerability=finding.get("message", ""),
                        severity=self._map_semgrep_severity(finding.get("extra", {}).get("severity", "medium")),
                        recommendation=finding.get("extra", {}).get("message", ""),
                        tool_name="semgrep",
                        cwe_id=finding.get("extra", {}).get("metadata", {}).get("cwe_id"),
                        confidence="high"
                    )
                    vulnerabilities.append(vuln)
                    
        except subprocess.TimeoutExpired:
            logger.error("Semgrep JavaScript scan timed out")
        except Exception as e:
            logger.error(f"Error running Semgrep JavaScript scan: {e}")
            
        return vulnerabilities
    
    def _map_bandit_severity(self, severity: str) -> str:
        """Map Bandit severity to standard severity levels"""
        mapping = {
            "low": "low",
            "medium": "medium", 
            "high": "high"
        }
        return mapping.get(severity.lower(), "medium")
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standard severity levels"""
        mapping = {
            "error": "high",
            "warning": "medium",
            "info": "low"
        }
        return mapping.get(severity.lower(), "medium")
    
    def _map_pylint_severity(self, severity: str) -> str:
        """Map Pylint severity to standard severity levels"""
        mapping = {
            "error": "high",
            "warning": "medium",
            "convention": "low",
            "refactor": "info"
        }
        return mapping.get(severity.lower(), "medium")
    
    def _map_eslint_severity(self, severity: int) -> str:
        """Map ESLint severity to standard severity levels"""
        mapping = {
            0: "info",
            1: "low",
            2: "high"
        }
        return mapping.get(severity, "medium")
    
    def _severity_score(self, severity: str) -> int:
        """Get numeric score for severity sorting"""
        scores = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
        return scores.get(severity.lower(), 0)
    
    def _is_security_related_pylint(self, message_id: str) -> bool:
        """Check if Pylint message is security-related"""
        security_codes = [
            "C0114",  # missing-module-docstring
            "C0115",  # missing-class-docstring
            "C0116",  # missing-function-docstring
            "W0621",  # redefined-outer-name
            "W0622",  # redefined-builtin
            "W0703",  # broad-except
            "W0702",  # bare-except
        ]
        return message_id in security_codes
    
    def _is_security_related_eslint(self, rule_id: str) -> bool:
        """Check if ESLint rule is security-related"""
        security_rules = [
            "no-eval",
            "no-implied-eval",
            "no-new-func",
            "no-script-url",
            "no-unsafe-finally",
            "no-unsafe-negation",
            "no-unsafe-optional-chaining",
            "no-unsafe-unary-negation",
            "security/detect-object-injection",
            "security/detect-non-literal-regexp",
            "security/detect-unsafe-regex",
        ]
        return any(rule in rule_id.lower() for rule in security_rules)
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities based on file, line, and description"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln.file_path, vuln.line_no, vuln.vulnerability[:100])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
                
        return unique_vulns

class SASTScanManager:
    """Manages SAST scanning operations"""
    
    @staticmethod
    def extract_uploaded_code(upload_path: str, project_id: int) -> str:
        """Extract uploaded ZIP file to temporary directory"""
        temp_dir = tempfile.mkdtemp(prefix=f"sast_scan_{project_id}_")
        
        with zipfile.ZipFile(upload_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            
        return temp_dir
    
    @staticmethod
    def cleanup_temp_directory(temp_dir: str):
        """Clean up temporary directory"""
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    
    @staticmethod
    def get_scan_progress(scan_id: int) -> Dict[str, Any]:
        """Get scan progress information"""
        # This would typically query the database for scan status
        # For now, return mock progress
        return {
            "scan_id": scan_id,
            "status": "running",
            "progress_percentage": 75.0,
            "files_scanned": 150,
            "total_files": 200,
            "current_tool": "semgrep",
            "estimated_completion": datetime.now().isoformat()
        } 