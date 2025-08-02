#!/usr/bin/env python3
"""
Static Code Analysis (SAST) Scanner Engine
Supports multiple languages and integrates various static analysis tools
"""

import os
import json
import subprocess
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    id: str
    file_name: str
    line_number: int
    column: Optional[int]
    severity: str  # critical, high, medium, low
    vulnerability_type: str
    description: str
    recommendation: str
    rule_id: str
    tool: str  # bandit, pylint, semgrep, etc.
    cwe_id: Optional[str]
    scan_date: datetime
    code_snippet: Optional[str]
    context: Optional[Dict[str, Any]]

class SASTScanner:
    """Main SAST scanning engine"""
    
    def __init__(self, project_path: str, scan_id: str):
        self.project_path = Path(project_path)
        self.scan_id = scan_id
        self.results: List[Vulnerability] = []
        self.scan_start_time = datetime.now()
        
        # Supported file extensions for each language
        self.language_extensions = {
            'python': ['.py', '.pyw'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'java': ['.java'],
            'php': ['.php'],
            'go': ['.go'],
            'csharp': ['.cs'],
            'ruby': ['.rb']
        }
        
        # Tool configurations
        self.tools = {
            'python': ['bandit', 'pylint', 'semgrep'],
            'javascript': ['eslint', 'semgrep'],
            'java': ['semgrep', 'spotbugs'],
            'php': ['semgrep', 'phpcs'],
            'go': ['semgrep', 'gosec'],
            'csharp': ['semgrep'],
            'ruby': ['semgrep', 'rubocop']
        }
    
    def detect_languages(self) -> List[str]:
        """Detect programming languages in the project"""
        detected_languages = set()
        
        for root, dirs, files in os.walk(self.project_path):
            # Skip common directories to ignore
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                file_path = Path(file)
                for lang, extensions in self.language_extensions.items():
                    if file_path.suffix.lower() in extensions:
                        detected_languages.add(lang)
        
        logger.info(f"Detected languages: {list(detected_languages)}")
        return list(detected_languages)
    
    async def scan_project(self) -> List[Vulnerability]:
        """Main scanning method"""
        logger.info(f"Starting SAST scan for project: {self.project_path}")
        
        # Detect languages
        languages = self.detect_languages()
        
        # Run scans for each detected language
        scan_tasks = []
        for language in languages:
            if language in self.tools:
                for tool in self.tools[language]:
                    scan_tasks.append(self.run_tool_scan(language, tool))
        
        # Execute all scans concurrently
        if scan_tasks:
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    self.results.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Scan failed: {result}")
        
        # Remove duplicates and sort by severity
        self.results = self.deduplicate_results()
        self.results.sort(key=lambda x: self.severity_to_numeric(x.severity), reverse=True)
        
        logger.info(f"Scan completed. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def run_tool_scan(self, language: str, tool: str) -> List[Vulnerability]:
        """Run a specific tool scan"""
        try:
            if tool == 'bandit' and language == 'python':
                return await self.run_bandit_scan()
            elif tool == 'pylint' and language == 'python':
                return await self.run_pylint_scan()
            elif tool == 'semgrep':
                return await self.run_semgrep_scan(language)
            elif tool == 'eslint' and language == 'javascript':
                return await self.run_eslint_scan()
            else:
                logger.warning(f"Tool {tool} for {language} not implemented yet")
                return []
        except Exception as e:
            logger.error(f"Error running {tool} scan: {e}")
            return []
    
    async def run_bandit_scan(self) -> List[Vulnerability]:
        """Run Bandit security scan for Python"""
        vulnerabilities = []
        
        try:
            # Run bandit command
            cmd = [
                'bandit', '-r', str(self.project_path),
                '-f', 'json', '--severity-level', 'all'
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0 or result.returncode == 1:  # Bandit returns 1 if issues found
                data = json.loads(stdout.decode())
                
                for issue in data.get('results', []):
                    vuln = Vulnerability(
                        id=f"bandit_{issue.get('test_id', 'unknown')}_{issue.get('line_number', 0)}",
                        file_name=issue.get('filename', ''),
                        line_number=issue.get('line_number', 0),
                        column=issue.get('col_offset'),
                        severity=self.map_bandit_severity(issue.get('issue_severity', 'medium')),
                        vulnerability_type=issue.get('issue_text', 'Security Issue'),
                        description=issue.get('issue_text', ''),
                        recommendation=issue.get('more_info', ''),
                        rule_id=issue.get('test_id', ''),
                        tool='bandit',
                        cwe_id=issue.get('cwe', {}).get('id') if issue.get('cwe') else None,
                        scan_date=datetime.now(),
                        code_snippet=issue.get('code', ''),
                        context={'confidence': issue.get('issue_confidence', 'medium')}
                    )
                    vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
        
        return vulnerabilities
    
    async def run_pylint_scan(self) -> List[Vulnerability]:
        """Run Pylint scan for Python code quality"""
        vulnerabilities = []
        
        try:
            # Run pylint command
            cmd = [
                'pylint', str(self.project_path),
                '--output-format=json',
                '--disable=all',
                '--enable=security,convention'
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if stdout:
                data = json.loads(stdout.decode())
                
                for issue in data:
                    # Filter for security-related issues
                    if self.is_security_related(issue.get('symbol', '')):
                        vuln = Vulnerability(
                            id=f"pylint_{issue.get('symbol', 'unknown')}_{issue.get('line', 0)}",
                            file_name=issue.get('path', ''),
                            line_number=issue.get('line', 0),
                            column=issue.get('column', 0),
                            severity=self.map_pylint_severity(issue.get('type', 'convention')),
                            vulnerability_type=issue.get('symbol', 'Code Quality Issue'),
                            description=issue.get('message', ''),
                            recommendation=self.get_pylint_recommendation(issue.get('symbol', '')),
                            rule_id=issue.get('symbol', ''),
                            tool='pylint',
                            cwe_id=None,
                            scan_date=datetime.now(),
                            code_snippet='',
                            context={'confidence': 'medium'}
                        )
                        vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.error(f"Pylint scan failed: {e}")
        
        return vulnerabilities
    
    async def run_semgrep_scan(self, language: str) -> List[Vulnerability]:
        """Run Semgrep scan for multiple languages"""
        vulnerabilities = []
        
        try:
            # Run semgrep command
            cmd = [
                'semgrep', 'scan',
                '--config=auto',
                '--json',
                '--output=/tmp/semgrep_results.json',
                str(self.project_path)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            # Read results from file
            if os.path.exists('/tmp/semgrep_results.json'):
                with open('/tmp/semgrep_results.json', 'r') as f:
                    data = json.load(f)
                
                for result in data.get('results', []):
                    vuln = Vulnerability(
                        id=f"semgrep_{result.get('check_id', 'unknown')}_{result.get('start', {}).get('line', 0)}",
                        file_name=result.get('path', ''),
                        line_number=result.get('start', {}).get('line', 0),
                        column=result.get('start', {}).get('col', 0),
                        severity=self.map_semgrep_severity(result.get('extra', {}).get('severity', 'WARNING')),
                        vulnerability_type=result.get('check_id', 'Security Issue'),
                        description=result.get('extra', {}).get('message', ''),
                        recommendation=result.get('extra', {}).get('fix', ''),
                        rule_id=result.get('check_id', ''),
                        tool='semgrep',
                        cwe_id=result.get('extra', {}).get('metadata', {}).get('cwe', [None])[0] if result.get('extra', {}).get('metadata', {}).get('cwe') else None,
                        scan_date=datetime.now(),
                        code_snippet=result.get('extra', {}).get('lines', ''),
                        context={'confidence': result.get('extra', {}).get('metadata', {}).get('confidence', 'medium')}
                    )
                    vulnerabilities.append(vuln)
                
                # Clean up
                os.remove('/tmp/semgrep_results.json')
            
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
        
        return vulnerabilities
    
    async def run_eslint_scan(self) -> List[Vulnerability]:
        """Run ESLint scan for JavaScript/TypeScript"""
        vulnerabilities = []
        
        try:
            # Check if package.json exists and install dependencies if needed
            package_json = self.project_path / 'package.json'
            if package_json.exists():
                # Install ESLint if not present
                await asyncio.create_subprocess_exec(
                    'npm', 'install', 'eslint', '--save-dev',
                    cwd=str(self.project_path)
                )
            
            # Run ESLint
            cmd = [
                'npx', 'eslint',
                '--format=json',
                '--ext=.js,.jsx,.ts,.tsx',
                str(self.project_path)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.project_path)
            )
            
            stdout, stderr = await result.communicate()
            
            if stdout:
                data = json.loads(stdout.decode())
                
                for file_result in data:
                    for message in file_result.get('messages', []):
                        if self.is_security_related_eslint(message.get('ruleId', '')):
                            vuln = Vulnerability(
                                id=f"eslint_{message.get('ruleId', 'unknown')}_{message.get('line', 0)}",
                                file_name=file_result.get('filePath', ''),
                                line_number=message.get('line', 0),
                                column=message.get('column', 0),
                                severity=self.map_eslint_severity(message.get('severity', 1)),
                                vulnerability_type=message.get('ruleId', 'Code Quality Issue'),
                                description=message.get('message', ''),
                                recommendation=message.get('fix', {}).get('text', '') if message.get('fix') else '',
                                rule_id=message.get('ruleId', ''),
                                tool='eslint',
                                cwe_id=None,
                                scan_date=datetime.now(),
                                code_snippet='',
                                context={'confidence': 'medium'}
                            )
                            vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.error(f"ESLint scan failed: {e}")
        
        return vulnerabilities
    
    def map_bandit_severity(self, severity: str) -> str:
        """Map Bandit severity to standard severity levels"""
        mapping = {
            'LOW': 'low',
            'MEDIUM': 'medium',
            'HIGH': 'high'
        }
        return mapping.get(severity.upper(), 'medium')
    
    def map_pylint_severity(self, severity: str) -> str:
        """Map Pylint severity to standard severity levels"""
        mapping = {
            'convention': 'low',
            'refactor': 'low',
            'warning': 'medium',
            'error': 'high',
            'fatal': 'critical'
        }
        return mapping.get(severity.lower(), 'medium')
    
    def map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standard severity levels"""
        mapping = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        return mapping.get(severity.upper(), 'medium')
    
    def map_eslint_severity(self, severity: int) -> str:
        """Map ESLint severity to standard severity levels"""
        mapping = {
            0: 'low',
            1: 'medium',
            2: 'high'
        }
        return mapping.get(severity, 'medium')
    
    def severity_to_numeric(self, severity: str) -> int:
        """Convert severity to numeric for sorting"""
        mapping = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return mapping.get(severity.lower(), 0)
    
    def is_security_related(self, rule_id: str) -> bool:
        """Check if a Pylint rule is security-related"""
        security_rules = [
            'bad-builtin', 'eval-used', 'exec-used', 'bad-whitespace',
            'missing-docstring', 'invalid-name', 'too-many-arguments'
        ]
        return any(rule in rule_id.lower() for rule in security_rules)
    
    def is_security_related_eslint(self, rule_id: str) -> bool:
        """Check if an ESLint rule is security-related"""
        security_rules = [
            'no-eval', 'no-implied-eval', 'no-new-func', 'no-script-url',
            'security/detect-object-injection', 'security/detect-non-literal-regexp'
        ]
        return any(rule in rule_id.lower() for rule in security_rules)
    
    def get_pylint_recommendation(self, rule_id: str) -> str:
        """Get recommendation for Pylint rule"""
        recommendations = {
            'eval-used': 'Avoid using eval() as it can execute arbitrary code',
            'exec-used': 'Avoid using exec() as it can execute arbitrary code',
            'bad-builtin': 'Avoid using dangerous built-in functions',
            'missing-docstring': 'Add docstring for better code documentation'
        }
        return recommendations.get(rule_id, 'Review and fix the identified issue')
    
    def deduplicate_results(self) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities based on file, line, and rule"""
        seen = set()
        unique_results = []
        
        for vuln in self.results:
            key = (vuln.file_name, vuln.line_number, vuln.rule_id, vuln.tool)
            if key not in seen:
                seen.add(key)
                unique_results.append(vuln)
        
        return unique_results
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary statistics of the scan"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        tool_counts = {}
        language_counts = {}
        
        for vuln in self.results:
            severity_counts[vuln.severity] += 1
            tool_counts[vuln.tool] = tool_counts.get(vuln.tool, 0) + 1
            
            # Determine language from file extension
            file_ext = Path(vuln.file_name).suffix.lower()
            for lang, extensions in self.language_extensions.items():
                if file_ext in extensions:
                    language_counts[lang] = language_counts.get(lang, 0) + 1
                    break
        
        return {
            'total_vulnerabilities': len(self.results),
            'severity_breakdown': severity_counts,
            'tool_breakdown': tool_counts,
            'language_breakdown': language_counts,
            'scan_duration': (datetime.now() - self.scan_start_time).total_seconds(),
            'scan_id': self.scan_id
        }

class SASTScanManager:
    """Manages SAST scanning operations"""
    
    def __init__(self, upload_dir: str = "/tmp/sast_uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
    
    async def scan_uploaded_code(self, file_path: str, scan_id: str) -> List[Vulnerability]:
        """Scan uploaded code file (zip, tar, etc.)"""
        try:
            # Extract uploaded file
            extract_path = self.upload_dir / scan_id
            extract_path.mkdir(exist_ok=True)
            
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            else:
                # Copy single file
                shutil.copy2(file_path, extract_path)
            
            # Run scan
            scanner = SASTScanner(str(extract_path), scan_id)
            results = await scanner.scan_project()
            
            # Clean up
            shutil.rmtree(extract_path, ignore_errors=True)
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning uploaded code: {e}")
            raise
    
    async def scan_project_path(self, project_path: str, scan_id: str) -> List[Vulnerability]:
        """Scan code from a project path"""
        try:
            scanner = SASTScanner(project_path, scan_id)
            results = await scanner.scan_project()
            return results
        except Exception as e:
            logger.error(f"Error scanning project path: {e}")
            raise 