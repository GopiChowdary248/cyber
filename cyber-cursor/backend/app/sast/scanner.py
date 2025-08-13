#!/usr/bin/env python3
"""
Static Code Analysis (SAST) Scanner Engine
Enhanced with performance optimizations and parallel processing
"""

import os
import json
import subprocess
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import logging
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import hashlib
import pickle
from functools import lru_cache
import multiprocessing
import re

# Import our custom rule engine
from .rule_engine import rule_engine, RuleMatch

# Import advanced analysis engines
from .advanced_analyzer import AdvancedCodeAnalyzer
from .data_flow_engine import DataFlowAnalyzer
from .taint_analyzer import TaintAnalyzer

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

@dataclass
class ScanCache:
    """Cache for scan results to improve performance"""
    file_hash: str
    last_modified: float
    vulnerabilities: List[Vulnerability]
    scan_timestamp: datetime

class PerformanceOptimizedSASTScanner:
    """Performance-optimized SAST scanning engine"""
    
    def __init__(self, project_path: str, scan_id: str, use_cache: bool = True, max_workers: Optional[int] = None):
        self.project_path = Path(project_path)
        self.scan_id = scan_id
        self.use_cache = use_cache
        self.max_workers = max_workers or min(multiprocessing.cpu_count(), 8)
        self.results: List[Vulnerability] = []
        self.scan_start_time = datetime.now()
        
        # Cache for scan results
        self.cache_dir = Path("cache/sast")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.scan_cache: Dict[str, ScanCache] = {}
        
        # Performance metrics
        self.files_scanned = 0
        self.files_cached = 0
        self.scan_duration = 0.0
        
        # Advanced analysis engines
        self.advanced_analyzer = AdvancedCodeAnalyzer()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.taint_analyzer = TaintAnalyzer()
        
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
        
        # Tool configurations with performance weights
        self.tools = {
            'python': ['bandit', 'pylint', 'semgrep'],
            'javascript': ['eslint', 'semgrep'],
            'java': ['semgrep', 'spotbugs'],
            'php': ['semgrep', 'phpcs'],
            'go': ['semgrep', 'gosec'],
            'csharp': ['semgrep'],
            'ruby': ['semgrep', 'rubocop']
        }
        
        # Load existing cache
        if self.use_cache:
            self._load_cache()
    
    def _load_cache(self):
        """Load existing scan cache"""
        try:
            cache_file = self.cache_dir / f"scan_cache_{self.scan_id}.pkl"
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    self.scan_cache = pickle.load(f)
                logger.info(f"Loaded cache with {len(self.scan_cache)} entries")
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            self.scan_cache = {}
    
    def _save_cache(self):
        """Save scan cache to disk"""
        try:
            cache_file = self.cache_dir / f"scan_cache_{self.scan_id}.pkl"
            with open(cache_file, 'wb') as f:
                pickle.dump(self.scan_cache, f)
            logger.info(f"Saved cache with {len(self.scan_cache)} entries")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate file hash for caching"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return hashlib.md5(content).hexdigest()
        except Exception:
            return ""
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on common patterns"""
        skip_patterns = [
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            '.pytest_cache', '.mypy_cache', '.coverage', '*.pyc',
            '*.min.js', '*.min.css', '*.map', '*.log', '*.tmp'
        ]
        
        file_str = str(file_path)
        return any(pattern in file_str for pattern in skip_patterns)
    
    def detect_languages(self) -> List[str]:
        """Detect programming languages in the project with performance optimization"""
        detected_languages = set()
        
        # Use faster file discovery
        for file_path in self.project_path.rglob('*'):
            if file_path.is_file() and not self._should_skip_file(file_path):
                for lang, extensions in self.language_extensions.items():
                    if file_path.suffix.lower() in extensions:
                        detected_languages.add(lang)
                        break  # Found language for this file, move to next
        
        logger.info(f"Detected languages: {list(detected_languages)}")
        return list(detected_languages)
    
    async def scan_project(self) -> List[Vulnerability]:
        """Main scanning method with performance optimizations"""
        logger.info(f"Starting optimized SAST scan for project: {self.project_path}")
        
        start_time = datetime.now()
        
        # Detect languages
        languages = self.detect_languages()
        
        # Get all files to scan
        files_to_scan = self._get_files_to_scan()
        
        # Process files in parallel
        vulnerabilities = await self._scan_files_parallel(files_to_scan, languages)
        
        # Deduplicate results
        self.results = self._deduplicate_results(vulnerabilities)
        
        # Save cache
        if self.use_cache:
            self._save_cache()
        
        # Calculate performance metrics
        end_time = datetime.now()
        self.scan_duration = (end_time - start_time).total_seconds()
        
        logger.info(f"Scan completed in {self.scan_duration:.2f}s")
        logger.info(f"Files scanned: {self.files_scanned}, Files cached: {self.files_cached}")
        logger.info(f"Total vulnerabilities found: {len(self.results)}")
        
        return self.results
    
    def _get_files_to_scan(self) -> List[Path]:
        """Get list of files to scan with caching optimization"""
        files_to_scan = []
        
        for file_path in self.project_path.rglob('*'):
            if file_path.is_file() and not self._should_skip_file(file_path):
                # Check if file should be scanned based on language detection
                if self._is_scannable_file(file_path):
                    files_to_scan.append(file_path)
        
        logger.info(f"Found {len(files_to_scan)} files to scan")
        return files_to_scan
    
    def _is_scannable_file(self, file_path: Path) -> bool:
        """Check if file is scannable based on extensions"""
        for extensions in self.language_extensions.values():
            if file_path.suffix.lower() in extensions:
                return True
        return False
    
    async def _scan_files_parallel(self, files: List[Path], languages: List[str]) -> List[Vulnerability]:
        """Scan files in parallel for better performance"""
        vulnerabilities = []
        
        # Group files by language for better tool selection
        files_by_language = self._group_files_by_language(files)
        
        # Create tasks for parallel processing
        tasks = []
        for language, language_files in files_by_language.items():
            if language_files:
                # Process files in batches for better memory management
                batches = self._create_file_batches(language_files, batch_size=50)
                for batch in batches:
                    task = self._scan_file_batch(batch, language)
                    tasks.append(task)
        
        # Execute all tasks in parallel
        if tasks:
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect results
            for result in batch_results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Batch scan error: {result}")
        
        return vulnerabilities
    
    async def _perform_advanced_analysis(self, languages: List[str]) -> List[Vulnerability]:
        """Perform advanced code analysis including data flow and taint analysis"""
        try:
            logger.info("Starting advanced code analysis")
            
            # Convert advanced analysis results to Vulnerability format
            vulnerabilities = []
            
            # Perform advanced analysis
            analysis_result = await self.advanced_analyzer.analyze_project(
                str(self.project_path), 
                self.scan_id, 
                self.scan_id, 
                languages
            )
            
            # Convert advanced vulnerabilities to standard format
            for adv_vuln in analysis_result.vulnerabilities:
                vuln = Vulnerability(
                    id=adv_vuln.id,
                    file_name=Path(adv_vuln.file_path).name,
                    line_number=adv_vuln.line_number,
                    column=adv_vuln.column,
                    severity=adv_vuln.severity,
                    vulnerability_type=adv_vuln.category.value,
                    description=adv_vuln.description,
                    recommendation="; ".join(adv_vuln.recommendations),
                    rule_id=f"advanced_{adv_vuln.category.value}",
                    tool="advanced_analyzer",
                    cwe_id=adv_vuln.cwe_id,
                    scan_date=datetime.now(),
                    code_snippet="; ".join(adv_vuln.evidence),
                    context={
                        'confidence': adv_vuln.confidence,
                        'owasp_category': adv_vuln.owasp_category,
                        'cvss_score': adv_vuln.cvss_score,
                        'analysis_type': 'advanced'
                    }
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"Advanced analysis completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error during advanced analysis: {e}")
            return []
    
    def _group_files_by_language(self, files: List[Path]) -> Dict[str, List[Path]]:
        """Group files by programming language"""
        files_by_language = {}
        
        for file_path in files:
            for language, extensions in self.language_extensions.items():
                if file_path.suffix.lower() in extensions:
                    if language not in files_by_language:
                        files_by_language[language] = []
                    files_by_language[language].append(file_path)
                    break
        
        return files_by_language
    
    def _create_file_batches(self, files: List[Path], batch_size: int) -> List[List[Path]]:
        """Create batches of files for processing"""
        batches = []
        for i in range(0, len(files), batch_size):
            batches.append(files[i:i + batch_size])
        return batches
    
    async def _scan_file_batch(self, files: List[Path], language: str) -> List[Vulnerability]:
        """Scan a batch of files"""
        vulnerabilities = []
        
        # Use ThreadPoolExecutor for I/O-bound operations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit file scanning tasks
            future_to_file = {
                executor.submit(self._scan_single_file, file_path, language): file_path
                for file_path in files
            }
            
            # Collect results as they complete
            for future in asyncio.as_completed(future_to_file):
                try:
                    result = await asyncio.wrap_future(future)
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    file_path = future_to_file[future]
                    logger.error(f"Error scanning file {file_path}: {e}")
        
        return vulnerabilities
    
    async def _scan_single_file(self, file_path: Path, language: str) -> List[Vulnerability]:
        """Scan a single file with caching"""
        try:
            # Check cache first
            if self.use_cache:
                cached_result = self._get_cached_result(file_path)
                if cached_result:
                    self.files_cached += 1
                    return cached_result
            
            # Perform actual scan
            vulnerabilities = await self._perform_file_scan(file_path, language)
            
            # Cache results
            if self.use_cache and vulnerabilities:
                self._cache_result(file_path, vulnerabilities)
            
            self.files_scanned += 1
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []
    
    def _get_cached_result(self, file_path: Path) -> Optional[List[Vulnerability]]:
        """Get cached scan result for a file"""
        try:
            file_hash = self._get_file_hash(file_path)
            if not file_hash:
                return None
            
            cache_key = str(file_path)
            if cache_key in self.scan_cache:
                cache_entry = self.scan_cache[cache_key]
                
                # Check if cache is still valid
                if (cache_entry.file_hash == file_hash and 
                    cache_entry.last_modified == file_path.stat().st_mtime):
                    return cache_entry.vulnerabilities
            
            return None
            
        except Exception as e:
            logger.warning(f"Cache lookup error for {file_path}: {e}")
            return None
    
    def _cache_result(self, file_path: Path, vulnerabilities: List[Vulnerability]):
        """Cache scan result for a file"""
        try:
            file_hash = self._get_file_hash(file_path)
            if not file_hash:
                return
            
            cache_entry = ScanCache(
                file_hash=file_hash,
                last_modified=file_path.stat().st_mtime,
                vulnerabilities=vulnerabilities,
                scan_timestamp=datetime.now()
            )
            
            self.scan_cache[str(file_path)] = cache_entry
            
        except Exception as e:
            logger.warning(f"Cache save error for {file_path}: {e}")
    
    async def _perform_file_scan(self, file_path: Path, language: str) -> List[Vulnerability]:
        """Perform actual file scanning using multiple tools"""
        vulnerabilities = []
        
        try:
            # Use custom rule engine first (fastest)
            custom_rule_matches = await rule_engine.scan_file(str(file_path), language)
            vulnerabilities.extend(self._convert_rule_matches_to_vulnerabilities(custom_rule_matches, file_path))
            
            # Use external tools in parallel
            tool_tasks = []
            for tool in self.tools.get(language, []):
                task = self._run_tool_scan(language, tool, file_path)
                tool_tasks.append(task)
            
            if tool_tasks:
                tool_results = await asyncio.gather(*tool_tasks, return_exceptions=True)
                
                for result in tool_results:
                    if isinstance(result, list):
                        vulnerabilities.extend(result)
                    elif isinstance(result, Exception):
                        logger.warning(f"Tool scan error: {result}")
            
        except Exception as e:
            logger.error(f"Error in file scan {file_path}: {e}")
        
        return vulnerabilities
    
    def _convert_rule_matches_to_vulnerabilities(self, rule_matches: List[RuleMatch], file_path: Path) -> List[Vulnerability]:
        """Convert rule engine matches to vulnerability objects"""
        vulnerabilities = []
        
        for match in rule_matches:
            vuln = Vulnerability(
                id=f"rule_{match.rule_id}_{hash(match.file_path + str(match.line_number))}",
                file_name=str(file_path),
                line_number=match.line_number,
                column=match.start_column,
                severity=match.severity.value.lower(),
                vulnerability_type=match.rule_type.value.lower(),
                description=match.message,
                recommendation=f"Review and fix the identified {match.rule_type.value.lower()}",
                rule_id=match.rule_id,
                tool="custom_rule_engine",
                cwe_id=match.cwe_id,
                scan_date=datetime.now(),
                code_snippet=match.code_snippet,
                context=match.context
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _run_tool_scan(self, language: str, tool: str, file_path: Path) -> List[Vulnerability]:
        """Run a specific tool scan on a file"""
        try:
            if tool == "bandit" and language == "python":
                return await self._run_bandit_scan_single_file(file_path)
            elif tool == "pylint" and language == "python":
                return await self._run_pylint_scan_single_file(file_path)
            elif tool == "semgrep":
                return await self._run_semgrep_scan_single_file(file_path, language)
            elif tool == "eslint" and language in ["javascript", "typescript"]:
                return await self._run_eslint_scan_single_file(file_path)
            else:
                # Fallback to basic pattern matching
                return await self._run_basic_scan(file_path, language)
                
        except Exception as e:
            logger.warning(f"Tool {tool} scan error for {file_path}: {e}")
            return []
    
    async def _run_bandit_scan_single_file(self, file_path: Path) -> List[Vulnerability]:
        """Run bandit scan on a single Python file"""
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', '-r', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return self._parse_bandit_results(data, file_path)
            
            return []
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Bandit scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.warning(f"Bandit scan error for {file_path}: {e}")
            return []
    
    async def _run_pylint_scan_single_file(self, file_path: Path) -> List[Vulnerability]:
        """Run pylint scan on a single Python file"""
        try:
            result = subprocess.run(
                ['pylint', '--output-format=json', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode in [0, 1]:  # Pylint returns 1 for issues found
                data = json.loads(result.stdout)
                return self._parse_pylint_results(data, file_path)
            
            return []
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Pylint scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.warning(f"Pylint scan error for {file_path}: {e}")
            return []
    
    async def _run_semgrep_scan_single_file(self, file_path: Path, language: str) -> List[Vulnerability]:
        """Run semgrep scan on a single file"""
        try:
            result = subprocess.run(
                ['semgrep', '--json', '--config=auto', str(file_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode in [0, 1]:  # Semgrep returns 1 for issues found
                data = json.loads(result.stdout)
                return self._parse_semgrep_results(data, file_path)
            
            return []
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.warning(f"Semgrep scan error for {file_path}: {e}")
            return []
    
    async def _run_eslint_scan_single_file(self, file_path: Path) -> List[Vulnerability]:
        """Run ESLint scan on a single JavaScript/TypeScript file"""
        try:
            result = subprocess.run(
                ['eslint', '--format=json', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode in [0, 1]:  # ESLint returns 1 for issues found
                data = json.loads(result.stdout)
                return self._parse_eslint_results(data, file_path)
            
            return []
            
        except subprocess.TimeoutExpired:
            logger.warning(f"ESLint scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.warning(f"ESLint scan error for {file_path}: {e}")
            return []
    
    async def _run_basic_scan(self, file_path: Path, language: str) -> List[Vulnerability]:
        """Run basic pattern-based scan as fallback"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
            
            # Basic security pattern matching
            patterns = self._get_security_patterns(language)
            
            for i, line in enumerate(lines, 1):
                for pattern_name, pattern in patterns.items():
                    if pattern.search(line):
                        vuln = Vulnerability(
                            id=f"basic_{pattern_name}_{hash(str(file_path) + str(i))}",
                            file_name=str(file_path),
                            line_number=i,
                            column=0,
                            severity="medium",
                            vulnerability_type="potential_security_issue",
                            description=f"Potential {pattern_name} detected",
                            recommendation="Review this line for security implications",
                            rule_id=f"basic_{pattern_name}",
                            tool="basic_scanner",
                            cwe_id=None,
                            scan_date=datetime.now(),
                            code_snippet=line,
                            context={"pattern": pattern_name}
                        )
                        vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.warning(f"Basic scan error for {file_path}: {e}")
        
        return vulnerabilities
    
    def _get_security_patterns(self, language: str) -> Dict[str, re.Pattern]:
        """Get security patterns for basic scanning"""
        patterns = {
            "sql_injection": re.compile(r"execute\s*\(\s*[\"'].*\+\s*\w+", re.IGNORECASE),
            "xss": re.compile(r"innerHTML\s*=\s*[\"'].*\+\s*\w+", re.IGNORECASE),
            "hardcoded_password": re.compile(r"password\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE),
            "eval_usage": re.compile(r"\beval\s*\(", re.IGNORECASE),
            "exec_usage": re.compile(r"\bexec\s*\(", re.IGNORECASE)
        }
        
        return patterns
    
    def _parse_bandit_results(self, data: Dict[str, Any], file_path: Path) -> List[Vulnerability]:
        """Parse bandit scan results"""
        vulnerabilities = []
        
        for result in data.get("results", []):
            vuln = Vulnerability(
                id=f"bandit_{result.get('issue_id', 'unknown')}_{hash(str(file_path) + str(result.get('line_number', 0)))}",
                file_name=str(file_path),
                line_number=result.get("line_number", 0),
                column=0,
                severity=self._map_bandit_severity(result.get("issue_severity", "medium")),
                vulnerability_type="security_vulnerability",
                description=result.get("issue_text", "Security issue detected"),
                recommendation=result.get("more_info", "Review and fix the security issue"),
                rule_id=result.get("test_id", "unknown"),
                tool="bandit",
                cwe_id=result.get("cwe", {}).get("id") if result.get("cwe") else None,
                scan_date=datetime.now(),
                code_snippet=result.get("code", ""),
                context={"confidence": result.get("issue_confidence", "medium")}
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_pylint_results(self, data: List[Dict[str, Any]], file_path: Path) -> List[Vulnerability]:
        """Parse pylint scan results"""
        vulnerabilities = []
        
        for result in data:
            # Only include security-related issues
            if self._is_security_related_pylint(result.get("symbol", "")):
                vuln = Vulnerability(
                    id=f"pylint_{result.get('symbol', 'unknown')}_{hash(str(file_path) + str(result.get('line', 0)))}",
                    file_name=str(file_path),
                    line_number=result.get("line", 0),
                    column=result.get("column", 0),
                    severity=self._map_pylint_severity(result.get("type", "convention")),
                    vulnerability_type="code_quality",
                    description=result.get("message", "Code quality issue detected"),
                    recommendation=self._get_pylint_recommendation(result.get("symbol", "")),
                    rule_id=result.get("symbol", "unknown"),
                    tool="pylint",
                    cwe_id=None,
                    scan_date=datetime.now(),
                    code_snippet=result.get("message", ""),
                    context={"type": result.get("type", "convention")}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_semgrep_results(self, data: Dict[str, Any], file_path: Path) -> List[Vulnerability]:
        """Parse semgrep scan results"""
        vulnerabilities = []
        
        for result in data.get("results", []):
            vuln = Vulnerability(
                id=f"semgrep_{result.get('check_id', 'unknown')}_{hash(str(file_path) + str(result.get('start', {}).get('line', 0)))}",
                file_name=str(file_path),
                line_number=result.get("start", {}).get("line", 0),
                column=result.get("start", {}).get("col", 0),
                severity=self._map_semgrep_severity(result.get("extra", {}).get("severity", "WARNING")),
                vulnerability_type="security_vulnerability",
                description=result.get("extra", {}).get("message", "Security issue detected"),
                recommendation=result.get("extra", {}).get("fix", "Review and fix the security issue"),
                rule_id=result.get("check_id", "unknown"),
                tool="semgrep",
                cwe_id=result.get("extra", {}).get("metadata", {}).get("cwe", [None])[0] if result.get("extra", {}).get("metadata", {}).get("cwe") else None,
                scan_date=datetime.now(),
                code_snippet=result.get("extra", {}).get("lines", ""),
                context={"confidence": result.get("extra", {}).get("confidence", "medium")}
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_eslint_results(self, data: List[Dict[str, Any]], file_path: Path) -> List[Vulnerability]:
        """Parse ESLint scan results"""
        vulnerabilities = []
        
        for result in data:
            # Only include security-related issues
            if self._is_security_related_eslint(result.get("ruleId", "")):
                vuln = Vulnerability(
                    id=f"eslint_{result.get('ruleId', 'unknown')}_{hash(str(file_path) + str(result.get('line', 0)))}",
                    file_name=str(file_path),
                    line_number=result.get("line", 0),
                    column=result.get("column", 0),
                    severity=self._map_eslint_severity(result.get("severity", 2)),
                    vulnerability_type="security_vulnerability",
                    description=result.get("message", "Security issue detected"),
                    recommendation="Review and fix the security issue",
                    rule_id=result.get("ruleId", "unknown"),
                    tool="eslint",
                    cwe_id=None,
                    scan_date=datetime.now(),
                    code_snippet=result.get("message", ""),
                    context={"severity": result.get("severity", 2)}
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _map_bandit_severity(self, severity: str) -> str:
        """Map bandit severity to standard severity"""
        severity_mapping = {
            "LOW": "low",
            "MEDIUM": "medium",
            "HIGH": "high"
        }
        return severity_mapping.get(severity.upper(), "medium")
    
    def _map_pylint_severity(self, severity: str) -> str:
        """Map pylint severity to standard severity"""
        severity_mapping = {
            "convention": "low",
            "refactor": "low",
            "warning": "medium",
            "error": "high",
            "fatal": "critical"
        }
        return severity_mapping.get(severity, "medium")
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map semgrep severity to standard severity"""
        severity_mapping = {
            "INFO": "low",
            "WARNING": "medium",
            "ERROR": "high"
        }
        return severity_mapping.get(severity.upper(), "medium")
    
    def _map_eslint_severity(self, severity: int) -> str:
        """Map ESLint severity to standard severity"""
        severity_mapping = {
            0: "low",      # off
            1: "medium",   # warn
            2: "high"      # error
        }
        return severity_mapping.get(severity, "medium")
    
    def _is_security_related_pylint(self, symbol: str) -> bool:
        """Check if pylint issue is security-related"""
        security_symbols = {
            "bad-builtin", "eval-used", "exec-used", "bad-whitespace",
            "missing-final-newline", "trailing-whitespace"
        }
        return symbol in security_symbols
    
    def _is_security_related_eslint(self, rule_id: str) -> bool:
        """Check if ESLint issue is security-related"""
        security_rules = {
            "no-eval", "no-implied-eval", "no-new-func", "no-script-url",
            "no-unsafe-finally", "no-unsafe-negation"
        }
        return rule_id in security_rules
    
    def _get_pylint_recommendation(self, symbol: str) -> str:
        """Get recommendation for pylint issue"""
        recommendations = {
            "bad-builtin": "Avoid using built-in functions that can be dangerous",
            "eval-used": "Avoid using eval() as it can execute arbitrary code",
            "exec-used": "Avoid using exec() as it can execute arbitrary code"
        }
        return recommendations.get(symbol, "Review and fix the code quality issue")
    
    def _deduplicate_results(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities based on file, line, and rule"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create unique key for deduplication
            key = (vuln.file_name, vuln.line_number, vuln.rule_id)
            
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get comprehensive scan summary with performance metrics"""
        severity_counts = {}
        tool_counts = {}
        
        for vuln in self.results:
            # Count by severity
            severity = vuln.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by tool
            tool = vuln.tool
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        return {
            "total_vulnerabilities": len(self.results),
            "files_scanned": self.files_scanned,
            "files_cached": self.files_cached,
            "scan_duration_seconds": self.scan_duration,
            "performance_metrics": {
                "files_per_second": self.files_scanned / self.scan_duration if self.scan_duration > 0 else 0,
                "cache_hit_rate": self.files_cached / (self.files_scanned + self.files_cached) if (self.files_scanned + self.files_cached) > 0 else 0
            },
            "vulnerabilities_by_severity": severity_counts,
            "vulnerabilities_by_tool": tool_counts,
            "scan_start_time": self.scan_start_time.isoformat(),
            "scan_end_time": (self.scan_start_time + timedelta(seconds=self.scan_duration)).isoformat()
        }

# Legacy compatibility
class SASTScanner(PerformanceOptimizedSASTScanner):
    """Legacy SASTScanner class for backward compatibility"""
    pass

# Import missing dependency
from datetime import timedelta 