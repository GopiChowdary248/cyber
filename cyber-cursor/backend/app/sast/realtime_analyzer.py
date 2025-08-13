#!/usr/bin/env python3
"""
Real-time Analysis Engine for SAST
Provides continuous monitoring and immediate security feedback
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent
from watchdog.observers.polling import PollingObserver

from .scanner import PerformanceOptimizedSASTScanner
from .advanced_analyzer import AdvancedCodeAnalyzer
from .data_flow_engine import DataFlowAnalyzer
from .taint_analyzer import TaintAnalyzer

logger = logging.getLogger(__name__)

class AnalysisPriority(Enum):
    """Priority levels for real-time analysis"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FileChangeType(Enum):
    """Types of file changes"""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"

@dataclass
class FileChange:
    """Represents a file change event"""
    file_path: Path
    change_type: FileChangeType
    timestamp: datetime
    file_hash: str
    priority: AnalysisPriority = AnalysisPriority.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RealTimeVulnerability:
    """Real-time vulnerability finding"""
    id: str
    file_path: str
    line_number: int
    severity: str
    vulnerability_type: str
    description: str
    timestamp: datetime
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RealTimeAnalysisResult:
    """Result of real-time analysis"""
    analysis_id: str
    timestamp: datetime
    file_path: str
    vulnerabilities: List[RealTimeVulnerability]
    analysis_time: float
    file_hash: str
    change_type: FileChangeType

class RealTimeFileHandler(FileSystemEventHandler):
    """Handles file system events for real-time analysis"""
    
    def __init__(self, analyzer: 'RealTimeAnalyzer'):
        self.analyzer = analyzer
        self.pending_changes: Dict[str, FileChange] = {}
        self.debounce_timer: Optional[asyncio.Task] = None
        
    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_change(event.src_path, FileChangeType.CREATED)
    
    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_change(event.src_path, FileChangeType.MODIFIED)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_file_change(event.src_path, FileChangeType.DELETED)
    
    def on_moved(self, event):
        if not event.is_directory:
            self._handle_file_change(event.dest_path, FileChangeType.RENAMED)
    
    def _handle_file_change(self, file_path: str, change_type: FileChangeType):
        """Handle file change with debouncing"""
        try:
            path = Path(file_path)
            if self._should_analyze_file(path):
                file_hash = self._calculate_file_hash(path)
                change = FileChange(
                    file_path=path,
                    change_type=change_type,
                    timestamp=datetime.now(),
                    file_hash=file_hash,
                    priority=self._determine_priority(path, change_type)
                )
                
                # Store the change
                self.pending_changes[str(path)] = change
                
                # Debounce analysis
                if self.debounce_timer:
                    self.debounce_timer.cancel()
                
                self.debounce_timer = asyncio.create_task(self._debounced_analysis())
                
        except Exception as e:
            logger.error(f"Error handling file change {file_path}: {e}")
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Determine if file should be analyzed"""
        # Skip common non-code files
        skip_extensions = {'.log', '.tmp', '.cache', '.pyc', '.pyo', '.git', '.DS_Store'}
        skip_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env'}
        
        if file_path.suffix in skip_extensions:
            return False
        
        for part in file_path.parts:
            if part in skip_dirs:
                return False
        
        # Only analyze code files
        code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go'}
        return file_path.suffix in code_extensions
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate file hash for change detection"""
        try:
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    content = f.read()
                    return hashlib.md5(content).hexdigest()
            return ""
        except Exception:
            return ""
    
    def _determine_priority(self, file_path: Path, change_type: FileChangeType) -> AnalysisPriority:
        """Determine analysis priority based on file and change type"""
        # High priority for security-critical files
        security_files = {'auth', 'security', 'crypto', 'encryption', 'password', 'token', 'jwt'}
        if any(term in file_path.name.lower() for term in security_files):
            return AnalysisPriority.HIGH
        
        # High priority for configuration files
        config_files = {'.env', 'config', 'settings', 'secrets'}
        if any(term in file_path.name.lower() for term in config_files):
            return AnalysisPriority.HIGH
        
        # Medium priority for modified files
        if change_type == FileChangeType.MODIFIED:
            return AnalysisPriority.MEDIUM
        
        # Low priority for created files
        return AnalysisPriority.LOW
    
    async def _debounced_analysis(self):
        """Debounced analysis to avoid excessive processing"""
        await asyncio.sleep(2)  # Wait 2 seconds after last change
        
        if self.pending_changes:
            changes = list(self.pending_changes.values())
            self.pending_changes.clear()
            
            # Process changes by priority
            changes.sort(key=lambda x: x.priority.value, reverse=True)
            
            for change in changes:
                await self.analyzer.analyze_file_change(change)

class RealTimeAnalyzer:
    """Real-time code analysis engine"""
    
    def __init__(self, project_path: str, config: Optional[Dict[str, Any]] = None):
        self.project_path = Path(project_path)
        self.config = config or {}
        self.observer: Optional[Observer] = None
        self.file_handler: Optional[RealTimeFileHandler] = None
        self.is_monitoring = False
        
        # Analysis engines
        self.scanner = PerformanceOptimizedSASTScanner(str(project_path), "realtime")
        self.advanced_analyzer = AdvancedCodeAnalyzer()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.taint_analyzer = TaintAnalyzer()
        
        # Results storage
        self.analysis_results: Dict[str, RealTimeAnalysisResult] = {}
        self.vulnerability_history: List[RealTimeVulnerability] = []
        self.file_hashes: Dict[str, str] = {}
        
        # Configuration
        self.analysis_delay = self.config.get('analysis_delay', 2.0)
        self.max_concurrent_analyses = self.config.get('max_concurrent_analyses', 3)
        self.analysis_timeout = self.config.get('analysis_timeout', 30.0)
        self.enable_advanced_analysis = self.config.get('enable_advanced_analysis', True)
        
        # Statistics
        self.stats = {
            'files_analyzed': 0,
            'vulnerabilities_found': 0,
            'analysis_time_total': 0.0,
            'last_analysis': None
        }
    
    async def start_monitoring(self):
        """Start real-time file monitoring"""
        if self.is_monitoring:
            logger.warning("Monitoring already started")
            return
        
        try:
            # Initialize file handler
            self.file_handler = RealTimeFileHandler(self)
            
            # Create observer (use polling for better cross-platform support)
            self.observer = PollingObserver(timeout=1.0)
            self.observer.schedule(self.file_handler, str(self.project_path), recursive=True)
            
            # Start monitoring
            self.observer.start()
            self.is_monitoring = True
            
            logger.info(f"Started real-time monitoring for {self.project_path}")
            
            # Initial analysis of existing files
            await self._perform_initial_analysis()
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            raise
    
    async def stop_monitoring(self):
        """Stop real-time file monitoring"""
        if not self.is_monitoring:
            return
        
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None
            
            self.is_monitoring = False
            logger.info("Stopped real-time monitoring")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
    
    async def _perform_initial_analysis(self):
        """Perform initial analysis of existing files"""
        try:
            logger.info("Performing initial analysis of existing files")
            
            code_files = []
            for ext in ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.rb', '.go']:
                code_files.extend(self.project_path.rglob(f'*{ext}'))
            
            # Analyze files in batches
            batch_size = 10
            for i in range(0, len(code_files), batch_size):
                batch = code_files[i:i + batch_size]
                tasks = [self._analyze_existing_file(f) for f in batch]
                await asyncio.gather(*tasks, return_exceptions=True)
                
                # Small delay between batches
                await asyncio.sleep(0.5)
            
            logger.info(f"Initial analysis completed. Analyzed {len(code_files)} files")
            
        except Exception as e:
            logger.error(f"Error during initial analysis: {e}")
    
    async def _analyze_existing_file(self, file_path: Path):
        """Analyze an existing file"""
        try:
            if file_path.exists():
                file_hash = self._calculate_file_hash(file_path)
                self.file_hashes[str(file_path)] = file_hash
                
                change = FileChange(
                    file_path=file_path,
                    change_type=FileChangeType.MODIFIED,
                    timestamp=datetime.now(),
                    file_hash=file_hash,
                    priority=AnalysisPriority.LOW
                )
                
                await self.analyze_file_change(change)
                
        except Exception as e:
            logger.error(f"Error analyzing existing file {file_path}: {e}")
    
    async def analyze_file_change(self, change: FileChange):
        """Analyze a file change in real-time"""
        try:
            start_time = time.time()
            
            # Check if file has actually changed
            current_hash = self._calculate_file_hash(change.file_path)
            if current_hash == self.file_hashes.get(str(change.file_path), ""):
                return  # No actual change
            
            # Update file hash
            self.file_hashes[str(change.file_path)] = current_hash
            
            # Perform analysis
            vulnerabilities = await self._analyze_file(change.file_path)
            
            # Create analysis result
            analysis_time = time.time() - start_time
            analysis_id = f"realtime_{int(start_time)}"
            
            result = RealTimeAnalysisResult(
                analysis_id=analysis_id,
                timestamp=datetime.now(),
                file_path=str(change.file_path),
                vulnerabilities=vulnerabilities,
                analysis_time=analysis_time,
                file_hash=current_hash,
                change_type=change.change_type
            )
            
            # Store results
            self.analysis_results[analysis_id] = result
            self.vulnerability_history.extend(vulnerabilities)
            
            # Update statistics
            self.stats['files_analyzed'] += 1
            self.stats['vulnerabilities_found'] += len(vulnerabilities)
            self.stats['analysis_time_total'] += analysis_time
            self.stats['last_analysis'] = datetime.now()
            
            # Log results
            if vulnerabilities:
                logger.warning(f"Found {len(vulnerabilities)} vulnerabilities in {change.file_path}")
                for vuln in vulnerabilities:
                    logger.warning(f"  - {vuln.vulnerability_type}: {vuln.description} (line {vuln.line_number})")
            else:
                logger.info(f"No vulnerabilities found in {change.file_path}")
            
            # Trigger real-time notifications
            await self._notify_vulnerabilities(vulnerabilities, change)
            
        except Exception as e:
            logger.error(f"Error analyzing file change {change.file_path}: {e}")
    
    async def _analyze_file(self, file_path: Path) -> List[RealTimeVulnerability]:
        """Analyze a single file for vulnerabilities"""
        try:
            vulnerabilities = []
            
            # Basic SAST scanning
            file_vulns = await self.scanner._perform_file_scan(str(file_path))
            for vuln in file_vulns:
                realtime_vuln = RealTimeVulnerability(
                    id=vuln.id,
                    file_path=str(file_path),
                    line_number=vuln.line_number,
                    severity=vuln.severity,
                    vulnerability_type=vuln.vulnerability_type,
                    description=vuln.description,
                    timestamp=datetime.now(),
                    confidence=0.8,
                    context={
                        'tool': vuln.tool,
                        'rule_id': vuln.rule_id,
                        'cwe_id': vuln.cwe_id
                    }
                )
                vulnerabilities.append(realtime_vuln)
            
            # Advanced analysis if enabled
            if self.enable_advanced_analysis:
                language = self._detect_language(file_path)
                if language:
                    # Data flow analysis
                    data_flow_paths = self.data_flow_analyzer.analyze_file(file_path, language)
                    
                    # Taint analysis
                    taint_flows = self.taint_analyzer.analyze_file(file_path, language)
                    
                    # Convert advanced findings to vulnerabilities
                    for flow in data_flow_paths:
                        if flow.risk_level in ['high', 'critical']:
                            vuln = RealTimeVulnerability(
                                id=f"dataflow_{len(vulnerabilities)}",
                                file_path=str(file_path),
                                line_number=flow.start_line,
                                severity=flow.risk_level,
                                vulnerability_type="Data Flow Risk",
                                description=f"High-risk data flow detected: {flow.description}",
                                timestamp=datetime.now(),
                                confidence=0.7,
                                context={
                                    'analysis_type': 'data_flow',
                                    'flow_path': [str(p) for p in flow.path],
                                    'risk_factors': flow.risk_factors
                                }
                            )
                            vulnerabilities.append(vuln)
                    
                    for flow in taint_flows:
                        if flow.severity in ['high', 'critical']:
                            vuln = RealTimeVulnerability(
                                id=f"taint_{len(vulnerabilities)}",
                                file_path=str(file_path),
                                line_number=flow.source_line,
                                severity=flow.severity,
                                vulnerability_type="Taint Flow",
                                description=f"Taint flow detected: {flow.description}",
                                timestamp=datetime.now(),
                                confidence=0.8,
                                context={
                                    'analysis_type': 'taint_analysis',
                                    'source': flow.source,
                                    'sink': flow.sink,
                                    'sanitized': flow.sanitized
                                }
                            )
                            vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return []
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go'
        }
        return ext_map.get(file_path.suffix)
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate file hash"""
        try:
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    content = f.read()
                    return hashlib.md5(content).hexdigest()
            return ""
        except Exception:
            return ""
    
    async def _notify_vulnerabilities(self, vulnerabilities: List[RealTimeVulnerability], change: FileChange):
        """Notify about discovered vulnerabilities"""
        if not vulnerabilities:
            return
        
        # Group by severity
        by_severity = {}
        for vuln in vulnerabilities:
            if vuln.severity not in by_severity:
                by_severity[vuln.severity] = []
            by_severity[vuln.severity].append(vuln)
        
        # Log summary
        logger.warning(f"Real-time analysis found vulnerabilities in {change.file_path}:")
        for severity, vulns in by_severity.items():
            logger.warning(f"  {severity.upper()}: {len(vulns)} vulnerabilities")
        
        # TODO: Implement real-time notifications (WebSocket, webhook, etc.)
        # This could include:
        # - WebSocket notifications to frontend
        # - Webhook calls to external systems
        # - Email/Slack notifications
        # - Integration with CI/CD pipelines
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get real-time analysis statistics"""
        return {
            **self.stats,
            'monitoring_active': self.is_monitoring,
            'total_analysis_results': len(self.analysis_results),
            'total_vulnerabilities': len(self.vulnerability_history),
            'file_hashes_tracked': len(self.file_hashes)
        }
    
    def get_recent_vulnerabilities(self, hours: int = 24) -> List[RealTimeVulnerability]:
        """Get vulnerabilities from the last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [v for v in self.vulnerability_history if v.timestamp >= cutoff]
    
    def get_file_analysis_history(self, file_path: str) -> List[RealTimeAnalysisResult]:
        """Get analysis history for a specific file"""
        return [r for r in self.analysis_results.values() if r.file_path == file_path]
    
    def export_analysis_data(self, format: str = 'json') -> str:
        """Export analysis data in specified format"""
        if format == 'json':
            data = {
                'statistics': self.get_statistics(),
                'recent_vulnerabilities': [
                    {
                        'id': v.id,
                        'file_path': v.file_path,
                        'line_number': v.line_number,
                        'severity': v.severity,
                        'vulnerability_type': v.vulnerability_type,
                        'description': v.description,
                        'timestamp': v.timestamp.isoformat(),
                        'confidence': v.confidence,
                        'context': v.context
                    }
                    for v in self.vulnerability_history[-100:]  # Last 100 vulnerabilities
                ],
                'analysis_results': [
                    {
                        'analysis_id': r.analysis_id,
                        'timestamp': r.timestamp.isoformat(),
                        'file_path': r.file_path,
                        'vulnerabilities_count': len(r.vulnerabilities),
                        'analysis_time': r.analysis_time,
                        'change_type': r.change_type.value
                    }
                    for r in list(self.analysis_results.values())[-50:]  # Last 50 analyses
                ]
            }
            return json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")

# Global real-time analyzer instance
_realtime_analyzers: Dict[str, RealTimeAnalyzer] = {}

async def get_realtime_analyzer(project_path: str, config: Optional[Dict[str, Any]] = None) -> RealTimeAnalyzer:
    """Get or create a real-time analyzer for a project"""
    if project_path not in _realtime_analyzers:
        _realtime_analyzers[project_path] = RealTimeAnalyzer(project_path, config)
    
    return _realtime_analyzers[project_path]

async def start_realtime_monitoring(project_path: str, config: Optional[Dict[str, Any]] = None):
    """Start real-time monitoring for a project"""
    analyzer = await get_realtime_analyzer(project_path, config)
    await analyzer.start_monitoring()
    return analyzer

async def stop_realtime_monitoring(project_path: str):
    """Stop real-time monitoring for a project"""
    if project_path in _realtime_analyzers:
        analyzer = _realtime_analyzers[project_path]
        await analyzer.stop_monitoring()
        del _realtime_analyzers[project_path]
