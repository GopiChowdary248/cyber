#!/usr/bin/env python3
"""
Taint Analysis Engine for SAST
Tracks untrusted data flow and identifies security vulnerabilities
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import json

logger = logging.getLogger(__name__)

class TaintType(str, Enum):
    """Types of taint"""
    USER_INPUT = "user_input"
    NETWORK_DATA = "network_data"
    FILE_DATA = "file_data"
    DATABASE_DATA = "database_data"
    ENVIRONMENT_VARIABLE = "environment_variable"
    COMMAND_LINE_ARGUMENT = "command_line_argument"
    COOKIE_DATA = "cookie_data"
    HEADER_DATA = "header_data"
    QUERY_PARAMETER = "query_parameter"
    FORM_DATA = "form_data"
    JSON_DATA = "json_data"
    XML_DATA = "xml_data"

class TaintSeverity(str, Enum):
    """Severity levels for taint analysis"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class TaintStatus(str, Enum):
    """Status of taint analysis"""
    UNTAINTED = "untainted"
    TAINTED = "tainted"
    SANITIZED = "sanitized"
    BLOCKED = "blocked"

@dataclass
class TaintSource:
    """Represents a source of tainted data"""
    id: str
    name: str
    taint_type: TaintType
    file_path: str
    line_number: int
    column: int
    description: str
    severity: TaintSeverity
    confidence: float  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaintSink:
    """Represents a sink where tainted data could cause harm"""
    id: str
    name: str
    sink_type: str  # 'sql_injection', 'xss', 'command_injection', etc.
    file_path: str
    line_number: int
    column: int
    description: str
    severity: TaintSeverity
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaintFlow:
    """Represents a flow of tainted data from source to sink"""
    id: str
    source: TaintSource
    sink: TaintSink
    flow_path: List[Tuple[str, int]]  # List of (file_path, line_number) tuples
    taint_status: TaintStatus
    severity: TaintSeverity
    description: str
    sanitization_points: List[Tuple[str, int]] = field(default_factory=list)
    blocking_points: List[Tuple[str, int]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaintSanitizer:
    """Represents a function that sanitizes tainted data"""
    id: str
    name: str
    sanitizer_type: str  # 'html_escape', 'sql_escape', 'input_validation', etc.
    file_path: str
    line_number: int
    description: str
    effectiveness: float  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

class TaintAnalyzer:
    """Main taint analysis engine"""
    
    def __init__(self):
        self.sources: Dict[str, TaintSource] = {}
        self.sinks: Dict[str, TaintSink] = {}
        self.sanitizers: Dict[str, TaintSanitizer] = {}
        self.flows: List[TaintFlow] = []
        
        # Initialize taint patterns
        self._initialize_taint_patterns()
    
    def _initialize_taint_patterns(self):
        """Initialize taint sources, sinks, and sanitizers"""
        # Taint sources by language
        self.taint_sources = {
            'python': {
                'request.args': {'type': TaintType.QUERY_PARAMETER, 'severity': TaintSeverity.HIGH},
                'request.form': {'type': TaintType.FORM_DATA, 'severity': TaintSeverity.HIGH},
                'request.json': {'type': TaintType.JSON_DATA, 'severity': TaintSeverity.HIGH},
                'request.cookies': {'type': TaintType.COOKIE_DATA, 'severity': TaintSeverity.MEDIUM},
                'request.headers': {'type': TaintType.HEADER_DATA, 'severity': TaintSeverity.MEDIUM},
                'request.files': {'type': TaintType.FILE_DATA, 'severity': TaintSeverity.HIGH},
                'input()': {'type': TaintType.USER_INPUT, 'severity': TaintSeverity.CRITICAL},
                'sys.argv': {'type': TaintType.COMMAND_LINE_ARGUMENT, 'severity': TaintSeverity.HIGH},
                'os.environ': {'type': TaintType.ENVIRONMENT_VARIABLE, 'severity': TaintSeverity.MEDIUM},
                'urllib.parse.parse_qs': {'type': TaintType.QUERY_PARAMETER, 'severity': TaintSeverity.HIGH}
            },
            'javascript': {
                'document.getElementById': {'type': TaintType.USER_INPUT, 'severity': TaintSeverity.HIGH},
                'document.querySelector': {'type': TaintType.USER_INPUT, 'severity': TaintSeverity.HIGH},
                'location.search': {'type': TaintType.QUERY_PARAMETER, 'severity': TaintSeverity.HIGH},
                'location.hash': {'type': TaintType.QUERY_PARAMETER, 'severity': TaintSeverity.HIGH},
                'localStorage.getItem': {'type': TaintType.USER_INPUT, 'severity': TaintSeverity.MEDIUM},
                'sessionStorage.getItem': {'type': TaintType.USER_INPUT, 'severity': TaintSeverity.MEDIUM},
                'event.target': {'type': TaintType.USER_INPUT, 'severity': TaintSeverity.HIGH}
            },
            'java': {
                'request.getParameter': {'type': TaintType.QUERY_PARAMETER, 'severity': TaintSeverity.HIGH},
                'request.getHeader': {'type': TaintType.HEADER_DATA, 'severity': TaintSeverity.MEDIUM},
                'request.getCookie': {'type': TaintType.COOKIE_DATA, 'severity': TaintSeverity.MEDIUM},
                'System.getenv': {'type': TaintType.ENVIRONMENT_VARIABLE, 'severity': TaintSeverity.MEDIUM},
                'System.getProperty': {'type': TaintType.ENVIRONMENT_VARIABLE, 'severity': TaintSeverity.MEDIUM}
            }
        }
        
        # Taint sinks by vulnerability type
        self.taint_sinks = {
            'sql_injection': {
                'python': ['sqlite3.execute', 'mysql.connector.execute', 'psycopg2.execute'],
                'javascript': ['db.query', 'db.execute', 'connection.query'],
                'java': ['Statement.execute', 'PreparedStatement.execute', 'Connection.createStatement']
            },
            'xss': {
                'python': ['print', 'render_template', 'jinja2.Template'],
                'javascript': ['innerHTML', 'outerHTML', 'document.write', 'eval'],
                'java': ['out.println', 'response.getWriter().write', 'JSPWriter.println']
            },
            'command_injection': {
                'python': ['os.system', 'subprocess.call', 'subprocess.Popen'],
                'javascript': ['child_process.exec', 'child_process.spawn'],
                'java': ['Runtime.exec', 'ProcessBuilder']
            },
            'path_traversal': {
                'python': ['open', 'file', 'os.path.join'],
                'javascript': ['fs.readFile', 'fs.writeFile', 'path.join'],
                'java': ['File', 'FileInputStream', 'FileOutputStream']
            },
            'deserialization': {
                'python': ['pickle.loads', 'yaml.load', 'json.loads'],
                'javascript': ['JSON.parse', 'eval'],
                'java': ['ObjectInputStream.readObject', 'XMLDecoder.readObject']
            }
        }
        
        # Sanitizers by type
        self.sanitizer_patterns = {
            'html_escape': {
                'python': ['html.escape', 'cgi.escape', 'markupsafe.escape'],
                'javascript': ['escapeHtml', 'DOMPurify.sanitize'],
                'java': ['StringEscapeUtils.escapeHtml', 'HtmlUtils.htmlEscape']
            },
            'sql_escape': {
                'python': ['sqlite3.escape_string', 'mysql.connector.escape_string'],
                'javascript': ['mysql.escape', 'pg.escapeLiteral'],
                'java': ['PreparedStatement.setString', 'StringEscapeUtils.escapeSql']
            },
            'input_validation': {
                'python': ['re.match', 're.search', 'isinstance'],
                'javascript': ['/^[a-zA-Z0-9]+$/.test', 'typeof'],
                'java': ['Pattern.matches', 'instanceof']
            }
        }
    
    def analyze_file(self, file_path: Path, language: str) -> List[TaintFlow]:
        """Analyze a single file for taint flows"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find taint sources
            sources = self._find_taint_sources(content, str(file_path), language)
            self.sources.update({s.id: s for s in sources})
            
            # Find taint sinks
            sinks = self._find_taint_sinks(content, str(file_path), language)
            self.sinks.update({s.id: s for s in sinks})
            
            # Find sanitizers
            sanitizers = self._find_sanitizers(content, str(file_path), language)
            self.sanitizers.update({s.id: s for s in sanitizers})
            
            # Find taint flows
            flows = self._find_taint_flows(sources, sinks, sanitizers, language)
            self.flows.extend(flows)
            
            return flows
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return []
    
    def _find_taint_sources(self, content: str, file_path: str, language: str) -> List[TaintSource]:
        """Find taint sources in the content"""
        sources = []
        lines = content.split('\n')
        
        if language not in self.taint_sources:
            return sources
        
        for line_num, line in enumerate(lines, 1):
            for pattern, config in self.taint_sources[language].items():
                if pattern in line:
                    source_id = f"{file_path}_{line_num}_{pattern}"
                    source = TaintSource(
                        id=source_id,
                        name=pattern,
                        taint_type=config['type'],
                        file_path=file_path,
                        line_number=line_num,
                        column=line.find(pattern),
                        description=f"Taint source: {pattern}",
                        severity=config['severity'],
                        confidence=0.9,
                        metadata={'pattern': pattern, 'line_content': line.strip()}
                    )
                    sources.append(source)
        
        return sources
    
    def _find_taint_sinks(self, content: str, file_path: str, language: str) -> List[TaintSink]:
        """Find taint sinks in the content"""
        sinks = []
        lines = content.split('\n')
        
        for vuln_type, patterns in self.taint_sinks.items():
            if language in patterns:
                for pattern in patterns[language]:
                    for line_num, line in enumerate(lines, 1):
                        if pattern in line:
                            sink_id = f"{file_path}_{line_num}_{pattern}"
                            sink = TaintSink(
                                id=sink_id,
                                name=pattern,
                                sink_type=vuln_type,
                                file_path=file_path,
                                line_number=line_num,
                                column=line.find(pattern),
                                description=f"Potential {vuln_type} vulnerability",
                                severity=self._get_sink_severity(vuln_type),
                                cwe_id=self._get_cwe_id(vuln_type),
                                owasp_category=self._get_owasp_category(vuln_type),
                                metadata={'pattern': pattern, 'line_content': line.strip()}
                            )
                            sinks.append(sink)
        
        return sinks
    
    def _find_sanitizers(self, content: str, file_path: str, language: str) -> List[TaintSanitizer]:
        """Find sanitizers in the content"""
        sanitizers = []
        lines = content.split('\n')
        
        for sanitizer_type, patterns in self.sanitizer_patterns.items():
            if language in patterns:
                for pattern in patterns[language]:
                    for line_num, line in enumerate(lines, 1):
                        if pattern in line:
                            sanitizer_id = f"{file_path}_{line_num}_{pattern}"
                            sanitizer = TaintSanitizer(
                                id=sanitizer_id,
                                name=pattern,
                                sanitizer_type=sanitizer_type,
                                file_path=file_path,
                                line_number=line_num,
                                description=f"Sanitizer: {pattern}",
                                effectiveness=0.8,
                                metadata={'pattern': pattern, 'line_content': line.strip()}
                            )
                            sanitizers.append(sanitizer)
        
        return sanitizers
    
    def _find_taint_flows(self, sources: List[TaintSource], sinks: List[TaintSink], 
                          sanitizers: List[TaintSanitizer], language: str) -> List[TaintFlow]:
        """Find taint flows from sources to sinks"""
        flows = []
        
        for source in sources:
            for sink in sinks:
                # Check if there's a potential flow
                if self._can_flow_to(source, sink, language):
                    flow_id = f"flow_{source.id}_{sink.id}"
                    
                    # Check if taint is sanitized or blocked
                    taint_status, sanitization_points, blocking_points = self._analyze_taint_status(
                        source, sink, sanitizers, language
                    )
                    
                    flow = TaintFlow(
                        id=flow_id,
                        source=source,
                        sink=sink,
                        flow_path=self._build_flow_path(source, sink),
                        taint_status=taint_status,
                        severity=self._calculate_flow_severity(source, sink, taint_status),
                        description=f"Taint flow from {source.name} to {sink.name}",
                        sanitization_points=sanitization_points,
                        blocking_points=blocking_points
                    )
                    flows.append(flow)
        
        return flows
    
    def _can_flow_to(self, source: TaintSource, sink: TaintSink, language: str) -> bool:
        """Check if taint can potentially flow from source to sink"""
        # Simple heuristic: if they're in the same file and source comes before sink
        if source.file_path == sink.file_path:
            return source.line_number < sink.line_number
        
        # More sophisticated analysis could check function calls, imports, etc.
        return True
    
    def _analyze_taint_status(self, source: TaintSource, sink: TaintSink, 
                             sanitizers: List[TaintSanitizer], language: str) -> Tuple[TaintStatus, List, List]:
        """Analyze the status of taint flow"""
        sanitization_points = []
        blocking_points = []
        
        # Check if there are sanitizers between source and sink
        for sanitizer in sanitizers:
            if (sanitizer.file_path == source.file_path and 
                source.line_number < sanitizer.line_number < sink.line_number):
                sanitization_points.append((sanitizer.file_path, sanitizer.line_number))
        
        # Determine taint status
        if sanitization_points:
            return TaintStatus.SANITIZED, sanitization_points, blocking_points
        elif blocking_points:
            return TaintStatus.BLOCKED, sanitization_points, blocking_points
        else:
            return TaintStatus.TAINTED, sanitization_points, blocking_points
    
    def _build_flow_path(self, source: TaintSource, sink: TaintSink) -> List[Tuple[str, int]]:
        """Build the path from source to sink"""
        path = []
        
        # Add source
        path.append((source.file_path, source.line_number))
        
        # Add intermediate points (simplified)
        if source.file_path == sink.file_path:
            # Same file, add intermediate lines
            for line_num in range(source.line_number + 1, sink.line_number):
                path.append((source.file_path, line_num))
        
        # Add sink
        path.append((sink.file_path, sink.line_number))
        
        return path
    
    def _calculate_flow_severity(self, source: TaintSource, sink: TaintSink, 
                                taint_status: TaintStatus) -> TaintSeverity:
        """Calculate the severity of a taint flow"""
        if taint_status == TaintStatus.SANITIZED:
            return TaintSeverity.LOW
        elif taint_status == TaintStatus.BLOCKED:
            return TaintSeverity.INFO
        
        # Combine source and sink severity
        severity_scores = {
            TaintSeverity.CRITICAL: 4,
            TaintSeverity.HIGH: 3,
            TaintSeverity.MEDIUM: 2,
            TaintSeverity.LOW: 1,
            TaintSeverity.INFO: 0
        }
        
        combined_score = severity_scores[source.severity] + severity_scores[sink.severity]
        
        if combined_score >= 6:
            return TaintSeverity.CRITICAL
        elif combined_score >= 4:
            return TaintSeverity.HIGH
        elif combined_score >= 2:
            return TaintSeverity.MEDIUM
        else:
            return TaintSeverity.LOW
    
    def _get_sink_severity(self, vuln_type: str) -> TaintSeverity:
        """Get severity for a vulnerability type"""
        severity_map = {
            'sql_injection': TaintSeverity.CRITICAL,
            'xss': TaintSeverity.HIGH,
            'command_injection': TaintSeverity.CRITICAL,
            'path_traversal': TaintSeverity.HIGH,
            'deserialization': TaintSeverity.HIGH
        }
        return severity_map.get(vuln_type, TaintSeverity.MEDIUM)
    
    def _get_cwe_id(self, vuln_type: str) -> str:
        """Get CWE ID for a vulnerability type"""
        cwe_map = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'deserialization': 'CWE-502'
        }
        return cwe_map.get(vuln_type, 'CWE-200')
    
    def _get_owasp_category(self, vuln_type: str) -> str:
        """Get OWASP category for a vulnerability type"""
        owasp_map = {
            'sql_injection': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection',
            'command_injection': 'A03:2021 - Injection',
            'path_traversal': 'A01:2021 - Broken Access Control',
            'deserialization': 'A08:2021 - Software and Data Integrity Failures'
        }
        return owasp_map.get(vuln_type, 'A99:2021 - Security Misconfiguration')
    
    def get_taint_summary(self) -> Dict[str, Any]:
        """Get a summary of the taint analysis"""
        return {
            "total_sources": len(self.sources),
            "total_sinks": len(self.sinks),
            "total_sanitizers": len(self.sanitizers),
            "total_flows": len(self.flows),
            "tainted_flows": len([f for f in self.flows if f.taint_status == TaintStatus.TAINTED]),
            "sanitized_flows": len([f for f in self.flows if f.taint_status == TaintStatus.SANITIZED]),
            "blocked_flows": len([f for f in self.flows if f.taint_status == TaintStatus.BLOCKED]),
            "flows_by_severity": {
                "critical": len([f for f in self.flows if f.severity == TaintSeverity.CRITICAL]),
                "high": len([f for f in self.flows if f.severity == TaintSeverity.HIGH]),
                "medium": len([f for f in self.flows if f.severity == TaintSeverity.MEDIUM]),
                "low": len([f for f in self.flows if f.severity == TaintSeverity.LOW]),
                "info": len([f for f in self.flows if f.severity == TaintSeverity.INFO])
            },
            "flows_by_vulnerability_type": {}
        }
    
    def export_taint_report(self, output_path: str) -> bool:
        """Export taint analysis results to a JSON report"""
        try:
            report = {
                "summary": self.get_taint_summary(),
                "sources": [self._source_to_dict(s) for s in self.sources.values()],
                "sinks": [self._sink_to_dict(s) for s in self.sinks.values()],
                "sanitizers": [self._sanitizer_to_dict(s) for s in self.sanitizers.values()],
                "flows": [self._flow_to_dict(f) for f in self.flows]
            }
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting taint report: {e}")
            return False
    
    def _source_to_dict(self, source: TaintSource) -> Dict[str, Any]:
        """Convert TaintSource to dictionary"""
        return {
            "id": source.id,
            "name": source.name,
            "taint_type": source.taint_type.value,
            "file_path": source.file_path,
            "line_number": source.line_number,
            "column": source.column,
            "description": source.description,
            "severity": source.severity.value,
            "confidence": source.confidence,
            "metadata": source.metadata
        }
    
    def _sink_to_dict(self, sink: TaintSink) -> Dict[str, Any]:
        """Convert TaintSink to dictionary"""
        return {
            "id": sink.id,
            "name": sink.name,
            "sink_type": sink.sink_type,
            "file_path": sink.file_path,
            "line_number": sink.line_number,
            "column": sink.column,
            "description": sink.description,
            "severity": sink.severity.value,
            "cwe_id": sink.cwe_id,
            "owasp_category": sink.owasp_category,
            "metadata": sink.metadata
        }
    
    def _sanitizer_to_dict(self, sanitizer: TaintSanitizer) -> Dict[str, Any]:
        """Convert TaintSanitizer to dictionary"""
        return {
            "id": sanitizer.id,
            "name": sanitizer.name,
            "sanitizer_type": sanitizer.sanitizer_type,
            "file_path": sanitizer.file_path,
            "line_number": sanitizer.line_number,
            "description": sanitizer.description,
            "effectiveness": sanitizer.effectiveness,
            "metadata": sanitizer.metadata
        }
    
    def _flow_to_dict(self, flow: TaintFlow) -> Dict[str, Any]:
        """Convert TaintFlow to dictionary"""
        return {
            "id": flow.id,
            "source_id": flow.source.id,
            "sink_id": flow.sink.id,
            "flow_path": flow.flow_path,
            "taint_status": flow.taint_status.value,
            "severity": flow.severity.value,
            "description": flow.description,
            "sanitization_points": flow.sanitization_points,
            "blocking_points": flow.blocking_points,
            "metadata": flow.metadata
        }
