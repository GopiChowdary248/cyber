#!/usr/bin/env python3
"""
Advanced Code Analysis Engine for SAST
Integrates data flow analysis, taint analysis, and advanced vulnerability detection
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
from datetime import datetime
import re # Added missing import for re

from .data_flow_engine import DataFlowAnalyzer, DataFlowPath
from .taint_analyzer import TaintAnalyzer, TaintFlow, TaintSource, TaintSink

logger = logging.getLogger(__name__)

class AnalysisType(str, Enum):
    """Types of advanced analysis"""
    DATA_FLOW = "data_flow"
    TAINT_ANALYSIS = "taint_analysis"
    CONTROL_FLOW = "control_flow"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    COMPLEXITY_ANALYSIS = "complexity_analysis"
    SECURITY_PATTERN = "security_pattern"

class VulnerabilityCategory(str, Enum):
    """Categories of vulnerabilities"""
    INJECTION = "injection"
    BROKEN_AUTHENTICATION = "broken_authentication"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    XML_EXTERNAL_ENTITY = "xml_external_entity"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    COMPONENTS_WITH_KNOWN_VULNERABILITIES = "components_with_known_vulnerabilities"
    INSUFFICIENT_LOGGING = "insufficient_logging"

@dataclass
class AdvancedVulnerability:
    """Represents an advanced vulnerability found by the analyzer"""
    id: str
    title: str
    description: str
    category: VulnerabilityCategory
    severity: str
    confidence: float
    file_path: str
    line_number: int
    column: int
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    data_flow_path: Optional[DataFlowPath] = None
    taint_flow: Optional[TaintFlow] = None
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class AnalysisResult:
    """Result of advanced code analysis"""
    analysis_id: str
    project_id: str
    scan_id: str
    analysis_type: AnalysisType
    vulnerabilities: List[AdvancedVulnerability]
    data_flow_paths: List[DataFlowPath]
    taint_flows: List[TaintFlow]
    summary: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

class AdvancedCodeAnalyzer:
    """Main advanced code analysis engine"""
    
    def __init__(self):
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.taint_analyzer = TaintAnalyzer()
        self.analysis_results: Dict[str, AnalysisResult] = {}
        
        # Initialize security patterns
        self._initialize_security_patterns()
    
    def _initialize_security_patterns(self):
        """Initialize security vulnerability patterns"""
        self.security_patterns = {
            'hardcoded_credentials': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'api_key\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'token\s*=\s*["\'][^"\']+["\']'
                ],
                'category': VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
                'severity': 'high',
                'cwe_id': 'CWE-259'
            },
            'weak_cryptography': {
                'patterns': [
                    r'md5\(',
                    r'sha1\(',
                    r'hashlib\.md5',
                    r'hashlib\.sha1'
                ],
                'category': VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                'severity': 'medium',
                'cwe_id': 'CWE-327'
            },
            'insecure_random': {
                'patterns': [
                    r'random\.randint',
                    r'random\.choice',
                    r'Math\.random',
                    r'new Random\('
                ],
                'category': VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                'severity': 'medium',
                'cwe_id': 'CWE-338'
            },
            'debug_code': {
                'patterns': [
                    r'console\.log',
                    r'print\(',
                    r'System\.out\.println',
                    r'debugger;'
                ],
                'category': VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                'severity': 'low',
                'cwe_id': 'CWE-489'
            }
        }
    
    async def analyze_project(self, project_path: str, project_id: str, scan_id: str, 
                            languages: List[str]) -> AnalysisResult:
        """Perform comprehensive analysis of a project"""
        analysis_id = f"analysis_{project_id}_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Starting advanced analysis {analysis_id} for project {project_id}")
        
        # Perform data flow analysis
        data_flow_paths = await self._perform_data_flow_analysis(project_path, languages)
        
        # Perform taint analysis
        taint_flows = await self._perform_taint_analysis(project_path, languages)
        
        # Perform security pattern analysis
        security_vulnerabilities = await self._perform_security_pattern_analysis(project_path, languages)
        
        # Perform control flow analysis
        control_flow_vulnerabilities = await self._perform_control_flow_analysis(project_path, languages)
        
        # Perform dependency analysis
        dependency_vulnerabilities = await self._perform_dependency_analysis(project_path, languages)
        
        # Combine all vulnerabilities
        all_vulnerabilities = (
            security_vulnerabilities + 
            control_flow_vulnerabilities + 
            dependency_vulnerabilities
        )
        
        # Create analysis result
        result = AnalysisResult(
            analysis_id=analysis_id,
            project_id=project_id,
            scan_id=scan_id,
            analysis_type=AnalysisType.SECURITY_PATTERN,
            vulnerabilities=all_vulnerabilities,
            data_flow_paths=data_flow_paths,
            taint_flows=taint_flows,
            summary=self._generate_analysis_summary(all_vulnerabilities, data_flow_paths, taint_flows),
            metadata={
                'languages_analyzed': languages,
                'total_files_analyzed': len(list(Path(project_path).rglob('*'))),
                'analysis_duration': 0  # Will be updated
            }
        )
        
        self.analysis_results[analysis_id] = result
        logger.info(f"Completed advanced analysis {analysis_id}")
        
        return result
    
    async def _perform_data_flow_analysis(self, project_path: str, languages: List[str]) -> List[DataFlowPath]:
        """Perform data flow analysis on the project"""
        logger.info("Starting data flow analysis")
        
        all_paths = []
        project_path_obj = Path(project_path)
        
        for language in languages:
            # Find files of this language
            language_files = self._find_language_files(project_path_obj, language)
            
            for file_path in language_files:
                try:
                    paths = self.data_flow_analyzer.analyze_file(file_path, language)
                    all_paths.extend(paths)
                except Exception as e:
                    logger.error(f"Error in data flow analysis for {file_path}: {e}")
        
        logger.info(f"Data flow analysis completed. Found {len(all_paths)} paths")
        return all_paths
    
    async def _perform_taint_analysis(self, project_path: str, languages: List[str]) -> List[TaintFlow]:
        """Perform taint analysis on the project"""
        logger.info("Starting taint analysis")
        
        all_flows = []
        project_path_obj = Path(project_path)
        
        for language in languages:
            # Find files of this language
            language_files = self._find_language_files(project_path_obj, language)
            
            for file_path in language_files:
                try:
                    flows = self.taint_analyzer.analyze_file(file_path, language)
                    all_flows.extend(flows)
                except Exception as e:
                    logger.error(f"Error in taint analysis for {file_path}: {e}")
        
        logger.info(f"Taint analysis completed. Found {len(all_flows)} flows")
        return all_flows
    
    async def _perform_security_pattern_analysis(self, project_path: str, languages: List[str]) -> List[AdvancedVulnerability]:
        """Perform security pattern analysis on the project"""
        logger.info("Starting security pattern analysis")
        
        vulnerabilities = []
        project_path_obj = Path(project_path)
        
        for language in languages:
            # Find files of this language
            language_files = self._find_language_files(project_path_obj, language)
            
            for file_path in language_files:
                try:
                    file_vulnerabilities = self._analyze_file_security_patterns(file_path, language)
                    vulnerabilities.extend(file_vulnerabilities)
                except Exception as e:
                    logger.error(f"Error in security pattern analysis for {file_path}: {e}")
        
        logger.info(f"Security pattern analysis completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def _perform_control_flow_analysis(self, project_path: str, languages: List[str]) -> List[AdvancedVulnerability]:
        """Perform control flow analysis on the project"""
        logger.info("Starting control flow analysis")
        
        vulnerabilities = []
        project_path_obj = Path(project_path)
        
        for language in languages:
            # Find files of this language
            language_files = self._find_language_files(project_path_obj, language)
            
            for file_path in language_files:
                try:
                    file_vulnerabilities = self._analyze_file_control_flow(file_path, language)
                    vulnerabilities.extend(file_vulnerabilities)
                except Exception as e:
                    logger.error(f"Error in control flow analysis for {file_path}: {e}")
        
        logger.info(f"Control flow analysis completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def _perform_dependency_analysis(self, project_path: str, languages: List[str]) -> List[AdvancedVulnerability]:
        """Perform dependency analysis on the project"""
        logger.info("Starting dependency analysis")
        
        vulnerabilities = []
        
        # Check for dependency files
        dependency_files = [
            'requirements.txt', 'package.json', 'pom.xml', 'build.gradle',
            'Gemfile', 'composer.json', 'Cargo.toml'
        ]
        
        for dep_file in dependency_files:
            dep_path = Path(project_path) / dep_file
            if dep_path.exists():
                try:
                    file_vulnerabilities = self._analyze_dependency_file(dep_path)
                    vulnerabilities.extend(file_vulnerabilities)
                except Exception as e:
                    logger.error(f"Error in dependency analysis for {dep_path}: {e}")
        
        logger.info(f"Dependency analysis completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _find_language_files(self, project_path: Path, language: str) -> List[Path]:
        """Find all files of a specific language in the project"""
        language_extensions = {
            'python': ['.py', '.pyw'],
            'javascript': ['.js', '.jsx'],
            'typescript': ['.ts', '.tsx'],
            'java': ['.java'],
            'php': ['.php'],
            'go': ['.go'],
            'csharp': ['.cs'],
            'ruby': ['.rb']
        }
        
        extensions = language_extensions.get(language, [])
        files = []
        
        for ext in extensions:
            files.extend(project_path.rglob(f'*{ext}'))
        
        return files
    
    def _analyze_file_security_patterns(self, file_path: Path, language: str) -> List[AdvancedVulnerability]:
        """Analyze a single file for security patterns"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for pattern_name, pattern_config in self.security_patterns.items():
                for pattern in pattern_config['patterns']:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            vuln_id = f"{file_path}_{line_num}_{pattern_name}"
                            
                            vulnerability = AdvancedVulnerability(
                                id=vuln_id,
                                title=f"Security Pattern: {pattern_name.replace('_', ' ').title()}",
                                description=f"Found {pattern_name} pattern in {file_path.name}",
                                category=pattern_config['category'],
                                severity=pattern_config['severity'],
                                confidence=0.8,
                                file_path=str(file_path),
                                line_number=line_num,
                                column=line.find(re.search(pattern, line).group()),
                                cwe_id=pattern_config['cwe_id'],
                                evidence=[line.strip()],
                                recommendations=[
                                    f"Remove or secure the {pattern_name}",
                                    "Use environment variables for sensitive data",
                                    "Implement proper encryption for secrets"
                                ]
                            )
                            vulnerabilities.append(vulnerability)
        
        except Exception as e:
            logger.error(f"Error analyzing security patterns in {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_file_control_flow(self, file_path: Path, language: str) -> List[AdvancedVulnerability]:
        """Analyze a single file for control flow vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Check for common control flow issues
            control_flow_patterns = [
                {
                    'pattern': r'if\s*\([^)]*\)\s*{[^}]*}',
                    'name': 'unprotected_conditional',
                    'description': 'Unprotected conditional statement',
                    'severity': 'medium'
                },
                {
                    'pattern': r'try\s*{[^}]*}\s*catch\s*\([^)]*\)\s*{[^}]*}',
                    'name': 'generic_exception_handling',
                    'description': 'Generic exception handling',
                    'severity': 'low'
                }
            ]
            
            for pattern_config in control_flow_patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern_config['pattern'], line):
                        vuln_id = f"{file_path}_{line_num}_{pattern_config['name']}"
                        
                        vulnerability = AdvancedVulnerability(
                            id=vuln_id,
                            title=f"Control Flow: {pattern_config['name'].replace('_', ' ').title()}",
                            description=pattern_config['description'],
                            category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                            severity=pattern_config['severity'],
                            confidence=0.6,
                            file_path=str(file_path),
                            line_number=line_num,
                            column=0,
                            evidence=[line.strip()],
                            recommendations=[
                                "Implement proper access controls",
                                "Add specific exception handling",
                                "Validate all inputs"
                            ]
                        )
                        vulnerabilities.append(vulnerability)
        
        except Exception as e:
            logger.error(f"Error analyzing control flow in {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_dependency_file(self, dep_file: Path) -> List[AdvancedVulnerability]:
        """Analyze a dependency file for known vulnerabilities"""
        vulnerabilities = []
        
        try:
            # This is a simplified analysis - in a real implementation,
            # you would check against vulnerability databases
            if dep_file.name == 'requirements.txt':
                with open(dep_file, 'r') as f:
                    content = f.read()
                
                # Check for known vulnerable packages (simplified)
                vulnerable_packages = {
                    'django': '1.11.29',
                    'flask': '0.12.3',
                    'requests': '2.20.0'
                }
                
                for package, min_version in vulnerable_packages.items():
                    if package in content:
                        vuln_id = f"{dep_file}_{package}"
                        
                        vulnerability = AdvancedVulnerability(
                            id=vuln_id,
                            title=f"Outdated Package: {package}",
                            description=f"Package {package} may have known vulnerabilities",
                            category=VulnerabilityCategory.COMPONENTS_WITH_KNOWN_VULNERABILITIES,
                            severity='medium',
                            confidence=0.7,
                            file_path=str(dep_file),
                            line_number=0,
                            column=0,
                            evidence=[f"Found {package} in dependencies"],
                            recommendations=[
                                f"Update {package} to latest version",
                                "Check for known vulnerabilities",
                                "Review changelog for security fixes"
                            ]
                        )
                        vulnerabilities.append(vulnerability)
        
        except Exception as e:
            logger.error(f"Error analyzing dependency file {dep_file}: {e}")
        
        return vulnerabilities
    
    def _generate_analysis_summary(self, vulnerabilities: List[AdvancedVulnerability], 
                                 data_flow_paths: List[DataFlowPath], 
                                 taint_flows: List[TaintFlow]) -> Dict[str, Any]:
        """Generate a summary of the analysis results"""
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_by_severity": {
                "critical": len([v for v in vulnerabilities if v.severity == 'critical']),
                "high": len([v for v in vulnerabilities if v.severity == 'high']),
                "medium": len([v for v in vulnerabilities if v.severity == 'medium']),
                "low": len([v for v in vulnerabilities if v.severity == 'low'])
            },
            "vulnerabilities_by_category": {
                cat.value: len([v for v in vulnerabilities if v.category == cat])
                for cat in VulnerabilityCategory
            },
            "data_flow_paths": len(data_flow_paths),
            "taint_flows": len(taint_flows),
            "high_risk_data_flows": len([p for p in data_flow_paths if p.risk_level == 'high']),
            "critical_taint_flows": len([f for f in taint_flows if f.severity.value == 'critical'])
        }
    
    def get_analysis_result(self, analysis_id: str) -> Optional[AnalysisResult]:
        """Get analysis result by ID"""
        return self.analysis_results.get(analysis_id)
    
    def export_analysis_report(self, analysis_id: str, output_path: str) -> bool:
        """Export analysis results to a JSON report"""
        try:
            result = self.get_analysis_result(analysis_id)
            if not result:
                return False
            
            report = {
                "analysis_id": result.analysis_id,
                "project_id": result.project_id,
                "scan_id": result.scan_id,
                "analysis_type": result.analysis_type.value,
                "summary": result.summary,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "title": v.title,
                        "description": v.description,
                        "category": v.category.value,
                        "severity": v.severity,
                        "confidence": v.confidence,
                        "file_path": v.file_path,
                        "line_number": v.line_number,
                        "column": v.column,
                        "cwe_id": v.cwe_id,
                        "owasp_category": v.owasp_category,
                        "cvss_score": v.cvss_score,
                        "evidence": v.evidence,
                        "recommendations": v.recommendations,
                        "created_at": v.created_at.isoformat()
                    }
                    for v in result.vulnerabilities
                ],
                "data_flow_paths": len(result.data_flow_paths),
                "taint_flows": len(result.taint_flows),
                "metadata": result.metadata,
                "created_at": result.created_at.isoformat()
            }
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting analysis report: {e}")
            return False
    
    def get_all_analysis_results(self) -> List[AnalysisResult]:
        """Get all analysis results"""
        return list(self.analysis_results.values())
    
    def clear_analysis_results(self):
        """Clear all analysis results"""
        self.analysis_results.clear()
