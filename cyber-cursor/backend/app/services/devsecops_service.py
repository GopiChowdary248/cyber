import asyncio
import json
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
import structlog

logger = structlog.get_logger()

class ScanType(Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    CONTAINER = "container"
    IAC = "iac"
    SECRETS = "secrets"
    POLICY = "policy"

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class PipelineStage(Enum):
    BUILD = "build"
    TEST = "test"
    DEPLOY = "deploy"
    PRODUCTION = "production"

@dataclass
class SecurityScan:
    id: str
    scan_type: ScanType
    project_name: str
    repository_url: str
    branch: str
    commit_hash: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

@dataclass
class SecurityFinding:
    id: str
    scan_id: str
    finding_type: str
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ContainerImage:
    id: str
    image_name: str
    image_tag: str
    digest: str
    registry: str
    scan_status: ScanStatus
    vulnerabilities_count: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    last_scan: Optional[datetime] = None

@dataclass
class InfrastructureCode:
    id: str
    project_name: str
    file_path: str
    file_type: str
    scan_status: ScanStatus
    issues_count: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    last_scan: Optional[datetime] = None

@dataclass
class SecretDetection:
    id: str
    project_name: str
    file_path: str
    secret_type: str
    severity: Severity
    line_number: int
    is_verified: bool = False
    remediation_status: str = "open"
    detected_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class DependencyVulnerability:
    id: str
    project_name: str
    dependency_name: str
    dependency_version: str
    vulnerability_id: str
    severity: Severity
    title: str
    description: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    detected_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityPolicy:
    id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    enabled: bool = True
    severity_threshold: Severity = Severity.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class PipelineExecution:
    id: str
    pipeline_name: str
    project_name: str
    branch: str
    commit_hash: str
    stage: PipelineStage
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    security_gates_passed: bool = False
    security_scan_results: List[str] = field(default_factory=list)

@dataclass
class DevSecOpsSummary:
    total_scans: int
    active_scans: int
    failed_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    container_images: int
    vulnerable_containers: int
    infrastructure_files: int
    policy_violations: int
    last_updated: datetime

class DevSecOpsService:
    def __init__(self):
        self.security_scans: List[SecurityScan] = []
        self.security_findings: List[SecurityFinding] = []
        self.container_images: List[ContainerImage] = []
        self.infrastructure_code: List[InfrastructureCode] = []
        self.secret_detections: List[SecretDetection] = []
        self.dependency_vulnerabilities: List[DependencyVulnerability] = []
        self.security_policies: List[SecurityPolicy] = []
        self.pipeline_executions: List[PipelineExecution] = []
        self.background_tasks: List[asyncio.Task] = []
        self._running = False
        
        # Initialize sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize sample data for demonstration"""
        # Sample security scans
        for i in range(20):
            scan = SecurityScan(
                id=str(uuid.uuid4()),
                scan_type=ScanType.SAST if i % 4 == 0 else ScanType.DAST if i % 4 == 1 else ScanType.SCA,
                project_name=f"project-{i % 5}",
                repository_url=f"https://github.com/org/project-{i % 5}",
                branch="main" if i % 3 == 0 else "develop",
                commit_hash=f"abc123{i:03d}",
                status=ScanStatus.COMPLETED if i < 15 else ScanStatus.IN_PROGRESS,
                started_at=datetime.utcnow() - timedelta(hours=i),
                completed_at=datetime.utcnow() - timedelta(hours=i, minutes=30) if i < 15 else None,
                findings_count=10 + (i % 20),
                critical_findings=i % 3,
                high_findings=2 + (i % 5),
                medium_findings=3 + (i % 8),
                low_findings=5 + (i % 10)
            )
            self.security_scans.append(scan)
        
        # Sample container images
        for i in range(10):
            container = ContainerImage(
                id=str(uuid.uuid4()),
                image_name=f"app-{i % 3}",
                image_tag="latest" if i % 3 == 0 else f"v{i % 5}.{i % 3}",
                digest=f"sha256:abc123{i:03d}",
                registry="docker.io" if i % 2 == 0 else "gcr.io",
                scan_status=ScanStatus.COMPLETED if i < 8 else ScanStatus.IN_PROGRESS,
                vulnerabilities_count=5 + (i % 10),
                critical_vulnerabilities=i % 2,
                high_vulnerabilities=1 + (i % 4),
                last_scan=datetime.utcnow() - timedelta(days=i)
            )
            self.container_images.append(container)
        
        # Sample infrastructure code
        for i in range(15):
            infra = InfrastructureCode(
                id=str(uuid.uuid4()),
                project_name=f"infra-project-{i % 4}",
                file_path=f"terraform/main{i}.tf" if i % 3 == 0 else f"k8s/deployment{i}.yaml",
                file_type="terraform" if i % 3 == 0 else "kubernetes",
                scan_status=ScanStatus.COMPLETED if i < 12 else ScanStatus.IN_PROGRESS,
                issues_count=3 + (i % 8),
                critical_issues=i % 2,
                high_issues=1 + (i % 3),
                last_scan=datetime.utcnow() - timedelta(days=i * 2)
            )
            self.infrastructure_code.append(infra)
        
        # Sample secret detections
        for i in range(20):
            secret = SecretDetection(
                id=str(uuid.uuid4()),
                project_name=f"project-{i % 5}",
                file_path=f"config/database{i}.yml" if i % 3 == 0 else f"src/main/resources/application{i}.properties",
                secret_type="API Key" if i % 4 == 0 else "Database Password" if i % 4 == 1 else "SSH Private Key",
                severity=Severity.CRITICAL if i % 5 == 0 else Severity.HIGH,
                line_number=15 + (i % 30),
                is_verified=i > 15,
                remediation_status="open" if i < 15 else "fixed"
            )
            self.secret_detections.append(secret)
        
        # Sample dependency vulnerabilities
        for i in range(15):
            vuln = DependencyVulnerability(
                id=str(uuid.uuid4()),
                project_name=f"project-{i % 5}",
                dependency_name=f"lib-{i % 4}",
                dependency_version=f"{1 + (i % 5)}.{i % 10}.{i % 5}",
                vulnerability_id=f"CVE-2024-{1000 + i}",
                severity=Severity.CRITICAL if i % 6 == 0 else Severity.HIGH if i % 3 == 0 else Severity.MEDIUM,
                title=f"Vulnerability in lib-{i % 4}",
                description=f"Security vulnerability in dependency lib-{i % 4}",
                cve_id=f"CVE-2024-{1000 + i}",
                cvss_score=8.5 + (i * 0.1)
            )
            self.dependency_vulnerabilities.append(vuln)
        
        # Sample security policies
        for i in range(5):
            policy = SecurityPolicy(
                id=str(uuid.uuid4()),
                name=f"Policy {i + 1}",
                description=f"Security policy {i + 1}",
                rules=[{"rule": "no_critical_vulns", "enabled": True}],
                severity_threshold=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM
            )
            self.security_policies.append(policy)
        
        # Sample pipeline executions
        for i in range(15):
            pipeline = PipelineExecution(
                id=str(uuid.uuid4()),
                pipeline_name=f"pipeline-{i % 3}",
                project_name=f"project-{i % 5}",
                branch="main" if i % 3 == 0 else "feature-branch",
                commit_hash=f"def456{i:03d}",
                stage=PipelineStage.BUILD if i % 3 == 0 else PipelineStage.TEST if i % 3 == 1 else PipelineStage.DEPLOY,
                status=ScanStatus.COMPLETED if i < 12 else ScanStatus.IN_PROGRESS,
                started_at=datetime.utcnow() - timedelta(hours=i * 2),
                completed_at=datetime.utcnow() - timedelta(hours=i * 2, minutes=45) if i < 12 else None,
                security_gates_passed=i < 10
            )
            self.pipeline_executions.append(pipeline)
    
    async def start_devsecops_service(self):
        """Start the DevSecOps service"""
        if self._running:
            return
        
        self._running = True
        logger.info("Starting DevSecOps service")
        
        # Start background tasks
        self.background_tasks.extend([
            asyncio.create_task(self._scan_scheduler()),
            asyncio.create_task(self._policy_enforcer())
        ])
        
        logger.info("DevSecOps service started successfully")
    
    async def stop_devsecops_service(self):
        """Stop the DevSecOps service"""
        if not self._running:
            return
        
        self._running = False
        logger.info("Stopping DevSecOps service")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        self.background_tasks.clear()
        
        logger.info("DevSecOps service stopped")
    
    async def _scan_scheduler(self):
        """Background task for scheduling security scans"""
        while self._running:
            try:
                await asyncio.sleep(300)  # 5 minutes
                logger.debug("Scheduling security scans...")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scan scheduler: {e}")
    
    async def _policy_enforcer(self):
        """Background task for enforcing security policies"""
        while self._running:
            try:
                await asyncio.sleep(600)  # 10 minutes
                logger.debug("Enforcing security policies...")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in policy enforcer: {e}")
    
    # Security Scan Management
    async def create_security_scan(self, scan_type: ScanType, project_name: str, repository_url: str,
                                 branch: str, commit_hash: str) -> SecurityScan:
        """Create a new security scan"""
        scan = SecurityScan(
            id=str(uuid.uuid4()),
            scan_type=scan_type,
            project_name=project_name,
            repository_url=repository_url,
            branch=branch,
            commit_hash=commit_hash,
            status=ScanStatus.PENDING,
            started_at=datetime.utcnow()
        )
        
        self.security_scans.append(scan)
        logger.info(f"Created security scan: {scan.id}")
        return scan
    
    async def get_scans(self, scan_type: ScanType = None, project_name: str = None,
                       status: ScanStatus = None, limit: int = 100) -> List[SecurityScan]:
        """Get security scans with optional filtering"""
        filtered_scans = self.security_scans
        
        if scan_type:
            filtered_scans = [scan for scan in filtered_scans if scan.scan_type == scan_type]
        if project_name:
            filtered_scans = [scan for scan in filtered_scans if scan.project_name == project_name]
        if status:
            filtered_scans = [scan for scan in filtered_scans if scan.status == status]
        
        return filtered_scans[-limit:]
    
    # Container Security Management
    async def add_container_image(self, image_name: str, image_tag: str, digest: str,
                                registry: str) -> ContainerImage:
        """Add a new container image for scanning"""
        container = ContainerImage(
            id=str(uuid.uuid4()),
            image_name=image_name,
            image_tag=image_tag,
            digest=digest,
            registry=registry,
            scan_status=ScanStatus.PENDING
        )
        
        self.container_images.append(container)
        logger.info(f"Added container image: {container.id}")
        return container
    
    async def get_containers(self, scan_status: ScanStatus = None, registry: str = None,
                           limit: int = 100) -> List[ContainerImage]:
        """Get container images with optional filtering"""
        filtered_containers = self.container_images
        
        if scan_status:
            filtered_containers = [c for c in filtered_containers if c.scan_status == scan_status]
        if registry:
            filtered_containers = [c for c in filtered_containers if c.registry == registry]
        
        return filtered_containers[-limit:]
    
    # Infrastructure as Code Management
    async def add_infrastructure_code(self, project_name: str, file_path: str,
                                    file_type: str) -> InfrastructureCode:
        """Add infrastructure code for scanning"""
        infra = InfrastructureCode(
            id=str(uuid.uuid4()),
            project_name=project_name,
            file_path=file_path,
            file_type=file_type,
            scan_status=ScanStatus.PENDING
        )
        
        self.infrastructure_code.append(infra)
        logger.info(f"Added infrastructure code: {infra.id}")
        return infra
    
    async def get_infrastructure(self, project_name: str = None, file_type: str = None,
                               scan_status: ScanStatus = None, limit: int = 100) -> List[InfrastructureCode]:
        """Get infrastructure code with optional filtering"""
        filtered_infra = self.infrastructure_code
        
        if project_name:
            filtered_infra = [i for i in filtered_infra if i.project_name == project_name]
        if file_type:
            filtered_infra = [i for i in filtered_infra if i.file_type == file_type]
        if scan_status:
            filtered_infra = [i for i in filtered_infra if i.scan_status == scan_status]
        
        return filtered_infra[-limit:]
    
    # Secrets Detection Management
    async def add_secret_detection(self, project_name: str, file_path: str,
                                 secret_type: str, severity: Severity,
                                 line_number: int) -> SecretDetection:
        """Add a new secret detection"""
        secret = SecretDetection(
            id=str(uuid.uuid4()),
            project_name=project_name,
            file_path=file_path,
            secret_type=secret_type,
            severity=severity,
            line_number=line_number
        )
        
        self.secret_detections.append(secret)
        logger.info(f"Added secret detection: {secret.id}")
        return secret
    
    async def get_secrets(self, project_name: str = None, secret_type: str = None,
                         severity: Severity = None, limit: int = 100) -> List[SecretDetection]:
        """Get secret detections with optional filtering"""
        filtered_secrets = self.secret_detections
        
        if project_name:
            filtered_secrets = [s for s in filtered_secrets if s.project_name == project_name]
        if secret_type:
            filtered_secrets = [s for s in filtered_secrets if s.secret_type == secret_type]
        if severity:
            filtered_secrets = [s for s in filtered_secrets if s.severity == severity]
        
        return filtered_secrets[-limit:]
    
    # Dependency Vulnerability Management
    async def add_dependency_vulnerability(self, project_name: str, dependency_name: str,
                                         dependency_version: str, vulnerability_id: str,
                                         severity: Severity, title: str, description: str,
                                         cve_id: str = None, cvss_score: float = None) -> DependencyVulnerability:
        """Add a new dependency vulnerability"""
        vuln = DependencyVulnerability(
            id=str(uuid.uuid4()),
            project_name=project_name,
            dependency_name=dependency_name,
            dependency_version=dependency_version,
            vulnerability_id=vulnerability_id,
            severity=severity,
            title=title,
            description=description,
            cve_id=cve_id,
            cvss_score=cvss_score
        )
        
        self.dependency_vulnerabilities.append(vuln)
        logger.info(f"Added dependency vulnerability: {vuln.id}")
        return vuln
    
    async def get_dependency_vulnerabilities(self, project_name: str = None,
                                           dependency_name: str = None,
                                           severity: Severity = None,
                                           limit: int = 100) -> List[DependencyVulnerability]:
        """Get dependency vulnerabilities with optional filtering"""
        filtered_vulns = self.dependency_vulnerabilities
        
        if project_name:
            filtered_vulns = [v for v in filtered_vulns if v.project_name == project_name]
        if dependency_name:
            filtered_vulns = [v for v in filtered_vulns if v.dependency_name == dependency_name]
        if severity:
            filtered_vulns = [v for v in filtered_vulns if v.severity == severity]
        
        return filtered_vulns[-limit:]
    
    # Security Policy Management
    async def create_security_policy(self, name: str, description: str,
                                   rules: List[Dict[str, Any]],
                                   severity_threshold: Severity = Severity.MEDIUM) -> SecurityPolicy:
        """Create a new security policy"""
        policy = SecurityPolicy(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            rules=rules,
            severity_threshold=severity_threshold
        )
        
        self.security_policies.append(policy)
        logger.info(f"Created security policy: {policy.id}")
        return policy
    
    async def get_policies(self, enabled: bool = None, limit: int = 100) -> List[SecurityPolicy]:
        """Get security policies with optional filtering"""
        filtered_policies = self.security_policies
        
        if enabled is not None:
            filtered_policies = [p for p in filtered_policies if p.enabled == enabled]
        
        return filtered_policies[-limit:]
    
    # Pipeline Execution Management
    async def create_pipeline_execution(self, pipeline_name: str, project_name: str,
                                      branch: str, commit_hash: str,
                                      stage: PipelineStage) -> PipelineExecution:
        """Create a new pipeline execution"""
        pipeline = PipelineExecution(
            id=str(uuid.uuid4()),
            pipeline_name=pipeline_name,
            project_name=project_name,
            branch=branch,
            commit_hash=commit_hash,
            stage=stage,
            status=ScanStatus.PENDING,
            started_at=datetime.utcnow()
        )
        
        self.pipeline_executions.append(pipeline)
        logger.info(f"Created pipeline execution: {pipeline.id}")
        return pipeline
    
    async def get_pipeline_executions(self, pipeline_name: str = None,
                                    project_name: str = None,
                                    stage: PipelineStage = None,
                                    status: ScanStatus = None,
                                    limit: int = 100) -> List[PipelineExecution]:
        """Get pipeline executions with optional filtering"""
        filtered_pipelines = self.pipeline_executions
        
        if pipeline_name:
            filtered_pipelines = [p for p in filtered_pipelines if p.pipeline_name == pipeline_name]
        if project_name:
            filtered_pipelines = [p for p in filtered_pipelines if p.project_name == project_name]
        if stage:
            filtered_pipelines = [p for p in filtered_pipelines if p.stage == stage]
        if status:
            filtered_pipelines = [p for p in filtered_pipelines if p.status == status]
        
        return filtered_pipelines[-limit:]
    
    # Summary and Analytics
    async def get_devsecops_summary(self) -> DevSecOpsSummary:
        """Get DevSecOps summary statistics"""
        active_scans = len([scan for scan in self.security_scans if scan.status == ScanStatus.IN_PROGRESS])
        failed_scans = len([scan for scan in self.security_scans if scan.status == ScanStatus.FAILED])
        critical_findings = sum([scan.critical_findings for scan in self.security_scans])
        high_findings = sum([scan.high_findings for scan in self.security_scans])
        vulnerable_containers = len([c for c in self.container_images if c.vulnerabilities_count > 0])
        policy_violations = len([p for p in self.pipeline_executions if not p.security_gates_passed])
        
        return DevSecOpsSummary(
            total_scans=len(self.security_scans),
            active_scans=active_scans,
            failed_scans=failed_scans,
            total_findings=sum([scan.findings_count for scan in self.security_scans]),
            critical_findings=critical_findings,
            high_findings=high_findings,
            container_images=len(self.container_images),
            vulnerable_containers=vulnerable_containers,
            infrastructure_files=len(self.infrastructure_code),
            policy_violations=policy_violations,
            last_updated=datetime.utcnow()
        )

# Global service instance
devsecops_service = DevSecOpsService() 