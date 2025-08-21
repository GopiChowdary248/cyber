"""
Enhanced Cloud Security Pydantic Schemas
Provides comprehensive schemas for container security, serverless security, and Kubernetes security
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum
import uuid

# ============================================================================
# Enums
# ============================================================================

class ContainerScanStatus(str, Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

class ContainerSecurityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"

class ServerlessRuntime(str, Enum):
    PYTHON = "python"
    NODEJS = "nodejs"
    JAVA = "java"
    DOTNET = "dotnet"
    GO = "go"
    RUBY = "ruby"
    CUSTOM = "custom"

class KubernetesResourceType(str, Enum):
    POD = "pod"
    DEPLOYMENT = "deployment"
    SERVICE = "service"
    CONFIGMAP = "configmap"
    SECRET = "secret"
    ROLE = "role"
    ROLEBINDING = "rolebinding"
    NETWORK_POLICY = "network_policy"
    POD_SECURITY_POLICY = "pod_security_policy"

# ============================================================================
# Container Security Schemas
# ============================================================================

class ContainerImageBase(BaseModel):
    image_name: str = Field(..., description="Container image name")
    image_tag: Optional[str] = Field(None, description="Image tag")
    image_digest: Optional[str] = Field(None, description="Image digest")
    registry: Optional[str] = Field(None, description="Registry URL")
    architecture: Optional[str] = Field(None, description="Image architecture")
    os_type: Optional[str] = Field(None, description="Operating system type")

class ContainerImageCreate(ContainerImageBase):
    asset_id: uuid.UUID = Field(..., description="Associated asset ID")

class ContainerImageUpdate(BaseModel):
    image_name: Optional[str] = None
    image_tag: Optional[str] = None
    image_digest: Optional[str] = None
    registry: Optional[str] = None
    architecture: Optional[str] = None
    os_type: Optional[str] = None

class ContainerImageResponse(ContainerImageBase):
    id: uuid.UUID
    asset_id: uuid.UUID
    created_date: Optional[datetime]
    last_scan_date: Optional[datetime]
    vulnerability_count: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    security_score: float
    scan_status: ContainerScanStatus
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class ContainerVulnerabilityBase(BaseModel):
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    package_name: Optional[str] = Field(None, description="Affected package name")
    package_version: Optional[str] = Field(None, description="Package version")
    fixed_version: Optional[str] = Field(None, description="Fixed version")
    severity: ContainerSecurityLevel
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    description: Optional[str] = Field(None, description="Vulnerability description")
    affected_layer: Optional[str] = Field(None, description="Affected container layer")
    remediation: Optional[str] = Field(None, description="Remediation steps")

class ContainerVulnerabilityCreate(ContainerVulnerabilityBase):
    image_id: uuid.UUID = Field(..., description="Container image ID")

class ContainerVulnerabilityUpdate(BaseModel):
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    severity: Optional[ContainerSecurityLevel] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    affected_layer: Optional[str] = None
    remediation: Optional[str] = None

class ContainerVulnerabilityResponse(ContainerVulnerabilityBase):
    id: uuid.UUID
    image_id: uuid.UUID
    discovered_at: datetime

    class Config:
        from_attributes = True

class ContainerLayerBase(BaseModel):
    layer_index: int = Field(..., description="Layer index in the image")
    layer_digest: Optional[str] = Field(None, description="Layer digest")
    layer_size: Optional[int] = Field(None, description="Layer size in bytes")
    created_by: Optional[str] = Field(None, description="Command that created the layer")
    commands: List[str] = Field(default_factory=list, description="Dockerfile commands")
    packages: List[Dict[str, Any]] = Field(default_factory=list, description="Installed packages")
    security_issues: List[Dict[str, Any]] = Field(default_factory=list, description="Security issues")

class ContainerLayerCreate(ContainerLayerBase):
    image_id: uuid.UUID = Field(..., description="Container image ID")

class ContainerLayerUpdate(BaseModel):
    layer_digest: Optional[str] = None
    layer_size: Optional[int] = None
    created_by: Optional[str] = None
    commands: Optional[List[str]] = None
    packages: Optional[List[Dict[str, Any]]] = None
    security_issues: Optional[List[Dict[str, Any]]] = None

class ContainerLayerResponse(ContainerLayerBase):
    id: uuid.UUID
    image_id: uuid.UUID

    class Config:
        from_attributes = True

class ContainerRuntimeBase(BaseModel):
    runtime_type: str = Field(..., description="Runtime type (docker, containerd, cri-o)")
    version: Optional[str] = Field(None, description="Runtime version")
    security_features: Dict[str, Any] = Field(default_factory=dict, description="Security features")
    runtime_config: Dict[str, Any] = Field(default_factory=dict, description="Runtime configuration")

class ContainerRuntimeCreate(ContainerRuntimeBase):
    asset_id: uuid.UUID = Field(..., description="Associated asset ID")

class ContainerRuntimeUpdate(BaseModel):
    runtime_type: Optional[str] = None
    version: Optional[str] = None
    security_features: Optional[Dict[str, Any]] = None
    runtime_config: Optional[Dict[str, Any]] = None

class ContainerRuntimeResponse(ContainerRuntimeBase):
    id: uuid.UUID
    asset_id: uuid.UUID
    last_scan_date: Optional[datetime]
    security_score: float
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class ContainerInstanceBase(BaseModel):
    container_id: str = Field(..., description="Container ID")
    container_name: Optional[str] = Field(None, description="Container name")
    status: Optional[str] = Field(None, description="Container status")
    security_context: Dict[str, Any] = Field(default_factory=dict, description="Security context")
    network_config: Dict[str, Any] = Field(default_factory=dict, description="Network configuration")
    volume_mounts: List[Dict[str, Any]] = Field(default_factory=list, description="Volume mounts")
    environment_vars: List[Dict[str, Any]] = Field(default_factory=list, description="Environment variables")

class ContainerInstanceCreate(ContainerInstanceBase):
    runtime_id: uuid.UUID = Field(..., description="Container runtime ID")
    image_id: Optional[uuid.UUID] = Field(None, description="Container image ID")

class ContainerInstanceUpdate(BaseModel):
    container_name: Optional[str] = None
    status: Optional[str] = None
    security_context: Optional[Dict[str, Any]] = None
    network_config: Optional[Dict[str, Any]] = None
    volume_mounts: Optional[List[Dict[str, Any]]] = None
    environment_vars: Optional[List[Dict[str, Any]]] = None

class ContainerInstanceResponse(ContainerInstanceBase):
    id: uuid.UUID
    runtime_id: uuid.UUID
    image_id: Optional[uuid.UUID]
    created_at: Optional[datetime]
    security_score: float
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# ============================================================================
# Serverless Security Schemas
# ============================================================================

class ServerlessFunctionBase(BaseModel):
    function_name: str = Field(..., description="Function name")
    function_arn: Optional[str] = Field(None, description="Function ARN")
    runtime: Optional[ServerlessRuntime] = Field(None, description="Runtime environment")
    handler: Optional[str] = Field(None, description="Function handler")
    timeout: Optional[int] = Field(None, description="Timeout in seconds")
    memory_size: Optional[int] = Field(None, description="Memory size in MB")
    code_size: Optional[int] = Field(None, description="Code size in bytes")
    environment_vars: List[Dict[str, Any]] = Field(default_factory=list, description="Environment variables")
    tags: Dict[str, str] = Field(default_factory=dict, description="Function tags")

class ServerlessFunctionCreate(ServerlessFunctionBase):
    asset_id: uuid.UUID = Field(..., description="Associated asset ID")

class ServerlessFunctionUpdate(BaseModel):
    function_name: Optional[str] = None
    function_arn: Optional[str] = None
    runtime: Optional[ServerlessRuntime] = None
    handler: Optional[str] = None
    timeout: Optional[int] = None
    memory_size: Optional[int] = None
    code_size: Optional[int] = None
    environment_vars: Optional[List[Dict[str, Any]]] = None
    tags: Optional[Dict[str, str]] = None

class ServerlessFunctionResponse(ServerlessFunctionBase):
    id: uuid.UUID
    asset_id: uuid.UUID
    last_modified: Optional[datetime]
    security_score: float
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class ServerlessPermissionBase(BaseModel):
    permission_type: str = Field(..., description="Permission type")
    resource_arn: Optional[str] = Field(None, description="Resource ARN")
    actions: List[str] = Field(default_factory=list, description="Allowed actions")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Permission conditions")
    risk_level: Optional[ContainerSecurityLevel] = Field(None, description="Risk level")

class ServerlessPermissionCreate(ServerlessPermissionBase):
    function_id: uuid.UUID = Field(..., description="Serverless function ID")

class ServerlessPermissionUpdate(BaseModel):
    permission_type: Optional[str] = None
    resource_arn: Optional[str] = None
    actions: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    risk_level: Optional[ContainerSecurityLevel] = None

class ServerlessPermissionResponse(ServerlessPermissionBase):
    id: uuid.UUID
    function_id: uuid.UUID
    last_updated: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class ServerlessVulnerabilityBase(BaseModel):
    vulnerability_type: str = Field(..., description="Type of vulnerability")
    severity: ContainerSecurityLevel
    description: Optional[str] = Field(None, description="Vulnerability description")
    affected_component: Optional[str] = Field(None, description="Affected component")
    remediation: Optional[str] = Field(None, description="Remediation steps")

class ServerlessVulnerabilityCreate(ServerlessVulnerabilityBase):
    function_id: uuid.UUID = Field(..., description="Serverless function ID")

class ServerlessVulnerabilityUpdate(BaseModel):
    vulnerability_type: Optional[str] = None
    severity: Optional[ContainerSecurityLevel] = None
    description: Optional[str] = None
    affected_component: Optional[str] = None
    remediation: Optional[str] = None

class ServerlessVulnerabilityResponse(ServerlessVulnerabilityBase):
    id: uuid.UUID
    function_id: uuid.UUID
    discovered_at: datetime

    class Config:
        from_attributes = True

# ============================================================================
# Kubernetes Security Schemas
# ============================================================================

class KubernetesClusterBase(BaseModel):
    cluster_name: str = Field(..., description="Cluster name")
    cluster_version: Optional[str] = Field(None, description="Kubernetes version")
    provider: Optional[str] = Field(None, description="Cloud provider")
    region: Optional[str] = Field(None, description="Cluster region")
    node_count: Optional[int] = Field(None, description="Number of nodes")
    pod_count: Optional[int] = Field(None, description="Number of pods")
    namespace_count: Optional[int] = Field(None, description="Number of namespaces")

class KubernetesClusterCreate(KubernetesClusterBase):
    asset_id: uuid.UUID = Field(..., description="Associated asset ID")

class KubernetesClusterUpdate(BaseModel):
    cluster_name: Optional[str] = None
    cluster_version: Optional[str] = None
    provider: Optional[str] = None
    region: Optional[str] = None
    node_count: Optional[int] = None
    pod_count: Optional[int] = None
    namespace_count: Optional[int] = None

class KubernetesClusterResponse(KubernetesClusterBase):
    id: uuid.UUID
    asset_id: uuid.UUID
    security_score: float
    last_scan_date: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class KubernetesNamespaceBase(BaseModel):
    namespace_name: str = Field(..., description="Namespace name")
    labels: Dict[str, str] = Field(default_factory=dict, description="Namespace labels")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Namespace annotations")
    status: Optional[str] = Field(None, description="Namespace status")
    security_policies: List[str] = Field(default_factory=list, description="Applied security policies")

class KubernetesNamespaceCreate(KubernetesNamespaceBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")

class KubernetesNamespaceUpdate(BaseModel):
    namespace_name: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None
    status: Optional[str] = None
    security_policies: Optional[List[str]] = None

class KubernetesNamespaceResponse(KubernetesNamespaceBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    risk_score: float
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class KubernetesResourceBase(BaseModel):
    resource_type: KubernetesResourceType
    resource_name: str = Field(..., description="Resource name")
    resource_version: Optional[str] = Field(None, description="Resource version")
    labels: Dict[str, str] = Field(default_factory=dict, description="Resource labels")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Resource annotations")
    spec: Dict[str, Any] = Field(default_factory=dict, description="Resource specification")
    status: Dict[str, Any] = Field(default_factory=dict, description="Resource status")
    security_context: Dict[str, Any] = Field(default_factory=dict, description="Security context")

class KubernetesResourceCreate(KubernetesResourceBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")
    namespace_id: Optional[uuid.UUID] = Field(None, description="Namespace ID")

class KubernetesResourceUpdate(BaseModel):
    resource_name: Optional[str] = None
    resource_version: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None
    spec: Optional[Dict[str, Any]] = None
    status: Optional[Dict[str, Any]] = None
    security_context: Optional[Dict[str, Any]] = None

class KubernetesResourceResponse(KubernetesResourceBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    namespace_id: Optional[uuid.UUID]
    security_score: float
    last_updated: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class KubernetesSecurityIssueBase(BaseModel):
    issue_type: str = Field(..., description="Type of security issue")
    severity: ContainerSecurityLevel
    description: Optional[str] = Field(None, description="Issue description")
    recommendation: Optional[str] = Field(None, description="Security recommendation")
    compliance_framework: Optional[str] = Field(None, description="Compliance framework")
    control_id: Optional[str] = Field(None, description="Framework control ID")

class KubernetesSecurityIssueCreate(KubernetesSecurityIssueBase):
    resource_id: uuid.UUID = Field(..., description="Kubernetes resource ID")

class KubernetesSecurityIssueUpdate(BaseModel):
    issue_type: Optional[str] = None
    severity: Optional[ContainerSecurityLevel] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    compliance_framework: Optional[str] = None
    control_id: Optional[str] = None

class KubernetesSecurityIssueResponse(KubernetesSecurityIssueBase):
    id: uuid.UUID
    resource_id: uuid.UUID
    discovered_at: datetime

    class Config:
        from_attributes = True

# ============================================================================
# Pod Security Policy Schemas
# ============================================================================

class PodSecurityPolicyBase(BaseModel):
    policy_name: str = Field(..., description="Policy name")
    policy_version: Optional[str] = Field(None, description="Policy version")
    privileged: bool = Field(False, description="Allow privileged containers")
    allow_privilege_escalation: bool = Field(False, description="Allow privilege escalation")
    run_as_user: Dict[str, Any] = Field(default_factory=dict, description="Run as user settings")
    run_as_group: Dict[str, Any] = Field(default_factory=dict, description="Run as group settings")
    fs_group: Dict[str, Any] = Field(default_factory=dict, description="FS group settings")
    volumes: List[str] = Field(default_factory=list, description="Allowed volume types")
    host_network: bool = Field(False, description="Allow host networking")
    host_pid: bool = Field(False, description="Allow host PID namespace")
    host_ipc: bool = Field(False, description="Allow host IPC namespace")
    se_linux: Dict[str, Any] = Field(default_factory=dict, description="SELinux settings")
    supplemental_groups: Dict[str, Any] = Field(default_factory=dict, description="Supplemental groups")
    read_only_root_filesystem: bool = Field(False, description="Read-only root filesystem")
    default_allow_privilege_escalation: bool = Field(False, description="Default privilege escalation")

class PodSecurityPolicyCreate(PodSecurityPolicyBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")

class PodSecurityPolicyUpdate(BaseModel):
    policy_name: Optional[str] = None
    policy_version: Optional[str] = None
    privileged: Optional[bool] = None
    allow_privilege_escalation: Optional[bool] = None
    run_as_user: Optional[Dict[str, Any]] = None
    run_as_group: Optional[Dict[str, Any]] = None
    fs_group: Optional[Dict[str, Any]] = None
    volumes: Optional[List[str]] = None
    host_network: Optional[bool] = None
    host_pid: Optional[bool] = None
    host_ipc: Optional[bool] = None
    se_linux: Optional[Dict[str, Any]] = None
    supplemental_groups: Optional[Dict[str, Any]] = None
    read_only_root_filesystem: Optional[bool] = None
    default_allow_privilege_escalation: Optional[bool] = None

class PodSecurityPolicyResponse(PodSecurityPolicyBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# ============================================================================
# RBAC Schemas
# ============================================================================

class RBACRoleBase(BaseModel):
    role_name: str = Field(..., description="Role name")
    role_namespace: Optional[str] = Field(None, description="Role namespace")
    role_type: str = Field(..., description="Role type (Role, ClusterRole)")
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="RBAC rules")
    labels: Dict[str, str] = Field(default_factory=dict, description="Role labels")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Role annotations")

class RBACRoleCreate(RBACRoleBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")

class RBACRoleUpdate(BaseModel):
    role_name: Optional[str] = None
    role_namespace: Optional[str] = None
    role_type: Optional[str] = None
    rules: Optional[List[Dict[str, Any]]] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None

class RBACRoleResponse(RBACRoleBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    risk_score: float
    last_updated: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class RBACBindingBase(BaseModel):
    binding_name: str = Field(..., description="Binding name")
    binding_namespace: Optional[str] = Field(None, description="Binding namespace")
    binding_type: str = Field(..., description="Binding type (RoleBinding, ClusterRoleBinding)")
    subjects: List[Dict[str, Any]] = Field(default_factory=list, description="Binding subjects")
    labels: Dict[str, str] = Field(default_factory=dict, description="Binding labels")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Binding annotations")

class RBACBindingCreate(RBACBindingBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")
    role_id: uuid.UUID = Field(..., description="RBAC role ID")

class RBACBindingUpdate(BaseModel):
    binding_name: Optional[str] = None
    binding_namespace: Optional[str] = None
    binding_type: Optional[str] = None
    subjects: Optional[List[Dict[str, Any]]] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None

class RBACBindingResponse(RBACBindingBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    role_id: uuid.UUID
    risk_score: float
    last_updated: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# ============================================================================
# Network Policy Schemas
# ============================================================================

class NetworkPolicyBase(BaseModel):
    policy_name: str = Field(..., description="Network policy name")
    pod_selector: Dict[str, Any] = Field(default_factory=dict, description="Pod selector")
    policy_types: List[str] = Field(default_factory=list, description="Policy types (Ingress, Egress)")
    ingress_rules: List[Dict[str, Any]] = Field(default_factory=list, description="Ingress rules")
    egress_rules: List[Dict[str, Any]] = Field(default_factory=list, description="Egress rules")
    labels: Dict[str, str] = Field(default_factory=dict, description="Policy labels")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Policy annotations")

class NetworkPolicyCreate(NetworkPolicyBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")
    namespace_id: Optional[uuid.UUID] = Field(None, description="Namespace ID")

class NetworkPolicyUpdate(BaseModel):
    policy_name: Optional[str] = None
    pod_selector: Optional[Dict[str, Any]] = None
    policy_types: Optional[List[str]] = None
    ingress_rules: Optional[List[Dict[str, Any]]] = None
    egress_rules: Optional[List[Dict[str, Any]]] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None

class NetworkPolicyResponse(NetworkPolicyBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    namespace_id: Optional[uuid.UUID]
    security_score: float
    last_updated: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# ============================================================================
# Admission Controller Schemas
# ============================================================================

class AdmissionControllerBase(BaseModel):
    controller_name: str = Field(..., description="Controller name")
    controller_type: str = Field(..., description="Controller type")
    enabled: bool = Field(True, description="Whether controller is enabled")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Controller configuration")
    webhook_config: Dict[str, Any] = Field(default_factory=dict, description="Webhook configuration")
    failure_policy: Optional[str] = Field(None, description="Failure policy")
    timeout_seconds: Optional[int] = Field(None, description="Timeout in seconds")

class AdmissionControllerCreate(AdmissionControllerBase):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster ID")

class AdmissionControllerUpdate(BaseModel):
    controller_name: Optional[str] = None
    controller_type: Optional[str] = None
    enabled: Optional[bool] = None
    configuration: Optional[Dict[str, Any]] = None
    webhook_config: Optional[Dict[str, Any]] = None
    failure_policy: Optional[str] = None
    timeout_seconds: Optional[int] = None

class AdmissionControllerResponse(AdmissionControllerBase):
    id: uuid.UUID
    cluster_id: uuid.UUID
    security_score: float
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

# ============================================================================
# Summary and Dashboard Schemas
# ============================================================================

class EnhancedCloudSecuritySummaryBase(BaseModel):
    summary_date: datetime = Field(..., description="Summary date")
    total_containers: int = Field(0, description="Total container count")
    container_vulnerabilities: int = Field(0, description="Container vulnerability count")
    container_security_score: float = Field(0.0, description="Container security score")
    total_functions: int = Field(0, description="Total serverless function count")
    function_vulnerabilities: int = Field(0, description="Function vulnerability count")
    function_security_score: float = Field(0.0, description="Function security score")
    total_clusters: int = Field(0, description="Total Kubernetes cluster count")
    total_pods: int = Field(0, description="Total pod count")
    kubernetes_security_score: float = Field(0.0, description="Kubernetes security score")
    overall_security_score: float = Field(0.0, description="Overall security score")
    critical_issues: int = Field(0, description="Critical security issues")
    high_issues: int = Field(0, description="High security issues")
    medium_issues: int = Field(0, description="Medium security issues")
    low_issues: int = Field(0, description="Low security issues")

class EnhancedCloudSecuritySummaryCreate(EnhancedCloudSecuritySummaryBase):
    project_id: uuid.UUID = Field(..., description="Project ID")

class EnhancedCloudSecuritySummaryUpdate(BaseModel):
    summary_date: Optional[datetime] = None
    total_containers: Optional[int] = None
    container_vulnerabilities: Optional[int] = None
    container_security_score: Optional[float] = None
    total_functions: Optional[int] = None
    function_vulnerabilities: Optional[int] = None
    function_security_score: Optional[float] = None
    total_clusters: Optional[int] = None
    total_pods: Optional[int] = None
    kubernetes_security_score: Optional[float] = None
    overall_security_score: Optional[float] = None
    critical_issues: Optional[int] = None
    high_issues: Optional[int] = None
    medium_issues: Optional[int] = None
    low_issues: Optional[int] = None

class EnhancedCloudSecuritySummaryResponse(EnhancedCloudSecuritySummaryBase):
    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

# ============================================================================
# Scan and Analysis Schemas
# ============================================================================

class ContainerScanRequest(BaseModel):
    image_id: uuid.UUID = Field(..., description="Container image to scan")
    scan_type: str = Field("vulnerability", description="Type of scan to perform")
    include_layers: bool = Field(True, description="Include layer analysis")
    include_packages: bool = Field(True, description="Include package analysis")

class ServerlessScanRequest(BaseModel):
    function_id: uuid.UUID = Field(..., description="Serverless function to scan")
    scan_type: str = Field("comprehensive", description="Type of scan to perform")
    include_permissions: bool = Field(True, description="Include permission analysis")
    include_code_analysis: bool = Field(True, description="Include code analysis")

class KubernetesScanRequest(BaseModel):
    cluster_id: uuid.UUID = Field(..., description="Kubernetes cluster to scan")
    scan_type: str = Field("security", description="Type of scan to perform")
    include_rbac: bool = Field(True, description="Include RBAC analysis")
    include_network_policies: bool = Field(True, description="Include network policy analysis")
    include_pod_security: bool = Field(True, description="Include pod security analysis")

class ScanResult(BaseModel):
    scan_id: str
    scan_type: str
    target_id: uuid.UUID
    target_type: str
    status: str
    findings_count: int
    security_score: float
    scan_duration: int  # seconds
    started_at: datetime
    completed_at: Optional[datetime]
    findings: List[Dict[str, Any]]

# ============================================================================
# Dashboard and Analytics Schemas
# ============================================================================

class EnhancedCloudSecurityDashboard(BaseModel):
    overall_score: float
    container_security: Dict[str, Any]
    serverless_security: Dict[str, Any]
    kubernetes_security: Dict[str, Any]
    recent_findings: List[Dict[str, Any]]
    security_trends: Dict[str, Any]
    compliance_status: Dict[str, Any]

class SecurityMetrics(BaseModel):
    vulnerability_distribution: Dict[str, int]
    risk_level_distribution: Dict[str, int]
    scan_coverage: Dict[str, float]
    remediation_rate: Dict[str, float]
    compliance_scores: Dict[str, float]
