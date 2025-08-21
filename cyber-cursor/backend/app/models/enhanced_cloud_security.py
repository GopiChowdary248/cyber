from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum, UUID, SmallInteger, Numeric, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
import enum
import uuid

Base = declarative_base()

# Enums
class ContainerScanStatus(str, enum.Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

class ContainerSecurityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"

class ServerlessRuntime(str, enum.Enum):
    PYTHON = "python"
    NODEJS = "nodejs"
    JAVA = "java"
    DOTNET = "dotnet"
    GO = "go"
    RUBY = "ruby"
    CUSTOM = "custom"

class KubernetesResourceType(str, enum.Enum):
    POD = "pod"
    DEPLOYMENT = "deployment"
    SERVICE = "service"
    CONFIGMAP = "configmap"
    SECRET = "secret"
    ROLE = "role"
    ROLEBINDING = "rolebinding"
    NETWORK_POLICY = "network_policy"
    POD_SECURITY_POLICY = "pod_security_policy"

# Container Security Models
class ContainerImage(Base):
    __tablename__ = "container_images"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    image_name = Column(String(500), nullable=False)
    image_tag = Column(String(100))
    image_digest = Column(String(255))
    registry = Column(String(255))
    architecture = Column(String(50))
    os_type = Column(String(50))
    created_date = Column(DateTime(timezone=True))
    last_scan_date = Column(DateTime(timezone=True))
    vulnerability_count = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    high_vulnerabilities = Column(Integer, default=0)
    security_score = Column(Numeric(5, 2), default=0.0)
    scan_status = Column(Enum(ContainerScanStatus), default=ContainerScanStatus.PENDING)
    
    # Relationships
    asset = relationship("Asset")
    vulnerabilities = relationship("ContainerVulnerability", back_populates="image")
    layers = relationship("ContainerLayer", back_populates="image")

class ContainerVulnerability(Base):
    __tablename__ = "container_vulnerabilities"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    image_id = Column(PGUUID(as_uuid=True), ForeignKey("container_images.id"), nullable=False)
    cve_id = Column(String(20))  # CVE identifier
    package_name = Column(String(255))
    package_version = Column(String(100))
    fixed_version = Column(String(100))
    severity = Column(Enum(ContainerSecurityLevel), nullable=False)
    cvss_score = Column(Float)
    description = Column(Text)
    affected_layer = Column(String(100))
    remediation = Column(Text)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    image = relationship("ContainerImage", back_populates="vulnerabilities")

class ContainerLayer(Base):
    __tablename__ = "container_layers"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    image_id = Column(PGUUID(as_uuid=True), ForeignKey("container_images.id"), nullable=False)
    layer_index = Column(Integer, nullable=False)
    layer_digest = Column(String(255))
    layer_size = Column(BigInteger)
    created_by = Column(String(255))
    commands = Column(JSONB, default=[])  # Dockerfile commands
    packages = Column(JSONB, default=[])  # Installed packages
    security_issues = Column(JSONB, default=[])
    
    # Relationships
    image = relationship("ContainerImage", back_populates="layers")

class ContainerRuntime(Base):
    __tablename__ = "container_runtimes"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    runtime_type = Column(String(100))  # docker, containerd, cri-o
    version = Column(String(100))
    security_features = Column(JSONB, default={})  # AppArmor, SELinux, seccomp
    runtime_config = Column(JSONB, default={})  # Runtime configuration
    last_scan_date = Column(DateTime(timezone=True))
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    asset = relationship("Asset")
    containers = relationship("ContainerInstance", back_populates="runtime")

class ContainerInstance(Base):
    __tablename__ = "container_instances"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    runtime_id = Column(PGUUID(as_uuid=True), ForeignKey("container_runtimes.id"), nullable=False)
    container_id = Column(String(255), nullable=False)
    container_name = Column(String(255))
    image_id = Column(PGUUID(as_uuid=True), ForeignKey("container_images.id"))
    status = Column(String(50))
    created_at = Column(DateTime(timezone=True))
    security_context = Column(JSONB, default={})  # Security context settings
    network_config = Column(JSONB, default={})  # Network configuration
    volume_mounts = Column(JSONB, default=[])  # Volume mounts
    environment_vars = Column(JSONB, default=[])  # Environment variables
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    runtime = relationship("ContainerRuntime", back_populates="containers")
    image = relationship("ContainerImage")

# Serverless Security Models
class ServerlessFunction(Base):
    __tablename__ = "serverless_functions"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    function_name = Column(String(255), nullable=False)
    function_arn = Column(String(500))
    runtime = Column(Enum(ServerlessRuntime))
    handler = Column(String(255))
    timeout = Column(Integer)  # seconds
    memory_size = Column(Integer)  # MB
    code_size = Column(BigInteger)  # bytes
    last_modified = Column(DateTime(timezone=True))
    environment_vars = Column(JSONB, default=[])
    tags = Column(JSONB, default={})
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    asset = relationship("Asset")
    permissions = relationship("ServerlessPermission", back_populates="function")
    vulnerabilities = relationship("ServerlessVulnerability", back_populates="function")

class ServerlessPermission(Base):
    __tablename__ = "serverless_permissions"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    function_id = Column(PGUUID(as_uuid=True), ForeignKey("serverless_functions.id"), nullable=False)
    permission_type = Column(String(100))  # IAM role, resource policy, etc.
    resource_arn = Column(String(500))
    actions = Column(JSONB, default=[])  # Allowed actions
    conditions = Column(JSONB, default={})  # Permission conditions
    risk_level = Column(Enum(ContainerSecurityLevel))
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    function = relationship("ServerlessFunction", back_populates="permissions")

class ServerlessVulnerability(Base):
    __tablename__ = "serverless_vulnerabilities"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    function_id = Column(PGUUID(as_uuid=True), ForeignKey("serverless_functions.id"), nullable=False)
    vulnerability_type = Column(String(100))  # code, dependency, configuration
    severity = Column(Enum(ContainerSecurityLevel), nullable=False)
    description = Column(Text)
    affected_component = Column(String(255))
    remediation = Column(Text)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    function = relationship("ServerlessFunction", back_populates="vulnerabilities")

# Kubernetes Security Models
class KubernetesCluster(Base):
    __tablename__ = "kubernetes_clusters"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    cluster_name = Column(String(255), nullable=False)
    cluster_version = Column(String(50))
    provider = Column(String(100))  # EKS, AKS, GKE, on-premises
    region = Column(String(100))
    node_count = Column(Integer)
    pod_count = Column(Integer)
    namespace_count = Column(Integer)
    security_score = Column(Numeric(5, 2), default=0.0)
    last_scan_date = Column(DateTime(timezone=True))
    
    # Relationships
    asset = relationship("Asset")
    namespaces = relationship("KubernetesNamespace", back_populates="cluster")
    resources = relationship("KubernetesResource", back_populates="cluster")

class KubernetesNamespace(Base):
    __tablename__ = "kubernetes_namespaces"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    namespace_name = Column(String(255), nullable=False)
    labels = Column(JSONB, default={})
    annotations = Column(JSONB, default={})
    status = Column(String(50))
    security_policies = Column(JSONB, default=[])  # Applied security policies
    risk_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    cluster = relationship("KubernetesCluster", back_populates="namespaces")
    resources = relationship("KubernetesResource", back_populates="namespace")

class KubernetesResource(Base):
    __tablename__ = "kubernetes_resources"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    namespace_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_namespaces.id"))
    resource_type = Column(Enum(KubernetesResourceType), nullable=False)
    resource_name = Column(String(255), nullable=False)
    resource_version = Column(String(50))
    labels = Column(JSONB, default={})
    annotations = Column(JSONB, default={})
    spec = Column(JSONB, default={})  # Resource specification
    status = Column(JSONB, default={})  # Resource status
    security_context = Column(JSONB, default={})  # Security context
    security_score = Column(Numeric(5, 2), default=0.0)
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    cluster = relationship("KubernetesCluster", back_populates="resources")
    namespace = relationship("KubernetesNamespace", back_populates="resources")
    security_issues = relationship("KubernetesSecurityIssue", back_populates="resource")

class KubernetesSecurityIssue(Base):
    __tablename__ = "kubernetes_security_issues"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    resource_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_resources.id"), nullable=False)
    issue_type = Column(String(100))  # pod_security, rbac, network_policy, etc.
    severity = Column(Enum(ContainerSecurityLevel), nullable=False)
    description = Column(Text)
    recommendation = Column(Text)
    compliance_framework = Column(String(100))  # CIS, NIST, etc.
    control_id = Column(String(100))  # Framework control ID
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    resource = relationship("KubernetesResource", back_populates="security_issues")

# Pod Security Policies
class PodSecurityPolicy(Base):
    __tablename__ = "pod_security_policies"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    policy_name = Column(String(255), nullable=False)
    policy_version = Column(String(50))
    privileged = Column(Boolean, default=False)
    allow_privilege_escalation = Column(Boolean, default=False)
    run_as_user = Column(JSONB, default={})
    run_as_group = Column(JSONB, default={})
    fs_group = Column(JSONB, default={})
    volumes = Column(JSONB, default=[])
    host_network = Column(Boolean, default=False)
    host_pid = Column(Boolean, default=False)
    host_ipc = Column(Boolean, default=False)
    se_linux = Column(JSONB, default={})
    supplemental_groups = Column(JSONB, default={})
    read_only_root_filesystem = Column(Boolean, default=False)
    default_allow_privilege_escalation = Column(Boolean, default=False)
    allowed_host_paths = Column(JSONB, default=[])
    allowed_flex_volumes = Column(JSONB, default=[])
    allowed_csi_drivers = Column(JSONB, default=[])
    allowed_unsafe_sysctls = Column(JSONB, default=[])
    forbidden_sysctls = Column(JSONB, default=[])
    allowed_proc_mount_types = Column(JSONB, default=[])
    run_as_user_options = Column(JSONB, default={})
    run_as_group_options = Column(JSONB, default={})
    fs_group_options = Column(JSONB, default={})
    supplemental_groups_options = Column(JSONB, default={})
    
    # Relationships
    cluster = relationship("KubernetesCluster")

# RBAC Analysis
class RBACRole(Base):
    __tablename__ = "rbac_roles"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    role_name = Column(String(255), nullable=False)
    role_namespace = Column(String(255))
    role_type = Column(String(50))  # Role, ClusterRole
    rules = Column(JSONB, default=[])  # RBAC rules
    labels = Column(JSONB, default={})
    annotations = Column(JSONB, default={})
    risk_score = Column(Numeric(5, 2), default=0.0)
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    cluster = relationship("KubernetesCluster")
    bindings = relationship("RBACBinding", back_populates="role")

class RBACBinding(Base):
    __tablename__ = "rbac_bindings"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    binding_name = Column(String(255), nullable=False)
    binding_namespace = Column(String(255))
    binding_type = Column(String(50))  # RoleBinding, ClusterRoleBinding
    role_id = Column(PGUUID(as_uuid=True), ForeignKey("rbac_roles.id"), nullable=False)
    subjects = Column(JSONB, default=[])  # Subjecs: users, groups, service accounts
    labels = Column(JSONB, default={})
    annotations = Column(JSONB, default={})
    risk_score = Column(Numeric(5, 2), default=0.0)
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    cluster = relationship("KubernetesCluster")
    role = relationship("RBACRole", back_populates="bindings")

# Network Policies
class NetworkPolicy(Base):
    __tablename__ = "network_policies"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    namespace_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_namespaces.id"))
    policy_name = Column(String(255), nullable=False)
    pod_selector = Column(JSONB, default={})
    policy_types = Column(JSONB, default=[])  # Ingress, Egress
    ingress_rules = Column(JSONB, default=[])
    egress_rules = Column(JSONB, default=[])
    labels = Column(JSONB, default={})
    annotations = Column(JSONB, default={})
    security_score = Column(Numeric(5, 2), default=0.0)
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    cluster = relationship("KubernetesCluster")
    namespace = relationship("KubernetesNamespace")

# Admission Controllers
class AdmissionController(Base):
    __tablename__ = "admission_controllers"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(PGUUID(as_uuid=True), ForeignKey("kubernetes_clusters.id"), nullable=False)
    controller_name = Column(String(255), nullable=False)
    controller_type = Column(String(100))  # Validating, Mutating, Webhook
    enabled = Column(Boolean, default=True)
    configuration = Column(JSONB, default={})
    webhook_config = Column(JSONB, default={})
    failure_policy = Column(String(50))  # Ignore, Fail
    timeout_seconds = Column(Integer)
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    cluster = relationship("KubernetesCluster")

# Enhanced Cloud Security Summary
class EnhancedCloudSecuritySummary(Base):
    __tablename__ = "enhanced_cloud_security_summary"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    summary_date = Column(DateTime(timezone=True), nullable=False)
    
    # Container Security
    total_containers = Column(Integer, default=0)
    container_vulnerabilities = Column(Integer, default=0)
    container_security_score = Column(Numeric(5, 2), default=0.0)
    
    # Serverless Security
    total_functions = Column(Integer, default=0)
    function_vulnerabilities = Column(Integer, default=0)
    function_security_score = Column(Numeric(5, 2), default=0.0)
    
    # Kubernetes Security
    total_clusters = Column(Integer, default=0)
    total_pods = Column(Integer, default=0)
    kubernetes_security_score = Column(Numeric(5, 2), default=0.0)
    
    # Overall Security
    overall_security_score = Column(Numeric(5, 2), default=0.0)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project")
