-- Enhanced Cloud Security Tables Migration
-- This script creates all the necessary tables for enhanced cloud security features

-- Container Security Tables
CREATE TABLE IF NOT EXISTS container_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id),
    image_name VARCHAR(500) NOT NULL,
    image_tag VARCHAR(100),
    image_digest VARCHAR(255),
    registry VARCHAR(255),
    architecture VARCHAR(50),
    os_type VARCHAR(50),
    created_date TIMESTAMP WITH TIME ZONE,
    last_scan_date TIMESTAMP WITH TIME ZONE,
    vulnerability_count INTEGER DEFAULT 0,
    critical_vulnerabilities INTEGER DEFAULT 0,
    high_vulnerabilities INTEGER DEFAULT 0,
    security_score NUMERIC(5,2) DEFAULT 0.0,
    scan_status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS container_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES container_images(id),
    cve_id VARCHAR(20),
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    fixed_version VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    cvss_score FLOAT,
    description TEXT,
    affected_layer VARCHAR(100),
    remediation TEXT,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS container_layers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES container_images(id),
    layer_index INTEGER NOT NULL,
    layer_digest VARCHAR(255),
    layer_size BIGINT,
    created_by VARCHAR(255),
    commands JSONB DEFAULT '[]',
    packages JSONB DEFAULT '[]',
    security_issues JSONB DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS container_runtimes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id),
    runtime_type VARCHAR(100) NOT NULL,
    version VARCHAR(100),
    security_features JSONB DEFAULT '{}',
    runtime_config JSONB DEFAULT '{}',
    last_scan_date TIMESTAMP WITH TIME ZONE,
    security_score NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS container_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    runtime_id UUID NOT NULL REFERENCES container_runtimes(id),
    container_id VARCHAR(255) NOT NULL,
    container_name VARCHAR(255),
    image_id UUID REFERENCES container_images(id),
    status VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE,
    security_context JSONB DEFAULT '{}',
    network_config JSONB DEFAULT '{}',
    volume_mounts JSONB DEFAULT '[]',
    environment_vars JSONB DEFAULT '[]',
    security_score NUMERIC(5,2) DEFAULT 0.0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Serverless Security Tables
CREATE TABLE IF NOT EXISTS serverless_functions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id),
    function_name VARCHAR(255) NOT NULL,
    function_arn VARCHAR(500),
    runtime VARCHAR(20),
    handler VARCHAR(255),
    timeout INTEGER,
    memory_size INTEGER,
    code_size BIGINT,
    last_modified TIMESTAMP WITH TIME ZONE,
    environment_vars JSONB DEFAULT '[]',
    tags JSONB DEFAULT '{}',
    security_score NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS serverless_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    function_id UUID NOT NULL REFERENCES serverless_functions(id),
    permission_type VARCHAR(100) NOT NULL,
    resource_arn VARCHAR(500),
    actions JSONB DEFAULT '[]',
    conditions JSONB DEFAULT '{}',
    risk_level VARCHAR(20),
    last_updated TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS serverless_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    function_id UUID NOT NULL REFERENCES serverless_functions(id),
    vulnerability_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    affected_component VARCHAR(255),
    remediation TEXT,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Kubernetes Security Tables
CREATE TABLE IF NOT EXISTS kubernetes_clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id),
    cluster_name VARCHAR(255) NOT NULL,
    cluster_version VARCHAR(50),
    provider VARCHAR(100),
    region VARCHAR(100),
    node_count INTEGER,
    pod_count INTEGER,
    namespace_count INTEGER,
    security_score NUMERIC(5,2) DEFAULT 0.0,
    last_scan_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kubernetes_namespaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    namespace_name VARCHAR(255) NOT NULL,
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    status VARCHAR(50),
    security_policies JSONB DEFAULT '[]',
    risk_score NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kubernetes_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    namespace_id UUID REFERENCES kubernetes_namespaces(id),
    resource_type VARCHAR(50) NOT NULL,
    resource_name VARCHAR(255) NOT NULL,
    resource_version VARCHAR(50),
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    spec JSONB DEFAULT '{}',
    status JSONB DEFAULT '{}',
    security_context JSONB DEFAULT '{}',
    security_score NUMERIC(5,2) DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kubernetes_security_issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID NOT NULL REFERENCES kubernetes_resources(id),
    issue_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    recommendation TEXT,
    compliance_framework VARCHAR(100),
    control_id VARCHAR(100),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Pod Security Policy Tables
CREATE TABLE IF NOT EXISTS pod_security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    policy_name VARCHAR(255) NOT NULL,
    policy_version VARCHAR(50),
    privileged BOOLEAN DEFAULT FALSE,
    allow_privilege_escalation BOOLEAN DEFAULT FALSE,
    run_as_user JSONB DEFAULT '{}',
    run_as_group JSONB DEFAULT '{}',
    fs_group JSONB DEFAULT '{}',
    volumes JSONB DEFAULT '[]',
    host_network BOOLEAN DEFAULT FALSE,
    host_pid BOOLEAN DEFAULT FALSE,
    host_ipc BOOLEAN DEFAULT FALSE,
    se_linux JSONB DEFAULT '{}',
    supplemental_groups JSONB DEFAULT '{}',
    read_only_root_filesystem BOOLEAN DEFAULT FALSE,
    default_allow_privilege_escalation BOOLEAN DEFAULT FALSE,
    allowed_host_paths JSONB DEFAULT '[]',
    allowed_flex_volumes JSONB DEFAULT '[]',
    allowed_csi_drivers JSONB DEFAULT '[]',
    allowed_unsafe_sysctls JSONB DEFAULT '[]',
    forbidden_sysctls JSONB DEFAULT '[]',
    allowed_proc_mount_types JSONB DEFAULT '[]',
    run_as_user_options JSONB DEFAULT '{}',
    run_as_group_options JSONB DEFAULT '{}',
    fs_group_options JSONB DEFAULT '{}',
    supplemental_groups_options JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RBAC Tables
CREATE TABLE IF NOT EXISTS rbac_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    role_name VARCHAR(255) NOT NULL,
    role_namespace VARCHAR(255),
    role_type VARCHAR(50) NOT NULL,
    rules JSONB DEFAULT '[]',
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    risk_score NUMERIC(5,2) DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rbac_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    binding_name VARCHAR(255) NOT NULL,
    binding_namespace VARCHAR(255),
    binding_type VARCHAR(50) NOT NULL,
    role_id UUID NOT NULL REFERENCES rbac_roles(id),
    subjects JSONB DEFAULT '[]',
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    risk_score NUMERIC(5,2) DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Network Policy Tables
CREATE TABLE IF NOT EXISTS network_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    namespace_id UUID REFERENCES kubernetes_namespaces(id),
    policy_name VARCHAR(255) NOT NULL,
    pod_selector JSONB DEFAULT '{}',
    policy_types JSONB DEFAULT '[]',
    ingress_rules JSONB DEFAULT '[]',
    egress_rules JSONB DEFAULT '[]',
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    security_score NUMERIC(5,2) DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Admission Controller Tables
CREATE TABLE IF NOT EXISTS admission_controllers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id),
    controller_name VARCHAR(255) NOT NULL,
    controller_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    configuration JSONB DEFAULT '{}',
    webhook_config JSONB DEFAULT '{}',
    failure_policy VARCHAR(50),
    timeout_seconds INTEGER,
    security_score NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Summary Table
CREATE TABLE IF NOT EXISTS enhanced_cloud_security_summary (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    summary_date TIMESTAMP WITH TIME ZONE NOT NULL,
    total_containers INTEGER DEFAULT 0,
    container_vulnerabilities INTEGER DEFAULT 0,
    container_security_score NUMERIC(5,2) DEFAULT 0.0,
    total_functions INTEGER DEFAULT 0,
    function_vulnerabilities INTEGER DEFAULT 0,
    function_security_score NUMERIC(5,2) DEFAULT 0.0,
    total_clusters INTEGER DEFAULT 0,
    total_pods INTEGER DEFAULT 0,
    kubernetes_security_score NUMERIC(5,2) DEFAULT 0.0,
    overall_security_score NUMERIC(5,2) DEFAULT 0.0,
    critical_issues INTEGER DEFAULT 0,
    high_issues INTEGER DEFAULT 0,
    medium_issues INTEGER DEFAULT 0,
    low_issues INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_container_images_asset_id ON container_images(asset_id);
CREATE INDEX IF NOT EXISTS idx_container_images_scan_status ON container_images(scan_status);
CREATE INDEX IF NOT EXISTS idx_container_vulnerabilities_image_id ON container_vulnerabilities(image_id);
CREATE INDEX IF NOT EXISTS idx_container_vulnerabilities_severity ON container_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_serverless_functions_asset_id ON serverless_functions(asset_id);
CREATE INDEX IF NOT EXISTS idx_kubernetes_clusters_asset_id ON kubernetes_clusters(asset_id);
CREATE INDEX IF NOT EXISTS idx_kubernetes_resources_cluster_id ON kubernetes_resources(cluster_id);
CREATE INDEX IF NOT EXISTS idx_kubernetes_resources_namespace_id ON kubernetes_resources(namespace_id);
CREATE INDEX IF NOT EXISTS idx_enhanced_cloud_security_summary_project_id ON enhanced_cloud_security_summary(project_id);

-- Add comments for documentation
COMMENT ON TABLE container_images IS 'Container images with security scanning results';
COMMENT ON TABLE container_vulnerabilities IS 'Vulnerabilities found in container images';
COMMENT ON TABLE container_layers IS 'Individual layers within container images';
COMMENT ON TABLE container_runtimes IS 'Container runtime environments';
COMMENT ON TABLE container_instances IS 'Running container instances';
COMMENT ON TABLE serverless_functions IS 'Serverless functions with security metadata';
COMMENT ON TABLE serverless_permissions IS 'Permissions assigned to serverless functions';
COMMENT ON TABLE serverless_vulnerabilities IS 'Vulnerabilities in serverless functions';
COMMENT ON TABLE kubernetes_clusters IS 'Kubernetes clusters with security posture';
COMMENT ON TABLE kubernetes_namespaces IS 'Kubernetes namespaces with security policies';
COMMENT ON TABLE kubernetes_resources IS 'Kubernetes resources with security context';
COMMENT ON TABLE kubernetes_security_issues IS 'Security issues found in Kubernetes resources';
COMMENT ON TABLE pod_security_policies IS 'Pod security policies for Kubernetes clusters';
COMMENT ON TABLE rbac_roles IS 'RBAC roles with security analysis';
COMMENT ON TABLE rbac_bindings IS 'RBAC role bindings with risk assessment';
COMMENT ON TABLE network_policies IS 'Network policies for Kubernetes clusters';
COMMENT ON TABLE admission_controllers IS 'Admission controllers with security configuration';
COMMENT ON TABLE enhanced_cloud_security_summary IS 'Summary of enhanced cloud security posture';
