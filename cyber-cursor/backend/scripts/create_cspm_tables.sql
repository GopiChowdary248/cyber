-- CSPM Database Schema Creation Script
-- This script creates all the necessary tables for the Cloud Security Posture Management module

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Connectors table
CREATE TABLE IF NOT EXISTS connectors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('aws', 'azure', 'gcp', 'oci', 'kubernetes')),
    config JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connecting', 'connected', 'disconnected', 'error', 'syncing')),
    last_synced TIMESTAMPTZ,
    sync_interval INTEGER DEFAULT 3600 CHECK (sync_interval >= 300),
    permissions_check JSONB DEFAULT '{}',
    error_details TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Assets table
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID REFERENCES connectors(id) ON DELETE SET NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cloud VARCHAR(50) CHECK (cloud IN ('aws', 'azure', 'gcp', 'oci', 'kubernetes')),
    resource_id VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    name VARCHAR(255),
    region VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    tags JSONB DEFAULT '{}',
    relationships JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    risk_score NUMERIC(5,2) DEFAULT 0.0 CHECK (risk_score >= 0 AND risk_score <= 100),
    UNIQUE(connector_id, resource_id)
);

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    framework VARCHAR(50) DEFAULT 'custom' CHECK (framework IN ('cis', 'nist', 'pci_dss', 'iso27001', 'hipaa', 'gdpr', 'custom')),
    rule JSONB NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category VARCHAR(100),
    compliance_standards JSONB DEFAULT '[]',
    remediation_steps TEXT,
    auto_remediable BOOLEAN DEFAULT FALSE,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(50) DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'in_progress', 'resolved', 'suppressed')),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    evidence JSONB DEFAULT '{}',
    risk_score NUMERIC(5,2) DEFAULT 0.0 CHECK (risk_score >= 0 AND risk_score <= 100),
    owner_id UUID,
    comments JSONB DEFAULT '[]',
    remediation_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Jobs table
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id UUID REFERENCES connectors(id) ON DELETE SET NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('sync', 'scan', 'policy_evaluation', 'remediation')),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    parameters JSONB DEFAULT '{}',
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    result JSONB DEFAULT '{}',
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Remediations table
CREATE TABLE IF NOT EXISTS remediations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    steps JSONB NOT NULL,
    auto_remediable BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    executed_by UUID,
    executed_at TIMESTAMPTZ,
    result JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Integrations table
CREATE TABLE IF NOT EXISTS integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    last_test TIMESTAMPTZ,
    test_status VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert Rules table
CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    conditions JSONB NOT NULL,
    integrations JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Compliance Frameworks table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    controls JSONB NOT NULL,
    policy_mappings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Compliance Reports table
CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    score NUMERIC(5,2) DEFAULT 0.0 CHECK (score >= 0 AND score <= 100),
    total_controls INTEGER DEFAULT 0,
    passed_controls INTEGER DEFAULT 0,
    failed_controls INTEGER DEFAULT 0,
    report_data JSONB DEFAULT '{}',
    generated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID,
    action VARCHAR(255) NOT NULL,
    object_type VARCHAR(100),
    object_id VARCHAR(255),
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_connectors_project_id ON connectors(project_id);
CREATE INDEX IF NOT EXISTS idx_connectors_type ON connectors(type);
CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);

CREATE INDEX IF NOT EXISTS idx_assets_project_id ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_assets_connector_id ON assets(connector_id);
CREATE INDEX IF NOT EXISTS idx_assets_cloud ON assets(cloud);
CREATE INDEX IF NOT EXISTS idx_assets_resource_type ON assets(resource_type);
CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN (metadata jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN (tags jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_policy_id ON findings(policy_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score);

CREATE INDEX IF NOT EXISTS idx_policies_framework ON policies(framework);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
CREATE INDEX IF NOT EXISTS idx_policies_severity ON policies(severity);
CREATE INDEX IF NOT EXISTS idx_policies_category ON policies(category);

CREATE INDEX IF NOT EXISTS idx_jobs_project_id ON jobs(project_id);
CREATE INDEX IF NOT EXISTS idx_jobs_connector_id ON jobs(connector_id);
CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(type);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);

CREATE INDEX IF NOT EXISTS idx_remediations_finding_id ON remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status);

CREATE INDEX IF NOT EXISTS idx_integrations_project_id ON integrations(project_id);
CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type);
CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled);

CREATE INDEX IF NOT EXISTS idx_alert_rules_project_id ON alert_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_project_id ON compliance_reports(project_id);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework_id ON compliance_reports(framework_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_object_type ON audit_logs(object_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Create unique constraints
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_org_name ON projects(org_id, name);

-- Create foreign key constraints
ALTER TABLE assets ADD CONSTRAINT fk_assets_connector_id FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE SET NULL;
ALTER TABLE assets ADD CONSTRAINT fk_assets_project_id FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

ALTER TABLE findings ADD CONSTRAINT fk_findings_asset_id FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE;
ALTER TABLE findings ADD CONSTRAINT fk_findings_policy_id FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE;

ALTER TABLE jobs ADD CONSTRAINT fk_jobs_connector_id FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE SET NULL;
ALTER TABLE jobs ADD CONSTRAINT fk_jobs_project_id FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

ALTER TABLE remediations ADD CONSTRAINT fk_remediations_finding_id FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE;

ALTER TABLE integrations ADD CONSTRAINT fk_integrations_project_id FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

ALTER TABLE alert_rules ADD CONSTRAINT fk_alert_rules_project_id FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

ALTER TABLE compliance_reports ADD CONSTRAINT fk_compliance_reports_project_id FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE compliance_reports ADD CONSTRAINT fk_compliance_reports_framework_id FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id) ON DELETE CASCADE;

-- Insert some sample data for testing
INSERT INTO organizations (id, name, description) VALUES 
    (uuid_generate_v4(), 'Default Organization', 'Default organization for CSPM module')
ON CONFLICT (name) DO NOTHING;

-- Insert sample compliance frameworks
INSERT INTO compliance_frameworks (name, version, description, controls) VALUES 
    ('CIS AWS Foundations Benchmark', '1.5.0', 'Center for Internet Security AWS Foundations Benchmark', '[]'),
    ('NIST Cybersecurity Framework', '1.1', 'National Institute of Standards and Technology Cybersecurity Framework', '[]'),
    ('PCI DSS', '4.0', 'Payment Card Industry Data Security Standard', '[]')
ON CONFLICT DO NOTHING;

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_connectors_updated_at BEFORE UPDATE ON connectors FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON integrations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_alert_rules_updated_at BEFORE UPDATE ON alert_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_app_user;

COMMENT ON TABLE organizations IS 'Organizations that use the CSPM system';
COMMENT ON TABLE projects IS 'Projects within organizations for organizing cloud resources';
COMMENT ON TABLE connectors IS 'Cloud provider connectors for asset discovery';
COMMENT ON TABLE assets IS 'Cloud resources discovered through connectors';
COMMENT ON TABLE policies IS 'Security policies for compliance checking';
COMMENT ON TABLE findings IS 'Security findings from policy evaluation';
COMMENT ON TABLE jobs IS 'Background jobs for sync and evaluation tasks';
COMMENT ON TABLE remediations IS 'Remediation playbooks for findings';
COMMENT ON TABLE integrations IS 'Third-party integrations for notifications and ticketing';
COMMENT ON TABLE alert_rules IS 'Alerting rules for security events';
COMMENT ON TABLE compliance_frameworks IS 'Compliance frameworks and standards';
COMMENT ON TABLE compliance_reports IS 'Compliance assessment reports';
COMMENT ON TABLE audit_logs IS 'Audit trail for all system activities';
