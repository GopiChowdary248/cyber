-- Complete CyberShield Database Initialization Script
-- This script creates all missing tables to ensure ALL application data is stored in PostgreSQL

-- Connect to the database
\c cybershield;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create missing enum types
DO $$ BEGIN
    CREATE TYPE cloud_provider AS ENUM ('aws', 'azure', 'gcp');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE risk_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE compliance_standard AS ENUM ('cis', 'nist', 'iso27001', 'pci_dss', 'gdpr', 'hipaa');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE asset_type AS ENUM (
        'ec2', 's3', 'rds', 'lambda', 'vpc', 'iam', 'cloudfront', 'ecs', 'eks',
        'vm', 'blob', 'sql', 'app_service', 'key_vault', 'compute_engine',
        'cloud_storage', 'cloud_sql', 'kubernetes'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE workflow_status AS ENUM ('draft', 'active', 'paused', 'completed', 'failed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE workflow_trigger_type AS ENUM ('manual', 'scheduled', 'event', 'webhook');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE analytics_metric_type AS ENUM ('count', 'percentage', 'duration', 'score', 'trend');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- CLOUD SECURITY TABLES
-- ============================================================================

-- Cloud Accounts Table
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    provider cloud_provider NOT NULL,
    region VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    last_scan TIMESTAMP WITH TIME ZONE,
    security_score FLOAT DEFAULT 0.0,
    risk_level risk_level DEFAULT 'info',
    account_metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Cloud Assets Table
CREATE TABLE IF NOT EXISTS cloud_assets (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    asset_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    asset_type asset_type NOT NULL,
    region VARCHAR(100) NOT NULL,
    status VARCHAR(50),
    tags JSONB,
    asset_metadata JSONB,
    risk_score FLOAT DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Misconfigurations Table
CREATE TABLE IF NOT EXISTS misconfigurations (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES cloud_assets(id) ON DELETE CASCADE,
    rule_id VARCHAR(255),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity risk_level NOT NULL,
    category VARCHAR(100),
    compliance_standards JSONB,
    remediation_steps TEXT,
    auto_remediable BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'open',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Compliance Reports Table
CREATE TABLE IF NOT EXISTS compliance_reports (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    standard compliance_standard NOT NULL,
    score FLOAT,
    total_checks INTEGER,
    passed_checks INTEGER,
    failed_checks INTEGER,
    report_data JSONB,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- SaaS Applications Table
CREATE TABLE IF NOT EXISTS saas_applications (
    id SERIAL PRIMARY KEY,
    app_name VARCHAR(255) NOT NULL,
    app_category VARCHAR(100),
    vendor VARCHAR(255),
    risk_score FLOAT DEFAULT 0.0,
    status VARCHAR(50) DEFAULT 'discovered',
    user_count INTEGER DEFAULT 0,
    data_classification JSONB,
    security_features JSONB,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE
);

-- User Activities Table
CREATE TABLE IF NOT EXISTS user_activities (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    app_id INTEGER REFERENCES saas_applications(id) ON DELETE CASCADE,
    activity_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    location VARCHAR(255),
    device_info JSONB,
    risk_score FLOAT DEFAULT 0.0,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Cloud DLP Incidents Table
CREATE TABLE IF NOT EXISTS cloud_dlp_incidents (
    id SERIAL PRIMARY KEY,
    app_id INTEGER REFERENCES saas_applications(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    incident_type VARCHAR(100) NOT NULL,
    file_name VARCHAR(255),
    file_size INTEGER,
    action_taken VARCHAR(100),
    confidence_score FLOAT,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Cloud Threats Table
CREATE TABLE IF NOT EXISTS cloud_threats (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    threat_id VARCHAR(255),
    threat_type VARCHAR(100) NOT NULL,
    severity risk_level NOT NULL,
    source_ip VARCHAR(45),
    target_resource VARCHAR(255),
    description TEXT,
    threat_data JSONB,
    status VARCHAR(50) DEFAULT 'active',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- IAM Risks Table
CREATE TABLE IF NOT EXISTS iam_risks (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    entity_id VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    risk_type VARCHAR(100) NOT NULL,
    severity risk_level NOT NULL,
    permissions JSONB,
    recommendations JSONB,
    status VARCHAR(50) DEFAULT 'open',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DDoS Protection Table
CREATE TABLE IF NOT EXISTS ddos_protection (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    protection_id VARCHAR(255),
    service VARCHAR(100) NOT NULL,
    status VARCHAR(50),
    protected_resources JSONB,
    attack_statistics JSONB,
    last_attack TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- WORKFLOWS TABLES
-- ============================================================================

-- Workflows Table
CREATE TABLE IF NOT EXISTS workflows (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    workflow_type VARCHAR(100) NOT NULL,
    status workflow_status DEFAULT 'draft',
    trigger_type workflow_trigger_type DEFAULT 'manual',
    trigger_config JSONB,
    steps JSONB NOT NULL,
    variables JSONB,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_executed TIMESTAMP WITH TIME ZONE
);

-- Workflow Executions Table
CREATE TABLE IF NOT EXISTS workflow_executions (
    id SERIAL PRIMARY KEY,
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE CASCADE,
    execution_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'running',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    input_data JSONB,
    output_data JSONB,
    error_message TEXT,
    execution_log JSONB
);

-- Workflow Steps Table
CREATE TABLE IF NOT EXISTS workflow_steps (
    id SERIAL PRIMARY KEY,
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE CASCADE,
    step_order INTEGER NOT NULL,
    step_type VARCHAR(100) NOT NULL,
    step_name VARCHAR(255) NOT NULL,
    step_config JSONB,
    conditions JSONB,
    actions JSONB,
    timeout INTEGER DEFAULT 300
);

-- ============================================================================
-- ANALYTICS TABLES
-- ============================================================================

-- Analytics Metrics Table
CREATE TABLE IF NOT EXISTS analytics_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,
    metric_type analytics_metric_type NOT NULL,
    metric_value FLOAT NOT NULL,
    metric_unit VARCHAR(50),
    tags JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(100),
    context JSONB
);

-- Analytics Dashboards Table
CREATE TABLE IF NOT EXISTS analytics_dashboards (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    layout JSONB NOT NULL,
    widgets JSONB,
    filters JSONB,
    created_by INTEGER REFERENCES users(id),
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Analytics Reports Table
CREATE TABLE IF NOT EXISTS analytics_reports (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(100) NOT NULL,
    report_data JSONB NOT NULL,
    parameters JSONB,
    generated_by INTEGER REFERENCES users(id),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- AI/ML TABLES
-- ============================================================================

-- AI Models Table
CREATE TABLE IF NOT EXISTS ai_models (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    model_type VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    description TEXT,
    model_path VARCHAR(500),
    model_config JSONB,
    performance_metrics JSONB,
    training_data_info JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- AI Predictions Table
CREATE TABLE IF NOT EXISTS ai_predictions (
    id SERIAL PRIMARY KEY,
    model_id INTEGER REFERENCES ai_models(id) ON DELETE CASCADE,
    input_data JSONB NOT NULL,
    prediction_result JSONB NOT NULL,
    confidence_score FLOAT,
    prediction_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- AI Training Jobs Table
CREATE TABLE IF NOT EXISTS ai_training_jobs (
    id SERIAL PRIMARY KEY,
    model_id INTEGER REFERENCES ai_models(id) ON DELETE CASCADE,
    job_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'queued',
    training_config JSONB,
    training_data_path VARCHAR(500),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    training_metrics JSONB,
    error_message TEXT
);

-- ============================================================================
-- INTEGRATIONS TABLES
-- ============================================================================

-- External Integrations Table
CREATE TABLE IF NOT EXISTS external_integrations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    integration_type VARCHAR(100) NOT NULL,
    provider VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'inactive',
    config JSONB NOT NULL,
    credentials JSONB,
    last_sync TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(50),
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Integration Logs Table
CREATE TABLE IF NOT EXISTS integration_logs (
    id SERIAL PRIMARY KEY,
    integration_id INTEGER REFERENCES external_integrations(id) ON DELETE CASCADE,
    log_level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- COMPLIANCE TABLES
-- ============================================================================

-- Compliance Frameworks Table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    requirements JSONB,
    controls JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Compliance Assessments Table
CREATE TABLE IF NOT EXISTS compliance_assessments (
    id SERIAL PRIMARY KEY,
    framework_id INTEGER REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    assessment_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'in_progress',
    start_date DATE NOT NULL,
    end_date DATE,
    assessor VARCHAR(255),
    score FLOAT,
    findings JSONB,
    recommendations JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- MFA TABLES
-- ============================================================================

-- MFA Devices Table
CREATE TABLE IF NOT EXISTS mfa_devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    device_type VARCHAR(50) NOT NULL,
    device_name VARCHAR(255),
    device_id VARCHAR(255) UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- MFA Backup Codes Table
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- PHISHING TABLES
-- ============================================================================

-- Phishing Campaigns Table
CREATE TABLE IF NOT EXISTS phishing_campaigns (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'draft',
    target_audience JSONB,
    email_template_id INTEGER,
    campaign_config JSONB,
    start_date DATE,
    end_date DATE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Phishing Results Table
CREATE TABLE IF NOT EXISTS phishing_results (
    id SERIAL PRIMARY KEY,
    campaign_id INTEGER REFERENCES phishing_campaigns(id) ON DELETE CASCADE,
    target_email VARCHAR(255) NOT NULL,
    target_name VARCHAR(255),
    email_sent BOOLEAN DEFAULT FALSE,
    email_opened BOOLEAN DEFAULT FALSE,
    link_clicked BOOLEAN DEFAULT FALSE,
    credentials_entered BOOLEAN DEFAULT FALSE,
    response_time INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INCIDENTS TABLES
-- ============================================================================

-- Incident Categories Table
CREATE TABLE IF NOT EXISTS incident_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity risk_level NOT NULL,
    sla_hours INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Incident Priorities Table
CREATE TABLE IF NOT EXISTS incident_priorities (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    sla_hours INTEGER NOT NULL,
    escalation_hours INTEGER,
    color VARCHAR(7),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Incident Statuses Table
CREATE TABLE IF NOT EXISTS incident_statuses (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- APPLICATION SECURITY TABLES
-- ============================================================================

-- Application Security Scans Table
CREATE TABLE IF NOT EXISTS app_security_scans (
    id SERIAL PRIMARY KEY,
    application_name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    scan_config JSONB,
    vulnerabilities_found INTEGER DEFAULT 0,
    scan_duration INTEGER,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    scan_results JSONB,
    error_message TEXT
);

-- Application Security Issues Table
CREATE TABLE IF NOT EXISTS app_security_issues (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES app_security_scans(id) ON DELETE CASCADE,
    issue_type VARCHAR(100) NOT NULL,
    severity risk_level NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    location VARCHAR(500),
    recommendation TEXT,
    cwe_id VARCHAR(20),
    cvss_score FLOAT,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- ENHANCED CLOUD SECURITY TABLES
-- ============================================================================

-- Cloud Security Posture Table
CREATE TABLE IF NOT EXISTS cloud_security_posture (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    assessment_date DATE NOT NULL,
    overall_score FLOAT NOT NULL,
    category_scores JSONB,
    risk_distribution JSONB,
    compliance_status JSONB,
    recommendations JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Cloud Security Alerts Table
CREATE TABLE IF NOT EXISTS cloud_security_alerts (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    alert_type VARCHAR(100) NOT NULL,
    severity risk_level NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    affected_resources JSONB,
    alert_data JSONB,
    status VARCHAR(50) DEFAULT 'active',
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- ENDPOINT SECURITY TABLES
-- ============================================================================

-- Endpoint Agents Table
CREATE TABLE IF NOT EXISTS endpoint_agents (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    os_type VARCHAR(50),
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    status VARCHAR(50) DEFAULT 'active',
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scan TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Endpoint Threats Table
CREATE TABLE IF NOT EXISTS endpoint_threats (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES endpoint_agents(id) ON DELETE CASCADE,
    threat_type VARCHAR(100) NOT NULL,
    threat_name VARCHAR(255) NOT NULL,
    severity risk_level NOT NULL,
    file_path VARCHAR(500),
    process_name VARCHAR(255),
    threat_signature VARCHAR(500),
    status VARCHAR(50) DEFAULT 'detected',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- CREATE INDEXES FOR PERFORMANCE
-- ============================================================================

-- Cloud Security Indexes
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider ON cloud_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_region ON cloud_accounts(region);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_account ON cloud_assets(account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_type ON cloud_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_misconfigurations_asset ON misconfigurations(asset_id);
CREATE INDEX IF NOT EXISTS idx_misconfigurations_severity ON misconfigurations(severity);

-- Workflow Indexes
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
CREATE INDEX IF NOT EXISTS idx_workflows_type ON workflows(workflow_type);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status);

-- Analytics Indexes
CREATE INDEX IF NOT EXISTS idx_analytics_metrics_name ON analytics_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_analytics_metrics_timestamp ON analytics_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_analytics_dashboards_public ON analytics_dashboards(is_public);

-- AI/ML Indexes
CREATE INDEX IF NOT EXISTS idx_ai_models_type ON ai_models(model_type);
CREATE INDEX IF NOT EXISTS idx_ai_models_active ON ai_models(is_active);
CREATE INDEX IF NOT EXISTS idx_ai_predictions_model ON ai_predictions(model_id);
CREATE INDEX IF NOT EXISTS idx_ai_training_jobs_status ON ai_training_jobs(status);

-- Integration Indexes
CREATE INDEX IF NOT EXISTS idx_external_integrations_type ON external_integrations(integration_type);
CREATE INDEX IF NOT EXISTS idx_external_integrations_status ON external_integrations(status);
CREATE INDEX IF NOT EXISTS idx_integration_logs_level ON integration_logs(log_level);

-- Compliance Indexes
CREATE INDEX IF NOT EXISTS idx_compliance_frameworks_name ON compliance_frameworks(name);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_framework ON compliance_assessments(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_status ON compliance_assessments(status);

-- MFA Indexes
CREATE INDEX IF NOT EXISTS idx_mfa_devices_user ON mfa_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_type ON mfa_devices(device_type);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);

-- Phishing Indexes
CREATE INDEX IF NOT EXISTS idx_phishing_campaigns_status ON phishing_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_phishing_results_campaign ON phishing_results(campaign_id);
CREATE INDEX IF NOT EXISTS idx_phishing_results_email ON phishing_results(target_email);

-- Incident Indexes
CREATE INDEX IF NOT EXISTS idx_incident_categories_severity ON incident_categories(severity);
CREATE INDEX IF NOT EXISTS idx_incident_priorities_name ON incident_priorities(name);
CREATE INDEX IF NOT EXISTS idx_incident_statuses_active ON incident_statuses(is_active);

-- Application Security Indexes
CREATE INDEX IF NOT EXISTS idx_app_security_scans_application ON app_security_scans(application_name);
CREATE INDEX IF NOT EXISTS idx_app_security_scans_status ON app_security_scans(status);
CREATE INDEX IF NOT EXISTS idx_app_security_issues_scan ON app_security_issues(scan_id);
CREATE INDEX IF NOT EXISTS idx_app_security_issues_severity ON app_security_issues(severity);

-- Endpoint Security Indexes
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_hostname ON endpoint_agents(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_status ON endpoint_agents(status);
CREATE INDEX IF NOT EXISTS idx_endpoint_threats_agent ON endpoint_threats(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_threats_severity ON endpoint_threats(severity);

-- ============================================================================
-- GRANT PERMISSIONS
-- ============================================================================

-- Grant all privileges to the application user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cybershield_user;

-- ============================================================================
-- INSERT DEFAULT DATA
-- ============================================================================

-- Insert default incident statuses
INSERT INTO incident_statuses (name, description, sort_order) VALUES
('New', 'New incident created', 1),
('In Progress', 'Incident is being investigated', 2),
('On Hold', 'Incident investigation is paused', 3),
('Resolved', 'Incident has been resolved', 4),
('Closed', 'Incident is closed', 5)
ON CONFLICT (name) DO NOTHING;

-- Insert default incident priorities
INSERT INTO incident_priorities (name, description, sla_hours, escalation_hours, color) VALUES
('Critical', 'Immediate attention required', 1, 2, '#FF0000'),
('High', 'High priority issue', 4, 8, '#FF6600'),
('Medium', 'Medium priority issue', 24, 48, '#FFCC00'),
('Low', 'Low priority issue', 72, 168, '#00CC00')
ON CONFLICT (name) DO NOTHING;

-- Insert default incident categories
INSERT INTO incident_categories (name, description, severity, sla_hours) VALUES
('Malware', 'Malware detection and response', 'high', 4),
('Data Breach', 'Unauthorized data access', 'critical', 1),
('Phishing', 'Phishing attack response', 'high', 4),
('Network Attack', 'Network-based attacks', 'high', 4),
('Insider Threat', 'Internal security threats', 'critical', 2),
('Vulnerability', 'Security vulnerability exploitation', 'medium', 24)
ON CONFLICT (name) DO NOTHING;

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (name, version, description) VALUES
('CIS Controls', '8.0', 'Center for Internet Security Critical Security Controls'),
('NIST Cybersecurity Framework', '2.0', 'National Institute of Standards and Technology Cybersecurity Framework'),
('ISO 27001', '2022', 'Information Security Management System'),
('PCI DSS', '4.0', 'Payment Card Industry Data Security Standard'),
('GDPR', '2018', 'General Data Protection Regulation'),
('HIPAA', '1996', 'Health Insurance Portability and Accountability Act')
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- VERIFICATION
-- ============================================================================

-- Display table count
SELECT COUNT(*) as total_tables FROM information_schema.tables WHERE table_schema = 'public';

-- Display all tables
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;

-- Display table sizes
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats 
WHERE schemaname = 'public' 
ORDER BY tablename, attname;
