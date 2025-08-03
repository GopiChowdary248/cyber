-- Initialize Cloud Security Database Tables
-- This script creates all tables for CSPM, CASB, and Cloud-Native Security modules

-- ============================================================================
-- CSPM (Cloud Security Posture Management) Tables
-- ============================================================================

-- Cloud Accounts Table
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(20) NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    region VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    last_scan TIMESTAMP WITH TIME ZONE,
    security_score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'info' CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Cloud Assets Table
CREATE TABLE IF NOT EXISTS cloud_assets (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    asset_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL CHECK (asset_type IN (
        'ec2', 's3', 'rds', 'lambda', 'vpc', 'iam', 'cloudfront', 'ecs', 'eks',
        'vm', 'blob', 'sql', 'app_service', 'key_vault', 'compute_engine',
        'cloud_storage', 'cloud_sql', 'kubernetes'
    )),
    region VARCHAR(100) NOT NULL,
    status VARCHAR(50),
    tags JSONB,
    metadata JSONB,
    risk_score FLOAT DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Misconfigurations Table
CREATE TABLE IF NOT EXISTS misconfigurations (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES cloud_assets(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category VARCHAR(100) NOT NULL,
    compliance_standards JSONB NOT NULL, -- Array of compliance standards
    remediation_steps TEXT NOT NULL,
    auto_remediable BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'open',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Compliance Reports Table
CREATE TABLE IF NOT EXISTS compliance_reports (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    standard VARCHAR(20) NOT NULL CHECK (standard IN ('cis', 'nist', 'iso27001', 'pci_dss', 'gdpr', 'hipaa')),
    score FLOAT NOT NULL CHECK (score >= 0 AND score <= 100),
    total_checks INTEGER NOT NULL DEFAULT 0,
    passed_checks INTEGER NOT NULL DEFAULT 0,
    failed_checks INTEGER NOT NULL DEFAULT 0,
    report_data JSONB NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- CASB (Cloud Access Security Broker) Tables
-- ============================================================================

-- SaaS Applications Table
CREATE TABLE IF NOT EXISTS saas_applications (
    id SERIAL PRIMARY KEY,
    app_name VARCHAR(255) NOT NULL,
    app_category VARCHAR(100) NOT NULL,
    vendor VARCHAR(255) NOT NULL,
    risk_score FLOAT DEFAULT 0.0 CHECK (risk_score >= 0 AND risk_score <= 100),
    status VARCHAR(50) DEFAULT 'discovered' CHECK (status IN ('discovered', 'sanctioned', 'blocked')),
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
    activity_type VARCHAR(100) NOT NULL, -- login, upload, download, share, admin_action
    ip_address VARCHAR(45) NOT NULL,
    location VARCHAR(255),
    device_info JSONB,
    risk_score FLOAT DEFAULT 0.0 CHECK (risk_score >= 0 AND risk_score <= 100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DLP Incidents Table
CREATE TABLE IF NOT EXISTS dlp_incidents (
    id SERIAL PRIMARY KEY,
    app_id INTEGER REFERENCES saas_applications(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    incident_type VARCHAR(100) NOT NULL, -- pii, pci, phi, intellectual_property
    file_name VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    action_taken VARCHAR(100) NOT NULL, -- blocked, quarantined, allowed, alerted
    confidence_score FLOAT NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
    details JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Cloud-Native Security Tables
-- ============================================================================

-- Cloud Threats Table
CREATE TABLE IF NOT EXISTS cloud_threats (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    threat_id VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100) NOT NULL, -- ddos, malware, unauthorized_access, data_exfiltration
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    source_ip VARCHAR(45) NOT NULL,
    target_resource VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    threat_data JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- IAM Risks Table
CREATE TABLE IF NOT EXISTS iam_risks (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    entity_id VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL, -- user, role, group, service_account
    risk_type VARCHAR(100) NOT NULL, -- over_privileged, unused_permissions, weak_policies
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    permissions JSONB NOT NULL,
    recommendations JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DDoS Protection Table
CREATE TABLE IF NOT EXISTS ddos_protection (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    protection_id VARCHAR(255) NOT NULL,
    service VARCHAR(100) NOT NULL, -- aws_shield, azure_ddos, gcp_armor
    status VARCHAR(50) NOT NULL,
    protected_resources JSONB NOT NULL, -- Array of protected resource IDs
    attack_statistics JSONB NOT NULL,
    last_attack TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes for Performance
-- ============================================================================

-- Cloud Accounts Indexes
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_account_id ON cloud_accounts(account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider ON cloud_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_risk_level ON cloud_accounts(risk_level);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_status ON cloud_accounts(status);

-- Cloud Assets Indexes
CREATE INDEX IF NOT EXISTS idx_cloud_assets_account_id ON cloud_assets(account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_asset_id ON cloud_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_type ON cloud_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_region ON cloud_assets(region);

-- Misconfigurations Indexes
CREATE INDEX IF NOT EXISTS idx_misconfigurations_asset_id ON misconfigurations(asset_id);
CREATE INDEX IF NOT EXISTS idx_misconfigurations_severity ON misconfigurations(severity);
CREATE INDEX IF NOT EXISTS idx_misconfigurations_status ON misconfigurations(status);
CREATE INDEX IF NOT EXISTS idx_misconfigurations_detected_at ON misconfigurations(detected_at);

-- Compliance Reports Indexes
CREATE INDEX IF NOT EXISTS idx_compliance_reports_account_id ON compliance_reports(account_id);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_standard ON compliance_reports(standard);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_at ON compliance_reports(generated_at);

-- SaaS Applications Indexes
CREATE INDEX IF NOT EXISTS idx_saas_apps_name ON saas_applications(app_name);
CREATE INDEX IF NOT EXISTS idx_saas_apps_category ON saas_applications(app_category);
CREATE INDEX IF NOT EXISTS idx_saas_apps_status ON saas_applications(status);
CREATE INDEX IF NOT EXISTS idx_saas_apps_risk_score ON saas_applications(risk_score);

-- User Activities Indexes
CREATE INDEX IF NOT EXISTS idx_user_activities_user_id ON user_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_user_activities_app_id ON user_activities(app_id);
CREATE INDEX IF NOT EXISTS idx_user_activities_timestamp ON user_activities(timestamp);
CREATE INDEX IF NOT EXISTS idx_user_activities_activity_type ON user_activities(activity_type);

-- DLP Incidents Indexes
CREATE INDEX IF NOT EXISTS idx_dlp_incidents_app_id ON dlp_incidents(app_id);
CREATE INDEX IF NOT EXISTS idx_dlp_incidents_user_id ON dlp_incidents(user_id);
CREATE INDEX IF NOT EXISTS idx_dlp_incidents_incident_type ON dlp_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_dlp_incidents_timestamp ON dlp_incidents(timestamp);

-- Cloud Threats Indexes
CREATE INDEX IF NOT EXISTS idx_cloud_threats_account_id ON cloud_threats(account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_threats_threat_id ON cloud_threats(threat_id);
CREATE INDEX IF NOT EXISTS idx_cloud_threats_severity ON cloud_threats(severity);
CREATE INDEX IF NOT EXISTS idx_cloud_threats_status ON cloud_threats(status);
CREATE INDEX IF NOT EXISTS idx_cloud_threats_detected_at ON cloud_threats(detected_at);

-- IAM Risks Indexes
CREATE INDEX IF NOT EXISTS idx_iam_risks_account_id ON iam_risks(account_id);
CREATE INDEX IF NOT EXISTS idx_iam_risks_entity_id ON iam_risks(entity_id);
CREATE INDEX IF NOT EXISTS idx_iam_risks_severity ON iam_risks(severity);
CREATE INDEX IF NOT EXISTS idx_iam_risks_status ON iam_risks(status);

-- DDoS Protection Indexes
CREATE INDEX IF NOT EXISTS idx_ddos_protection_account_id ON ddos_protection(account_id);
CREATE INDEX IF NOT EXISTS idx_ddos_protection_service ON ddos_protection(service);
CREATE INDEX IF NOT EXISTS idx_ddos_protection_status ON ddos_protection(status);

-- ============================================================================
-- Views for Analytics
-- ============================================================================

-- Cloud Security Overview View
CREATE OR REPLACE VIEW cloud_security_overview AS
SELECT 
    COUNT(DISTINCT ca.id) as total_accounts,
    COUNT(DISTINCT cass.id) as total_assets,
    COUNT(DISTINCT m.id) as total_misconfigurations,
    COUNT(DISTINCT ct.id) as total_threats,
    COUNT(DISTINCT sa.id) as total_saas_apps,
    AVG(ca.security_score) as overall_security_score,
    COUNT(CASE WHEN m.severity = 'critical' THEN 1 END) as critical_issues,
    COUNT(CASE WHEN m.severity = 'high' THEN 1 END) as high_issues,
    COUNT(CASE WHEN m.severity = 'medium' THEN 1 END) as medium_issues,
    COUNT(CASE WHEN m.severity = 'low' THEN 1 END) as low_issues
FROM cloud_accounts ca
LEFT JOIN cloud_assets cass ON ca.id = cass.account_id
LEFT JOIN misconfigurations m ON cass.id = m.asset_id
LEFT JOIN cloud_threats ct ON ca.id = ct.account_id
LEFT JOIN saas_applications sa ON 1=1;

-- Provider Distribution View
CREATE OR REPLACE VIEW provider_distribution AS
SELECT 
    provider,
    COUNT(*) as account_count,
    AVG(security_score) as avg_security_score
FROM cloud_accounts
GROUP BY provider;

-- Asset Type Distribution View
CREATE OR REPLACE VIEW asset_type_distribution AS
SELECT 
    asset_type,
    COUNT(*) as asset_count,
    AVG(risk_score) as avg_risk_score
FROM cloud_assets
GROUP BY asset_type;

-- Risk Distribution View
CREATE OR REPLACE VIEW risk_distribution AS
SELECT 
    severity,
    COUNT(*) as count,
    COUNT(CASE WHEN status = 'open' THEN 1 END) as open_count,
    COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_count
FROM misconfigurations
GROUP BY severity;

-- ============================================================================
-- Sample Data for Testing
-- ============================================================================

-- Insert sample cloud accounts
INSERT INTO cloud_accounts (account_id, name, provider, region, security_score, risk_level) VALUES
('123456789012', 'Production AWS Account', 'aws', 'us-east-1', 85.5, 'medium'),
('987654321098', 'Development Azure Account', 'azure', 'eastus', 92.0, 'low'),
('555666777888', 'Staging GCP Account', 'gcp', 'us-central1', 78.5, 'high')
ON CONFLICT (account_id) DO NOTHING;

-- Insert sample cloud assets
INSERT INTO cloud_assets (account_id, asset_id, name, asset_type, region, status, risk_score) VALUES
(1, 'i-1234567890abcdef0', 'Web Server 1', 'ec2', 'us-east-1', 'running', 15.0),
(1, 's3-bucket-production-data', 'Production Data Bucket', 's3', 'us-east-1', 'active', 45.0),
(1, 'db-1234567890abcdef0', 'Production Database', 'rds', 'us-east-1', 'available', 25.0),
(2, 'vm-web-server-001', 'Web Server VM', 'vm', 'eastus', 'running', 20.0),
(3, 'gce-instance-001', 'Compute Instance', 'compute_engine', 'us-central1', 'running', 30.0)
ON CONFLICT DO NOTHING;

-- Insert sample misconfigurations
INSERT INTO misconfigurations (asset_id, rule_id, title, description, severity, category, compliance_standards, remediation_steps, auto_remediable) VALUES
(2, 'S3_BUCKET_PUBLIC_ACCESS', 'S3 Bucket Publicly Accessible', 'S3 bucket is configured for public access', 'high', 'storage', '["cis", "nist"]', 'Remove public access and configure bucket policies', true),
(1, 'EC2_SECURITY_GROUP_OPEN', 'Security Group Allows All Traffic', 'Security group allows inbound traffic from 0.0.0.0/0', 'critical', 'network', '["cis", "pci_dss"]', 'Restrict security group rules to specific IP ranges', true),
(3, 'RDS_ENCRYPTION_DISABLED', 'RDS Encryption Not Enabled', 'RDS instance is not encrypted at rest', 'high', 'database', '["cis", "hipaa"]', 'Enable encryption for the RDS instance', false)
ON CONFLICT DO NOTHING;

-- Insert sample SaaS applications
INSERT INTO saas_applications (app_name, app_category, vendor, risk_score, status, user_count) VALUES
('Salesforce', 'CRM', 'Salesforce Inc', 15.0, 'sanctioned', 150),
('Slack', 'Communication', 'Slack Technologies', 25.0, 'sanctioned', 200),
('Dropbox', 'File Sharing', 'Dropbox Inc', 35.0, 'discovered', 50),
('Zoom', 'Video Conferencing', 'Zoom Video Communications', 20.0, 'sanctioned', 100)
ON CONFLICT DO NOTHING;

-- Insert sample user activities
INSERT INTO user_activities (user_id, app_id, activity_type, ip_address, location, risk_score) VALUES
('user123', 1, 'login', '192.168.1.100', 'New York, NY', 5.0),
('user456', 2, 'upload', '10.0.0.50', 'San Francisco, CA', 15.0),
('user789', 3, 'download', '172.16.0.25', 'London, UK', 25.0)
ON CONFLICT DO NOTHING;

-- Insert sample DLP incidents
INSERT INTO dlp_incidents (app_id, user_id, incident_type, file_name, file_size, action_taken, confidence_score, details) VALUES
(3, 'user456', 'pii', 'customer_data.csv', 2048576, 'blocked', 95.0, '{"detected_patterns": ["ssn", "credit_card"], "file_type": "csv"}'),
(2, 'user789', 'intellectual_property', 'product_specs.pdf', 1048576, 'quarantined', 87.0, '{"detected_patterns": ["confidential", "proprietary"], "file_type": "pdf"}')
ON CONFLICT DO NOTHING;

-- Insert sample cloud threats
INSERT INTO cloud_threats (account_id, threat_id, threat_type, severity, source_ip, target_resource, description, threat_data) VALUES
(1, 'threat-001', 'ddos', 'high', '203.0.113.1', 'i-1234567890abcdef0', 'DDoS attack detected on web server', '{"attack_volume": "10Gbps", "duration": "30min"}'),
(1, 'threat-002', 'unauthorized_access', 'critical', '198.51.100.50', 's3-bucket-production-data', 'Unauthorized access attempt to S3 bucket', '{"access_method": "api", "failed_attempts": 100}')
ON CONFLICT DO NOTHING;

-- Insert sample IAM risks
INSERT INTO iam_risks (account_id, entity_id, entity_type, risk_type, severity, permissions, recommendations) VALUES
(1, 'arn:aws:iam::123456789012:user/admin', 'user', 'over_privileged', 'high', '{"permissions": ["*"]}', '{"action": "reduce_permissions", "principle": "least_privilege"}'),
(2, 'service-principal-001', 'service_account', 'unused_permissions', 'medium', '{"permissions": ["storage.admin", "compute.admin"]}', '{"action": "remove_unused_permissions", "audit": "required"}')
ON CONFLICT DO NOTHING;

-- Insert sample DDoS protection
INSERT INTO ddos_protection (account_id, protection_id, service, status, protected_resources, attack_statistics) VALUES
(1, 'shield-001', 'aws_shield', 'active', '["i-1234567890abcdef0", "s3-bucket-production-data"]', '{"attacks_blocked": 5, "total_volume": "50Gbps"}'),
(2, 'ddos-001', 'azure_ddos', 'active', '["vm-web-server-001"]', '{"attacks_blocked": 2, "total_volume": "20Gbps"}')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE cloud_accounts IS 'Cloud provider accounts for CSPM monitoring';
COMMENT ON TABLE cloud_assets IS 'Cloud resources and assets discovered in accounts';
COMMENT ON TABLE misconfigurations IS 'Security misconfigurations found in cloud assets';
COMMENT ON TABLE compliance_reports IS 'Compliance assessment reports for cloud accounts';
COMMENT ON TABLE saas_applications IS 'SaaS applications discovered and monitored by CASB';
COMMENT ON TABLE user_activities IS 'User activities and behaviors in SaaS applications';
COMMENT ON TABLE dlp_incidents IS 'Data Loss Prevention incidents detected in cloud applications';
COMMENT ON TABLE cloud_threats IS 'Security threats detected in cloud environments';
COMMENT ON TABLE iam_risks IS 'Identity and Access Management risks and violations';
COMMENT ON TABLE ddos_protection IS 'DDoS protection status and statistics';

-- ============================================================================
-- Final Status
-- ============================================================================

SELECT 'Cloud Security database initialization completed successfully!' as status; 