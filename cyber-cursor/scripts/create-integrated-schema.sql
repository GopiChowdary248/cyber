-- CyberShield Integrated Database Schema
-- This script creates all necessary tables for the complete system

-- Connect to the cybershield database
\c cybershield;

-- Create enum types for all modules
DO $$
BEGIN
    -- SAST enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issueresolution') THEN
        CREATE TYPE issueresolution AS ENUM ('FIXED', 'WONTFIX', 'FALSE_POSITIVE', 'ACCEPTED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityhotspotresolution') THEN
        CREATE TYPE securityhotspotresolution AS ENUM ('FIXED', 'ACKNOWLEDGED', 'FALSE_POSITIVE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'qualitygatestatus') THEN
        CREATE TYPE qualitygatestatus AS ENUM ('PASSED', 'FAILED', 'WARNING');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rating') THEN
        CREATE TYPE rating AS ENUM ('A', 'B', 'C', 'D', 'E');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scanstatus') THEN
        CREATE TYPE scanstatus AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityhotspotstatus') THEN
        CREATE TYPE securityhotspotstatus AS ENUM ('TO_REVIEW', 'REVIEWED', 'FIXED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issueseverity') THEN
        CREATE TYPE issueseverity AS ENUM ('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issuetype') THEN
        CREATE TYPE issuetype AS ENUM ('BUG', 'VULNERABILITY', 'CODE_SMELL');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issuestatus') THEN
        CREATE TYPE issuestatus AS ENUM ('OPEN', 'CONFIRMED', 'RESOLVED', 'REOPENED', 'CLOSED');
    END IF;
    
    -- DAST enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dastseverity') THEN
        CREATE TYPE dastseverity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'daststatus') THEN
        CREATE TYPE daststatus AS ENUM ('ACTIVE', 'INACTIVE', 'ARCHIVED');
    END IF;
    
    -- RASP enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'raspstatus') THEN
        CREATE TYPE raspstatus AS ENUM ('ACTIVE', 'INACTIVE', 'MAINTENANCE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'raspattacktype') THEN
        CREATE TYPE raspattacktype AS ENUM ('SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'LDAP_INJECTION');
    END IF;
    
    -- Cloud Security enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cloudprovider') THEN
        CREATE TYPE cloudprovider AS ENUM ('AWS', 'AZURE', 'GCP', 'DIGITAL_OCEAN', 'LINODE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risklevel') THEN
        CREATE TYPE risklevel AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
    END IF;
    
    -- IAM enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
        CREATE TYPE userrole AS ENUM ('ADMIN', 'USER', 'ANALYST', 'MANAGER', 'AUDITOR');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sessionstatus') THEN
        CREATE TYPE sessionstatus AS ENUM ('ACTIVE', 'EXPIRED', 'TERMINATED', 'SUSPENDED');
    END IF;
    
    -- Device Control enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'devicetype') THEN
        CREATE TYPE devicetype AS ENUM ('USB', 'BLUETOOTH', 'WIFI', 'ETHERNET', 'OPTICAL', 'OTHER');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'devicestatus') THEN
        CREATE TYPE devicestatus AS ENUM ('ALLOWED', 'BLOCKED', 'PENDING', 'QUARANTINED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policyaction') THEN
        CREATE TYPE policyaction AS ENUM ('ALLOW', 'BLOCK', 'AUDIT', 'QUARANTINE');
    END IF;
    
    -- Network Security enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alertseverity') THEN
        CREATE TYPE alertseverity AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alertstatus') THEN
        CREATE TYPE alertstatus AS ENUM ('NEW', 'IN_PROGRESS', 'RESOLVED', 'CLOSED');
    END IF;
END
$$;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100),
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_superuser BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    department VARCHAR(100),
    phone VARCHAR(20),
    avatar_url VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    preferences JSONB
);

-- Create SAST tables
CREATE TABLE IF NOT EXISTS sast_projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    repository_url VARCHAR(500),
    branch VARCHAR(100) DEFAULT 'main',
    language VARCHAR(50),
    framework VARCHAR(100),
    quality_gate_status qualitygatestatus DEFAULT 'PASSED',
    security_rating rating DEFAULT 'A',
    reliability_rating rating DEFAULT 'A',
    maintainability_rating rating DEFAULT 'A',
    coverage_percentage DECIMAL(5,2) DEFAULT 0.0,
    duplications_percentage DECIMAL(5,2) DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS sast_scans (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES sast_projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL,
    status scanstatus DEFAULT 'PENDING',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    total_issues INTEGER DEFAULT 0,
    critical_issues INTEGER DEFAULT 0,
    major_issues INTEGER DEFAULT 0,
    minor_issues INTEGER DEFAULT 0,
    info_issues INTEGER DEFAULT 0,
    scan_config JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sast_issues (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES sast_scans(id) ON DELETE CASCADE,
    issue_key VARCHAR(255) UNIQUE NOT NULL,
    rule_id VARCHAR(100),
    severity issueseverity NOT NULL,
    type issuetype NOT NULL,
    status issuestatus DEFAULT 'OPEN',
    resolution issueresolution,
    component VARCHAR(500),
    line_number INTEGER,
    message TEXT,
    effort VARCHAR(50),
    debt VARCHAR(50),
    author VARCHAR(100),
    assignee VARCHAR(100),
    tags TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create DAST tables
CREATE TABLE IF NOT EXISTS dast_projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_url VARCHAR(500) NOT NULL,
    scan_depth INTEGER DEFAULT 3,
    max_requests_per_second INTEGER DEFAULT 10,
    authentication_enabled BOOLEAN DEFAULT FALSE,
    auth_username VARCHAR(100),
    auth_password VARCHAR(255),
    custom_headers JSONB,
    excluded_paths TEXT[],
    included_paths TEXT[],
    status daststatus DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS dast_scans (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES dast_projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL,
    status scanstatus DEFAULT 'PENDING',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    total_requests INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_vulnerabilities INTEGER DEFAULT 0,
    high_vulnerabilities INTEGER DEFAULT 0,
    medium_vulnerabilities INTEGER DEFAULT 0,
    low_vulnerabilities INTEGER DEFAULT 0,
    scan_config JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS dast_vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES dast_scans(id) ON DELETE CASCADE,
    vulnerability_type VARCHAR(100) NOT NULL,
    severity dastseverity NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    evidence TEXT,
    url VARCHAR(500),
    parameter VARCHAR(100),
    payload TEXT,
    cwe_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    remediation TEXT,
    status VARCHAR(50) DEFAULT 'OPEN',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP tables
CREATE TABLE IF NOT EXISTS rasp_agents (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    agent_id VARCHAR(100) UNIQUE NOT NULL,
    application_name VARCHAR(255),
    environment VARCHAR(50),
    version VARCHAR(50),
    status raspstatus DEFAULT 'ACTIVE',
    last_heartbeat TIMESTAMP,
    ip_address INET,
    hostname VARCHAR(255),
    os_info JSONB,
    java_version VARCHAR(50),
    memory_usage JSONB,
    cpu_usage JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS rasp_attacks (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES rasp_agents(id) ON DELETE CASCADE,
    attack_type raspattacktype NOT NULL,
    severity VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    request_id VARCHAR(100),
    url VARCHAR(500),
    method VARCHAR(10),
    headers JSONB,
    body TEXT,
    ip_address INET,
    user_agent TEXT,
    blocked BOOLEAN DEFAULT FALSE,
    action_taken VARCHAR(100),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Cloud Security tables
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    provider cloudprovider NOT NULL,
    account_id VARCHAR(100),
    region VARCHAR(100),
    access_key_id VARCHAR(255),
    secret_access_key VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    last_sync TIMESTAMP,
    sync_status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    asset_type VARCHAR(100) NOT NULL,
    asset_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    region VARCHAR(100),
    tags JSONB,
    configuration JSONB,
    risk_level risklevel DEFAULT 'LOW',
    compliance_status VARCHAR(50),
    last_audit TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS misconfigurations (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES cloud_assets(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'OPEN',
    remediation TEXT,
    cwe_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create IAM tables
CREATE TABLE IF NOT EXISTS iam_users (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    external_id VARCHAR(255),
    groups TEXT[],
    permissions JSONB,
    last_access_review TIMESTAMP,
    access_review_status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS privileged_accounts (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255) NOT NULL,
    account_type VARCHAR(100),
    username VARCHAR(100),
    description TEXT,
    risk_level risklevel DEFAULT 'MEDIUM',
    justification TEXT,
    approval_status VARCHAR(50) DEFAULT 'PENDING',
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Device Control tables
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    type devicetype NOT NULL,
    manufacturer VARCHAR(255),
    model VARCHAR(255),
    serial_number VARCHAR(255),
    status devicestatus DEFAULT 'PENDING',
    last_seen TIMESTAMP,
    ip_address INET,
    mac_address VARCHAR(17),
    user_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    device_type devicetype,
    action policyaction NOT NULL,
    conditions JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create Network Security tables
CREATE TABLE IF NOT EXISTS network_devices (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(100),
    ip_address INET NOT NULL,
    mac_address VARCHAR(17),
    location VARCHAR(255),
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES network_devices(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    action VARCHAR(20),
    rule_id VARCHAR(100),
    severity alertseverity DEFAULT 'LOW',
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

CREATE INDEX IF NOT EXISTS idx_sast_projects_name ON sast_projects(name);
CREATE INDEX IF NOT EXISTS idx_sast_projects_created_by ON sast_projects(created_by);
CREATE INDEX IF NOT EXISTS idx_sast_scans_project_id ON sast_scans(project_id);
CREATE INDEX IF NOT EXISTS idx_sast_scans_status ON sast_scans(status);
CREATE INDEX IF NOT EXISTS idx_sast_issues_scan_id ON sast_issues(scan_id);
CREATE INDEX IF NOT EXISTS idx_sast_issues_severity ON sast_issues(severity);

CREATE INDEX IF NOT EXISTS idx_dast_projects_name ON dast_projects(name);
CREATE INDEX IF NOT EXISTS idx_dast_projects_created_by ON dast_projects(created_by);
CREATE INDEX IF NOT EXISTS idx_dast_scans_project_id ON dast_scans(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_scan_id ON dast_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_severity ON dast_vulnerabilities(severity);

CREATE INDEX IF NOT EXISTS idx_rasp_agents_name ON rasp_agents(name);
CREATE INDEX IF NOT EXISTS idx_rasp_agents_status ON rasp_agents(status);
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_agent_id ON rasp_attacks(agent_id);
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_timestamp ON rasp_attacks(timestamp);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider ON cloud_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_account_id ON cloud_assets(account_id);
CREATE INDEX IF NOT EXISTS idx_misconfigurations_asset_id ON misconfigurations(asset_id);

CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_device_policies_type ON device_policies(device_type);

CREATE INDEX IF NOT EXISTS idx_network_devices_ip ON network_devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_timestamp ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_source_ip ON firewall_logs(source_ip);

-- Grant permissions on all tables
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;

-- Insert sample data for testing
INSERT INTO users (username, email, hashed_password, is_active, is_superuser, role)
VALUES 
    ('admin', 'admin@cybershield.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', TRUE, TRUE, 'ADMIN'),
    ('testuser', 'test@cybershield.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', TRUE, FALSE, 'USER'),
    ('analyst', 'analyst@cybershield.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', TRUE, FALSE, 'ANALYST')
ON CONFLICT (username) DO NOTHING;

-- Insert sample SAST project
INSERT INTO sast_projects (name, description, repository_url, language, framework, created_by)
SELECT 'Sample Web Application', 'A sample web application for testing SAST capabilities', 'https://github.com/sample/webapp', 'Python', 'Flask', u.id
FROM users u WHERE u.username = 'admin'
ON CONFLICT DO NOTHING;

-- Insert sample DAST project
INSERT INTO dast_projects (name, description, target_url, created_by)
SELECT 'Sample Web App Testing', 'Dynamic testing of the sample web application', 'http://localhost:5000', u.id
FROM users u WHERE u.username = 'admin'
ON CONFLICT DO NOTHING;

-- Insert sample RASP agent
INSERT INTO rasp_agents (name, agent_id, application_name, environment, created_by)
SELECT 'Sample RASP Agent', 'agent-001', 'Sample Web App', 'development', u.id
FROM users u WHERE u.username = 'admin'
ON CONFLICT DO NOTHING;

-- Insert sample cloud account
INSERT INTO cloud_accounts (name, provider, account_id, region, created_by)
SELECT 'Sample AWS Account', 'AWS', '123456789012', 'us-east-1', u.id
FROM users u WHERE u.username = 'admin'
ON CONFLICT DO NOTHING;

COMMIT;
