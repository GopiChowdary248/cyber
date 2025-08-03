-- DAST Database Initialization Script
-- This script creates all necessary tables and initial data for the DAST module

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scan TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create DAST Scans table
CREATE TABLE IF NOT EXISTS dast_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES dast_projects(id) ON DELETE CASCADE,
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
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    initiated_by INTEGER REFERENCES users(id)
);

-- Create DAST Vulnerabilities table
CREATE TABLE IF NOT EXISTS dast_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES dast_scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES dast_projects(id) ON DELETE CASCADE,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create DAST Reports table
CREATE TABLE IF NOT EXISTS dast_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES dast_scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES dast_projects(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    report_data JSONB,
    report_file_path TEXT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_public BOOLEAN DEFAULT FALSE,
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    generated_by INTEGER REFERENCES users(id)
);

-- Create DAST Sessions table
CREATE TABLE IF NOT EXISTS dast_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES dast_projects(id) ON DELETE CASCADE,
    session_name VARCHAR(255) NOT NULL,
    session_type VARCHAR(50) NOT NULL,
    session_config JSONB,
    auth_config JSONB,
    requests_log JSONB,
    responses_log JSONB,
    cookies JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_dast_projects_created_by ON dast_projects(created_by);
CREATE INDEX IF NOT EXISTS idx_dast_projects_auth_type ON dast_projects(auth_type);
CREATE INDEX IF NOT EXISTS idx_dast_projects_is_active ON dast_projects(is_active);

CREATE INDEX IF NOT EXISTS idx_dast_scans_project_id ON dast_scans(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_scans_status ON dast_scans(status);
CREATE INDEX IF NOT EXISTS idx_dast_scans_scan_type ON dast_scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_dast_scans_initiated_by ON dast_scans(initiated_by);
CREATE INDEX IF NOT EXISTS idx_dast_scans_started_at ON dast_scans(started_at);

CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_scan_id ON dast_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_project_id ON dast_vulnerabilities(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_severity ON dast_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_vuln_type ON dast_vulnerabilities(vuln_type);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_status ON dast_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_dast_vulnerabilities_cwe_id ON dast_vulnerabilities(cwe_id);

CREATE INDEX IF NOT EXISTS idx_dast_payloads_vuln_type ON dast_payloads(vuln_type);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_severity ON dast_payloads(severity);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_is_active ON dast_payloads(is_active);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_is_custom ON dast_payloads(is_custom);
CREATE INDEX IF NOT EXISTS idx_dast_payloads_created_by ON dast_payloads(created_by);

CREATE INDEX IF NOT EXISTS idx_dast_reports_scan_id ON dast_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_dast_reports_project_id ON dast_reports(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_reports_report_type ON dast_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_dast_reports_generated_at ON dast_reports(generated_at);

CREATE INDEX IF NOT EXISTS idx_dast_sessions_project_id ON dast_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_dast_sessions_session_type ON dast_sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_dast_sessions_is_active ON dast_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_dast_sessions_created_by ON dast_sessions(created_by);

-- Insert initial payloads
INSERT INTO dast_payloads (name, vuln_type, payload, description, severity, cwe_id, owasp_category, language, is_custom) VALUES
-- SQL Injection Payloads
('Basic SQL Injection - OR 1=1', 'sqli', ''' OR 1=1 --', 'Basic SQL injection to bypass authentication', 'critical', 'CWE-89', 'A03:2021-Injection', 'sql', false),
('SQL Injection - UNION SELECT', 'sqli', ''' UNION SELECT NULL,NULL,NULL--', 'UNION-based SQL injection for data extraction', 'critical', 'CWE-89', 'A03:2021-Injection', 'sql', false),
('SQL Injection - Boolean Based', 'sqli', ''' AND 1=1--', 'Boolean-based SQL injection', 'critical', 'CWE-89', 'A03:2021-Injection', 'sql', false),
('SQL Injection - Time Based', 'sqli', '''; WAITFOR DELAY ''00:00:05''--', 'Time-based SQL injection for blind detection', 'critical', 'CWE-89', 'A03:2021-Injection', 'sql', false),
('SQL Injection - Stacked Queries', 'sqli', '''; DROP TABLE users--', 'Stacked queries for destructive operations', 'critical', 'CWE-89', 'A03:2021-Injection', 'sql', false),

-- XSS Payloads
('Basic XSS - Script Tag', 'xss', '<script>alert(''XSS'')</script>', 'Basic reflected XSS using script tag', 'high', 'CWE-79', 'A03:2021-Injection', 'javascript', false),
('XSS - Event Handler', 'xss', '<img src=x onerror=alert(''XSS'')>', 'XSS using event handler', 'high', 'CWE-79', 'A03:2021-Injection', 'javascript', false),
('XSS - JavaScript URI', 'xss', 'javascript:alert(''XSS'')', 'XSS using JavaScript URI scheme', 'high', 'CWE-79', 'A03:2021-Injection', 'javascript', false),
('XSS - DOM Based', 'xss', '#<script>alert(''XSS'')</script>', 'DOM-based XSS using fragment identifier', 'high', 'CWE-79', 'A03:2021-Injection', 'javascript', false),
('XSS - SVG', 'xss', '<svg onload=alert(''XSS'')>', 'XSS using SVG element', 'high', 'CWE-79', 'A03:2021-Injection', 'javascript', false),

-- Command Injection Payloads
('Command Injection - Basic', 'cmdi', '; ls -la', 'Basic command injection to list files', 'critical', 'CWE-78', 'A03:2021-Injection', 'shell', false),
('Command Injection - Sleep', 'cmdi', '; sleep 5', 'Time-based command injection detection', 'critical', 'CWE-78', 'A03:2021-Injection', 'shell', false),
('Command Injection - File Read', 'cmdi', '; cat /etc/passwd', 'Command injection to read system files', 'critical', 'CWE-78', 'A03:2021-Injection', 'shell', false),
('Command Injection - Process List', 'cmdi', '; ps aux', 'Command injection to list processes', 'critical', 'CWE-78', 'A03:2021-Injection', 'shell', false),

-- Path Traversal Payloads
('Path Traversal - Basic', 'lfi', '../../../etc/passwd', 'Basic path traversal to read system files', 'high', 'CWE-22', 'A01:2021-Broken Access Control', 'file', false),
('Path Traversal - Encoded', 'lfi', '..%2F..%2F..%2Fetc%2Fpasswd', 'URL-encoded path traversal', 'high', 'CWE-22', 'A01:2021-Broken Access Control', 'file', false),
('Path Traversal - Windows', 'lfi', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Windows-style path traversal', 'high', 'CWE-22', 'A01:2021-Broken Access Control', 'file', false),

-- SSRF Payloads
('SSRF - AWS Metadata', 'ssrf', 'http://169.254.169.254/latest/meta-data/', 'SSRF to access AWS metadata service', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration', 'http', false),
('SSRF - Azure Metadata', 'ssrf', 'http://169.254.169.254/metadata/instance', 'SSRF to access Azure metadata service', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration', 'http', false),
('SSRF - Internal Network', 'ssrf', 'http://192.168.1.1/', 'SSRF to access internal network', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration', 'http', false),
('SSRF - Localhost', 'ssrf', 'http://localhost:8080/', 'SSRF to access localhost services', 'high', 'CWE-918', 'A05:2021-Security Misconfiguration', 'http', false),

-- Open Redirect Payloads
('Open Redirect - Basic', 'open_redirect', 'https://evil.com', 'Basic open redirect to malicious site', 'medium', 'CWE-601', 'A01:2021-Broken Access Control', 'http', false),
('Open Redirect - Encoded', 'open_redirect', 'https%3A%2F%2Fevil.com', 'URL-encoded open redirect', 'medium', 'CWE-601', 'A01:2021-Broken Access Control', 'http', false),
('Open Redirect - Protocol Relative', 'open_redirect', '//evil.com', 'Protocol-relative open redirect', 'medium', 'CWE-601', 'A01:2021-Broken Access Control', 'http', false),

-- NoSQL Injection Payloads
('NoSQL Injection - Basic', 'nosql_injection', ''' || ''1''==''1', 'Basic NoSQL injection to bypass authentication', 'critical', 'CWE-943', 'A03:2021-Injection', 'nosql', false),
('NoSQL Injection - MongoDB', 'nosql_injection', 'admin'' && ''1''==''1', 'MongoDB-specific NoSQL injection', 'critical', 'CWE-943', 'A03:2021-Injection', 'nosql', false),

-- Template Injection Payloads
('Template Injection - Basic', 'template_injection', '{{7*7}}', 'Basic template injection test', 'high', 'CWE-94', 'A03:2021-Injection', 'template', false),
('Template Injection - RCE', 'template_injection', '{{config.__class__.__init__.__globals__[''os''].popen(''id'').read()}}', 'Template injection for remote code execution', 'critical', 'CWE-94', 'A03:2021-Injection', 'template', false)

ON CONFLICT (name) DO NOTHING;

-- Create sample projects for testing
INSERT INTO dast_projects (name, target_url, description, auth_type, scan_config, tags) VALUES
('E-commerce Web Application', 'https://demo-ecommerce.example.com', 'Sample e-commerce application for testing', 'none', '{"max_urls": 100, "max_depth": 3, "scan_timeout": 300}', '["web", "ecommerce", "testing"]'),
('API Testing Platform', 'https://api-test.example.com', 'REST API for security testing', 'jwt', '{"max_urls": 50, "max_depth": 2, "scan_timeout": 180}', '["api", "rest", "testing"]'),
('Admin Dashboard', 'https://admin.example.com', 'Administrative dashboard application', 'cookie', '{"max_urls": 75, "max_depth": 3, "scan_timeout": 240}', '["admin", "dashboard", "internal"]')

ON CONFLICT (name) DO NOTHING;

-- Create sample scans for testing
INSERT INTO dast_scans (project_id, scan_type, status, vulnerabilities_found, urls_scanned, requests_made, scan_duration, scan_summary) 
SELECT 
    p.id,
    'full',
    'completed',
    3,
    15,
    45,
    180.5,
    '{"security_score": 75, "critical_vulns": 1, "high_vulns": 2, "medium_vulns": 0, "low_vulns": 0}'
FROM dast_projects p 
WHERE p.name = 'E-commerce Web Application'
ON CONFLICT DO NOTHING;

-- Create sample vulnerabilities for testing
INSERT INTO dast_vulnerabilities (scan_id, project_id, title, description, severity, url, http_method, param_name, vuln_type, payload, cwe_id, owasp_category, response_code, response_time)
SELECT 
    s.id,
    s.project_id,
    'SQL Injection in Search Parameter',
    'SQL injection vulnerability detected in search functionality',
    'critical',
    'https://demo-ecommerce.example.com/search',
    'GET',
    'q',
    'sqli',
    ''' OR 1=1 --',
    'CWE-89',
    'A03:2021-Injection',
    200,
    0.5
FROM dast_scans s
WHERE s.status = 'completed'
ON CONFLICT DO NOTHING;

INSERT INTO dast_vulnerabilities (scan_id, project_id, title, description, severity, url, http_method, param_name, vuln_type, payload, cwe_id, owasp_category, response_code, response_time)
SELECT 
    s.id,
    s.project_id,
    'Cross-Site Scripting in Contact Form',
    'XSS vulnerability in contact form comment field',
    'high',
    'https://demo-ecommerce.example.com/contact',
    'POST',
    'message',
    'xss',
    '<script>alert(''XSS'')</script>',
    'CWE-79',
    'A03:2021-Injection',
    200,
    0.3
FROM dast_scans s
WHERE s.status = 'completed'
ON CONFLICT DO NOTHING;

INSERT INTO dast_vulnerabilities (scan_id, project_id, title, description, severity, url, http_method, param_name, vuln_type, payload, cwe_id, owasp_category, response_code, response_time)
SELECT 
    s.id,
    s.project_id,
    'Missing Security Headers',
    'Application missing important security headers',
    'medium',
    'https://demo-ecommerce.example.com',
    'GET',
    NULL,
    'security_headers',
    NULL,
    'CWE-693',
    'A05:2021-Security Misconfiguration',
    200,
    0.2
FROM dast_scans s
WHERE s.status = 'completed'
ON CONFLICT DO NOTHING;

-- Create sample reports
INSERT INTO dast_reports (scan_id, project_id, report_type, format, report_data, is_public)
SELECT 
    s.id,
    s.project_id,
    'detailed',
    'json',
    '{"scan_info": {"id": "' || s.id || '", "status": "completed", "vulnerabilities_found": 3}, "vulnerabilities": [{"title": "SQL Injection", "severity": "critical"}, {"title": "XSS", "severity": "high"}, {"title": "Missing Headers", "severity": "medium"}]}',
    false
FROM dast_scans s
WHERE s.status = 'completed'
ON CONFLICT DO NOTHING;

-- Create sample sessions
INSERT INTO dast_sessions (project_id, session_name, session_type, session_config, is_active)
SELECT 
    p.id,
    'Test Session',
    'proxy',
    '{"proxy_port": 8080, "intercept_requests": true}',
    true
FROM dast_projects p
WHERE p.name = 'E-commerce Web Application'
ON CONFLICT DO NOTHING;

-- Update project statistics
UPDATE dast_projects 
SET 
    total_scans = (SELECT COUNT(*) FROM dast_scans WHERE project_id = dast_projects.id),
    total_vulnerabilities = (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id),
    security_score = CASE 
        WHEN (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id AND severity = 'critical') > 0 THEN 20
        WHEN (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id AND severity = 'high') > 0 THEN 40
        WHEN (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id AND severity = 'medium') > 0 THEN 60
        ELSE 80
    END
WHERE id IN (SELECT DISTINCT project_id FROM dast_scans);

-- Create a function to update project statistics
CREATE OR REPLACE FUNCTION update_dast_project_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        UPDATE dast_projects 
        SET 
            total_scans = (SELECT COUNT(*) FROM dast_scans WHERE project_id = dast_projects.id),
            total_vulnerabilities = (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id),
            security_score = CASE 
                WHEN (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id AND severity = 'critical') > 0 THEN 20
                WHEN (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id AND severity = 'high') > 0 THEN 40
                WHEN (SELECT COUNT(*) FROM dast_vulnerabilities WHERE project_id = dast_projects.id AND severity = 'medium') > 0 THEN 60
                ELSE 80
            END
        WHERE id = COALESCE(NEW.project_id, OLD.project_id);
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create triggers to automatically update project statistics
CREATE TRIGGER trigger_update_project_stats_scans
    AFTER INSERT OR UPDATE OR DELETE ON dast_scans
    FOR EACH ROW EXECUTE FUNCTION update_dast_project_stats();

CREATE TRIGGER trigger_update_project_stats_vulnerabilities
    AFTER INSERT OR UPDATE OR DELETE ON dast_vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_dast_project_stats();

-- Grant necessary permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_app_user;

COMMIT; 