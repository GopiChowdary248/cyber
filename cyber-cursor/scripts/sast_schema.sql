-- SAST (Static Application Security Testing) Database Schema
-- PostgreSQL schema for CyberShield SAST module

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum types for SAST module
CREATE TYPE scan_status AS ENUM ('queued', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE vulnerability_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE vulnerability_status AS ENUM ('open', 'fixed', 'ignored', 'false_positive');
CREATE TYPE auto_fix_status AS ENUM ('available', 'applied', 'not_available', 'failed');

-- SAST Projects Table
CREATE TABLE sast_projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    repository_url TEXT,
    language VARCHAR(50),
    description TEXT,
    
    -- Project configuration
    scan_config JSONB,
    rules_config JSONB,
    
    -- Statistics
    total_scans INTEGER DEFAULT 0,
    avg_vulnerabilities DECIMAL(5,2) DEFAULT 0.0,
    security_score DECIMAL(5,2),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scan TIMESTAMP WITH TIME ZONE,
    
    -- Created by
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- SAST Scans Table
CREATE TABLE sast_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
    
    -- Scan details
    scan_type VARCHAR(50) NOT NULL,
    status scan_status DEFAULT 'queued',
    
    -- Scan configuration
    scan_config JSONB,
    rules_enabled JSONB,
    
    -- Scan results
    vulnerabilities_found INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    lines_of_code INTEGER DEFAULT 0,
    scan_duration DECIMAL(10,2),
    
    -- Scan metadata
    scan_logs JSONB,
    scan_summary JSONB,
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Initiated by
    initiated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- SAST Rules Table
CREATE TABLE sast_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- Rule configuration
    language VARCHAR(50) NOT NULL,
    regex_pattern TEXT,
    ast_pattern JSONB,
    
    -- Classification
    severity vulnerability_severity NOT NULL,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    
    -- Auto-fix configuration
    auto_fix_available BOOLEAN DEFAULT FALSE,
    auto_fix_template TEXT,
    recommendation TEXT,
    
    -- Rule metadata
    tags JSONB,
    metadata JSONB,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_custom BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Created by (for custom rules)
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- SAST Vulnerabilities Table
CREATE TABLE sast_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES sast_scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
    
    -- Vulnerability details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity vulnerability_severity NOT NULL,
    status vulnerability_status DEFAULT 'open',
    
    -- Code location
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    column_number INTEGER,
    function_name VARCHAR(255),
    
    -- Vulnerability classification
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    language VARCHAR(50),
    
    -- Code snippets
    vulnerable_code TEXT,
    fixed_code TEXT,
    context_before TEXT,
    context_after TEXT,
    
    -- Auto-fix information
    auto_fix_available BOOLEAN DEFAULT FALSE,
    auto_fix_status auto_fix_status DEFAULT 'not_available',
    auto_fix_suggestion TEXT,
    
    -- Additional metadata
    tags JSONB,
    metadata JSONB,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    fixed_at TIMESTAMP WITH TIME ZONE,
    
    -- Rule relationship
    rule_id UUID REFERENCES sast_rules(id) ON DELETE SET NULL
);

-- SAST Reports Table
CREATE TABLE sast_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES sast_scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
    
    -- Report details
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    
    -- Report content
    report_data JSONB,
    report_file_path TEXT,
    
    -- Report metadata
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Status
    is_public BOOLEAN DEFAULT FALSE,
    download_count INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Generated by
    generated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for better performance
CREATE INDEX idx_sast_projects_name ON sast_projects(name);
CREATE INDEX idx_sast_projects_language ON sast_projects(language);
CREATE INDEX idx_sast_projects_created_by ON sast_projects(created_by);
CREATE INDEX idx_sast_projects_is_active ON sast_projects(is_active);

CREATE INDEX idx_sast_scans_project_id ON sast_scans(project_id);
CREATE INDEX idx_sast_scans_status ON sast_scans(status);
CREATE INDEX idx_sast_scans_initiated_by ON sast_scans(initiated_by);
CREATE INDEX idx_sast_scans_started_at ON sast_scans(started_at);
CREATE INDEX idx_sast_scans_scan_type ON sast_scans(scan_type);

CREATE INDEX idx_sast_rules_language ON sast_rules(language);
CREATE INDEX idx_sast_rules_severity ON sast_rules(severity);
CREATE INDEX idx_sast_rules_is_active ON sast_rules(is_active);
CREATE INDEX idx_sast_rules_is_custom ON sast_rules(is_custom);
CREATE INDEX idx_sast_rules_created_by ON sast_rules(created_by);

CREATE INDEX idx_sast_vulnerabilities_scan_id ON sast_vulnerabilities(scan_id);
CREATE INDEX idx_sast_vulnerabilities_project_id ON sast_vulnerabilities(project_id);
CREATE INDEX idx_sast_vulnerabilities_severity ON sast_vulnerabilities(severity);
CREATE INDEX idx_sast_vulnerabilities_status ON sast_vulnerabilities(status);
CREATE INDEX idx_sast_vulnerabilities_file_path ON sast_vulnerabilities(file_path);
CREATE INDEX idx_sast_vulnerabilities_cwe_id ON sast_vulnerabilities(cwe_id);
CREATE INDEX idx_sast_vulnerabilities_rule_id ON sast_vulnerabilities(rule_id);
CREATE INDEX idx_sast_vulnerabilities_created_at ON sast_vulnerabilities(created_at);

CREATE INDEX idx_sast_reports_scan_id ON sast_reports(scan_id);
CREATE INDEX idx_sast_reports_project_id ON sast_reports(project_id);
CREATE INDEX idx_sast_reports_report_type ON sast_reports(report_type);
CREATE INDEX idx_sast_reports_format ON sast_reports(format);
CREATE INDEX idx_sast_reports_generated_by ON sast_reports(generated_by);
CREATE INDEX idx_sast_reports_generated_at ON sast_reports(generated_at);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_sast_projects_updated_at BEFORE UPDATE ON sast_projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_scans_updated_at BEFORE UPDATE ON sast_scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_rules_updated_at BEFORE UPDATE ON sast_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_vulnerabilities_updated_at BEFORE UPDATE ON sast_vulnerabilities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_reports_updated_at BEFORE UPDATE ON sast_reports FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert initial OWASP Top 10 detection rules
INSERT INTO sast_rules (name, title, description, language, regex_pattern, severity, cwe_id, owasp_category, auto_fix_available, recommendation) VALUES
-- SQL Injection (A03:2021)
('sql_injection_concatenation', 'SQL Injection via String Concatenation', 'Detects SQL injection vulnerabilities through string concatenation', 'python', 'cursor\.execute\(.*\+.*\)', 'critical', 'CWE-89', 'A03:2021-Injection', true, 'Use parameterized queries or ORM methods instead of string concatenation'),

-- XSS (A03:2021)
('xss_innerhtml', 'Cross-Site Scripting via innerHTML', 'Detects potential XSS vulnerabilities through innerHTML assignment', 'javascript', 'innerHTML\s*=\s*.*', 'high', 'CWE-79', 'A03:2021-Injection', true, 'Use textContent or a DOM sanitizer to prevent XSS'),

-- Hardcoded Secrets (A02:2021)
('hardcoded_secrets', 'Hardcoded API Keys and Secrets', 'Detects hardcoded API keys, secrets, and passwords', 'all', '(api_key|secret|password)\s*=\s*[''""][A-Za-z0-9]{20,}[''""]', 'high', 'CWE-798', 'A02:2021-Cryptographic Failures', false, 'Use environment variables or secret managers instead of hardcoding'),

-- Command Injection (A03:2021)
('command_injection_os_system', 'Command Injection via os.system', 'Detects command injection vulnerabilities through os.system', 'python', 'os\.system\(.*\+.*\)', 'critical', 'CWE-77', 'A03:2021-Injection', true, 'Use subprocess with argument arrays and avoid shell=True'),

-- Code Injection (A03:2021)
('code_injection_eval', 'Code Injection via eval', 'Detects code injection vulnerabilities through eval function', 'javascript', 'eval\(.*\)', 'critical', 'CWE-95', 'A03:2021-Injection', false, 'Avoid using eval() function. Use safer alternatives like JSON.parse()'),

-- Path Traversal (A01:2021)
('path_traversal', 'Path Traversal Vulnerability', 'Detects path traversal vulnerabilities', 'all', '\.\.\/|\.\.\\', 'high', 'CWE-22', 'A01:2021-Broken Access Control', false, 'Validate and sanitize file paths to prevent directory traversal'),

-- Insecure Deserialization (A08:2021)
('insecure_deserialization', 'Insecure Deserialization', 'Detects insecure deserialization practices', 'python', 'pickle\.loads\(|yaml\.load\(', 'high', 'CWE-502', 'A08:2021-Software and Data Integrity Failures', false, 'Use safe deserialization methods and validate input'),

-- Broken Authentication (A07:2021)
('weak_password_validation', 'Weak Password Validation', 'Detects weak password validation patterns', 'all', 'password.*len.*<.*8|password.*length.*<.*8', 'medium', 'CWE-521', 'A07:2021-Identification and Authentication Failures', false, 'Implement strong password policies with minimum length and complexity requirements'),

-- Security Misconfiguration (A05:2021)
('debug_mode_enabled', 'Debug Mode Enabled in Production', 'Detects debug mode enabled in production code', 'python', 'DEBUG\s*=\s*True|debug\s*=\s*True', 'medium', 'CWE-16', 'A05:2021-Security Misconfiguration', true, 'Disable debug mode in production environments'),

-- Sensitive Data Exposure (A02:2021)
('sensitive_data_logging', 'Sensitive Data in Logs', 'Detects sensitive data being logged', 'all', 'log.*password|log.*secret|log.*token|log.*key', 'medium', 'CWE-532', 'A02:2021-Cryptographic Failures', false, 'Avoid logging sensitive information like passwords, tokens, or secrets');

-- Insert sample SAST projects
INSERT INTO sast_projects (name, repository_url, language, description, security_score) VALUES
('E-commerce Platform', 'https://github.com/company/ecommerce', 'python', 'Main e-commerce application with Django backend', 85.5),
('Mobile API', 'https://github.com/company/mobile-api', 'javascript', 'REST API for mobile applications', 92.3),
('Admin Dashboard', 'https://github.com/company/admin-dashboard', 'typescript', 'React-based admin dashboard', 78.9),
('Payment Gateway', 'https://github.com/company/payment-gateway', 'java', 'Secure payment processing service', 95.2),
('User Management', 'https://github.com/company/user-management', 'csharp', '.NET Core user management service', 88.7);

-- Insert sample SAST scans
INSERT INTO sast_scans (project_id, scan_type, status, vulnerabilities_found, files_scanned, lines_of_code, scan_duration, started_at, completed_at) VALUES
((SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1), 'full', 'completed', 3, 156, 12450, 134.5, CURRENT_TIMESTAMP - INTERVAL '2 hours', CURRENT_TIMESTAMP - INTERVAL '1 hour 58 minutes'),
((SELECT id FROM sast_projects WHERE name = 'Mobile API' LIMIT 1), 'full', 'completed', 1, 89, 5670, 89.2, CURRENT_TIMESTAMP - INTERVAL '4 hours', CURRENT_TIMESTAMP - INTERVAL '3 hours 58 minutes'),
((SELECT id FROM sast_projects WHERE name = 'Admin Dashboard' LIMIT 1), 'full', 'completed', 5, 234, 18900, 245.7, CURRENT_TIMESTAMP - INTERVAL '6 hours', CURRENT_TIMESTAMP - INTERVAL '5 hours 54 minutes'),
((SELECT id FROM sast_projects WHERE name = 'Payment Gateway' LIMIT 1), 'full', 'completed', 0, 67, 8900, 123.4, CURRENT_TIMESTAMP - INTERVAL '8 hours', CURRENT_TIMESTAMP - INTERVAL '7 hours 56 minutes'),
((SELECT id FROM sast_projects WHERE name = 'User Management' LIMIT 1), 'full', 'completed', 2, 145, 11200, 167.8, CURRENT_TIMESTAMP - INTERVAL '12 hours', CURRENT_TIMESTAMP - INTERVAL '11 hours 52 minutes');

-- Insert sample vulnerabilities
INSERT INTO sast_vulnerabilities (scan_id, project_id, title, description, severity, file_path, line_number, cwe_id, owasp_category, vulnerable_code, auto_fix_available, auto_fix_suggestion) VALUES
((SELECT id FROM sast_scans WHERE project_id = (SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1) LIMIT 1), (SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1), 'SQL Injection', 'User input is directly concatenated into SQL query without proper sanitization', 'critical', 'src/database/user_queries.py', 45, 'CWE-89', 'A03:2021-Injection', 'cursor.execute("SELECT * FROM users WHERE id=" + user_input)', true, 'cursor.execute("SELECT * FROM users WHERE id=%s", (user_input,))'),
((SELECT id FROM sast_scans WHERE project_id = (SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1) LIMIT 1), (SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1), 'Hardcoded API Key', 'API key is hardcoded in source code', 'high', 'src/config/settings.py', 23, 'CWE-798', 'A02:2021-Cryptographic Failures', 'api_key = "ABCD1234XYZSECRETKEY"', false, 'Use environment variables: api_key = os.getenv("API_KEY")'),
((SELECT id FROM sast_scans WHERE project_id = (SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1) LIMIT 1), (SELECT id FROM sast_projects WHERE name = 'E-commerce Platform' LIMIT 1), 'Debug Mode Enabled', 'Debug mode is enabled in production code', 'medium', 'src/config/settings.py', 15, 'CWE-16', 'A05:2021-Security Misconfiguration', 'DEBUG = True', true, 'DEBUG = False'),
((SELECT id FROM sast_scans WHERE project_id = (SELECT id FROM sast_projects WHERE name = 'Mobile API' LIMIT 1) LIMIT 1), (SELECT id FROM sast_projects WHERE name = 'Mobile API' LIMIT 1), 'XSS via innerHTML', 'User input is assigned to innerHTML without sanitization', 'high', 'src/components/UserProfile.js', 67, 'CWE-79', 'A03:2021-Injection', 'document.getElementById("profile").innerHTML = userInput', true, 'document.getElementById("profile").textContent = userInput'),
((SELECT id FROM sast_scans WHERE project_id = (SELECT id FROM sast_projects WHERE name = 'Admin Dashboard' LIMIT 1) LIMIT 1), (SELECT id FROM sast_projects WHERE name = 'Admin Dashboard' LIMIT 1), 'Command Injection', 'User input is used in system command without validation', 'critical', 'src/utils/system.js', 34, 'CWE-77', 'A03:2021-Injection', 'exec("rm -rf " + userInput)', true, 'Use fs.unlinkSync() or similar safe file operations');

-- Create view for SAST overview statistics
CREATE VIEW sast_overview_stats AS
SELECT 
    COUNT(DISTINCT p.id) as total_projects,
    COUNT(DISTINCT s.id) as total_scans,
    COUNT(DISTINCT v.id) as total_vulnerabilities,
    COUNT(DISTINCT CASE WHEN s.status = 'running' THEN s.id END) as active_scans,
    AVG(p.security_score) as avg_security_score,
    COUNT(DISTINCT CASE WHEN v.severity = 'critical' THEN v.id END) as critical_vulnerabilities,
    COUNT(DISTINCT CASE WHEN v.severity = 'high' THEN v.id END) as high_vulnerabilities,
    COUNT(DISTINCT CASE WHEN v.severity = 'medium' THEN v.id END) as medium_vulnerabilities,
    COUNT(DISTINCT CASE WHEN v.severity = 'low' THEN v.id END) as low_vulnerabilities
FROM sast_projects p
LEFT JOIN sast_scans s ON p.id = s.project_id
LEFT JOIN sast_vulnerabilities v ON p.id = v.project_id;

-- Create view for vulnerability trends
CREATE VIEW sast_vulnerability_trends AS
SELECT 
    DATE_TRUNC('day', v.created_at) as date,
    COUNT(*) as vulnerabilities_found,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.severity = 'medium' THEN 1 END) as medium_count,
    COUNT(CASE WHEN v.severity = 'low' THEN 1 END) as low_count
FROM sast_vulnerabilities v
GROUP BY DATE_TRUNC('day', v.created_at)
ORDER BY date DESC;

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO cybershield_user;

COMMENT ON TABLE sast_projects IS 'SAST projects for code analysis';
COMMENT ON TABLE sast_scans IS 'SAST scan history and results';
COMMENT ON TABLE sast_rules IS 'Detection rules for SAST analysis';
COMMENT ON TABLE sast_vulnerabilities IS 'Vulnerabilities found during SAST scans';
COMMENT ON TABLE sast_reports IS 'Generated SAST reports and exports'; 