-- SAST Database Initialization Script
-- Creates the necessary tables and schemas for the SAST tool

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create SAST schema
CREATE SCHEMA IF NOT EXISTS sast;

-- SAST Scans table
CREATE TABLE IF NOT EXISTS sast.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_name VARCHAR(255) NOT NULL,
    project_path TEXT,
    scan_config JSONB,
    status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    scan_duration FLOAT,
    languages_detected TEXT[],
    tools_used TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SAST Vulnerabilities table
CREATE TABLE IF NOT EXISTS sast.vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES sast.scans(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    line_number INTEGER,
    column_number INTEGER,
    severity VARCHAR(20) NOT NULL,
    vulnerability_type VARCHAR(100) NOT NULL,
    description TEXT,
    recommendation TEXT,
    rule_id VARCHAR(100),
    tool VARCHAR(50) NOT NULL,
    cwe_id VARCHAR(20),
    code_snippet TEXT,
    context JSONB,
    status VARCHAR(50) DEFAULT 'open',
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SAST Recommendations table
CREATE TABLE IF NOT EXISTS sast.recommendations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID REFERENCES sast.vulnerabilities(id) ON DELETE CASCADE,
    recommendation_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    code_fix TEXT,
    before_code TEXT,
    after_code TEXT,
    confidence_score FLOAT,
    reasoning TEXT,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SAST Projects table
CREATE TABLE IF NOT EXISTS sast.projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    repository_url TEXT,
    branch VARCHAR(100) DEFAULT 'main',
    scan_config JSONB,
    last_scan_id UUID REFERENCES sast.scans(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SAST Scan Configurations table
CREATE TABLE IF NOT EXISTS sast.scan_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    config JSONB NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SAST Reports table
CREATE TABLE IF NOT EXISTS sast.reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES sast.scans(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    file_path TEXT,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- SAST Integrations table
CREATE TABLE IF NOT EXISTS sast.integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    integration_type VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SAST Notifications table
CREATE TABLE IF NOT EXISTS sast.notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES sast.scans(id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    severity VARCHAR(20),
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sast_scans_project_name ON sast.scans(project_name);
CREATE INDEX IF NOT EXISTS idx_sast_scans_status ON sast.scans(status);
CREATE INDEX IF NOT EXISTS idx_sast_scans_started_at ON sast.scans(started_at);
CREATE INDEX IF NOT EXISTS idx_sast_vulnerabilities_scan_id ON sast.vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_sast_vulnerabilities_severity ON sast.vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_sast_vulnerabilities_type ON sast.vulnerabilities(vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_sast_vulnerabilities_file ON sast.vulnerabilities(file_name);
CREATE INDEX IF NOT EXISTS idx_sast_recommendations_vuln_id ON sast.recommendations(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_sast_projects_name ON sast.projects(name);
CREATE INDEX IF NOT EXISTS idx_sast_reports_scan_id ON sast.reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_sast_integrations_type ON sast.integrations(integration_type);
CREATE INDEX IF NOT EXISTS idx_sast_notifications_scan_id ON sast.notifications(scan_id);

-- Create full-text search indexes
CREATE INDEX IF NOT EXISTS idx_sast_vulnerabilities_description_fts ON sast.vulnerabilities USING gin(to_tsvector('english', description));
CREATE INDEX IF NOT EXISTS idx_sast_recommendations_description_fts ON sast.recommendations USING gin(to_tsvector('english', description));

-- Insert default scan configuration
INSERT INTO sast.scan_configs (name, description, config, is_default) VALUES (
    'Default Configuration',
    'Default SAST scan configuration with common tools',
    '{
        "languages": ["python", "javascript", "java"],
        "tools": ["bandit", "pylint", "semgrep", "eslint"],
        "severity_threshold": "low",
        "max_file_size": 10485760,
        "exclude_patterns": ["node_modules", ".git", "__pycache__", "venv"],
        "include_patterns": ["*.py", "*.js", "*.java", "*.php", "*.go"]
    }',
    TRUE
) ON CONFLICT DO NOTHING;

-- Grant permissions to sast_user
GRANT USAGE ON SCHEMA sast TO sast_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA sast TO sast_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA sast TO sast_user;
GRANT CREATE ON SCHEMA sast TO sast_user;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_sast_scans_updated_at BEFORE UPDATE ON sast.scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_vulnerabilities_updated_at BEFORE UPDATE ON sast.vulnerabilities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_projects_updated_at BEFORE UPDATE ON sast.projects FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_scan_configs_updated_at BEFORE UPDATE ON sast.scan_configs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sast_integrations_updated_at BEFORE UPDATE ON sast.integrations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(); 