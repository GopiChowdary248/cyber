-- SAST Tool Database Schema
-- PostgreSQL schema for Static Application Security Testing tool

-- Create projects table
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    repo_url TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create sast_scans table
CREATE TABLE IF NOT EXISTS sast_scans (
    id SERIAL PRIMARY KEY,
    project_id INT REFERENCES projects(id) ON DELETE CASCADE,
    triggered_by VARCHAR(255) NOT NULL,
    start_time TIMESTAMP DEFAULT NOW(),
    end_time TIMESTAMP,
    status VARCHAR(20) DEFAULT 'running', -- 'running', 'completed', 'failed'
    scan_type VARCHAR(50) DEFAULT 'full', -- 'full', 'incremental', 'quick'
    total_files INT DEFAULT 0,
    scanned_files INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create sast_results table
CREATE TABLE IF NOT EXISTS sast_results (
    id SERIAL PRIMARY KEY,
    scan_id INT REFERENCES sast_scans(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_no INT,
    column_no INT,
    vulnerability TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
    recommendation TEXT,
    tool_name VARCHAR(50) NOT NULL, -- 'bandit', 'eslint', 'semgrep', 'pylint'
    cwe_id VARCHAR(20),
    confidence VARCHAR(20) DEFAULT 'medium', -- 'high', 'medium', 'low'
    detected_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'open' -- 'open', 'fixed', 'false_positive', 'wont_fix'
);

-- Create sast_reports table
CREATE TABLE IF NOT EXISTS sast_reports (
    id SERIAL PRIMARY KEY,
    scan_id INT REFERENCES sast_scans(id) ON DELETE CASCADE,
    report_type VARCHAR(20) NOT NULL, -- 'summary', 'detailed', 'pdf', 'csv'
    report_data JSONB,
    generated_at TIMESTAMP DEFAULT NOW(),
    file_path TEXT
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sast_scans_project_id ON sast_scans(project_id);
CREATE INDEX IF NOT EXISTS idx_sast_scans_status ON sast_scans(status);
CREATE INDEX IF NOT EXISTS idx_sast_results_scan_id ON sast_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_sast_results_severity ON sast_results(severity);
CREATE INDEX IF NOT EXISTS idx_sast_results_file_path ON sast_results(file_path);
CREATE INDEX IF NOT EXISTS idx_sast_reports_scan_id ON sast_reports(scan_id);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for projects table
CREATE TRIGGER update_projects_updated_at 
    BEFORE UPDATE ON projects 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert sample project for testing
INSERT INTO projects (name, repo_url, description) VALUES 
('Sample Project', 'https://github.com/example/sample-project', 'A sample project for SAST testing')
ON CONFLICT DO NOTHING; 