-- RASP Database Schema
-- Runtime Application Self-Protection Database

-- Create RASP agents table
CREATE TABLE IF NOT EXISTS rasp_agents (
    agent_id SERIAL PRIMARY KEY,
    app_name VARCHAR(255) NOT NULL,
    language VARCHAR(50) NOT NULL,
    version VARCHAR(50) NOT NULL,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active',
    config JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP attacks table
CREATE TABLE IF NOT EXISTS rasp_attacks (
    attack_id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES rasp_agents(agent_id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    url TEXT,
    payload TEXT,
    vuln_type VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    stack_trace TEXT,
    blocked BOOLEAN DEFAULT false,
    context JSONB DEFAULT '{}',
    request_data JSONB DEFAULT '{}',
    response_data JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP rules table
CREATE TABLE IF NOT EXISTS rasp_rules (
    rule_id SERIAL PRIMARY KEY,
    vuln_type VARCHAR(50) NOT NULL,
    language VARCHAR(50) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL,
    auto_block BOOLEAN DEFAULT false,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP vulnerabilities table
CREATE TABLE IF NOT EXISTS rasp_vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES rasp_agents(agent_id) ON DELETE CASCADE,
    vuln_type VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    description TEXT,
    affected_file VARCHAR(255),
    affected_line INTEGER,
    affected_method VARCHAR(255),
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(50),
    evidence JSONB DEFAULT '{}',
    remediation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP virtual patches table
CREATE TABLE IF NOT EXISTS rasp_virtual_patches (
    patch_id SERIAL PRIMARY KEY,
    vuln_id INTEGER REFERENCES rasp_vulnerabilities(vuln_id) ON DELETE CASCADE,
    agent_id INTEGER REFERENCES rasp_agents(agent_id) ON DELETE CASCADE,
    patch_type VARCHAR(50) NOT NULL,
    patch_config JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    created_by INTEGER
);

-- Create RASP telemetry table
CREATE TABLE IF NOT EXISTS rasp_telemetry (
    telemetry_id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES rasp_agents(agent_id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metric_name VARCHAR(100) NOT NULL,
    metric_value FLOAT,
    metric_data JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP alerts table
CREATE TABLE IF NOT EXISTS rasp_alerts (
    alert_id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES rasp_agents(agent_id) ON DELETE CASCADE,
    attack_id INTEGER REFERENCES rasp_attacks(attack_id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'new',
    acknowledged_by INTEGER,
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RASP integrations table
CREATE TABLE IF NOT EXISTS rasp_integrations (
    integration_id SERIAL PRIMARY KEY,
    integration_type VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    last_sync TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_agent_id ON rasp_attacks(agent_id);
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_timestamp ON rasp_attacks(timestamp);
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_vuln_type ON rasp_attacks(vuln_type);
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_severity ON rasp_attacks(severity);
CREATE INDEX IF NOT EXISTS idx_rasp_attacks_blocked ON rasp_attacks(blocked);

CREATE INDEX IF NOT EXISTS idx_rasp_vulnerabilities_agent_id ON rasp_vulnerabilities(agent_id);
CREATE INDEX IF NOT EXISTS idx_rasp_vulnerabilities_status ON rasp_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_rasp_vulnerabilities_severity ON rasp_vulnerabilities(severity);

CREATE INDEX IF NOT EXISTS idx_rasp_rules_language ON rasp_rules(language);
CREATE INDEX IF NOT EXISTS idx_rasp_rules_enabled ON rasp_rules(enabled);

CREATE INDEX IF NOT EXISTS idx_rasp_alerts_agent_id ON rasp_alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_rasp_alerts_status ON rasp_alerts(status);
CREATE INDEX IF NOT EXISTS idx_rasp_alerts_severity ON rasp_alerts(severity);

-- Insert default RASP rules
INSERT INTO rasp_rules (vuln_type, language, pattern, severity, auto_block, description) VALUES
-- SQL Injection rules
('SQLi', 'python', '.*SELECT.*FROM.*\\+.*', 'critical', true, 'Detect concatenated SQL with untrusted input'),
('SQLi', 'python', '.*INSERT.*INTO.*\\+.*', 'critical', true, 'Detect concatenated INSERT statements'),
('SQLi', 'python', '.*UPDATE.*SET.*\\+.*', 'critical', true, 'Detect concatenated UPDATE statements'),
('SQLi', 'python', '.*DELETE.*FROM.*\\+.*', 'critical', true, 'Detect concatenated DELETE statements'),

-- Command Injection rules
('Command Injection', 'python', '.*(;|&&|\\|\\||`).*', 'critical', true, 'Block if input contains shell operators'),
('Command Injection', 'python', '.*os\\.system\\(.*\\).*', 'high', true, 'Detect os.system calls with user input'),
('Command Injection', 'python', '.*subprocess\\.call\\(.*shell=True.*\\).*', 'high', true, 'Detect subprocess calls with shell=True'),

-- Path Traversal rules
('Path Traversal', 'python', '.*\\.\\./.*', 'high', true, 'Block if path contains directory traversal sequences'),
('Path Traversal', 'python', '.*\\.\\.\\\\.*', 'high', true, 'Block if path contains Windows directory traversal'),

-- XSS rules
('XSS', 'python', '.*<script.*>.*', 'high', true, 'Detect script tags in user input'),
('XSS', 'python', '.*javascript:.*', 'high', true, 'Detect javascript: protocol in user input'),

-- File Inclusion rules
('LFI', 'python', '.*\\.\\./.*\\.php.*', 'high', true, 'Detect potential PHP file inclusion'),
('LFI', 'python', '.*\\.\\./.*\\.jsp.*', 'high', true, 'Detect potential JSP file inclusion'),

-- Deserialization rules
('Deserialization', 'python', '.*pickle\\.loads\\(.*\\).*', 'critical', true, 'Detect pickle deserialization with user input'),
('Deserialization', 'python', '.*yaml\\.load\\(.*\\).*', 'high', true, 'Detect YAML load with user input');

-- Insert sample agent
INSERT INTO rasp_agents (app_name, language, version, status) VALUES
('Sample Web App', 'python', '1.0.0', 'active'),
('API Gateway', 'java', '2.1.0', 'active'),
('Microservice', 'nodejs', '1.5.0', 'active');

-- Create views for common queries
CREATE OR REPLACE VIEW rasp_attack_summary AS
SELECT 
    vuln_type,
    severity,
    COUNT(*) as attack_count,
    COUNT(CASE WHEN blocked = true THEN 1 END) as blocked_count,
    COUNT(CASE WHEN blocked = false THEN 1 END) as successful_count
FROM rasp_attacks
GROUP BY vuln_type, severity;

CREATE OR REPLACE VIEW rasp_agent_status AS
SELECT 
    agent_id,
    app_name,
    language,
    version,
    status,
    last_seen,
    CASE 
        WHEN last_seen > CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 'online'
        WHEN last_seen > CURRENT_TIMESTAMP - INTERVAL '1 hour' THEN 'recent'
        ELSE 'offline'
    END as connection_status
FROM rasp_agents; 