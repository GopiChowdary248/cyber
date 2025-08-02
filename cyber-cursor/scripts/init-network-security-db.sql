-- Network Security Database Initialization Script
-- This script creates the network security tables and inserts sample data

-- Network Devices Table
CREATE TABLE IF NOT EXISTS network_devices (
    id SERIAL PRIMARY KEY,
    device_name VARCHAR(255) NOT NULL,
    device_type VARCHAR(50) NOT NULL, -- firewall, ids, vpn, nac
    ip_address VARCHAR(50) NOT NULL,
    vendor VARCHAR(100),
    model VARCHAR(100),
    status VARCHAR(20) DEFAULT 'offline', -- online, offline, maintenance
    last_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Configuration
    api_key VARCHAR(500),
    username VARCHAR(100),
    password_hash VARCHAR(255),
    port INTEGER DEFAULT 22
);

-- Firewall Logs Table
CREATE TABLE IF NOT EXISTS firewall_logs (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES network_devices(id),
    log_time TIMESTAMP NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    dest_ip VARCHAR(50) NOT NULL,
    source_port INTEGER,
    dest_port INTEGER,
    action VARCHAR(20) NOT NULL, -- allow, deny, drop
    protocol VARCHAR(20), -- tcp, udp, icmp
    application VARCHAR(100),
    rule_name VARCHAR(255),
    session_id VARCHAR(100),
    bytes_sent INTEGER,
    bytes_received INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- IDS Alerts Table
CREATE TABLE IF NOT EXISTS ids_alerts (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES network_devices(id),
    alert_time TIMESTAMP NOT NULL,
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    alert_type VARCHAR(100) NOT NULL, -- signature, anomaly, policy
    description TEXT NOT NULL,
    source_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    source_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(20),
    signature_id VARCHAR(100),
    signature_name VARCHAR(255),
    category VARCHAR(100), -- malware, dos, reconnaissance
    status VARCHAR(20) DEFAULT 'new', -- new, acknowledged, resolved
    created_at TIMESTAMP DEFAULT NOW()
);

-- VPN Sessions Table
CREATE TABLE IF NOT EXISTS vpn_sessions (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES network_devices(id),
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    connection_start TIMESTAMP NOT NULL,
    connection_end TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active', -- active, disconnected, expired
    vpn_type VARCHAR(50), -- ssl, ipsec, l2tp
    client_ip VARCHAR(50),
    bytes_sent INTEGER,
    bytes_received INTEGER,
    session_duration INTEGER, -- in seconds
    created_at TIMESTAMP DEFAULT NOW()
);

-- NAC Logs Table
CREATE TABLE IF NOT EXISTS nac_logs (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES network_devices(id),
    event_time TIMESTAMP NOT NULL,
    device_mac VARCHAR(50) NOT NULL,
    device_ip VARCHAR(50),
    device_name VARCHAR(255),
    action VARCHAR(20) NOT NULL, -- allowed, blocked, quarantined
    description TEXT,
    user_name VARCHAR(255),
    switch_port VARCHAR(100),
    vlan VARCHAR(50),
    policy_name VARCHAR(255),
    reason VARCHAR(255), -- policy violation, unknown device
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_network_devices_type ON network_devices(device_type);
CREATE INDEX IF NOT EXISTS idx_network_devices_status ON network_devices(status);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_device_time ON firewall_logs(device_id, log_time);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_action ON firewall_logs(action);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_source_ip ON firewall_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_firewall_logs_dest_ip ON firewall_logs(dest_ip);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_device_time ON ids_alerts(device_id, alert_time);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_severity ON ids_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_status ON ids_alerts(status);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_status ON vpn_sessions(status);
CREATE INDEX IF NOT EXISTS idx_vpn_sessions_username ON vpn_sessions(username);
CREATE INDEX IF NOT EXISTS idx_nac_logs_device_time ON nac_logs(device_id, event_time);
CREATE INDEX IF NOT EXISTS idx_nac_logs_action ON nac_logs(action);
CREATE INDEX IF NOT EXISTS idx_nac_logs_device_mac ON nac_logs(device_mac);

-- Insert sample network devices
INSERT INTO network_devices (device_name, device_type, ip_address, vendor, model, status) VALUES
('PaloAlto-FW-01', 'firewall', '192.168.1.1', 'Palo Alto Networks', 'PA-820', 'online'),
('Cisco-ASA-01', 'firewall', '192.168.1.2', 'Cisco', 'ASA 5525-X', 'online'),
('Snort-IDS-01', 'ids', '192.168.1.10', 'Cisco', 'Snort', 'online'),
('Suricata-IPS-01', 'ids', '192.168.1.11', 'OISF', 'Suricata', 'online'),
('OpenVPN-Server-01', 'vpn', '192.168.1.20', 'OpenVPN', 'OpenVPN', 'online'),
('Cisco-ISE-01', 'nac', '192.168.1.30', 'Cisco', 'ISE', 'online'),
('Aruba-ClearPass-01', 'nac', '192.168.1.31', 'Aruba', 'ClearPass', 'online')
ON CONFLICT DO NOTHING;

-- Insert sample firewall logs
INSERT INTO firewall_logs (device_id, log_time, source_ip, dest_ip, action, protocol, source_port, dest_port, application, rule_name, bytes_sent, bytes_received) VALUES
(1, NOW() - INTERVAL '1 hour', '192.168.10.100', '8.8.8.8', 'allow', 'tcp', 12345, 443, 'HTTPS', 'Allow-Outbound-HTTPS', 1024, 2048),
(1, NOW() - INTERVAL '30 minutes', '10.0.0.50', '192.168.1.100', 'deny', 'tcp', 54321, 22, 'SSH', 'Block-Inbound-SSH', 0, 0),
(1, NOW() - INTERVAL '15 minutes', '192.168.10.101', '1.1.1.1', 'allow', 'udp', 12345, 53, 'DNS', 'Allow-Outbound-DNS', 512, 256),
(2, NOW() - INTERVAL '45 minutes', '172.16.0.10', '192.168.1.50', 'allow', 'tcp', 12345, 80, 'HTTP', 'Allow-Inbound-HTTP', 2048, 4096),
(2, NOW() - INTERVAL '20 minutes', '192.168.0.100', '10.0.0.1', 'drop', 'tcp', 12345, 3389, 'RDP', 'Block-RDP', 0, 0)
ON CONFLICT DO NOTHING;

-- Insert sample IDS alerts
INSERT INTO ids_alerts (device_id, alert_time, severity, alert_type, description, source_ip, dest_ip, source_port, dest_port, protocol, signature_id, signature_name, category) VALUES
(3, NOW() - INTERVAL '2 hours', 'high', 'signature', 'Suspicious port scan detected', '192.168.10.200', '192.168.1.100', 12345, 22, 'tcp', 'SIG-001', 'Port-Scan', 'reconnaissance'),
(3, NOW() - INTERVAL '1 hour', 'critical', 'signature', 'Malware signature detected', '10.0.0.50', '192.168.1.50', 12345, 80, 'tcp', 'SIG-002', 'Malware-Trojan', 'malware'),
(4, NOW() - INTERVAL '30 minutes', 'medium', 'anomaly', 'Unusual traffic pattern detected', '172.16.0.20', '8.8.8.8', 12345, 443, 'tcp', 'SIG-003', 'Anomaly-Detection', 'anomaly'),
(4, NOW() - INTERVAL '15 minutes', 'low', 'policy', 'Policy violation: unauthorized access attempt', '192.168.0.150', '192.168.1.25', 12345, 23, 'tcp', 'SIG-004', 'Policy-Violation', 'policy')
ON CONFLICT DO NOTHING;

-- Insert sample VPN sessions
INSERT INTO vpn_sessions (device_id, username, ip_address, connection_start, status, vpn_type, client_ip, bytes_sent, bytes_received) VALUES
(5, 'john.doe@company.com', '10.0.0.100', NOW() - INTERVAL '2 hours', 'active', 'ssl', '203.0.113.10', 1048576, 2097152),
(5, 'jane.smith@company.com', '10.0.0.101', NOW() - INTERVAL '1 hour', 'active', 'ssl', '203.0.113.11', 524288, 1048576),
(5, 'bob.wilson@company.com', '10.0.0.102', NOW() - INTERVAL '30 minutes', 'active', 'ssl', '203.0.113.12', 262144, 524288),
(5, 'alice.jones@company.com', '10.0.0.103', NOW() - INTERVAL '4 hours', 'disconnected', 'ssl', '203.0.113.13', 2097152, 4194304)
ON CONFLICT DO NOTHING;

-- Insert sample NAC logs
INSERT INTO nac_logs (device_id, event_time, device_mac, device_ip, device_name, action, description, user_name, switch_port, vlan, policy_name, reason) VALUES
(6, NOW() - INTERVAL '1 hour', '00:11:22:33:44:55', '192.168.10.100', 'Laptop-John', 'allowed', 'Device authenticated successfully', 'john.doe', 'GigabitEthernet1/0/1', 'VLAN10', 'Employee-Policy', NULL),
(6, NOW() - INTERVAL '45 minutes', 'AA:BB:CC:DD:EE:FF', '192.168.10.101', 'Laptop-Jane', 'allowed', 'Device authenticated successfully', 'jane.smith', 'GigabitEthernet1/0/2', 'VLAN10', 'Employee-Policy', NULL),
(6, NOW() - INTERVAL '30 minutes', '11:22:33:44:55:66', '192.168.10.102', 'Unknown-Device', 'blocked', 'Unknown device detected', NULL, 'GigabitEthernet1/0/3', 'VLAN10', 'Guest-Policy', 'unknown device'),
(7, NOW() - INTERVAL '15 minutes', '22:33:44:55:66:77', '192.168.10.103', 'Tablet-Bob', 'quarantined', 'Device policy violation', 'bob.wilson', 'GigabitEthernet1/0/4', 'VLAN20', 'Contractor-Policy', 'policy violation'),
(7, NOW() - INTERVAL '5 minutes', '33:44:55:66:77:88', '192.168.10.104', 'Phone-Alice', 'allowed', 'Device authenticated successfully', 'alice.jones', 'GigabitEthernet1/0/5', 'VLAN30', 'Mobile-Policy', NULL)
ON CONFLICT DO NOTHING;

-- Update some VPN sessions to have connection_end times
UPDATE vpn_sessions 
SET connection_end = NOW() - INTERVAL '30 minutes', 
    status = 'disconnected',
    session_duration = 12600
WHERE username = 'alice.jones@company.com';

-- Create a view for network security overview
CREATE OR REPLACE VIEW network_security_overview AS
SELECT 
    (SELECT COUNT(*) FROM network_devices) as total_devices,
    (SELECT COUNT(*) FROM network_devices WHERE status = 'online') as online_devices,
    (SELECT COUNT(*) FROM network_devices WHERE status = 'offline') as offline_devices,
    (SELECT COUNT(*) FROM firewall_logs WHERE log_time >= NOW() - INTERVAL '24 hours') as firewall_logs_24h,
    (SELECT COUNT(*) FROM ids_alerts WHERE alert_time >= NOW() - INTERVAL '24 hours') as ids_alerts_24h,
    (SELECT COUNT(*) FROM vpn_sessions WHERE status = 'active') as active_vpn_sessions,
    (SELECT COUNT(*) FROM nac_logs WHERE event_time >= NOW() - INTERVAL '24 hours') as nac_events_24h,
    (SELECT COUNT(*) FROM ids_alerts WHERE severity = 'critical' AND alert_time >= NOW() - INTERVAL '24 hours') as critical_alerts,
    (SELECT COUNT(*) FROM ids_alerts WHERE severity = 'high' AND alert_time >= NOW() - INTERVAL '24 hours') as high_alerts,
    (SELECT COUNT(*) FROM ids_alerts WHERE severity = 'medium' AND alert_time >= NOW() - INTERVAL '24 hours') as medium_alerts,
    (SELECT COUNT(*) FROM ids_alerts WHERE severity = 'low' AND alert_time >= NOW() - INTERVAL '24 hours') as low_alerts;

-- Grant permissions to the application user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;
GRANT SELECT ON network_security_overview TO cybershield_user; 