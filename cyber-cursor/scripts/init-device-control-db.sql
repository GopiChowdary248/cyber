-- Device Control Database Initialization
-- This script creates the device control tables and inserts sample data

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create devices table
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_name VARCHAR(255) NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    vendor VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(255),
    device_id VARCHAR(255),
    capacity FLOAT,
    file_system VARCHAR(50),
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_approved BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'disconnected',
    last_seen TIMESTAMP,
    first_seen TIMESTAMP DEFAULT NOW(),
    endpoint_id VARCHAR(255),
    user_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create device_policies table
CREATE TABLE IF NOT EXISTS device_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(255) NOT NULL,
    description TEXT,
    device_type VARCHAR(50),
    vendor VARCHAR(100),
    model VARCHAR(100),
    device_id VARCHAR(255),
    action VARCHAR(20) NOT NULL DEFAULT 'block',
    auto_encrypt BOOLEAN DEFAULT FALSE,
    require_approval BOOLEAN DEFAULT FALSE,
    max_capacity FLOAT,
    allowed_file_types JSONB,
    blocked_file_types JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id)
);

-- Create device_events table
CREATE TABLE IF NOT EXISTS device_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id),
    policy_id UUID REFERENCES device_policies(id),
    event_type VARCHAR(50) NOT NULL,
    event_time TIMESTAMP DEFAULT NOW(),
    endpoint_id VARCHAR(255),
    user_id INTEGER REFERENCES users(id),
    process_name VARCHAR(255),
    file_path TEXT,
    action_taken VARCHAR(50),
    reason TEXT,
    severity VARCHAR(20) DEFAULT 'info',
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_endpoint ON devices(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_device_policies_type ON device_policies(device_type);
CREATE INDEX IF NOT EXISTS idx_device_policies_active ON device_policies(is_active);
CREATE INDEX IF NOT EXISTS idx_device_events_device ON device_events(device_id);
CREATE INDEX IF NOT EXISTS idx_device_events_type ON device_events(event_type);
CREATE INDEX IF NOT EXISTS idx_device_events_time ON device_events(event_time);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_device_policies_updated_at BEFORE UPDATE ON device_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample device policies
INSERT INTO device_policies (policy_name, description, device_type, action, auto_encrypt, require_approval, priority) VALUES
('USB Block Policy', 'Block all USB devices by default', 'usb', 'block', FALSE, FALSE, 100),
('USB Allow Approved', 'Allow only approved USB devices', 'usb', 'allow', FALSE, TRUE, 200),
('USB Encrypt Policy', 'Encrypt all USB devices automatically', 'usb', 'encrypt', TRUE, FALSE, 150),
('External HDD Block', 'Block external hard drives', 'external_hdd', 'block', FALSE, FALSE, 100),
('CD/DVD Read Only', 'Allow CD/DVD read access only', 'cd_dvd', 'audit', FALSE, FALSE, 50);

-- Insert sample devices
INSERT INTO devices (device_name, device_type, vendor, model, serial_number, device_id, capacity, file_system, status, endpoint_id) VALUES
('SanDisk USB Drive', 'usb', 'SanDisk', 'Cruzer', 'SN123456789', 'USB-VID-0781&PID-5567', 32.0, 'FAT32', 'connected', 'endpoint-001'),
('Seagate External HDD', 'external_hdd', 'Seagate', 'Backup Plus', 'SN987654321', 'USB-VID-0BC2&PID-3320', 1000.0, 'NTFS', 'disconnected', 'endpoint-002'),
('Samsung USB Drive', 'usb', 'Samsung', 'BAR Plus', 'SN555666777', 'USB-VID-090C&PID-1000', 64.0, 'FAT32', 'blocked', 'endpoint-001'),
('DVD-RW Drive', 'cd_dvd', 'LG', 'GH24NS95', 'SN111222333', 'SCSI-VID-1E0D&PID-0828', NULL, NULL, 'connected', 'endpoint-003');

-- Insert sample device events
INSERT INTO device_events (device_id, event_type, action_taken, reason, severity, endpoint_id) VALUES
((SELECT id FROM devices WHERE device_name = 'SanDisk USB Drive'), 'connect', 'allow', 'Approved USB device', 'info', 'endpoint-001'),
((SELECT id FROM devices WHERE device_name = 'SanDisk USB Drive'), 'access', 'allow', 'File access allowed', 'info', 'endpoint-001'),
((SELECT id FROM devices WHERE device_name = 'Samsung USB Drive'), 'connect', 'block', 'Unauthorized USB device', 'warning', 'endpoint-001'),
((SELECT id FROM devices WHERE device_name = 'Seagate External HDD'), 'connect', 'quarantine', 'Large capacity device requires approval', 'warning', 'endpoint-002'),
((SELECT id FROM devices WHERE device_name = 'DVD-RW Drive'), 'connect', 'allow', 'CD/DVD drive allowed', 'info', 'endpoint-003');

-- Create view for device summary
CREATE OR REPLACE VIEW device_summary AS
SELECT 
    COUNT(*) as total_devices,
    COUNT(CASE WHEN status = 'connected' THEN 1 END) as connected_devices,
    COUNT(CASE WHEN status = 'blocked' THEN 1 END) as blocked_devices,
    COUNT(CASE WHEN status = 'quarantined' THEN 1 END) as quarantined_devices,
    COUNT(CASE WHEN is_approved = TRUE THEN 1 END) as approved_devices
FROM devices;

-- Create view for recent device events
CREATE OR REPLACE VIEW recent_device_events AS
SELECT 
    de.id,
    de.event_type,
    de.event_time,
    de.action_taken,
    de.severity,
    d.device_name,
    d.device_type,
    dp.policy_name
FROM device_events de
LEFT JOIN devices d ON de.device_id = d.id
LEFT JOIN device_policies dp ON de.policy_id = dp.id
WHERE de.event_time >= NOW() - INTERVAL '24 hours'
ORDER BY de.event_time DESC;

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON TABLE devices TO your_app_user;
-- GRANT ALL PRIVILEGES ON TABLE device_policies TO your_app_user;
-- GRANT ALL PRIVILEGES ON TABLE device_events TO your_app_user;
-- GRANT ALL PRIVILEGES ON TABLE device_summary TO your_app_user;
-- GRANT ALL PRIVILEGES ON TABLE recent_device_events TO your_app_user; 