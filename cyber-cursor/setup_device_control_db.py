#!/usr/bin/env python3
"""
Setup script for Device Control database tables
"""

import asyncio
import sys
import os

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import uuid
from datetime import datetime

# Database URL - you can modify this as needed
DATABASE_URL = "postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield"

async def setup_device_control_database():
    """Set up device control database tables"""
    
    print("Setting up Device Control database...")
    
    # Create async engine
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    async with engine.begin() as conn:
        # Enable UUID extension
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"))
        
        # Create devices table
        await conn.execute(text("""
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
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        """))
        
        # Create device_policies table
        await conn.execute(text("""
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
                created_by INTEGER
            );
        """))
        
        # Create device_events table
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS device_events (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                device_id UUID NOT NULL REFERENCES devices(id),
                policy_id UUID REFERENCES device_policies(id),
                event_type VARCHAR(50) NOT NULL,
                event_time TIMESTAMP DEFAULT NOW(),
                endpoint_id VARCHAR(255),
                user_id INTEGER,
                process_name VARCHAR(255),
                file_path TEXT,
                action_taken VARCHAR(50),
                reason TEXT,
                severity VARCHAR(20) DEFAULT 'info',
                event_metadata JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            );
        """))
        
        # Create indexes
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_endpoint ON devices(endpoint_id);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_policies_type ON device_policies(device_type);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_policies_active ON device_policies(is_active);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_events_device ON device_events(device_id);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_events_type ON device_events(event_type);"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_events_time ON device_events(event_time);"))
        
        # Create function to update updated_at timestamp
        await conn.execute(text("""
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = NOW();
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """))
        
        # Create triggers for updated_at
        await conn.execute(text("""
            CREATE TRIGGER update_devices_updated_at 
            BEFORE UPDATE ON devices
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """))
        
        await conn.execute(text("""
            CREATE TRIGGER update_device_policies_updated_at 
            BEFORE UPDATE ON device_policies
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """))
        
        # Insert sample device policies
        await conn.execute(text("""
            INSERT INTO device_policies (policy_name, description, device_type, action, auto_encrypt, require_approval, priority) VALUES
            ('USB Block Policy', 'Block all USB devices by default', 'usb', 'block', FALSE, FALSE, 100),
            ('USB Allow Approved', 'Allow only approved USB devices', 'usb', 'allow', FALSE, TRUE, 200),
            ('USB Encrypt Policy', 'Encrypt all USB devices automatically', 'usb', 'encrypt', TRUE, FALSE, 150),
            ('External HDD Block', 'Block external hard drives', 'external_hdd', 'block', FALSE, FALSE, 100),
            ('CD/DVD Read Only', 'Allow CD/DVD read access only', 'cd_dvd', 'audit', FALSE, FALSE, 50)
            ON CONFLICT DO NOTHING;
        """))
        
        # Insert sample devices
        await conn.execute(text("""
            INSERT INTO devices (device_name, device_type, vendor, model, serial_number, device_id, capacity, file_system, status, endpoint_id) VALUES
            ('SanDisk USB Drive', 'usb', 'SanDisk', 'Cruzer', 'SN123456789', 'USB-VID-0781&PID-5567', 32.0, 'FAT32', 'connected', 'endpoint-001'),
            ('Seagate External HDD', 'external_hdd', 'Seagate', 'Backup Plus', 'SN987654321', 'USB-VID-0BC2&PID-3320', 1000.0, 'NTFS', 'disconnected', 'endpoint-002'),
            ('Samsung USB Drive', 'usb', 'Samsung', 'BAR Plus', 'SN555666777', 'USB-VID-090C&PID-1000', 64.0, 'FAT32', 'blocked', 'endpoint-001'),
            ('DVD-RW Drive', 'cd_dvd', 'LG', 'GH24NS95', 'SN111222333', 'SCSI-VID-1E0D&PID-0828', NULL, NULL, 'connected', 'endpoint-003')
            ON CONFLICT DO NOTHING;
        """))
        
        # Insert sample device events
        await conn.execute(text("""
            INSERT INTO device_events (device_id, event_type, action_taken, reason, severity, endpoint_id) 
            SELECT 
                d.id,
                'connect',
                'allow',
                'Approved USB device',
                'info',
                'endpoint-001'
            FROM devices d 
            WHERE d.device_name = 'SanDisk USB Drive'
            ON CONFLICT DO NOTHING;
        """))
        
        print("Device Control database setup completed successfully!")
    
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(setup_device_control_database()) 