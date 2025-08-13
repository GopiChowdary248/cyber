-- PostgreSQL Database Initialization Script for CyberShield
-- This script sets up the initial database structure

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone
SET timezone = 'UTC';

-- Create custom types if they don't exist
DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE issue_severity AS ENUM ('critical', 'major', 'minor', 'info');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE issue_type AS ENUM ('vulnerability', 'bug', 'code_smell', 'security_hotspot');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE issue_status AS ENUM ('open', 'confirmed', 'false_positive', 'fixed', 'wont_fix');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE security_hotspot_status AS ENUM ('to_review', 'reviewed', 'safe');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE quality_gate_status AS ENUM ('passed', 'failed', 'warning');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE rating AS ENUM ('A', 'B', 'C', 'D', 'E');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO cybershield_user;
