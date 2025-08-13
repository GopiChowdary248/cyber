-- CyberShield Enhanced Production Database Initialization Script
-- This script creates the complete database schema for all modules

-- Create user if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cybershield_user') THEN
        CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';
    END IF;
END
$$;

-- Create database if not exists
SELECT 'CREATE DATABASE cybershield'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybershield')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL ON SCHEMA public TO cybershield_user;

-- Connect to the cybershield database
\c cybershield;

-- Grant additional privileges
GRANT CREATE ON SCHEMA public TO cybershield_user;
GRANT USAGE ON SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO cybershield_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO cybershield_user;

-- Create enum types for all modules
DO $$
BEGIN
    -- SAST enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issueresolution') THEN
        CREATE TYPE issueresolution AS ENUM ('FIXED', 'WONTFIX', 'FALSE_POSITIVE', 'ACCEPTED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityhotspotresolution') THEN
        CREATE TYPE securityhotspotresolution AS ENUM ('FIXED', 'ACKNOWLEDGED', 'FALSE_POSITIVE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'qualitygatestatus') THEN
        CREATE TYPE qualitygatestatus AS ENUM ('PASSED', 'FAILED', 'WARNING');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rating') THEN
        CREATE TYPE rating AS ENUM ('A', 'B', 'C', 'D', 'E');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scanstatus') THEN
        CREATE TYPE scanstatus AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityhotspotstatus') THEN
        CREATE TYPE securityhotspotstatus AS ENUM ('TO_REVIEW', 'REVIEWED', 'FIXED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issueseverity') THEN
        CREATE TYPE issueseverity AS ENUM ('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issuetype') THEN
        CREATE TYPE issuetype AS ENUM ('BUG', 'VULNERABILITY', 'CODE_SMELL');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issuestatus') THEN
        CREATE TYPE issuestatus AS ENUM ('OPEN', 'CONFIRMED', 'RESOLVED', 'REOPENED', 'CLOSED');
    END IF;
    
    -- DAST enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dastseverity') THEN
        CREATE TYPE dastseverity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'daststatus') THEN
        CREATE TYPE daststatus AS ENUM ('ACTIVE', 'INACTIVE', 'ARCHIVED');
    END IF;
    
    -- RASP enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'raspstatus') THEN
        CREATE TYPE raspstatus AS ENUM ('ACTIVE', 'INACTIVE', 'MAINTENANCE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'raspattacktype') THEN
        CREATE TYPE raspattacktype AS ENUM ('SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'LDAP_INJECTION');
    END IF;
    
    -- Cloud Security enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cloudprovider') THEN
        CREATE TYPE cloudprovider AS ENUM ('AWS', 'AZURE', 'GCP', 'DIGITAL_OCEAN', 'LINODE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risklevel') THEN
        CREATE TYPE risklevel AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
    END IF;
    
    -- IAM enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
        CREATE TYPE userrole AS ENUM ('ADMIN', 'USER', 'ANALYST', 'MANAGER', 'AUDITOR');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sessionstatus') THEN
        CREATE TYPE sessionstatus AS ENUM ('ACTIVE', 'EXPIRED', 'TERMINATED', 'SUSPENDED');
    END IF;
    
    -- Device Control enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'devicetype') THEN
        CREATE TYPE devicetype AS ENUM ('USB', 'BLUETOOTH', 'WIFI', 'ETHERNET', 'OPTICAL', 'OTHER');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'devicestatus') THEN
        CREATE TYPE devicestatus AS ENUM ('ALLOWED', 'BLOCKED', 'PENDING', 'QUARANTINED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'policyaction') THEN
        CREATE TYPE policyaction AS ENUM ('ALLOW', 'BLOCK', 'AUDIT', 'QUARANTINE');
    END IF;
    
    -- Network Security enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alertseverity') THEN
        CREATE TYPE alertseverity AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alertstatus') THEN
        CREATE TYPE alertstatus AS ENUM ('NEW', 'IN_PROGRESS', 'RESOLVED', 'CLOSED');
    END IF;
END
$$;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100),
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_superuser BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    department VARCHAR(100),
    phone VARCHAR(20),
    avatar_url VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    preferences JSONB
);

-- Create admin user if not exists
INSERT INTO users (username, email, hashed_password, is_active, is_superuser, role)
VALUES (
    'admin',
    'admin@cybershield.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', -- password: admin123
    TRUE,
    TRUE,
    'ADMIN'
) ON CONFLICT (username) DO NOTHING;

-- Create test user if not exists
INSERT INTO users (username, email, hashed_password, is_active, is_superuser, role)
VALUES (
    'testuser',
    'test@cybershield.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', -- password: admin123
    TRUE,
    FALSE,
    'USER'
) ON CONFLICT (username) DO NOTHING;

-- Grant permissions on new tables
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
