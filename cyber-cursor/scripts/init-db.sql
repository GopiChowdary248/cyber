-- CyberShield Database Initialization Script
-- This script creates the database and user for the CyberShield application

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