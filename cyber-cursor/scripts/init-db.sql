-- Initialize CyberShield Database
-- This script runs when the PostgreSQL container starts for the first time

-- Create database if it doesn't exist (handled by POSTGRES_DB env var)
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create additional schemas if needed
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS analytics;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON SCHEMA audit TO cybershield_user;
GRANT ALL PRIVILEGES ON SCHEMA analytics TO cybershield_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO cybershield_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON SEQUENCES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON FUNCTIONS TO cybershield_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT ALL ON SEQUENCES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT ALL ON FUNCTIONS TO cybershield_user;

-- Create indexes for better performance
-- These will be created by SQLAlchemy, but we can add custom ones here if needed

-- Log the initialization
DO $$
BEGIN
    RAISE NOTICE 'CyberShield database initialized successfully';
END $$; 