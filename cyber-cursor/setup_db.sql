-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cybershield_user') THEN
        CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE cybershield'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybershield')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL ON SCHEMA public TO cybershield_user;
