-- Production Database Configuration for CyberShield
-- This script configures the database for production use

-- Connect to the database
\c cybershield;

-- ============================================================================
-- PRODUCTION SECURITY CONFIGURATION
-- ============================================================================

-- Set production security parameters
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL';
ALTER SYSTEM SET ssl_prefer_server_ciphers = on;
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';

-- Set connection limits for production
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements,auto_explain';

-- Set memory parameters for production
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';

-- Set WAL and checkpoint settings for production
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_writer_delay = '200ms';
ALTER SYSTEM SET max_wal_size = '2GB';
ALTER SYSTEM SET min_wal_size = '80MB';

-- Set query optimization for production
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET default_statistics_target = 100;

-- Set logging for production monitoring
ALTER SYSTEM SET log_destination = 'stderr';
ALTER SYSTEM SET logging_collector = on;
ALTER SYSTEM SET log_directory = 'log';
ALTER SYSTEM SET log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log';
ALTER SYSTEM SET log_rotation_age = '1d';
ALTER SYSTEM SET log_rotation_size = '100MB';
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_lock_waits = on;
ALTER SYSTEM SET log_temp_files = 0;
ALTER SYSTEM SET log_autovacuum_min_duration = 0;

-- Set autovacuum settings for production
ALTER SYSTEM SET autovacuum = on;
ALTER SYSTEM SET autovacuum_max_workers = 3;
ALTER SYSTEM SET autovacuum_naptime = '1min';
ALTER SYSTEM SET autovacuum_vacuum_threshold = 50;
ALTER SYSTEM SET autovacuum_analyze_threshold = 50;
ALTER SYSTEM SET autovacuum_vacuum_scale_factor = 0.2;
ALTER SYSTEM SET autovacuum_analyze_scale_factor = 0.1;

-- ============================================================================
-- PRODUCTION MONITORING SETUP
-- ============================================================================

-- Enable pg_stat_statements for query monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Create monitoring views for production
CREATE OR REPLACE VIEW production_metrics AS
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation,
    most_common_vals,
    most_common_freqs
FROM pg_stats 
WHERE schemaname = 'public';

-- Create performance monitoring view
CREATE OR REPLACE VIEW performance_metrics AS
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows,
    shared_blks_hit,
    shared_blks_read,
    shared_blks_written,
    shared_blks_dirtied,
    temp_blks_read,
    temp_blks_written,
    blk_read_time,
    blk_write_time
FROM pg_stat_statements
ORDER BY total_time DESC;

-- Create connection monitoring view
CREATE OR REPLACE VIEW connection_metrics AS
SELECT 
    datname,
    usename,
    application_name,
    client_addr,
    client_hostname,
    state,
    query_start,
    state_change,
    wait_event_type,
    wait_event
FROM pg_stat_activity
WHERE state IS NOT NULL;

-- Create table size monitoring view
CREATE OR REPLACE VIEW table_sizes AS
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- ============================================================================
-- PRODUCTION BACKUP CONFIGURATION
-- ============================================================================

-- Enable WAL archiving for point-in-time recovery
ALTER SYSTEM SET archive_mode = on;
ALTER SYSTEM SET archive_command = 'test ! -f /var/lib/postgresql/archive/%f && cp %p /var/lib/postgresql/archive/%f';

-- Set backup parameters
ALTER SYSTEM SET backup_standby = on;
ALTER SYSTEM SET hot_standby = on;

-- Create backup monitoring view
CREATE OR REPLACE VIEW backup_status AS
SELECT 
    pg_current_wal_lsn() as current_lsn,
    pg_last_wal_receive_lsn() as received_lsn,
    pg_last_wal_replay_lsn() as replayed_lsn,
    pg_is_in_recovery() as is_in_recovery;

-- ============================================================================
-- PRODUCTION MAINTENANCE PROCEDURES
-- ============================================================================

-- Create maintenance function for regular cleanup
CREATE OR REPLACE FUNCTION production_maintenance()
RETURNS void AS $$
BEGIN
    -- Update table statistics
    ANALYZE;
    
    -- Clean up old logs (keep last 30 days)
    DELETE FROM integration_logs WHERE timestamp < NOW() - INTERVAL '30 days';
    DELETE FROM incident_responses WHERE created_at < NOW() - INTERVAL '30 days';
    
    -- Vacuum tables that need it
    VACUUM ANALYZE;
    
    -- Log maintenance completion
    INSERT INTO integration_logs (integration_id, log_level, message, details)
    VALUES (1, 'INFO', 'Production maintenance completed', 
            jsonb_build_object('timestamp', NOW(), 'maintenance_type', 'daily'));
END;
$$ LANGUAGE plpgsql;

-- Create index maintenance function
CREATE OR REPLACE FUNCTION maintain_indexes()
RETURNS void AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN 
        SELECT schemaname, tablename, indexname 
        FROM pg_indexes 
        WHERE schemaname = 'public'
    LOOP
        -- Reindex if needed (this is a simplified version)
        EXECUTE 'REINDEX INDEX ' || quote_ident(r.schemaname) || '.' || quote_ident(r.indexname);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PRODUCTION ALERTING SETUP
-- ============================================================================

-- Create alert thresholds table
CREATE TABLE IF NOT EXISTS alert_thresholds (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    warning_threshold FLOAT NOT NULL,
    critical_threshold FLOAT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert default alert thresholds
INSERT INTO alert_thresholds (metric_name, warning_threshold, critical_threshold) VALUES
('connection_count', 150, 180),
('query_duration_ms', 5000, 10000),
('table_size_gb', 10, 20),
('index_fragmentation', 20, 40),
('vacuum_frequency_hours', 24, 48)
ON CONFLICT (metric_name) DO NOTHING;

-- Create alerting function
CREATE OR REPLACE FUNCTION check_production_alerts()
RETURNS TABLE(alert_type VARCHAR, metric_name VARCHAR, current_value FLOAT, threshold FLOAT) AS $$
BEGIN
    -- Check connection count
    IF (SELECT COUNT(*) FROM pg_stat_activity) > (SELECT critical_threshold FROM alert_thresholds WHERE metric_name = 'connection_count') THEN
        RETURN QUERY SELECT 'CRITICAL'::VARCHAR, 'connection_count'::VARCHAR, 
               (SELECT COUNT(*)::FLOAT FROM pg_stat_activity), 
               (SELECT critical_threshold FROM alert_thresholds WHERE metric_name = 'connection_count');
    END IF;
    
    -- Check for long-running queries
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE state = 'active' AND query_start < NOW() - INTERVAL '1 hour') THEN
        RETURN QUERY SELECT 'WARNING'::VARCHAR, 'long_running_queries'::VARCHAR, 
               1.0, 3600.0;
    END IF;
    
    -- Check table sizes
    IF EXISTS (SELECT 1 FROM table_sizes WHERE size_bytes > 10737418240) THEN -- 10GB
        RETURN QUERY SELECT 'WARNING'::VARCHAR, 'large_tables'::VARCHAR, 
               (SELECT MAX(size_bytes::FLOAT) FROM table_sizes), 10737418240.0;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PRODUCTION SECURITY HARDENING
-- ============================================================================

-- Create production user with limited privileges for monitoring
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cybershield_monitor') THEN
        CREATE ROLE cybershield_monitor WITH LOGIN PASSWORD 'monitor_password_2024';
    END IF;
END
$$;

-- Grant monitoring privileges
GRANT CONNECT ON DATABASE cybershield TO cybershield_monitor;
GRANT USAGE ON SCHEMA public TO cybershield_monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO cybershield_monitor;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO cybershield_monitor;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO cybershield_monitor;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO cybershield_monitor;

-- ============================================================================
-- PRODUCTION PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Create performance tuning function
CREATE OR REPLACE FUNCTION tune_production_performance()
RETURNS void AS $$
BEGIN
    -- Update statistics on all tables
    ANALYZE;
    
    -- Vacuum tables to reclaim space
    VACUUM ANALYZE;
    
    -- Reindex if needed
    PERFORM maintain_indexes();
    
    -- Log performance tuning
    INSERT INTO integration_logs (integration_id, log_level, message, details)
    VALUES (1, 'INFO', 'Production performance tuning completed', 
            jsonb_build_object('timestamp', NOW(), 'tuning_type', 'performance'));
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- APPLY ALL CONFIGURATIONS
-- ============================================================================

-- Reload configuration
SELECT pg_reload_conf();

-- Display production configuration status
SELECT 
    name,
    setting,
    unit,
    context,
    category
FROM pg_settings 
WHERE name IN (
    'max_connections',
    'shared_buffers',
    'effective_cache_size',
    'work_mem',
    'maintenance_work_mem',
    'wal_buffers',
    'checkpoint_completion_target',
    'log_min_duration_statement',
    'autovacuum',
    'ssl'
)
ORDER BY category, name;

-- Display monitoring views
SELECT 'Production monitoring views created successfully' as status;
SELECT 'Alert thresholds configured' as status;
SELECT 'Production maintenance procedures ready' as status;
SELECT 'Performance optimization functions available' as status;
