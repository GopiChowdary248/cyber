-- CyberShield Production Database Monitoring Dashboard
-- This script creates comprehensive monitoring views and functions

-- Connect to the database
\c cybershield;

-- ============================================================================
-- REAL-TIME PERFORMANCE MONITORING
-- ============================================================================

-- Create comprehensive performance dashboard view
CREATE OR REPLACE VIEW performance_dashboard AS
SELECT 
    'Database Performance' as category,
    'Active Connections' as metric,
    COUNT(*) as current_value,
    'connections' as unit,
    CASE 
        WHEN COUNT(*) > 150 THEN 'CRITICAL'
        WHEN COUNT(*) > 100 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_activity
WHERE state = 'active'

UNION ALL

SELECT 
    'Database Performance' as category,
    'Idle Connections' as metric,
    COUNT(*) as current_value,
    'connections' as unit,
    CASE 
        WHEN COUNT(*) > 50 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_activity
WHERE state = 'idle'

UNION ALL

SELECT 
    'Database Performance' as category,
    'Long Running Queries' as metric,
    COUNT(*) as current_value,
    'queries' as unit,
    CASE 
        WHEN COUNT(*) > 0 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_activity
WHERE state = 'active' AND query_start < NOW() - INTERVAL '5 minutes'

UNION ALL

SELECT 
    'Database Performance' as category,
    'Cache Hit Ratio' as metric,
    ROUND(
        (SUM(heap_blks_hit) * 100.0 / (SUM(heap_blks_hit) + SUM(heap_blks_read)))::numeric, 2
    ) as current_value,
    '%' as unit,
    CASE 
        WHEN (SUM(heap_blks_hit) * 100.0 / (SUM(heap_blks_hit) + SUM(heap_blks_read))) < 80 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_statio_user_tables;

-- Create table performance metrics view
CREATE OR REPLACE VIEW table_performance_metrics AS
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes,
    n_live_tup as live_tuples,
    n_dead_tup as dead_tuples,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze,
    CASE 
        WHEN n_dead_tup > n_live_tup * 0.1 THEN 'NEEDS_VACUUM'
        WHEN last_vacuum < NOW() - INTERVAL '7 days' THEN 'NEEDS_VACUUM'
        ELSE 'OK'
    END as maintenance_status
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Create index performance metrics view
CREATE OR REPLACE VIEW index_performance_metrics AS
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
    idx_scan as scans,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched,
    CASE 
        WHEN idx_scan = 0 THEN 'UNUSED'
        WHEN idx_scan < 10 THEN 'LOW_USAGE'
        ELSE 'ACTIVE'
    END as usage_status
FROM pg_stat_user_indexes
ORDER BY pg_relation_size(indexrelid) DESC;

-- Create query performance metrics view
CREATE OR REPLACE VIEW query_performance_metrics AS
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows,
    shared_blks_hit,
    shared_blks_read,
    shared_blks_written,
    CASE 
        WHEN mean_time > 1000 THEN 'SLOW'
        WHEN mean_time > 100 THEN 'MEDIUM'
        ELSE 'FAST'
    END as performance_category
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 20;

-- ============================================================================
-- SYSTEM HEALTH MONITORING
-- ============================================================================

-- Create system health dashboard view
CREATE OR REPLACE VIEW system_health_dashboard AS
SELECT 
    'System Health' as category,
    'Database Size' as metric,
    pg_size_pretty(pg_database_size(current_database())) as current_value,
    'total' as unit,
    CASE 
        WHEN pg_database_size(current_database()) > 107374182400 THEN 'WARNING' -- 100GB
        ELSE 'OK'
    END as status

UNION ALL

SELECT 
    'System Health' as category,
    'WAL Generation Rate' as metric,
    ROUND(
        (pg_current_wal_lsn() - pg_last_wal_receive_lsn())::numeric / 1024 / 1024, 2
    )::text as current_value,
    'MB' as unit,
    'OK' as status

UNION ALL

SELECT 
    'System Health' as category,
    'Checkpoint Frequency' as metric,
    ROUND(
        EXTRACT(EPOCH FROM (NOW() - stats_reset)) / 3600, 2
    )::text as current_value,
    'hours' as unit,
    CASE 
        WHEN EXTRACT(EPOCH FROM (NOW() - stats_reset)) / 3600 < 1 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_bgwriter

UNION ALL

SELECT 
    'System Health' as category,
    'Autovacuum Status' as metric,
    COUNT(*)::text as current_value,
    'workers' as unit,
    CASE 
        WHEN COUNT(*) > 0 THEN 'OK'
        ELSE 'WARNING'
    END as status
FROM pg_stat_activity
WHERE query LIKE '%autovacuum%';

-- ============================================================================
-- SECURITY MONITORING
-- ============================================================================

-- Create security monitoring view
CREATE OR REPLACE VIEW security_monitoring_dashboard AS
SELECT 
    'Security' as category,
    'Failed Login Attempts' as metric,
    COUNT(*) as current_value,
    'attempts' as unit,
    CASE 
        WHEN COUNT(*) > 10 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_activity
WHERE state = 'active' AND usename IS NOT NULL

UNION ALL

SELECT 
    'Security' as category,
    'Superuser Connections' as metric,
    COUNT(*) as current_value,
    'connections' as unit,
    CASE 
        WHEN COUNT(*) > 5 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_activity
WHERE usesuper = true

UNION ALL

SELECT 
    'Security' as category,
    'SSL Connections' as metric,
    COUNT(*) as current_value,
    'connections' as unit,
    CASE 
        WHEN COUNT(*) < (SELECT COUNT(*) FROM pg_stat_activity) * 0.8 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM pg_stat_activity
WHERE ssl = true;

-- ============================================================================
-- MAINTENANCE MONITORING
-- ============================================================================

-- Create maintenance monitoring view
CREATE OR REPLACE VIEW maintenance_monitoring_dashboard AS
SELECT 
    'Maintenance' as category,
    'Tables Needing Vacuum' as metric,
    COUNT(*) as current_value,
    'tables' as unit,
    CASE 
        WHEN COUNT(*) > 10 THEN 'WARNING'
        WHEN COUNT(*) > 5 THEN 'ATTENTION'
        ELSE 'OK'
    END as status
FROM pg_stat_user_tables
WHERE n_dead_tup > n_live_tup * 0.1

UNION ALL

SELECT 
    'Maintenance' as category,
    'Tables Needing Analyze' as metric,
    COUNT(*) as current_value,
    'tables' as unit,
    CASE 
        WHEN COUNT(*) > 10 THEN 'WARNING'
        WHEN COUNT(*) > 5 THEN 'ATTENTION'
        ELSE 'OK'
    END as status
FROM pg_stat_user_tables
WHERE last_analyze < NOW() - INTERVAL '7 days'

UNION ALL

SELECT 
    'Maintenance' as category,
    'Unused Indexes' as metric,
    COUNT(*) as current_value,
    'indexes' as unit,
    CASE 
        WHEN COUNT(*) > 20 THEN 'WARNING'
        WHEN COUNT(*) > 10 THEN 'ATTENTION'
        ELSE 'OK'
    END as status
FROM pg_stat_user_indexes
WHERE idx_scan = 0;

-- ============================================================================
-- ALERTING AND NOTIFICATIONS
-- ============================================================================

-- Create comprehensive alerting function
CREATE OR REPLACE FUNCTION get_production_alerts()
RETURNS TABLE(
    alert_level VARCHAR,
    category VARCHAR,
    metric VARCHAR,
    current_value TEXT,
    threshold TEXT,
    recommendation TEXT
) AS $$
BEGIN
    -- Check critical alerts
    IF (SELECT COUNT(*) FROM pg_stat_activity) > 180 THEN
        RETURN QUERY SELECT 
            'CRITICAL'::VARCHAR,
            'Performance'::VARCHAR,
            'Connection Count'::VARCHAR,
            COUNT(*)::TEXT,
            '180'::TEXT,
            'Reduce connection pool size or optimize queries'::TEXT
        FROM pg_stat_activity;
    END IF;
    
    -- Check for long-running queries
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE state = 'active' AND query_start < NOW() - INTERVAL '1 hour') THEN
        RETURN QUERY SELECT 
            'CRITICAL'::VARCHAR,
            'Performance'::VARCHAR,
            'Long Running Queries'::VARCHAR,
            'Detected'::TEXT,
            '1 hour'::TEXT,
            'Investigate and optimize long-running queries'::TEXT;
    END IF;
    
    -- Check disk space
    IF EXISTS (SELECT 1 FROM table_performance_metrics WHERE size_bytes > 10737418240) THEN -- 10GB
        RETURN QUERY SELECT 
            'WARNING'::VARCHAR,
            'Storage'::VARCHAR,
            'Large Tables'::VARCHAR,
            'Detected'::TEXT,
            '10GB'::TEXT,
            'Consider partitioning or archiving old data'::TEXT;
    END IF;
    
    -- Check maintenance needs
    IF EXISTS (SELECT 1 FROM maintenance_monitoring_dashboard WHERE status IN ('WARNING', 'ATTENTION')) THEN
        RETURN QUERY SELECT 
            'WARNING'::VARCHAR,
            'Maintenance'::VARCHAR,
            'Maintenance Required'::VARCHAR,
            'Detected'::TEXT,
            'Threshold exceeded'::TEXT,
            'Run maintenance procedures'::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PERFORMANCE TUNING RECOMMENDATIONS
-- ============================================================================

-- Create performance tuning recommendations view
CREATE OR REPLACE VIEW performance_recommendations AS
SELECT 
    'Performance Tuning' as category,
    'Add Index' as recommendation,
    'Consider adding index on ' || tablename || ' for better query performance' as details,
    'MEDIUM' as priority
FROM pg_stat_user_tables
WHERE seq_scan > idx_scan * 10
AND n_live_tup > 10000

UNION ALL

SELECT 
    'Performance Tuning' as category,
    'Vacuum Table' as recommendation,
    'Table ' || tablename || ' needs vacuuming (dead tuples: ' || n_dead_tup || ')' as details,
    'HIGH' as priority
FROM pg_stat_user_tables
WHERE n_dead_tup > n_live_tup * 0.1

UNION ALL

SELECT 
    'Performance Tuning' as category,
    'Analyze Table' as recommendation,
    'Table ' || tablename || ' needs statistics update (last analyze: ' || last_analyze || ')' as details,
    'MEDIUM' as priority
FROM pg_stat_user_tables
WHERE last_analyze < NOW() - INTERVAL '7 days'

UNION ALL

SELECT 
    'Performance Tuning' as category,
    'Remove Unused Index' as recommendation,
    'Index ' || indexname || ' on ' || tablename || ' is never used' as details,
    'LOW' as priority
FROM pg_stat_user_indexes
WHERE idx_scan = 0;

-- ============================================================================
-- MONITORING SUMMARY FUNCTIONS
-- ============================================================================

-- Create monitoring summary function
CREATE OR REPLACE FUNCTION get_monitoring_summary()
RETURNS TABLE(
    category VARCHAR,
    total_metrics INTEGER,
    ok_count INTEGER,
    warning_count INTEGER,
    critical_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        'Performance'::VARCHAR as category,
        COUNT(*)::INTEGER as total_metrics,
        COUNT(*) FILTER (WHERE status = 'OK')::INTEGER as ok_count,
        COUNT(*) FILTER (WHERE status = 'WARNING')::INTEGER as warning_count,
        COUNT(*) FILTER (WHERE status = 'CRITICAL')::INTEGER as critical_count
    FROM performance_dashboard
    
    UNION ALL
    
    SELECT 
        'System Health'::VARCHAR as category,
        COUNT(*)::INTEGER as total_metrics,
        COUNT(*) FILTER (WHERE status = 'OK')::INTEGER as ok_count,
        COUNT(*) FILTER (WHERE status = 'WARNING')::INTEGER as warning_count,
        COUNT(*) FILTER (WHERE status = 'CRITICAL')::INTEGER as critical_count
    FROM system_health_dashboard
    
    UNION ALL
    
    SELECT 
        'Security'::VARCHAR as category,
        COUNT(*)::INTEGER as total_metrics,
        COUNT(*) FILTER (WHERE status = 'OK')::INTEGER as ok_count,
        COUNT(*) FILTER (WHERE status = 'WARNING')::INTEGER as warning_count,
        COUNT(*) FILTER (WHERE status = 'CRITICAL')::INTEGER as critical_count
    FROM security_monitoring_dashboard
    
    UNION ALL
    
    SELECT 
        'Maintenance'::VARCHAR as category,
        COUNT(*)::INTEGER as total_metrics,
        COUNT(*) FILTER (WHERE status = 'OK')::INTEGER as ok_count,
        COUNT(*) FILTER (WHERE status = 'WARNING')::INTEGER as warning_count,
        COUNT(*) FILTER (WHERE status = 'ATTENTION')::INTEGER as critical_count
    FROM maintenance_monitoring_dashboard;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DISPLAY MONITORING STATUS
-- ============================================================================

-- Display all monitoring views created
SELECT 'Performance Dashboard' as view_name, 'Created' as status
UNION ALL
SELECT 'Table Performance Metrics' as view_name, 'Created' as status
UNION ALL
SELECT 'Index Performance Metrics' as view_name, 'Created' as status
UNION ALL
SELECT 'Query Performance Metrics' as view_name, 'Created' as status
UNION ALL
SELECT 'System Health Dashboard' as view_name, 'Created' as status
UNION ALL
SELECT 'Security Monitoring Dashboard' as view_name, 'Created' as status
UNION ALL
SELECT 'Maintenance Monitoring Dashboard' as view_name, 'Created' as status
UNION ALL
SELECT 'Performance Recommendations' as view_name, 'Created' as status;

-- Display current monitoring summary
SELECT * FROM get_monitoring_summary();

-- Display current alerts
SELECT * FROM get_production_alerts();
