-- Migration: Add Month 1 SAST Features
-- Date: 2024-01-15
-- Description: Add incremental analysis, enhanced security hotspots, and background jobs

-- 1. Add incremental analysis columns to sast_scans
ALTER TABLE sast_scans 
ADD COLUMN is_incremental BOOLEAN DEFAULT FALSE,
ADD COLUMN base_scan_id INTEGER REFERENCES sast_scans(id),
ADD COLUMN changed_files JSON,
ADD COLUMN new_files JSON,
ADD COLUMN deleted_files JSON;

-- Add index for base scan lookups
CREATE INDEX idx_sast_scans_base_scan ON sast_scans(base_scan_id);

-- 2. Create sast_file_changes table
CREATE TABLE sast_file_changes (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES sast_scans(id) ON DELETE CASCADE,
    file_path VARCHAR(500) NOT NULL,
    change_type VARCHAR(20) NOT NULL,
    old_hash VARCHAR(64),
    new_hash VARCHAR(64),
    lines_added INTEGER DEFAULT 0,
    lines_removed INTEGER DEFAULT 0,
    commit_hash VARCHAR(40),
    commit_message TEXT,
    author VARCHAR(100),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for sast_file_changes
CREATE INDEX idx_file_changes_project_scan ON sast_file_changes(project_id, scan_id);
CREATE INDEX idx_file_changes_path ON sast_file_changes(file_path);
CREATE INDEX idx_file_changes_type ON sast_file_changes(change_type);

-- 3. Create sast_background_jobs table
CREATE TABLE sast_background_jobs (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    parameters JSON,
    result JSON,
    progress FLOAT DEFAULT 0.0,
    current_step VARCHAR(100),
    total_steps INTEGER DEFAULT 0,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    scheduled_at TIMESTAMP,
    worker_id VARCHAR(100),
    worker_pid INTEGER
);

-- Create indexes for sast_background_jobs
CREATE INDEX idx_background_jobs_project_status ON sast_background_jobs(project_id, status);
CREATE INDEX idx_background_jobs_priority ON sast_background_jobs(priority);
CREATE INDEX idx_background_jobs_type ON sast_background_jobs(job_type);
CREATE INDEX idx_background_jobs_scheduled ON sast_background_jobs(scheduled_at);

-- 4. Add enhanced security hotspot columns
ALTER TABLE sast_security_hotspots 
ADD COLUMN risk_level VARCHAR(20) DEFAULT 'MEDIUM',
ADD COLUMN probability FLOAT DEFAULT 0.5,
ADD COLUMN impact FLOAT DEFAULT 0.5,
ADD COLUMN risk_score FLOAT DEFAULT 0.0,
ADD COLUMN review_priority INTEGER DEFAULT 5,
ADD COLUMN assigned_to VARCHAR(100),
ADD COLUMN assigned_at TIMESTAMP;

-- Create indexes for enhanced security hotspots
CREATE INDEX idx_security_hotspots_risk ON sast_security_hotspots(risk_level, risk_score);
CREATE INDEX idx_security_hotspots_priority ON sast_security_hotspots(review_priority);
CREATE INDEX idx_security_hotspots_assigned ON sast_security_hotspots(assigned_to);

-- 5. Create sast_hotspot_reviews table
CREATE TABLE sast_hotspot_reviews (
    id SERIAL PRIMARY KEY,
    hotspot_id INTEGER NOT NULL REFERENCES sast_security_hotspots(id) ON DELETE CASCADE,
    reviewer VARCHAR(100) NOT NULL,
    review_action VARCHAR(50) NOT NULL,
    review_status VARCHAR(20),
    review_resolution VARCHAR(20),
    comment TEXT,
    risk_assessment JSON,
    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    review_duration INTEGER
);

-- Create indexes for sast_hotspot_reviews
CREATE INDEX idx_hotspot_reviews_hotspot ON sast_hotspot_reviews(hotspot_id);
CREATE INDEX idx_hotspot_reviews_reviewer ON sast_hotspot_reviews(reviewer);
CREATE INDEX idx_hotspot_reviews_date ON sast_hotspot_reviews(review_date);

-- 6. Add comments for documentation
COMMENT ON TABLE sast_file_changes IS 'Track file changes for incremental analysis';
COMMENT ON TABLE sast_background_jobs IS 'Background jobs for long-running SAST operations';
COMMENT ON TABLE sast_hotspot_reviews IS 'Security hotspot review history and comments';

COMMENT ON COLUMN sast_scans.is_incremental IS 'Whether this scan is incremental';
COMMENT ON COLUMN sast_scans.base_scan_id IS 'Reference to the base scan for incremental analysis';
COMMENT ON COLUMN sast_scans.changed_files IS 'JSON array of changed file paths';
COMMENT ON COLUMN sast_scans.new_files IS 'JSON array of new file paths';
COMMENT ON COLUMN sast_scans.deleted_files IS 'JSON array of deleted file paths';

COMMENT ON COLUMN sast_security_hotspots.risk_level IS 'Risk level: LOW, MEDIUM, HIGH, CRITICAL';
COMMENT ON COLUMN sast_security_hotspots.probability IS 'Probability of exploitation (0.0-1.0)';
COMMENT ON COLUMN sast_security_hotspots.impact IS 'Impact if exploited (0.0-1.0)';
COMMENT ON COLUMN sast_security_hotspots.risk_score IS 'Calculated risk score';
COMMENT ON COLUMN sast_security_hotspots.review_priority IS 'Review priority (1-10, higher is more urgent)';
COMMENT ON COLUMN sast_security_hotspots.assigned_to IS 'Username of assigned reviewer';
COMMENT ON COLUMN sast_security_hotspots.assigned_at IS 'When the hotspot was assigned';

-- 7. Update existing records to have default values
UPDATE sast_security_hotspots 
SET risk_level = 'MEDIUM', 
    probability = 0.5, 
    impact = 0.5, 
    risk_score = 0.25,
    review_priority = 5
WHERE risk_level IS NULL;

-- 8. Create function to calculate risk score
CREATE OR REPLACE FUNCTION calculate_hotspot_risk_score(
    p_probability FLOAT,
    p_impact FLOAT
) RETURNS FLOAT AS $$
BEGIN
    -- Simple risk score calculation: probability * impact
    -- This can be enhanced with more sophisticated algorithms
    RETURN LEAST(p_probability * p_impact, 1.0);
END;
$$ LANGUAGE plpgsql;

-- 9. Create trigger to automatically update risk score
CREATE OR REPLACE FUNCTION update_hotspot_risk_score()
RETURNS TRIGGER AS $$
BEGIN
    NEW.risk_score = calculate_hotspot_risk_score(NEW.probability, NEW.impact);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_hotspot_risk_score
    BEFORE INSERT OR UPDATE ON sast_security_hotspots
    FOR EACH ROW
    EXECUTE FUNCTION update_hotspot_risk_score();
