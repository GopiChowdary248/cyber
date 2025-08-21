-- Migration: Create sast_saved_filters table
-- Date: 2024-01-15
-- Description: Create table for storing user's saved filters

-- Create the saved filters table
CREATE TABLE sast_saved_filters (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id INTEGER REFERENCES sast_projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    filter_type VARCHAR(50) NOT NULL,
    filter_criteria JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_saved_filter_user_type ON sast_saved_filters(user_id, filter_type);
CREATE INDEX idx_saved_filter_project ON sast_saved_filters(project_id);
CREATE INDEX idx_saved_filter_type ON sast_saved_filters(filter_type);

-- Add comments for documentation
COMMENT ON TABLE sast_saved_filters IS 'Stores user-defined saved filters for SAST issues, hotspots, coverage, etc.';
COMMENT ON COLUMN sast_saved_filters.filter_type IS 'Type of filter: issues, hotspots, coverage, etc.';
COMMENT ON COLUMN sast_saved_filters.filter_criteria IS 'JSON object containing the filter criteria';
COMMENT ON COLUMN sast_saved_filters.project_id IS 'Project-specific filter if not null, global filter if null';
