-- Migration: Add detailed_coverage column to sast_code_coverage table
-- Date: 2024-01-15
-- Description: Add JSON column to store detailed line-by-line coverage data

-- Add detailed_coverage column
ALTER TABLE sast_code_coverage 
ADD COLUMN detailed_coverage JSON;

-- Add index for better performance on JSON queries
CREATE INDEX idx_sast_code_coverage_detailed 
ON sast_code_coverage USING GIN (detailed_coverage);

-- Update existing records to have empty detailed coverage
UPDATE sast_code_coverage 
SET detailed_coverage = '{}'::json 
WHERE detailed_coverage IS NULL;

-- Make the column NOT NULL after setting default values
ALTER TABLE sast_code_coverage 
ALTER COLUMN detailed_coverage SET NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN sast_code_coverage.detailed_coverage IS 'JSON object storing detailed line-by-line coverage data with format: {line_number: {covered: boolean, coverage: number, hits: number}}';
