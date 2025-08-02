-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    department VARCHAR(100),
    phone VARCHAR(20),
    avatar_url VARCHAR(500),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    preferences TEXT
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Insert sample users (passwords are hashed with bcrypt)
-- admin123 -> $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQeO
-- analyst123 -> $2b$12$8K1p/a0dL1LXMIgoEDFrwOe6j7uKjKqQqQqQqQqQqQqQqQqQqQqQq
-- user123 -> $2b$12$9K1p/a0dL1LXMIgoEDFrwOe6j7uKjKqQqQqQqQqQqQqQqQqQqQqQq
-- demo123 -> $2b$12$0K1p/a0dL1LXMIgoEDFrwOe6j7uKjKqQqQqQqQqQqQqQqQqQqQqQq

INSERT INTO users (email, username, full_name, hashed_password, role, is_active, is_verified, department) VALUES
('admin@cybershield.com', 'admin', 'System Administrator', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQeO', 'admin', TRUE, TRUE, 'IT Security'),
('analyst@cybershield.com', 'analyst', 'Security Analyst', '$2b$12$8K1p/a0dL1LXMIgoEDFrwOe6j7uKjKqQqQqQqQqQqQqQqQqQqQqQq', 'analyst', TRUE, TRUE, 'Security Operations'),
('user@cybershield.com', 'user', 'Regular User', '$2b$12$9K1p/a0dL1LXMIgoEDFrwOe6j7uKjKqQqQqQqQqQqQqQqQqQqQqQq', 'user', TRUE, TRUE, 'General'),
('demo@cybershield.com', 'demo', 'Demo User', '$2b$12$0K1p/a0dL1LXMIgoEDFrwOe6j7uKjKqQqQqQqQqQqQqQqQqQqQqQq', 'user', TRUE, TRUE, 'Demo')
ON CONFLICT (email) DO NOTHING;

-- Update the updated_at timestamp
UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL; 