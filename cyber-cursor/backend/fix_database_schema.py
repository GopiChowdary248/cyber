#!/usr/bin/env python3
"""
Script to fix the database schema by creating the correct tables
that match the SQLAlchemy models for SQLite
"""

import sqlite3
import os

def fix_database_schema():
    """Fix the database schema by creating the correct tables"""
    
    # Remove existing database file
    if os.path.exists('cybershield.db'):
        print("Removing existing database file...")
        os.remove('cybershield.db')
    
    # Create new database connection
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    
    print("Creating database schema...")
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(100) UNIQUE NOT NULL,
            full_name VARCHAR(255),
            hashed_password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'viewer',
            is_active BOOLEAN DEFAULT 1,
            is_verified BOOLEAN DEFAULT 0,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create sast_projects table
    cursor.execute('''
        CREATE TABLE sast_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255) NOT NULL,
            key VARCHAR(255) UNIQUE NOT NULL,
            language VARCHAR(50) NOT NULL,
            repository_url VARCHAR(500),
            branch VARCHAR(100) DEFAULT 'main',
            quality_gate VARCHAR(20) DEFAULT 'PASSED',
            maintainability_rating VARCHAR(1) DEFAULT 'A',
            security_rating VARCHAR(1) DEFAULT 'A',
            reliability_rating VARCHAR(1) DEFAULT 'A',
            vulnerability_count INTEGER DEFAULT 0,
            bug_count INTEGER DEFAULT 0,
            code_smell_count INTEGER DEFAULT 0,
            security_hotspot_count INTEGER DEFAULT 0,
            lines_of_code INTEGER DEFAULT 0,
            duplicated_lines INTEGER DEFAULT 0,
            duplicated_blocks INTEGER DEFAULT 0,
            coverage FLOAT DEFAULT 0.0,
            uncovered_lines INTEGER DEFAULT 0,
            uncovered_conditions INTEGER DEFAULT 0,
            technical_debt INTEGER DEFAULT 0,
            debt_ratio FLOAT DEFAULT 0.0,
            created_by INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_analysis DATETIME,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Create sast_scans table
    cursor.execute('''
        CREATE TABLE sast_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            scan_type VARCHAR(50) NOT NULL,
            branch VARCHAR(100) NOT NULL,
            status VARCHAR(20) DEFAULT 'PENDING',
            progress FLOAT DEFAULT 0.0,
            total_files INTEGER DEFAULT 0,
            scanned_files INTEGER DEFAULT 0,
            issues_found INTEGER DEFAULT 0,
            vulnerabilities_found INTEGER DEFAULT 0,
            bugs_found INTEGER DEFAULT 0,
            code_smells_found INTEGER DEFAULT 0,
            security_hotspots_found INTEGER DEFAULT 0,
            lines_of_code INTEGER DEFAULT 0,
            lines_of_comment INTEGER DEFAULT 0,
            duplicated_lines INTEGER DEFAULT 0,
            duplicated_blocks INTEGER DEFAULT 0,
            coverage FLOAT DEFAULT 0.0,
            uncovered_lines INTEGER DEFAULT 0,
            uncovered_conditions INTEGER DEFAULT 0,
            technical_debt INTEGER DEFAULT 0,
            debt_ratio FLOAT DEFAULT 0.0,
            started_by INTEGER NOT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            duration INTEGER,
            error_message TEXT,
            FOREIGN KEY (project_id) REFERENCES sast_projects(id),
            FOREIGN KEY (started_by) REFERENCES users(id)
        )
    ''')
    
    # Create sast_issues table
    cursor.execute('''
        CREATE TABLE sast_issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            scan_id INTEGER,
            rule_id VARCHAR(255) NOT NULL,
            rule_name VARCHAR(255) NOT NULL,
            rule_category VARCHAR(100),
            message TEXT NOT NULL,
            description TEXT,
            file_path VARCHAR(500) NOT NULL,
            line_number INTEGER NOT NULL,
            start_line INTEGER,
            end_line INTEGER,
            start_column INTEGER,
            end_column INTEGER,
            severity VARCHAR(20) NOT NULL,
            type VARCHAR(20) NOT NULL,
            status VARCHAR(20) DEFAULT 'OPEN',
            resolution VARCHAR(20) DEFAULT 'FALSE_POSITIVE',
            assignee VARCHAR(100),
            author VARCHAR(100),
            effort INTEGER DEFAULT 0,
            debt INTEGER DEFAULT 0,
            cwe_id VARCHAR(20),
            cvss_score FLOAT,
            owasp_category VARCHAR(100),
            tags TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES sast_projects(id),
            FOREIGN KEY (scan_id) REFERENCES sast_scans(id)
        )
    ''')
    
    # Create sast_security_hotspots table
    cursor.execute('''
        CREATE TABLE sast_security_hotspots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            scan_id INTEGER,
            rule_id VARCHAR(255) NOT NULL,
            rule_name VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            description TEXT,
            file_path VARCHAR(500) NOT NULL,
            line_number INTEGER NOT NULL,
            start_line INTEGER,
            end_line INTEGER,
            status VARCHAR(20) DEFAULT 'TO_REVIEW',
            resolution VARCHAR(20),
            cwe_id VARCHAR(20),
            cvss_score FLOAT,
            owasp_category VARCHAR(100),
            tags TEXT,
            reviewed_by VARCHAR(100),
            reviewed_at DATETIME,
            review_comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES sast_projects(id),
            FOREIGN KEY (scan_id) REFERENCES sast_scans(id)
        )
    ''')
    
    # Create sast_code_coverage table
    cursor.execute('''
        CREATE TABLE sast_code_coverage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            scan_id INTEGER,
            file_path VARCHAR(500) NOT NULL,
            lines_to_cover INTEGER DEFAULT 0,
            uncovered_lines INTEGER DEFAULT 0,
            covered_lines INTEGER DEFAULT 0,
            line_coverage FLOAT DEFAULT 0.0,
            conditions_to_cover INTEGER DEFAULT 0,
            uncovered_conditions INTEGER DEFAULT 0,
            covered_conditions INTEGER DEFAULT 0,
            branch_coverage FLOAT DEFAULT 0.0,
            overall_coverage FLOAT DEFAULT 0.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES sast_projects(id),
            FOREIGN KEY (scan_id) REFERENCES sast_scans(id)
        )
    ''')
    
    # Create sast_duplications table
    cursor.execute('''
        CREATE TABLE sast_duplications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            file_path VARCHAR(500) NOT NULL,
            duplicated_lines INTEGER NOT NULL,
            duplicated_blocks INTEGER NOT NULL,
            duplication_density FLOAT NOT NULL,
            language VARCHAR(50) NOT NULL,
            last_modified DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES sast_projects(id),
            FOREIGN KEY (scan_id) REFERENCES sast_scans(id)
        )
    ''')
    
    # Create sast_quality_gates table
    cursor.execute('''
        CREATE TABLE sast_quality_gates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            max_blocker_issues INTEGER DEFAULT 0,
            max_critical_issues INTEGER DEFAULT 5,
            max_major_issues INTEGER DEFAULT 20,
            max_minor_issues INTEGER DEFAULT 100,
            max_info_issues INTEGER DEFAULT 500,
            min_coverage FLOAT DEFAULT 80.0,
            min_branch_coverage FLOAT DEFAULT 80.0,
            max_debt_ratio FLOAT DEFAULT 5.0,
            max_technical_debt INTEGER DEFAULT 1440,
            max_duplicated_lines INTEGER DEFAULT 1000,
            max_duplicated_blocks INTEGER DEFAULT 100,
            min_maintainability_rating VARCHAR(1) DEFAULT 'C',
            min_security_rating VARCHAR(1) DEFAULT 'C',
            min_reliability_rating VARCHAR(1) DEFAULT 'C',
            status VARCHAR(20) DEFAULT 'PASSED',
            last_evaluation DATETIME,
            evaluation_results TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES sast_projects(id)
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX idx_sast_projects_key ON sast_projects(key)')
    cursor.execute('CREATE INDEX idx_sast_projects_language ON sast_projects(language)')
    cursor.execute('CREATE INDEX idx_sast_scans_project_id ON sast_scans(project_id)')
    cursor.execute('CREATE INDEX idx_sast_issues_project_id ON sast_issues(project_id)')
    cursor.execute('CREATE INDEX idx_sast_issues_severity ON sast_issues(severity)')
    cursor.execute('CREATE INDEX idx_users_email ON users(email)')
    cursor.execute('CREATE INDEX idx_users_username ON users(username)')
    
    # Insert a default user for testing
    cursor.execute('''
        INSERT INTO users (email, username, hashed_password, role, is_active, is_verified)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ('admin@cybershield.com', 'admin', 'hashed_password_placeholder', 'admin', 1, 1))
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print("Database schema created successfully!")
    print("Default admin user created:")
    print("  Email: admin@cybershield.com")
    print("  Username: admin")
    print("  Role: admin")

if __name__ == "__main__":
    fix_database_schema()
