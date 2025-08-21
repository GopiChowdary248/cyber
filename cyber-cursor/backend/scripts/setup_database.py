#!/usr/bin/env python3
"""
Comprehensive Database Setup Script for Cyber Cursor Security Platform
Initializes PostgreSQL with all security models and tables
"""

import os
import sys
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy import create_engine, text, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

Base = declarative_base()

class DatabaseSetup:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self.metadata = MetaData()
        
    async def initialize_database(self):
        """Initialize the database connection and create all tables"""
        try:
            logger.info("🚀 Initializing Cyber Cursor Security Platform Database...")
            
            # Create database engine
            self.engine = create_engine(
                settings.DATABASE_URL,
                echo=settings.DEBUG,
                pool_size=settings.DATABASE_POOL_SIZE,
                max_overflow=settings.DATABASE_MAX_OVERFLOW,
                pool_timeout=settings.DATABASE_POOL_TIMEOUT
            )
            
            # Test connection
            with self.engine.connect() as conn:
                result = conn.execute(text("SELECT version()"))
                version = result.fetchone()[0]
                logger.info(f"✅ Connected to PostgreSQL: {version}")
            
            # Create session factory
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            
            # Create all tables
            await self.create_all_tables()
            
            # Insert initial data
            await self.insert_initial_data()
            
            logger.info("🎉 Database setup completed successfully!")
            
        except Exception as e:
            logger.error(f"❌ Database setup failed: {e}")
            raise
    
    async def create_all_tables(self):
        """Create all security-related tables"""
        try:
            logger.info("📋 Creating security module tables...")
            
            # Import all models to ensure they're registered
            from app.models import (
                auth, cloud_security, compliance, data_security, 
                devsecops, endpoint_security, iam, incident_management,
                network_security, rasp, sast, threat_intelligence,
                user_management, audit_logs, reporting, integrations,
                ai_ml, admin
            )
            
            # Create all tables
            Base.metadata.create_all(bind=self.engine)
            
            logger.info("✅ All tables created successfully")
            
        except ImportError as e:
            logger.warning(f"⚠️ Some models not found (this is normal for placeholder models): {e}")
            # Create basic tables structure
            await self.create_basic_tables()
        except Exception as e:
            logger.error(f"❌ Error creating tables: {e}")
            raise
    
    async def create_basic_tables(self):
        """Create basic table structure when models are not available"""
        try:
            logger.info("📋 Creating basic table structure...")
            
            # Basic security tables
            basic_tables = [
                """
                CREATE TABLE IF NOT EXISTS security_modules (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    description TEXT,
                    status VARCHAR(50) DEFAULT 'active',
                    features JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS dast_projects (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(255) NOT NULL,
                    url TEXT NOT NULL,
                    status VARCHAR(50) DEFAULT 'active',
                    config JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS sast_projects (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(255) NOT NULL,
                    repository_url TEXT,
                    language VARCHAR(100),
                    status VARCHAR(50) DEFAULT 'active',
                    last_scan TIMESTAMP,
                    vulnerabilities_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS security_incidents (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    severity VARCHAR(50) NOT NULL,
                    status VARCHAR(50) DEFAULT 'new',
                    assigned_to VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    type VARCHAR(50) NOT NULL,
                    value TEXT NOT NULL,
                    threat_level VARCHAR(50),
                    source VARCHAR(100),
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    username VARCHAR(100) NOT NULL UNIQUE,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    full_name VARCHAR(255),
                    role VARCHAR(100) DEFAULT 'user',
                    status VARCHAR(50) DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID REFERENCES users(id),
                    action VARCHAR(100) NOT NULL,
                    resource VARCHAR(100),
                    details JSONB,
                    ip_address INET,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                
                """
                CREATE TABLE IF NOT EXISTS compliance_frameworks (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name VARCHAR(100) NOT NULL,
                    version VARCHAR(50),
                    status VARCHAR(50) DEFAULT 'active',
                    score INTEGER DEFAULT 0,
                    last_assessment TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            ]
            
            with self.engine.connect() as conn:
                for table_sql in basic_tables:
                    conn.execute(text(table_sql))
                conn.commit()
            
            logger.info("✅ Basic tables created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error creating basic tables: {e}")
            raise
    
    async def insert_initial_data(self):
        """Insert initial data for the security platform"""
        try:
            logger.info("📝 Inserting initial data...")
            
            with self.engine.connect() as conn:
                # Insert security modules
                modules_data = [
                    {
                        'name': 'DAST',
                        'description': 'Dynamic Application Security Testing',
                        'status': 'active',
                        'features': ['Web Application Scanning', 'API Security Testing', 'Penetration Testing']
                    },
                    {
                        'name': 'SAST',
                        'description': 'Static Application Security Testing',
                        'status': 'active',
                        'features': ['Source Code Analysis', 'Vulnerability Detection', 'Code Quality Metrics']
                    },
                    {
                        'name': 'RASP',
                        'description': 'Runtime Application Self-Protection',
                        'status': 'active',
                        'features': ['Runtime Protection', 'Behavior Monitoring', 'Attack Prevention']
                    },
                    {
                        'name': 'Cloud Security',
                        'description': 'Multi-cloud Security Management',
                        'status': 'active',
                        'features': ['AWS Security', 'Azure Security', 'GCP Security', 'Kubernetes Security']
                    },
                    {
                        'name': 'Endpoint Security',
                        'description': 'Device and Endpoint Protection',
                        'status': 'active',
                        'features': ['Device Control', 'Threat Detection', 'Response Automation']
                    },
                    {
                        'name': 'Network Security',
                        'description': 'Infrastructure Security',
                        'status': 'active',
                        'features': ['Traffic Analysis', 'Firewall Management', 'IDS/IPS']
                    },
                    {
                        'name': 'IAM',
                        'description': 'Identity and Access Management',
                        'status': 'active',
                        'features': ['User Management', 'Role-based Access Control', 'Multi-factor Authentication']
                    },
                    {
                        'name': 'Data Security',
                        'description': 'Data Protection and Privacy',
                        'status': 'active',
                        'features': ['Data Encryption', 'Data Loss Prevention', 'Privacy Management']
                    },
                    {
                        'name': 'Incident Management',
                        'description': 'Security Incident Response',
                        'status': 'active',
                        'features': ['Incident Detection', 'Response Automation', 'Remediation Tracking']
                    },
                    {
                        'name': 'Threat Intelligence',
                        'description': 'Threat Information and Analysis',
                        'status': 'active',
                        'features': ['IOC Management', 'Threat Feeds', 'Analysis Tools']
                    },
                    {
                        'name': 'Compliance',
                        'description': 'Regulatory Compliance Management',
                        'status': 'active',
                        'features': ['ISO27001', 'SOC2', 'PCI-DSS', 'GDPR', 'HIPAA', 'NIST', 'OWASP']
                    },
                    {
                        'name': 'DevSecOps',
                        'description': 'DevOps Security Integration',
                        'status': 'active',
                        'features': ['CI/CD Security', 'Container Security', 'Infrastructure as Code Security']
                    },
                    {
                        'name': 'AI/ML',
                        'description': 'Artificial Intelligence and Machine Learning',
                        'status': 'active',
                        'features': ['Anomaly Detection', 'Predictive Analytics', 'Threat Prediction']
                    },
                    {
                        'name': 'Admin',
                        'description': 'System Administration',
                        'status': 'active',
                        'features': ['System Monitoring', 'Configuration Management', 'Maintenance']
                    },
                    {
                        'name': 'User Management',
                        'description': 'User Account Management',
                        'status': 'active',
                        'features': ['User Registration', 'Profile Management', 'Access Control']
                    },
                    {
                        'name': 'Audit & Logging',
                        'description': 'Security Auditing and Logging',
                        'status': 'active',
                        'features': ['Activity Logging', 'Security Events', 'Compliance Auditing']
                    },
                    {
                        'name': 'Reporting & Analytics',
                        'description': 'Security Reports and Analytics',
                        'status': 'active',
                        'features': ['Security Reports', 'Compliance Reports', 'Analytics Dashboard']
                    },
                    {
                        'name': 'Integrations',
                        'description': 'Third-party Tool Integration',
                        'status': 'active',
                        'features': ['SIEM Integration', 'Ticketing Systems', 'Cloud Providers']
                    }
                ]
                
                for module in modules_data:
                    conn.execute(text("""
                        INSERT INTO security_modules (name, description, status, features)
                        VALUES (:name, :description, :status, :features)
                        ON CONFLICT (name) DO UPDATE SET
                        description = EXCLUDED.description,
                        status = EXCLUDED.status,
                        features = EXCLUDED.features,
                        updated_at = CURRENT_TIMESTAMP
                    """), module)
                
                # Insert default admin user
                conn.execute(text("""
                    INSERT INTO users (username, email, full_name, role, status)
                    VALUES ('admin', 'admin@cybercursor.com', 'System Administrator', 'admin', 'active')
                    ON CONFLICT (username) DO NOTHING
                """))
                
                # Insert default compliance frameworks
                frameworks_data = [
                    {'name': 'ISO27001', 'version': '2022', 'status': 'active'},
                    {'name': 'SOC2', 'version': '2017', 'status': 'active'},
                    {'name': 'PCI-DSS', 'version': '4.0', 'status': 'active'},
                    {'name': 'GDPR', 'version': '2018', 'status': 'active'},
                    {'name': 'HIPAA', 'version': '1996', 'status': 'active'},
                    {'name': 'NIST', 'version': '2.0', 'status': 'active'},
                    {'name': 'OWASP', 'version': '2021', 'status': 'active'}
                ]
                
                for framework in frameworks_data:
                    conn.execute(text("""
                        INSERT INTO compliance_frameworks (name, version, status)
                        VALUES (:name, :version, :status)
                        ON CONFLICT (name) DO UPDATE SET
                        version = EXCLUDED.version,
                        status = EXCLUDED.status,
                        updated_at = CURRENT_TIMESTAMP
                    """), framework)
                
                conn.commit()
            
            logger.info("✅ Initial data inserted successfully")
            
        except Exception as e:
            logger.error(f"❌ Error inserting initial data: {e}")
            raise
    
    async def verify_database_setup(self):
        """Verify that the database setup is correct"""
        try:
            logger.info("🔍 Verifying database setup...")
            
            with self.engine.connect() as conn:
                # Check if tables exist
                result = conn.execute(text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    ORDER BY table_name
                """))
                
                tables = [row[0] for row in result.fetchall()]
                logger.info(f"📋 Found {len(tables)} tables: {', '.join(tables)}")
                
                # Check security modules
                result = conn.execute(text("SELECT COUNT(*) FROM security_modules"))
                module_count = result.fetchone()[0]
                logger.info(f"🔒 Found {module_count} security modules")
                
                # Check users
                result = conn.execute(text("SELECT COUNT(*) FROM users"))
                user_count = result.fetchone()[0]
                logger.info(f"👥 Found {user_count} users")
                
                # Check compliance frameworks
                result = conn.execute(text("SELECT COUNT(*) FROM compliance_frameworks"))
                framework_count = result.fetchone()[0]
                logger.info(f"📊 Found {framework_count} compliance frameworks")
            
            logger.info("✅ Database verification completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Database verification failed: {e}")
            return False
    
    async def cleanup(self):
        """Clean up database connections"""
        if self.engine:
            self.engine.dispose()

async def main():
    """Main function to run the database setup"""
    db_setup = DatabaseSetup()
    
    try:
        await db_setup.initialize_database()
        await db_setup.verify_database_setup()
        
        logger.info("🎉 Cyber Cursor Security Platform database is ready!")
        logger.info("📊 You can now start the backend server and access the platform")
        
    except Exception as e:
        logger.error(f"💥 Database setup failed: {e}")
        sys.exit(1)
    
    finally:
        await db_setup.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
