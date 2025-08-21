#!/usr/bin/env python3
"""
DAST System Setup Script

This script initializes the DAST (Dynamic Application Security Testing) system
with sample data, default configurations, and initial setup.

Usage:
    python setup_dast_system.py [--env production|development]
"""

import os
import sys
import asyncio
import logging
from datetime import datetime
from uuid import uuid4
from typing import Dict, Any

# Add the parent directory to the path to import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import get_db, engine
from app.models.dast_models import (
    DASTProject, DASTScanProfile, DASTProjectSettings,
    DASTUserPermission
)
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DASTSystemSetup:
    """DAST System Setup and Initialization"""
    
    def __init__(self, environment: str = "development"):
        self.environment = environment
        self.db = next(get_db())
        
    async def setup_database(self):
        """Create database tables if they don't exist"""
        try:
            logger.info("Setting up DAST database tables...")
            
            # Import all models to ensure they are registered
            from app.models.dast_models import Base
            
            # Create tables
            Base.metadata.create_all(bind=engine)
            logger.info("✅ Database tables created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error setting up database: {e}")
            raise
    
    async def create_sample_projects(self):
        """Create sample DAST projects"""
        try:
            logger.info("Creating sample DAST projects...")
            
            # Sample project 1: Web Application Testing
            web_app_project = DASTProject(
                id=uuid4(),
                name="Web Application Security Assessment",
                description="Comprehensive security testing for the main web application",
                target_urls=["https://example.com", "https://api.example.com"],
                scope_config={
                    "include_patterns": ["*.example.com"],
                    "exclude_patterns": ["*.admin.example.com"],
                    "allowed_ports": [80, 443, 8080, 8443],
                    "max_depth": 5
                },
                status="active",
                created_by=uuid4()  # This should be an actual user ID
            )
            
            # Sample project 2: API Security Testing
            api_project = DASTProject(
                id=uuid4(),
                name="API Security Testing",
                description="Security assessment for REST and GraphQL APIs",
                target_urls=["https://api.example.com", "https://graphql.example.com"],
                scope_config={
                    "include_patterns": ["*.api.example.com"],
                    "exclude_patterns": ["*.internal.example.com"],
                    "allowed_ports": [443, 8443],
                    "max_depth": 3
                },
                status="active",
                created_by=uuid4()  # This should be an actual user ID
            )
            
            # Sample project 3: Mobile App Backend
            mobile_project = DASTProject(
                id=uuid4(),
                name="Mobile App Backend Security",
                description="Security testing for mobile application backend services",
                target_urls=["https://mobile.example.com", "https://push.example.com"],
                scope_config={
                    "include_patterns": ["*.mobile.example.com"],
                    "exclude_patterns": ["*.analytics.example.com"],
                    "allowed_ports": [443, 8443],
                    "max_depth": 4
                },
                status="active",
                created_by=uuid4()  # This should be an actual user ID
            )
            
            # Add projects to database
            self.db.add(web_app_project)
            self.db.add(api_project)
            self.db.add(mobile_project)
            self.db.commit()
            
            logger.info("✅ Sample projects created successfully")
            
            return [web_app_project, api_project, mobile_project]
            
        except Exception as e:
            logger.error(f"❌ Error creating sample projects: {e}")
            self.db.rollback()
            raise
    
    async def create_scan_profiles(self, projects):
        """Create default scan profiles for projects"""
        try:
            logger.info("Creating default scan profiles...")
            
            for project in projects:
                # Quick Scan Profile
                quick_profile = DASTScanProfile(
                    id=uuid4(),
                    project_id=project.id,
                    name="Quick Security Scan",
                    description="Fast scan with basic security checks",
                    modules=["sql_injection", "xss", "csrf", "open_redirect"],
                    settings={
                        "timeout": 30,
                        "max_requests": 1000,
                        "follow_redirects": True,
                        "verify_ssl": True
                    },
                    is_default=True,
                    created_by=project.created_by
                )
                
                # Full Scan Profile
                full_profile = DASTScanProfile(
                    id=uuid4(),
                    project_id=project.id,
                    name="Comprehensive Security Scan",
                    description="Thorough security assessment with all modules",
                    modules=[
                        "sql_injection", "xss", "csrf", "open_redirect",
                        "file_inclusion", "command_injection", "xxe",
                        "ssrf", "deserialization", "authentication_bypass"
                    ],
                    settings={
                        "timeout": 120,
                        "max_requests": 10000,
                        "follow_redirects": True,
                        "verify_ssl": True,
                        "aggressive_mode": True
                    },
                    is_default=False,
                    created_by=project.created_by
                )
                
                # API Scan Profile
                api_profile = DASTScanProfile(
                    id=uuid4(),
                    project_id=project.id,
                    name="API Security Scan",
                    description="Specialized scan for API endpoints",
                    modules=[
                        "sql_injection", "xss", "authentication_bypass",
                        "rate_limiting", "input_validation", "authorization"
                    ],
                    settings={
                        "timeout": 60,
                        "max_requests": 5000,
                        "follow_redirects": False,
                        "verify_ssl": True,
                        "api_mode": True
                    },
                    is_default=False,
                    created_by=project.created_by
                )
                
                # Add profiles to database
                self.db.add(quick_profile)
                self.db.add(full_profile)
                self.db.add(api_profile)
            
            self.db.commit()
            logger.info("✅ Scan profiles created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error creating scan profiles: {e}")
            self.db.rollback()
            raise
    
    async def create_project_settings(self, projects):
        """Create default project settings"""
        try:
            logger.info("Creating default project settings...")
            
            for project in projects:
                # Default proxy settings
                proxy_settings = {
                    "host": "127.0.0.1",
                    "port": 8080,
                    "intercept_requests": True,
                    "intercept_responses": False,
                    "auto_save": True,
                    "max_history": 10000
                }
                
                # Default scanner settings
                scanner_settings = {
                    "max_concurrent_scans": 3,
                    "default_timeout": 60,
                    "retry_failed_requests": True,
                    "max_retries": 3
                }
                
                # Default crawler settings
                crawler_settings = {
                    "max_depth": 5,
                    "max_pages": 1000,
                    "delay_between_requests": 1.0,
                    "follow_robots_txt": True,
                    "respect_rate_limits": True
                }
                
                # Default notification settings
                notification_settings = {
                    "email_notifications": False,
                    "webhook_notifications": False,
                    "scan_completion_alerts": True,
                    "critical_issue_alerts": True
                }
                
                # Default security settings
                security_settings = {
                    "require_authentication": True,
                    "session_timeout": 3600,
                    "max_login_attempts": 5,
                    "password_policy": "strong"
                }
                
                # Create project settings
                project_settings = DASTProjectSettings(
                    id=uuid4(),
                    project_id=project.id,
                    proxy_settings=proxy_settings,
                    scanner_settings=scanner_settings,
                    crawler_settings=crawler_settings,
                    notification_settings=notification_settings,
                    security_settings=security_settings
                )
                
                self.db.add(project_settings)
            
            self.db.commit()
            logger.info("✅ Project settings created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error creating project settings: {e}")
            self.db.rollback()
            raise
    
    async def create_sample_rules(self, projects):
        """Create sample match/replace rules"""
        try:
            logger.info("Creating sample match/replace rules...")
            
            from app.models.dast_models import DASTMatchReplaceRule
            
            # Sample rules for each project
            sample_rules = [
                {
                    "name": "Remove Authorization Header",
                    "description": "Remove Authorization header for testing unauthenticated access",
                    "match_pattern": "Authorization: Bearer .*",
                    "replace_pattern": "",
                    "match_type": "regex",
                    "apply_to": "request",
                    "enabled": True,
                    "priority": 1
                },
                {
                    "name": "Add Test User Agent",
                    "description": "Add custom user agent for testing",
                    "match_pattern": "User-Agent: .*",
                    "replace_pattern": "User-Agent: DAST-Test-Scanner/1.0",
                    "match_type": "regex",
                    "apply_to": "request",
                    "enabled": True,
                    "priority": 2
                },
                {
                    "name": "Remove CSRF Token",
                    "description": "Remove CSRF tokens to test CSRF protection",
                    "match_pattern": "csrf_token=[^&]*",
                    "replace_pattern": "",
                    "match_type": "regex",
                    "apply_to": "request",
                    "enabled": False,
                    "priority": 3
                }
            ]
            
            for project in projects:
                for rule_data in sample_rules:
                    rule = DASTMatchReplaceRule(
                        id=uuid4(),
                        project_id=project.id,
                        name=rule_data["name"],
                        description=rule_data["description"],
                        match_pattern=rule_data["match_pattern"],
                        replace_pattern=rule_data["replace_pattern"],
                        match_type=rule_data["match_type"],
                        apply_to=rule_data["apply_to"],
                        enabled=rule_data["enabled"],
                        priority=rule_data["priority"],
                        created_by=project.created_by
                    )
                    
                    self.db.add(rule)
            
            self.db.commit()
            logger.info("✅ Sample rules created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error creating sample rules: {e}")
            self.db.rollback()
            raise
    
    async def create_sample_data(self):
        """Create sample HTTP entries and crawl results"""
        try:
            logger.info("Creating sample data...")
            
            from app.models.dast_models import DASTHttpEntry, DASTCrawlResult
            
            # Get first project for sample data
            project = self.db.query(DASTProject).first()
            if not project:
                logger.warning("No projects found, skipping sample data creation")
                return
            
            # Sample HTTP entries
            sample_http_entries = [
                {
                    "method": "GET",
                    "url": "https://example.com/",
                    "host": "example.com",
                    "port": 443,
                    "protocol": "https",
                    "status_code": 200,
                    "content_type": "text/html",
                    "request_size": 500,
                    "response_size": 15000,
                    "duration": 150
                },
                {
                    "method": "POST",
                    "url": "https://example.com/login",
                    "host": "example.com",
                    "port": 443,
                    "protocol": "https",
                    "status_code": 302,
                    "content_type": "text/html",
                    "request_size": 800,
                    "response_size": 200,
                    "duration": 200
                },
                {
                    "method": "GET",
                    "url": "https://example.com/api/users",
                    "host": "example.com",
                    "port": 443,
                    "protocol": "https",
                    "status_code": 401,
                    "content_type": "application/json",
                    "request_size": 300,
                    "response_size": 100,
                    "duration": 100
                }
            ]
            
            for entry_data in sample_http_entries:
                entry = DASTHttpEntry(
                    id=uuid4(),
                    project_id=project.id,
                    method=entry_data["method"],
                    url=entry_data["url"],
                    host=entry_data["host"],
                    port=entry_data["port"],
                    protocol=entry_data["protocol"],
                    request_headers={"Host": entry_data["host"]},
                    response_headers={"Content-Type": entry_data["content_type"]},
                    status_code=entry_data["status_code"],
                    content_type=entry_data["content_type"],
                    request_size=entry_data["request_size"],
                    response_size=entry_data["response_size"],
                    duration=entry_data["duration"],
                    tags=["sample", "demo"]
                )
                
                self.db.add(entry)
            
            # Sample crawl results
            sample_crawl_results = [
                {
                    "url": "https://example.com/",
                    "method": "GET",
                    "status_code": 200,
                    "content_type": "text/html",
                    "title": "Example Domain",
                    "depth": 0,
                    "in_scope": True
                },
                {
                    "url": "https://example.com/login",
                    "method": "GET",
                    "status_code": 200,
                    "content_type": "text/html",
                    "title": "Login",
                    "depth": 1,
                    "parent_url": "https://example.com/",
                    "in_scope": True
                },
                {
                    "url": "https://example.com/api/users",
                    "method": "GET",
                    "status_code": 401,
                    "content_type": "application/json",
                    "title": None,
                    "depth": 1,
                    "parent_url": "https://example.com/",
                    "in_scope": True
                }
            ]
            
            for result_data in sample_crawl_results:
                result = DASTCrawlResult(
                    id=uuid4(),
                    project_id=project.id,
                    url=result_data["url"],
                    method=result_data["method"],
                    status_code=result_data["status_code"],
                    content_type=result_data["content_type"],
                    title=result_data["title"],
                    depth=result_data["depth"],
                    parent_url=result_data.get("parent_url"),
                    in_scope=result_data["in_scope"],
                    tags=["sample", "demo"]
                )
                
                self.db.add(result)
            
            self.db.commit()
            logger.info("✅ Sample data created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error creating sample data: {e}")
            self.db.rollback()
            raise
    
    async def setup_websocket_manager(self):
        """Initialize WebSocket manager"""
        try:
            logger.info("Setting up WebSocket manager...")
            
            from app.core.websocket_manager import websocket_manager
            
            # Start cleanup task
            import asyncio
            asyncio.create_task(websocket_manager.start_cleanup_task())
            
            logger.info("✅ WebSocket manager initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Error setting up WebSocket manager: {e}")
            raise
    
    async def run_setup(self):
        """Run complete DAST system setup"""
        try:
            logger.info("🚀 Starting DAST System Setup...")
            logger.info(f"Environment: {self.environment}")
            
            # Setup database
            await self.setup_database()
            
            # Create sample projects
            projects = await self.create_sample_projects()
            
            # Create scan profiles
            await self.create_scan_profiles(projects)
            
            # Create project settings
            await self.create_project_settings(projects)
            
            # Create sample rules
            await self.create_sample_rules(projects)
            
            # Create sample data
            await self.create_sample_data()
            
            # Setup WebSocket manager
            await self.setup_websocket_manager()
            
            logger.info("🎉 DAST System Setup Completed Successfully!")
            
            # Print summary
            self.print_setup_summary()
            
        except Exception as e:
            logger.error(f"❌ Setup failed: {e}")
            raise
        finally:
            self.db.close()
    
    def print_setup_summary(self):
        """Print setup summary"""
        try:
            logger.info("\n" + "="*50)
            logger.info("DAST SYSTEM SETUP SUMMARY")
            logger.info("="*50)
            
            # Count created items
            project_count = self.db.query(DASTProject).count()
            profile_count = self.db.query(DASTScanProfile).count()
            
            logger.info(f"✅ Projects created: {project_count}")
            logger.info(f"✅ Scan profiles created: {profile_count}")
            logger.info("✅ Project settings configured")
            logger.info("✅ Sample rules created")
            logger.info("✅ Sample data populated")
            logger.info("✅ WebSocket manager initialized")
            
            logger.info("\n🔧 Next Steps:")
            logger.info("1. Configure your database connection")
            logger.info("2. Set up user authentication")
            logger.info("3. Configure proxy settings")
            logger.info("4. Start the DAST application")
            
            logger.info("\n📚 Documentation:")
            logger.info("- Check README.md for usage instructions")
            logger.info("- Review API endpoints in dast_endpoints.py")
            logger.info("- Configure scan profiles as needed")
            
            logger.info("="*50)
            
        except Exception as e:
            logger.error(f"Error printing setup summary: {e}")


async def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DAST System Setup")
    parser.add_argument(
        "--env", 
        choices=["production", "development"], 
        default="development",
        help="Environment to setup (default: development)"
    )
    
    args = parser.parse_args()
    
    try:
        setup = DASTSystemSetup(args.env)
        await setup.run_setup()
        
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
