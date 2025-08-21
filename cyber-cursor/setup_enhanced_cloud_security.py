#!/usr/bin/env python3
"""
Enhanced Cloud Security Database Setup Script
This script creates all the necessary database tables for enhanced cloud security features
"""

import os
import sys
import sqlite3
from pathlib import Path

def setup_sqlite_database():
    """Set up SQLite database with enhanced cloud security tables"""
    
    print("Setting up Enhanced Cloud Security Database Tables...")
    
    # Database path
    db_path = Path("backend/cybershield.db")
    
    if not db_path.exists():
        print(f"Database not found at {db_path}")
        print("Creating new database...")
        db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Connect to database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("✓ Database connection successful")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False
    
    # SQL statements for creating tables
    tables_sql = [
        # Container Security Tables
        """
        CREATE TABLE IF NOT EXISTS container_images (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            image_name TEXT NOT NULL,
            image_tag TEXT,
            image_digest TEXT,
            registry TEXT,
            architecture TEXT,
            os_type TEXT,
            created_date TEXT,
            last_scan_date TEXT,
            vulnerability_count INTEGER DEFAULT 0,
            critical_vulnerabilities INTEGER DEFAULT 0,
            high_vulnerabilities INTEGER DEFAULT 0,
            security_score REAL DEFAULT 0.0,
            scan_status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS container_vulnerabilities (
            id TEXT PRIMARY KEY,
            image_id TEXT NOT NULL,
            cve_id TEXT,
            package_name TEXT,
            package_version TEXT,
            fixed_version TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL,
            description TEXT,
            affected_layer TEXT,
            remediation TEXT,
            discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS container_layers (
            id TEXT PRIMARY KEY,
            image_id TEXT NOT NULL,
            layer_index INTEGER NOT NULL,
            layer_digest TEXT,
            layer_size INTEGER,
            created_by TEXT,
            commands TEXT DEFAULT '[]',
            packages TEXT DEFAULT '[]',
            security_issues TEXT DEFAULT '[]'
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS container_runtimes (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            runtime_type TEXT NOT NULL,
            version TEXT,
            security_features TEXT DEFAULT '{}',
            runtime_config TEXT DEFAULT '{}',
            last_scan_date TEXT,
            security_score REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS container_instances (
            id TEXT PRIMARY KEY,
            runtime_id TEXT NOT NULL,
            container_id TEXT NOT NULL,
            container_name TEXT,
            image_id TEXT,
            status TEXT,
            created_at TEXT,
            security_context TEXT DEFAULT '{}',
            network_config TEXT DEFAULT '{}',
            volume_mounts TEXT DEFAULT '[]',
            environment_vars TEXT DEFAULT '[]',
            security_score REAL DEFAULT 0.0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # Serverless Security Tables
        """
        CREATE TABLE IF NOT EXISTS serverless_functions (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            function_name TEXT NOT NULL,
            function_arn TEXT,
            runtime TEXT,
            handler TEXT,
            timeout INTEGER,
            memory_size INTEGER,
            code_size INTEGER,
            last_modified TEXT,
            environment_vars TEXT DEFAULT '[]',
            tags TEXT DEFAULT '{}',
            security_score REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS serverless_permissions (
            id TEXT PRIMARY KEY,
            function_id TEXT NOT NULL,
            permission_type TEXT NOT NULL,
            resource_arn TEXT,
            actions TEXT DEFAULT '[]',
            conditions TEXT DEFAULT '{}',
            risk_level TEXT,
            last_updated TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS serverless_vulnerabilities (
            id TEXT PRIMARY KEY,
            function_id TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            affected_component TEXT,
            remediation TEXT,
            discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # Kubernetes Security Tables
        """
        CREATE TABLE IF NOT EXISTS kubernetes_clusters (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            cluster_name TEXT NOT NULL,
            cluster_version TEXT,
            provider TEXT,
            region TEXT,
            node_count INTEGER,
            pod_count INTEGER,
            namespace_count INTEGER,
            security_score REAL DEFAULT 0.0,
            last_scan_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS kubernetes_namespaces (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            namespace_name TEXT NOT NULL,
            labels TEXT DEFAULT '{}',
            annotations TEXT DEFAULT '{}',
            status TEXT,
            security_policies TEXT DEFAULT '[]',
            risk_score REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS kubernetes_resources (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            namespace_id TEXT,
            resource_type TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            resource_version TEXT,
            labels TEXT DEFAULT '{}',
            annotations TEXT DEFAULT '{}',
            spec TEXT DEFAULT '{}',
            status TEXT DEFAULT '{}',
            security_context TEXT DEFAULT '{}',
            security_score REAL DEFAULT 0.0,
            last_updated TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS kubernetes_security_issues (
            id TEXT PRIMARY KEY,
            resource_id TEXT NOT NULL,
            issue_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            recommendation TEXT,
            compliance_framework TEXT,
            control_id TEXT,
            discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # Pod Security Policy Tables
        """
        CREATE TABLE IF NOT EXISTS pod_security_policies (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            policy_version TEXT,
            privileged INTEGER DEFAULT 0,
            allow_privilege_escalation INTEGER DEFAULT 0,
            run_as_user TEXT DEFAULT '{}',
            run_as_group TEXT DEFAULT '{}',
            fs_group TEXT DEFAULT '{}',
            volumes TEXT DEFAULT '[]',
            host_network INTEGER DEFAULT 0,
            host_pid INTEGER DEFAULT 0,
            host_ipc INTEGER DEFAULT 0,
            se_linux TEXT DEFAULT '{}',
            supplemental_groups TEXT DEFAULT '{}',
            read_only_root_filesystem INTEGER DEFAULT 0,
            default_allow_privilege_escalation INTEGER DEFAULT 0,
            allowed_host_paths TEXT DEFAULT '[]',
            allowed_flex_volumes TEXT DEFAULT '[]',
            allowed_csi_drivers TEXT DEFAULT '[]',
            allowed_unsafe_sysctls TEXT DEFAULT '[]',
            forbidden_sysctls TEXT DEFAULT '[]',
            allowed_proc_mount_types TEXT DEFAULT '[]',
            run_as_user_options TEXT DEFAULT '{}',
            run_as_group_options TEXT DEFAULT '{}',
            fs_group_options TEXT DEFAULT '{}',
            supplemental_groups_options TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # RBAC Tables
        """
        CREATE TABLE IF NOT EXISTS rbac_roles (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            role_name TEXT NOT NULL,
            role_namespace TEXT,
            role_type TEXT NOT NULL,
            rules TEXT DEFAULT '[]',
            labels TEXT DEFAULT '{}',
            annotations TEXT DEFAULT '{}',
            risk_score REAL DEFAULT 0.0,
            last_updated TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        """
        CREATE TABLE IF NOT EXISTS rbac_bindings (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            binding_name TEXT NOT NULL,
            binding_namespace TEXT,
            binding_type TEXT NOT NULL,
            role_id TEXT NOT NULL,
            subjects TEXT DEFAULT '[]',
            labels TEXT DEFAULT '{}',
            annotations TEXT DEFAULT '{}',
            risk_score REAL DEFAULT 0.0,
            last_updated TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # Network Policy Tables
        """
        CREATE TABLE IF NOT EXISTS network_policies (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            namespace_id TEXT,
            policy_name TEXT NOT NULL,
            pod_selector TEXT DEFAULT '{}',
            policy_types TEXT DEFAULT '[]',
            ingress_rules TEXT DEFAULT '[]',
            egress_rules TEXT DEFAULT '[]',
            labels TEXT DEFAULT '{}',
            annotations TEXT DEFAULT '{}',
            security_score REAL DEFAULT 0.0,
            last_updated TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # Admission Controller Tables
        """
        CREATE TABLE IF NOT EXISTS admission_controllers (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            controller_name TEXT NOT NULL,
            controller_type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            configuration TEXT DEFAULT '{}',
            webhook_config TEXT DEFAULT '{}',
            failure_policy TEXT,
            timeout_seconds INTEGER,
            security_score REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """,
        
        # Summary Table
        """
        CREATE TABLE IF NOT EXISTS enhanced_cloud_security_summary (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            summary_date TEXT NOT NULL,
            total_containers INTEGER DEFAULT 0,
            container_vulnerabilities INTEGER DEFAULT 0,
            container_security_score REAL DEFAULT 0.0,
            total_functions INTEGER DEFAULT 0,
            function_vulnerabilities INTEGER DEFAULT 0,
            function_security_score REAL DEFAULT 0.0,
            total_clusters INTEGER DEFAULT 0,
            total_pods INTEGER DEFAULT 0,
            kubernetes_security_score REAL DEFAULT 0.0,
            overall_security_score REAL DEFAULT 0.0,
            critical_issues INTEGER DEFAULT 0,
            high_issues INTEGER DEFAULT 0,
            medium_issues INTEGER DEFAULT 0,
            low_issues INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
    
    # Create tables
    print("Creating Enhanced Cloud Security tables...")
    
    for i, sql in enumerate(tables_sql, 1):
        try:
            cursor.execute(sql)
            print(f"✓ Created table {i}/{len(tables_sql)}")
        except Exception as e:
            print(f"✗ Failed to create table {i}: {e}")
            return False
    
    # Create indexes for better performance
    print("Creating indexes...")
    
    indexes_sql = [
        "CREATE INDEX IF NOT EXISTS idx_container_images_asset_id ON container_images(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_container_images_scan_status ON container_images(scan_status)",
        "CREATE INDEX IF NOT EXISTS idx_container_vulnerabilities_image_id ON container_vulnerabilities(image_id)",
        "CREATE INDEX IF NOT EXISTS idx_container_vulnerabilities_severity ON container_vulnerabilities(severity)",
        "CREATE INDEX IF NOT EXISTS idx_serverless_functions_asset_id ON serverless_functions(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_kubernetes_clusters_asset_id ON kubernetes_clusters(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_kubernetes_resources_cluster_id ON kubernetes_resources(cluster_id)",
        "CREATE INDEX IF NOT EXISTS idx_kubernetes_resources_namespace_id ON kubernetes_resources(namespace_id)",
        "CREATE INDEX IF NOT EXISTS idx_enhanced_cloud_security_summary_project_id ON enhanced_cloud_security_summary(project_id)"
    ]
    
    for index_sql in indexes_sql:
        try:
            cursor.execute(index_sql)
        except Exception as e:
            print(f"Warning: Could not create index: {e}")
    
    # Commit changes
    conn.commit()
    
    # Verify tables were created
    print("Verifying table creation...")
    
    tables_to_check = [
        "container_images", "container_vulnerabilities", "container_layers",
        "container_runtimes", "container_instances", "serverless_functions",
        "serverless_permissions", "serverless_vulnerabilities", "kubernetes_clusters",
        "kubernetes_namespaces", "kubernetes_resources", "kubernetes_security_issues",
        "pod_security_policies", "rbac_roles", "rbac_bindings", "network_policies",
        "admission_controllers", "enhanced_cloud_security_summary"
    ]
    
    all_tables_exist = True
    
    for table in tables_to_check:
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
            if cursor.fetchone():
                print(f"✓ Table '{table}' exists")
            else:
                print(f"✗ Table '{table}' does not exist")
                all_tables_exist = False
        except Exception as e:
            print(f"✗ Could not check table '{table}': {e}")
            all_tables_exist = False
    
    # Close connection
    conn.close()
    
    if all_tables_exist:
        print("\n🎉 Enhanced Cloud Security setup completed successfully!")
        print("All required tables have been created in the database.")
        return True
    else:
        print("\n⚠️  Enhanced Cloud Security setup completed with warnings.")
        print("Some tables may not have been created properly.")
        return False

def main():
    """Main function"""
    print("Enhanced Cloud Security Database Setup")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("backend").exists():
        print("Error: Please run this script from the cyber-cursor directory")
        sys.exit(1)
    
    # Set up database
    success = setup_sqlite_database()
    
    if success:
        print("\nEnhanced Cloud Security is ready to use!")
        print("You can now use the API endpoints to manage:")
        print("- Container security (image scanning, vulnerability management)")
        print("- Serverless security (function analysis, permission review)")
        print("- Kubernetes security (cluster security, RBAC analysis)")
        print("\nAPI Base URL: /api/v1/enhanced-cloud-security")
    else:
        print("\nSetup failed. Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
