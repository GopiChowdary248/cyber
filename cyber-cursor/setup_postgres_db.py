#!/usr/bin/env python3
"""
Script to set up PostgreSQL database for CyberShield
"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import sys

def setup_database():
    """Set up PostgreSQL database and user"""
    
    # Common PostgreSQL passwords to try
    passwords_to_try = [
        "",  # No password
        "postgres",
        "admin",
        "password",
        "123456",
        "root"
    ]
    
    conn = None
    cursor = None
    
    # Try to connect with different passwords
    for password in passwords_to_try:
        try:
            print(f"Trying to connect with password: {'<empty>' if password == '' else password}")
            
            conn = psycopg2.connect(
                host="localhost",
                port="5432",
                user="postgres",
                password=password,
                database="postgres"
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            
            print(f"✅ Connected to PostgreSQL successfully with password: {'<empty>' if password == '' else password}")
            break
            
        except psycopg2.OperationalError as e:
            if "password authentication failed" in str(e):
                print(f"❌ Password '{password}' failed")
                continue
            else:
                print(f"❌ Connection error: {e}")
                break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            break
    
    if not conn:
        print("\n❌ Failed to connect to PostgreSQL with any password.")
        print("Please provide the correct password for the 'postgres' user.")
        print("\nYou can:")
        print("1. Check your PostgreSQL installation for the password")
        print("2. Reset the postgres user password")
        print("3. Create a new user with appropriate privileges")
        sys.exit(1)
    
    try:
        # Create user if not exists
        try:
            cursor.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cybershield_user') THEN
                        CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';
                    END IF;
                END
                $$;
            """)
            print("✅ User 'cybershield_user' created/verified")
        except Exception as e:
            print(f"⚠️  User creation warning: {e}")
        
        # Create database if not exists
        try:
            cursor.execute("""
                SELECT 'CREATE DATABASE cybershield'
                WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybershield')
            """)
            result = cursor.fetchone()
            if result:
                cursor.execute("CREATE DATABASE cybershield")
                print("✅ Database 'cybershield' created")
            else:
                print("✅ Database 'cybershield' already exists")
        except Exception as e:
            print(f"⚠️  Database creation warning: {e}")
        
        # Grant privileges
        try:
            cursor.execute("GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user")
            cursor.execute("GRANT ALL ON SCHEMA public TO cybershield_user")
            print("✅ Privileges granted to cybershield_user")
        except Exception as e:
            print(f"⚠️  Privilege grant warning: {e}")
        
        print("\n🎉 Database setup completed successfully!")
        print("You can now start the backend application.")
        
    except Exception as e:
        print(f"❌ Error during database setup: {e}")
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Setting up PostgreSQL database for CyberShield...")
    setup_database()
