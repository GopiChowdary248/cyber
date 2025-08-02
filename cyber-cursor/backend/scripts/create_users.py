#!/usr/bin/env python3
"""
Create users table and add sample users
"""

import sys
import os
from datetime import datetime

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import init_db, get_db
from app.models.user import User
from app.core.security import get_password_hash

def create_sample_users():
    """Create sample users with different roles"""
    
    # Sample users data
    sample_users = [
        {
            "email": "admin@cybershield.com",
            "username": "admin",
            "full_name": "System Administrator",
            "password": "admin123",
            "role": "admin",
            "department": "IT Security",
            "is_active": True,
            "is_verified": True
        },
        {
            "email": "analyst@cybershield.com", 
            "username": "analyst",
            "full_name": "Security Analyst",
            "password": "analyst123",
            "role": "analyst",
            "department": "Security Operations",
            "is_active": True,
            "is_verified": True
        },
        {
            "email": "user@cybershield.com",
            "username": "user",
            "full_name": "Regular User",
            "password": "user123", 
            "role": "user",
            "department": "General",
            "is_active": True,
            "is_verified": True
        },
        {
            "email": "demo@cybershield.com",
            "username": "demo",
            "full_name": "Demo User",
            "password": "demo123",
            "role": "user",
            "department": "Demo",
            "is_active": True,
            "is_verified": True
        }
    ]
    
    # Initialize database and create tables
    print("Initializing database...")
    init_db()
    
    # Get database session
    db = next(get_db())
    try:
        print("Creating sample users...")
        
        for user_data in sample_users:
            # Check if user already exists
            existing_user = db.query(User).filter(User.email == user_data["email"]).first()
            if existing_user:
                print(f"User {user_data['email']} already exists, skipping...")
                continue
            
            # Hash password
            hashed_password = get_password_hash(user_data["password"])
            
            # Create user
            user = User(
                email=user_data["email"],
                username=user_data["username"],
                full_name=user_data["full_name"],
                hashed_password=hashed_password,
                role=user_data["role"],
                department=user_data["department"],
                is_active=user_data["is_active"],
                is_verified=user_data["is_verified"]
            )
            
            db.add(user)
            print(f"Created user: {user.email} (Role: {user.role})")
        
        # Commit changes
        db.commit()
        print("Sample users created successfully!")
        
    except Exception as e:
        print(f"Error creating users: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def main():
    """Main function"""
    print("Creating users table and sample users...")
    create_sample_users()
    print("Done!")

if __name__ == "__main__":
    main() 