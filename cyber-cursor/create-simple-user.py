#!/usr/bin/env python3
"""
Simple script to create an admin user for CyberShield
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
from datetime import datetime

# Create async engine
engine = create_async_engine(
    "postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield",
    echo=False,
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Create base class for models
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class SimpleUser(Base):
    """Simple user model for testing"""
    __tablename__ = "iam_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="user")
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    department = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

async def create_admin_user():
    """Create an admin user in the database"""
    
    # Admin user data
    admin_data = {
        "username": "admin",
        "email": "admin@cybershield.com",
        "password_hash": pwd_context.hash("admin123"),
        "full_name": "CyberShield Administrator",
        "role": "admin",
        "is_active": True,
        "is_verified": True,
        "department": "IT Security",
        "phone": "+1234567890"
    }
    
    async with AsyncSessionLocal() as db:
        try:
            # Check if admin user already exists
            result = await db.execute(
                text("SELECT id FROM iam_users WHERE email = :email"),
                {"email": admin_data["email"]}
            )
            existing_user = result.fetchone()
            
            if existing_user:
                print("Admin user already exists!")
                return
            
            # Create new admin user
            await db.execute(
                text("""
                INSERT INTO iam_users (username, email, password_hash, full_name, role, is_active, is_verified, department, phone, created_at, updated_at)
                VALUES (:username, :email, :password_hash, :full_name, :role, :is_active, :is_verified, :department, :phone, NOW(), NOW())
                """),
                admin_data
            )
            await db.commit()
            
            print("✅ Admin user created successfully!")
            print(f"Username: {admin_data['username']}")
            print(f"Email: {admin_data['email']}")
            print(f"Role: {admin_data['role']}")
            print("Password: admin123")
            
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            await db.rollback()

if __name__ == "__main__":
    print("Creating admin user for CyberShield...")
    asyncio.run(create_admin_user()) 