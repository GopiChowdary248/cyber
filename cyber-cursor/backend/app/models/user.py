from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from datetime import datetime
from typing import Optional, List

from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="viewer")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Profile information
    department = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    
    # Security settings
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(255), nullable=True)
    
    # Preferences
    preferences = Column(Text, nullable=True)  # JSON string for user preferences
    
    @classmethod
    async def get_by_email(cls, db: AsyncSession, email: str) -> Optional["User"]:
        """Get user by email"""
        result = await db.execute(select(cls).where(cls.email == email))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: int) -> Optional["User"]:
        """Get user by ID"""
        result = await db.execute(select(cls).where(cls.id == user_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["User"]:
        """Get all users with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    @classmethod
    async def create_user(cls, db: AsyncSession, **kwargs) -> "User":
        """Create a new user"""
        user = cls(**kwargs)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user
    
    async def update(self, db: AsyncSession, **kwargs) -> "User":
        """Update user information"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        self.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(self)
        return self
    
    async def delete(self, db: AsyncSession) -> bool:
        """Delete user"""
        await db.delete(self)
        await db.commit()
        return True
    
    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', role='{self.role}')>" 