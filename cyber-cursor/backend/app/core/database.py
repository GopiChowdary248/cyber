"""
Database configuration and session management
"""

import os
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import MetaData, text
from app.core.config import settings

# Get database URL from environment or use default
DATABASE_URL = os.getenv("DATABASE_URL", settings.DATABASE_URL)

# Create async engine with proper database configuration
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Create base class for models
Base = declarative_base()

# Metadata for database migrations
metadata = MetaData()

async def get_db() -> AsyncSession:
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initialize database tables"""
    try:
        async with engine.begin() as conn:
            # Create all tables with checkfirst=True to avoid conflicts
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        # Continue even if there are table creation errors
        print("Continuing with existing database schema")

async def close_db():
    """Close database connections"""
    await engine.dispose()
    print("Database connections closed")

def create_tables():
    """Create database tables (synchronous version for scripts)"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(init_db())
        loop.close()
        return True
    except Exception as e:
        print(f"Failed to create tables: {e}")
        return False 