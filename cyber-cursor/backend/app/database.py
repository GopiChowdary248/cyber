from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import MetaData
import structlog
import os

from app.core.config import settings

logger = structlog.get_logger()

# Create async engine
engine = create_async_engine(
    settings.database.DATABASE_URL,
    echo=settings.api.DEBUG,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={
        "ssl": False if settings.database.DB_SSL_MODE == "disable" else True
    } if "postgresql" in settings.database.DATABASE_URL else {}
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
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
            logger.error("Database session error", error=str(e))
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initialize database tables"""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        raise

async def close_db():
    """Close database connections"""
    await engine.dispose()
    logger.info("Database connections closed") 