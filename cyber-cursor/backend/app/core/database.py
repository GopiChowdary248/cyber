from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import MetaData, text
import structlog
import os

from app.core.config import settings

logger = structlog.get_logger()

# Get database URL from environment or use default
DATABASE_URL = os.getenv("DATABASE_URL", settings.database.DATABASE_URL)

# Create async engine with proper database configuration
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.api.DEBUG,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=settings.database.DB_POOL_SIZE,
    max_overflow=settings.database.DB_MAX_OVERFLOW,
    pool_timeout=settings.database.DB_POOL_TIMEOUT,
    # Database specific optimizations
    connect_args={
        "server_settings": {
            "application_name": "cybershield",
            "timezone": "UTC",
        }
    } if "postgresql" in DATABASE_URL else {}
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
            logger.error("Database session error", error=str(e))
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
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        # Continue even if there are table creation errors
        logger.warning("Continuing with existing database schema")

async def close_db():
    """Close database connections"""
    await engine.dispose()
    logger.info("Database connections closed")

def check_db_connection():
    """Check if database connection is working (synchronous version for testing)"""
    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def test_connection():
            try:
                async with engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
                return True
            except Exception as e:
                logger.error(f"Database connection test failed: {e}")
                return False
        
        result = loop.run_until_complete(test_connection())
        loop.close()
        return result
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False

# Helper function to ensure proper async database operations
async def execute_query(session: AsyncSession, query, **kwargs):
    """Execute a query with proper error handling"""
    try:
        result = await session.execute(query, **kwargs)
        return result
    except Exception as e:
        logger.error(f"Database query execution failed: {e}")
        await session.rollback()
        raise 