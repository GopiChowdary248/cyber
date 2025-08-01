from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
import structlog
from datetime import datetime
import psutil
import os

from app.core.database import get_db
from app.core.config import settings

logger = structlog.get_logger()
router = APIRouter()

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Comprehensive health check endpoint"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "environment": settings.ENVIRONMENT,
            "services": {}
        }
        
        # Check database connection
        try:
            db = await get_db().__anext__()
            await db.execute("SELECT 1")
            health_status["services"]["database"] = {
                "status": "healthy",
                "type": "postgresql"
            }
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            health_status["services"]["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health_status["status"] = "degraded"
        
        # Check Redis connection
        try:
            import redis
            r = redis.Redis.from_url(settings.REDIS_URL)
            r.ping()
            health_status["services"]["redis"] = {
                "status": "healthy",
                "type": "redis"
            }
        except Exception as e:
            logger.error("Redis health check failed", error=str(e))
            health_status["services"]["redis"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health_status["status"] = "degraded"
        
        # System metrics
        try:
            health_status["system"] = {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "uptime": psutil.boot_time()
            }
        except Exception as e:
            logger.error("System metrics check failed", error=str(e))
            health_status["system"] = {
                "error": str(e)
            }
        
        # Application metrics
        health_status["application"] = {
            "pid": os.getpid(),
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "environment": settings.ENVIRONMENT,
            "debug": settings.DEBUG
        }
        
        return health_status
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@router.get("/health/ready")
async def readiness_check() -> Dict[str, Any]:
    """Readiness check for Kubernetes/container orchestration"""
    try:
        # Check critical dependencies
        checks = {}
        
        # Database check
        try:
            db = await get_db().__anext__()
            await db.execute("SELECT 1")
            checks["database"] = "ready"
        except Exception as e:
            checks["database"] = f"not_ready: {str(e)}"
        
        # Redis check
        try:
            import redis
            r = redis.Redis.from_url(settings.REDIS_URL)
            r.ping()
            checks["redis"] = "ready"
        except Exception as e:
            checks["redis"] = f"not_ready: {str(e)}"
        
        # Determine overall readiness
        all_ready = all(status == "ready" for status in checks.values())
        
        return {
            "ready": all_ready,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": checks
        }
        
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return {
            "ready": False,
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@router.get("/health/live")
async def liveness_check() -> Dict[str, Any]:
    """Liveness check for Kubernetes/container orchestration"""
    return {
        "alive": True,
        "timestamp": datetime.utcnow().isoformat(),
        "pid": os.getpid()
    }

@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """Prometheus-style metrics endpoint"""
    try:
        metrics_data = {
            "cybershield_up": 1,
            "cybershield_build_info": {
                "version": "1.0.0",
                "environment": settings.ENVIRONMENT
            }
        }
        
        # System metrics
        try:
            metrics_data.update({
                "cybershield_cpu_usage_percent": psutil.cpu_percent(interval=1),
                "cybershield_memory_usage_percent": psutil.virtual_memory().percent,
                "cybershield_disk_usage_percent": psutil.disk_usage('/').percent,
                "cybershield_uptime_seconds": datetime.utcnow().timestamp() - psutil.boot_time()
            })
        except Exception as e:
            logger.error("System metrics collection failed", error=str(e))
        
        # Database metrics
        try:
            db = await get_db().__anext__()
            result = await db.execute("SELECT count(*) FROM users")
            user_count = result.scalar()
            metrics_data["cybershield_users_total"] = user_count
        except Exception as e:
            logger.error("Database metrics collection failed", error=str(e))
            metrics_data["cybershield_users_total"] = -1
        
        return metrics_data
        
    except Exception as e:
        logger.error("Metrics collection failed", error=str(e))
        return {
            "cybershield_up": 0,
            "error": str(e)
        } 