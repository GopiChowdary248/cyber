"""
Security Middleware for CyberShield
Implements comprehensive security protections including headers, CORS, and rate limiting
"""

import time
import uuid
import hashlib
import hmac
import secrets
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import redis.asyncio as redis
from .security_config import security_config

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for FastAPI"""
    
    def __init__(self, app, redis_client: Optional[redis.Redis] = None):
        super().__init__(app)
        self.redis = redis_client
        self.config = security_config
        
        # Initialize rate limiting cache
        self.rate_limit_cache = {}
        
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method"""
        
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Add request ID to headers
        request.headers.__dict__["_list"].append(
            (b"x-request-id", request_id.encode())
        )
        
        try:
            # Rate limiting check
            if self.config.API_RATE_LIMIT_ENABLED:
                if not await self._check_rate_limit(request):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": "Rate limit exceeded",
                            "retry_after": self.config.RATE_LIMIT_WINDOW
                        },
                        headers={"Retry-After": str(self.config.RATE_LIMIT_WINDOW)}
                    )
            
            # Input validation for POST/PUT requests
            if self.config.INPUT_VALIDATION_ENABLED:
                if request.method in ["POST", "PUT", "PATCH"]:
                    if not await self._validate_input(request):
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={"detail": "Invalid input detected"}
                        )
            
            # Process the request
            response = await call_next(request)
            
            # Add security headers
            if self.config.SECURITY_HEADERS_ENABLED:
                self._add_security_headers(response, request_id)
            
            # Log audit event
            if self.config.AUDIT_LOGGING_ENABLED:
                await self._log_audit_event(request, response, success=True)
            
            return response
            
        except Exception as e:
            # Log audit event for failed requests
            if self.config.AUDIT_LOGGING_ENABLED:
                await self._log_audit_event(request, None, success=False, error=str(e))
            
            logger.error(f"Security middleware error: {e}")
            raise
    
    async def _check_rate_limit(self, request: Request) -> bool:
        """Check rate limiting for the request"""
        if not self.redis:
            return True  # Allow if Redis not available
        
        try:
            client_ip = self._get_client_ip(request)
            key = f"rate_limit:{client_ip}"
            
            # Get current request count
            current_count = await self.redis.get(key)
            current_count = int(current_count) if current_count else 0
            
            if current_count >= self.config.RATE_LIMIT_MAX_REQUESTS:
                return False
            
            # Increment counter
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.config.RATE_LIMIT_WINDOW)
            await pipe.execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return True  # Allow request if rate limiting fails
    
    async def _validate_input(self, request: Request) -> bool:
        """Validate and sanitize input data"""
        try:
            # Check content length
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.config.MAX_REQUEST_SIZE:
                return False
            
            # Basic XSS prevention for JSON requests
            if request.headers.get("content-type") == "application/json":
                body = await request.body()
                if body:
                    data = json.loads(body)
                    if not self._validate_json_data(data):
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Input validation error: {e}")
            return False
    
    def _validate_json_data(self, data: Any) -> bool:
        """Validate JSON data for security"""
        if isinstance(data, str):
            # Basic XSS prevention
            dangerous_patterns = [
                "<script", "javascript:", "onerror=", "onload=",
                "eval(", "document.cookie", "window.location"
            ]
            data_lower = data.lower()
            return not any(pattern in data_lower for pattern in dangerous_patterns)
        
        if isinstance(data, dict):
            return all(self._validate_json_data(value) for value in data.values())
        
        if isinstance(data, list):
            return all(self._validate_json_data(item) for item in data)
        
        return True
    
    def _add_security_headers(self, response: Response, request_id: str):
        """Add security headers to response"""
        # Add request ID
        response.headers["X-Request-ID"] = request_id
        
        # Add security headers from config
        for header, value in self.config.security_headers.items():
            if header == "X-Request-ID":
                response.headers[header] = request_id
            else:
                response.headers[header] = value
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    async def _log_audit_event(self, request: Request, response: Optional[Response], 
                              success: bool, error: str = None):
        """Log audit event"""
        try:
            audit_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": getattr(request.state, 'request_id', 'unknown'),
                "method": request.method,
                "url": str(request.url),
                "client_ip": self._get_client_ip(request),
                "user_agent": request.headers.get("User-Agent", ""),
                "success": success,
                "status_code": response.status_code if response else None,
                "error": error
            }
            
            # Store in Redis for immediate access
            if self.redis:
                log_key = f"audit_log:{int(time.time())}:{secrets.token_hex(8)}"
                await self.redis.setex(
                    log_key, 
                    self.config.AUDIT_LOG_RETENTION_DAYS * 24 * 3600,
                    json.dumps(audit_data)
                )
            
            # Log to file system
            if success:
                logger.info(f"AUDIT: {json.dumps(audit_data)}")
            else:
                logger.warning(f"AUDIT_FAILED: {json.dumps(audit_data)}")
                
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

def get_cors_middleware():
    """Get CORS middleware with secure configuration"""
    return CORSMiddleware(
        **security_config.cors_config
    )

def get_trusted_host_middleware():
    """Get trusted host middleware"""
    return TrustedHostMiddleware(
        **security_config.trusted_host_config
    )

def get_security_middleware(redis_client: Optional[redis.Redis] = None):
    """Get security middleware instance"""
    return SecurityMiddleware, {"redis_client": redis_client}

# Export middleware functions
__all__ = [
    "SecurityMiddleware",
    "get_cors_middleware", 
    "get_trusted_host_middleware",
    "get_security_middleware"
]
