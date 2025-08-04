from datetime import datetime, timedelta
from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func
import bcrypt

from app.core.database import get_db
from app.core.security import get_current_active_user, require_admin, require_analyst
from app.models.iam import IAMUser, Session, PrivilegedAccount, PrivilegedAccess, AuditLog, SSOProvider
from app.schemas.iam import (
    UserCreate, UserUpdate, UserResponse, UserListResponse,
    PrivilegedAccountCreate, PrivilegedAccountResponse, PrivilegedAccountListResponse,
    PrivilegedAccessCreate, PrivilegedAccessResponse, PrivilegedAccessListResponse,
    AuditLogResponse, AuditLogListResponse,
    LoginRequest, TokenResponse, MFAVerifyRequest, MFAVerifyResponse,
    IAMDashboardStats, IAMHealthCheck
)
from app.services.iam_service import iam_service
import structlog

logger = structlog.get_logger()
router = APIRouter()

# Authentication Endpoints
@router.post("/auth/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Authenticate user with username/password and optional MFA"""
    try:
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent")
        
        user, auth_status = await iam_service.authenticate_user(
            db, login_data.username, login_data.password,
            ip_address=client_ip, user_agent=user_agent,
            device_info=login_data.device_info
        )
        
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
        if auth_status == "mfa_required":
            return {
                "access_token": None, "refresh_token": None, "token_type": "bearer",
                "expires_in": 0, "user_id": user.id, "email": user.email,
                "role": user.role, "mfa_required": True
            }
        
        session = await iam_service.session_service.create_session(
            db, user.id, ip_address=client_ip, user_agent=user_agent,
            device_info=login_data.device_info
        )
        
        return {
            "access_token": session.token, "refresh_token": session.refresh_token,
            "token_type": "bearer", "expires_in": 3600, "user_id": user.id,
            "email": user.email, "role": user.role, "mfa_required": False
        }
        
    except Exception as e:
        logger.error("Login failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed")

@router.post("/auth/mfa/verify", response_model=MFAVerifyResponse)
async def verify_mfa(
    mfa_data: MFAVerifyRequest,
    user_id: int = Form(...),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Verify MFA token for user"""
    try:
        client_ip = request.client.host if request else None
        success = await iam_service.verify_mfa(db, user_id, mfa_data.token, ip_address=client_ip)
        
        if success:
            session = await iam_service.session_service.create_session(db, user_id, ip_address=client_ip)
            return {
                "success": True, "message": "MFA verification successful",
                "access_token": session.token, "refresh_token": session.refresh_token
            }
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA token")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("MFA verification failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="MFA verification failed")

# User Management Endpoints
@router.get("/users", response_model=UserListResponse)
async def get_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
) -> Any:
    """Get list of users with pagination and filtering"""
    try:
        query = select(IAMUser)
        
        if search:
            query = query.where(
                or_(
                    IAMUser.username.ilike(f"%{search}%"),
                    IAMUser.email.ilike(f"%{search}%"),
                    IAMUser.full_name.ilike(f"%{search}%")
                )
            )
        
        if role:
            query = query.where(IAMUser.role == role)
        
        if is_active is not None:
            query = query.where(IAMUser.is_active == is_active)
        
        total_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(total_query)
        total = total_result.scalar()
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        users = result.scalars().all()
        
        return {"users": users, "total": total, "page": skip // limit + 1, "size": limit}
        
    except Exception as e:
        logger.error("Failed to get users", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get users")

@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
) -> Any:
    """Create a new user"""
    try:
        existing_user = await IAMUser.get_by_email(db, user_data.email)
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User with this email already exists")
        
        existing_user = await IAMUser.get_by_username(db, user_data.username)
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User with this username already exists")
        
        password_hash = bcrypt.hashpw(user_data.password.encode(), bcrypt.gensalt()).decode()
        
        user = IAMUser(
            username=user_data.username, email=user_data.email,
            full_name=user_data.full_name, department=user_data.department,
            phone=user_data.phone, role=user_data.role, password_hash=password_hash,
            sso_provider=user_data.sso_provider, sso_external_id=user_data.sso_external_id
        )
        
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create user", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
) -> Any:
    """Get user by ID"""
    try:
        user = await IAMUser.get_by_id(db, user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        if current_user.role != "admin" and current_user.id != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this user")
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get user", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get user")

# Privileged Access Management Endpoints
@router.get("/pam/accounts", response_model=PrivilegedAccountListResponse)
async def get_privileged_accounts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    system_name: Optional[str] = Query(None),
    system_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_analyst)
) -> Any:
    """Get list of privileged accounts"""
    try:
        query = select(PrivilegedAccount)
        
        if system_name:
            query = query.where(PrivilegedAccount.system_name.ilike(f"%{system_name}%"))
        
        if system_type:
            query = query.where(PrivilegedAccount.system_type == system_type)
        
        if is_active is not None:
            query = query.where(PrivilegedAccount.is_active == is_active)
        
        total_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(total_query)
        total = total_result.scalar()
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        accounts = result.scalars().all()
        
        return {"accounts": accounts, "total": total, "page": skip // limit + 1, "size": limit}
        
    except Exception as e:
        logger.error("Failed to get privileged accounts", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get privileged accounts")

@router.post("/pam/accounts", response_model=PrivilegedAccountResponse)
async def create_privileged_account(
    account_data: PrivilegedAccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
) -> Any:
    """Create a new privileged account"""
    try:
        account = await iam_service.privileged_access_service.create_privileged_account(db, account_data)
        return account
        
    except Exception as e:
        logger.error("Failed to create privileged account", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create privileged account")

@router.post("/pam/access/request", response_model=PrivilegedAccessResponse)
async def request_privileged_access(
    access_data: PrivilegedAccessCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
) -> Any:
    """Request privileged access"""
    try:
        access = await iam_service.privileged_access_service.request_privileged_access(
            db, current_user.id, access_data
        )
        return access
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Failed to request privileged access", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to request privileged access")

@router.get("/pam/access/pending", response_model=PrivilegedAccessListResponse)
async def get_pending_approvals(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
) -> Any:
    """Get pending privileged access approvals"""
    try:
        query = select(PrivilegedAccess).where(PrivilegedAccess.status == "pending")
        
        total_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(total_query)
        total = total_result.scalar()
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        access_requests = result.scalars().all()
        
        return {"access_requests": access_requests, "total": total, "page": skip // limit + 1, "size": limit}
        
    except Exception as e:
        logger.error("Failed to get pending approvals", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get pending approvals")

# Dashboard and Analytics Endpoints
@router.get("/dashboard/stats", response_model=IAMDashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
) -> Any:
    """Get IAM dashboard statistics"""
    try:
        stats = await iam_service.get_dashboard_stats(db)
        return stats
        
    except Exception as e:
        logger.error("Failed to get dashboard stats", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get dashboard stats")

# Audit Logs Endpoint
@router.get("/audit/logs", response_model=AuditLogListResponse)
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_id: Optional[int] = Query(None),
    action: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_analyst)
) -> Any:
    """Get audit logs with filtering options"""
    try:
        logs = await iam_service.audit_service.get_filtered_logs(
            db, skip=skip, limit=limit, user_id=user_id,
            action=action, target_type=target_type, risk_level=risk_level,
            start_date=start_date, end_date=end_date
        )
        
        return {
            "logs": logs,
            "total": len(logs),
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error("Failed to get audit logs", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get audit logs")

# Health Check Endpoint
@router.get("/health", response_model=IAMHealthCheck)
async def health_check(db: AsyncSession = Depends(get_db)) -> Any:
    """Check IAM service health"""
    try:
        db_healthy = True
        try:
            await db.execute(select(1))
        except:
            db_healthy = False
        
        encryption_healthy = True
        try:
            test_data = "test"
            encrypted = iam_service.encryption_service.encrypt(test_data)
            decrypted = iam_service.encryption_service.decrypt(encrypted)
            if decrypted != test_data:
                encryption_healthy = False
        except:
            encryption_healthy = False
        
        overall_status = "healthy" if all([db_healthy, encryption_healthy]) else "unhealthy"
        
        return {
            "database": db_healthy,
            "redis": True,
            "encryption_service": encryption_healthy,
            "sso_providers": {"demo": True},
            "mfa_service": True,
            "audit_service": True,
            "overall_status": overall_status
        }
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return {
            "database": False, "redis": False, "encryption_service": False,
            "sso_providers": {"error": False}, "mfa_service": False,
            "audit_service": False, "overall_status": "unhealthy"
        } 