from datetime import timedelta, datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    authenticate_user, create_access_token, get_password_hash,
    get_current_active_user, require_admin
)
from app.core.config import settings
from app.models.user import User as DBUser
from app.schemas.auth import (
    Token, UserCreate, User as UserSchema, UserLogin,
    PasswordChange, PasswordReset, PasswordResetConfirm
)
from app.schemas.iam import LoginRequest, TokenResponse
# Temporarily disable iam_service import for demo
# from app.services.iam_service import iam_service
import structlog

logger = structlog.get_logger()
router = APIRouter()

@router.options("/login")
async def login_options():
    """Handle CORS preflight request for login endpoint"""
    return {}

@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    JSON-based login endpoint for React Native frontend
    """
    try:
        # Handle both username and email login
        username = login_data.username or login_data.email
        
        # Use database authentication
        user = await authenticate_user(db, username, login_data.password)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
        # Create access token
        access_token = create_access_token(data={"sub": str(user.id)})
        
        return {
            "access_token": access_token,
            "refresh_token": "mock_refresh_token",
            "token_type": "bearer",
            "expires_in": 3600,
            "user_id": user.id,
            "email": user.email,
            "role": user.role,
            "mfa_required": False
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed")

@router.post("/login/oauth", response_model=Token)
async def login_oauth(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    try:
        # Simple mock authentication for demo purposes
        demo_users = {
            "admin@cybershield.com": {
                "id": 1,
                "email": "admin@cybershield.com",
                "username": "admin",
                "role": "admin",
                "is_active": True,
                "password": "password"
            },
            "analyst@cybershield.com": {
                "id": 2,
                "email": "analyst@cybershield.com",
                "username": "analyst",
                "role": "analyst",
                "is_active": True,
                "password": "password"
            },
            "user@cybershield.com": {
                "id": 3,
                "email": "user@cybershield.com",
                "username": "user",
                "role": "user",
                "is_active": True,
                "password": "password"
            }
        }
        
        # Check if user exists and password matches
        user_data = demo_users.get(form_data.username)
        if not user_data or form_data.password != user_data["password"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user_data["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.security.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": user_data["email"],
                "user_id": user_data["id"],
                "email": user_data["email"],
                "role": user_data["role"]
            }, expires_delta=access_token_expires
        )
        
        logger.info("User logged in successfully", user_id=user_data["id"], email=user_data["email"])
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.security.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": user_data["id"],
            "email": user_data["email"],
            "role": user_data["role"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/register", response_model=UserSchema)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Register a new user
    """
    try:
        # Check if passwords match
        if user_in.password != user_in.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match"
            )
        
        # Check if user already exists
        existing_user = await DBUser.get_by_email(db, email=user_in.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )
        
        # Create new user
        user_data = user_in.dict()
        user_data.pop("confirm_password")
        user_data["hashed_password"] = get_password_hash(user_in.password)
        
        user = await DBUser.create_user(db, **user_data)
        
        logger.info("New user registered", user_id=user.id, email=user.email)
        
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error("User registration failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/refresh", response_model=Token)
async def refresh_token(
    current_user: DBUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Refresh access token
    """
    try:
        access_token_expires = timedelta(minutes=settings.security.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": current_user.email,
                "user_id": current_user.id,
                "email": current_user.email,
                "role": current_user.role
            }, expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.security.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": current_user.id,
            "email": current_user.email,
            "role": current_user.role
        }
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: DBUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Change user password
    """
    try:
        from app.core.security import verify_password
        
        # Verify current password
        if not verify_password(password_data.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Check if new passwords match
        if password_data.new_password != password_data.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New passwords do not match"
            )
        
        # Update password
        new_hashed_password = get_password_hash(password_data.new_password)
        await current_user.update(db, hashed_password=new_hashed_password)
        
        logger.info("Password changed successfully", user_id=current_user.id)
        
        return {"message": "Password changed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Password change failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

@router.post("/forgot-password")
async def forgot_password(
    password_reset: PasswordReset,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Send password reset email
    """
    try:
        # Check if user exists
        user = await DBUser.get_by_email(db, email=password_reset.email)
        if not user:
            # Don't reveal if user exists or not
            return {"message": "If the email exists, a password reset link has been sent"}
        
        # TODO: Implement email sending logic
        # For now, just return success message
        
        logger.info("Password reset requested", email=password_reset.email)
        
        return {"message": "If the email exists, a password reset link has been sent"}
    except Exception as e:
        logger.error("Password reset request failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset request failed"
        )

@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Reset password with token
    """
    try:
        # TODO: Implement token verification logic
        # For now, just return success message
        
        logger.info("Password reset completed")
        
        return {"message": "Password reset successfully"}
    except Exception as e:
        logger.error("Password reset failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )

@router.get("/me", response_model=UserSchema)
async def get_current_user_info(
    current_user: DBUser = Depends(get_current_active_user)
) -> Any:
    """
    Get current user information
    """
    try:
        # Return user info with safe attribute access
        return {
            "id": getattr(current_user, 'id', None),
            "email": getattr(current_user, 'email', None),
            "username": getattr(current_user, 'username', None),
            "full_name": getattr(current_user, 'full_name', None),
            "role": getattr(current_user, 'role', 'user'),
            "is_active": getattr(current_user, 'is_active', True),
            "is_verified": getattr(current_user, 'is_verified', False),
            "last_login": getattr(current_user, 'last_login', None),
            "created_at": getattr(current_user, 'created_at', datetime.utcnow()),
            "updated_at": getattr(current_user, 'updated_at', datetime.utcnow()),
            "department": getattr(current_user, 'department', None),
            "phone": getattr(current_user, 'phone', None),
            "avatar_url": getattr(current_user, 'avatar_url', None),
            "two_factor_enabled": getattr(current_user, 'two_factor_enabled', False),
            "preferences": getattr(current_user, 'preferences', None)
        }
    except Exception as e:
        logger.error("Error fetching user info", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user information"
        )

@router.post("/logout")
async def logout(
    current_user = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Logout user and invalidate session
    """
    try:
        # Log the logout event
        logger.info("User logged out", user_id=current_user.id, email=current_user.email)
        
        # In a production environment, you would:
        # 1. Add the token to a blacklist
        # 2. Update user's last logout time
        # 3. Clear any active sessions
        # 4. Send logout event to audit system
        
        return {
            "message": "Successfully logged out",
            "user_id": current_user.id,
            "email": current_user.email,
            "logout_time": datetime.utcnow().isoformat(),
            "status": "logged_out"
        }
    except Exception as e:
        logger.error("Logout failed", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@router.post("/logout-all")
async def logout_all_sessions(
    current_user = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Logout user from all active sessions
    """
    try:
        # Log the logout all event
        logger.info("User logged out from all sessions", user_id=current_user.id, email=current_user.email)
        
        # In a production environment, you would:
        # 1. Blacklist all tokens for this user
        # 2. Clear all active sessions
        # 3. Force re-authentication on all devices
        
        return {
            "message": "Successfully logged out from all sessions",
            "user_id": current_user.id,
            "email": current_user.email,
            "logout_time": datetime.utcnow().isoformat(),
            "status": "logged_out_all_sessions"
        }
    except Exception as e:
        logger.error("Logout all failed", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout all sessions failed"
        ) 