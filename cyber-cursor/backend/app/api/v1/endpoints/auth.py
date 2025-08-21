from datetime import timedelta, datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
# Temporarily removed database dependency for testing
# from sqlalchemy.ext.asyncio import AsyncSession
# from app.core.database import get_db
from app.core.security import (
    create_access_token, verify_token, get_current_user
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

async def authenticate_user(username: str, password: str):
    """Simple authentication function"""
    try:
        # For demo purposes, accept any username/password combination
        # In production, this would verify against the database
        if username and password:
            return {
                "id": 1,
                "email": username if "@" in username else f"{username}@example.com",
                "username": username,
                "role": "user",
                "is_active": True
            }
        return None
    except Exception:
        return None

def get_password_hash(password: str) -> str:
    """Simple password hashing for demo"""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

async def get_current_active_user(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Get current active user"""
    if not current_user or not current_user.get("is_active"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_admin(current_user: dict = Depends(get_current_user)):
    """Require admin role"""
    if not current_user or current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@router.options("/login")
async def login_options():
    """Handle CORS preflight request for login endpoint"""
    return {}

@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    request: Request
) -> Any:
    """
    JSON-based login endpoint for React Native frontend
    """
    try:
        # Handle both username and email login
        username = login_data.username or login_data.email
        
        # For now, use simple authentication without database
        # TODO: Replace with proper database authentication when PostgreSQL is available
        if username and login_data.password:
            # Create a mock user for testing
            user = {
                "id": 1,
                "email": username if "@" in username else f"{username}@example.com",
                "username": username,
                "role": "user",
                "is_active": True
            }
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
        # Create access token
        access_token = create_access_token(data={"sub": str(user["id"])})
        
        return {
            "access_token": access_token,
            "refresh_token": "mock_refresh_token",
            "token_type": "bearer",
            "expires_in": 3600,
            "user_id": user["id"],
            "email": user["email"],
            "role": user["role"],
            "mfa_required": False
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed")

@router.post("/login/oauth", response_model=Token)
async def login_oauth(
    form_data: OAuth2PasswordRequestForm = Depends()
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
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
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
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
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
    user_in: UserCreate
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
        
        # For now, just return a mock user since database is not available
        # TODO: Implement proper user creation when database is available
        mock_user = {
            "id": 1,
            "email": user_in.email,
            "username": user_in.username or user_in.email.split("@")[0],
            "role": "user",
            "is_active": True
        }
        
        logger.info("New user registered", user_id=mock_user["id"], email=mock_user["email"])
        
        return mock_user
        
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
    current_user: dict = Depends(get_current_active_user)
) -> Any:
    """
    Refresh access token
    """
    try:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": current_user.get("email"),
                "user_id": current_user.get("id"),
                "email": current_user.get("email"),
                "role": current_user.get("role")
            }, expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": current_user.get("id"),
            "email": current_user.get("email"),
            "role": current_user.get("role")
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
    current_user: dict = Depends(get_current_active_user)
) -> Any:
    """
    Change user password
    """
    try:
        from app.core.security import verify_password
        
        # Verify current password
        if not verify_password(password_data.current_password, current_user.get("hashed_password", "")):
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
        # The original code had 'db' and 'await current_user.update(db, hashed_password=new_hashed_password)'
        # Assuming 'current_user' here is a mock user or similar, and 'db' is not available.
        # For now, we'll just log the change.
        logger.info("Password changed successfully (mock)", user_id=current_user.get("id"))
        
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
    password_reset: PasswordReset
) -> Any:
    """
    Send password reset email
    """
    try:
        # Check if user exists
        # The original code had 'db' and 'user = await DBUser.get_by_email(db, email=password_reset.email)'
        # Assuming 'db' is not available.
        # For now, we'll just return success message.
        logger.info("Password reset requested (mock)", email=password_reset.email)
        
        return {"message": "If the email exists, a password reset link has been sent"}
    except Exception as e:
        logger.error("Password reset request failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset request failed"
        )

@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordResetConfirm
) -> Any:
    """
    Reset password with token
    """
    try:
        # TODO: Implement token verification logic
        # For now, just return success message
        
        logger.info("Password reset completed (mock)")
        
        return {"message": "Password reset successfully"}
    except Exception as e:
        logger.error("Password reset failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )

@router.get("/me", response_model=UserSchema)
async def get_current_user_info(
    current_user: dict = Depends(get_current_active_user)
) -> Any:
    """
    Get current user information
    """
    try:
        # Return user info with safe attribute access
        return {
            "id": current_user.get("id"),
            "email": current_user.get("email"),
            "username": current_user.get("username"),
            "full_name": current_user.get("full_name"),
            "role": current_user.get("role", "user"),
            "is_active": current_user.get("is_active", True),
            "is_verified": current_user.get("is_verified", False),
            "last_login": current_user.get("last_login"),
            "created_at": current_user.get("created_at", datetime.utcnow()),
            "updated_at": current_user.get("updated_at", datetime.utcnow()),
            "department": current_user.get("department"),
            "phone": current_user.get("phone"),
            "avatar_url": current_user.get("avatar_url"),
            "two_factor_enabled": current_user.get("two_factor_enabled", False),
            "preferences": current_user.get("preferences")
        }
    except Exception as e:
        logger.error("Error fetching user info", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user information"
        )

@router.post("/logout")
async def logout(
    current_user = Depends(get_current_active_user)
) -> Any:
    """
    Logout user and invalidate session
    """
    try:
        # Log the logout event
        logger.info("User logged out", user_id=current_user.get("id"), email=current_user.get("email"))
        
        # In a production environment, you would:
        # 1. Add the token to a blacklist
        # 2. Update user's last logout time
        # 3. Clear any active sessions
        # 4. Send logout event to audit system
        
        return {
            "message": "Successfully logged out",
            "user_id": current_user.get("id"),
            "email": current_user.get("email"),
            "logout_time": datetime.utcnow().isoformat(),
            "status": "logged_out"
        }
    except Exception as e:
        logger.error("Logout failed", error=str(e), user_id=current_user.get("id"))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@router.post("/logout-all")
async def logout_all_sessions(
    current_user = Depends(get_current_active_user)
) -> Any:
    """
    Logout user from all active sessions
    """
    try:
        # Log the logout all event
        logger.info("User logged out from all sessions", user_id=current_user.get("id"), email=current_user.get("email"))
        
        # In a production environment, you would:
        # 1. Blacklist all tokens for this user
        # 2. Clear all active sessions
        # 3. Force re-authentication on all devices
        
        return {
            "message": "Successfully logged out from all sessions",
            "user_id": current_user.get("id"),
            "email": current_user.get("email"),
            "logout_time": datetime.utcnow().isoformat(),
            "status": "logged_out_all_sessions"
        }
    except Exception as e:
        logger.error("Logout all failed", error=str(e), user_id=current_user.get("id"))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout all sessions failed"
        ) 