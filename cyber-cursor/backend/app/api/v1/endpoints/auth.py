from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    authenticate_user, create_access_token, get_password_hash,
    get_current_active_user, require_admin
)
from app.core.config import settings
from app.models.user import User
from app.schemas.auth import (
    Token, UserCreate, User as UserSchema, UserLogin,
    PasswordChange, PasswordReset, PasswordResetConfirm
)
import structlog

logger = structlog.get_logger()
router = APIRouter()

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    try:
        user = await authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        # Update last login
        user.last_login = timedelta()
        await user.update(db, last_login=user.last_login)
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        logger.info("User logged in successfully", user_id=user.id, email=user.email)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": user.id,
            "email": user.email,
            "role": user.role
        }
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
        existing_user = await User.get_by_email(db, email=user_in.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )
        
        # Create new user
        user_data = user_in.dict()
        user_data.pop("confirm_password")
        user_data["hashed_password"] = get_password_hash(user_in.password)
        
        user = await User.create_user(db, **user_data)
        
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Refresh access token
    """
    try:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": current_user.email}, expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
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
    current_user: User = Depends(get_current_active_user),
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
        user = await User.get_by_email(db, email=password_reset.email)
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
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Get current user information
    """
    return current_user

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Logout user (client should discard token)
    """
    logger.info("User logged out", user_id=current_user.id)
    return {"message": "Logged out successfully"} 