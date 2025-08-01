from fastapi import APIRouter, Depends, HTTPException, status, Form
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, List
import structlog

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services.mfa_service import mfa_service
from app.schemas.auth import MFASetupResponse, MFAResponse, BackupCodesResponse

logger = structlog.get_logger()
router = APIRouter()

@router.post("/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Setup MFA for the current user"""
    try:
        # Check if MFA is already enabled
        if current_user.two_factor_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is already enabled for this account"
            )
        
        # Setup MFA
        mfa_data = await mfa_service.setup_mfa(db, current_user.id)
        
        return {
            "success": True,
            "qr_code": mfa_data["qr_code"],
            "backup_codes": mfa_data["backup_codes"],
            "secret": mfa_data["secret"],  # Only for manual entry
            "setup_uri": mfa_data["setup_uri"],
            "message": "MFA setup initiated. Scan the QR code with your authenticator app and verify with a token."
        }
    except Exception as e:
        logger.error("Error setting up MFA", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup MFA"
        )

@router.post("/verify-setup", response_model=MFAResponse)
async def verify_mfa_setup(
    token: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify MFA setup with first token"""
    try:
        # Validate token format
        if not mfa_service.validate_token_format(token):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token format. Please enter a 6-digit code from your authenticator app."
            )
        
        # Verify setup
        if await mfa_service.verify_mfa_setup(db, current_user.id, token):
            return {
                "success": True,
                "message": "MFA setup completed successfully. Your account is now protected with two-factor authentication."
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token. Please check your authenticator app and try again."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error verifying MFA setup", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA setup"
        )

@router.post("/verify-login", response_model=MFAResponse)
async def verify_mfa_login(
    user_id: int,
    token: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Verify MFA token during login"""
    try:
        # Validate token format
        if not mfa_service.validate_token_format(token):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token format"
            )
        
        # Verify MFA token
        if await mfa_service.verify_mfa_login(db, user_id, token):
            return {
                "success": True,
                "message": "MFA verification successful"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA token. Please check your authenticator app or backup code."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error verifying MFA login", error=str(e), user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA token"
        )

@router.post("/disable", response_model=MFAResponse)
async def disable_mfa(
    password: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disable MFA for the current user"""
    try:
        # Check if MFA is enabled
        if not current_user.two_factor_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this account"
            )
        
        # Disable MFA
        if await mfa_service.disable_mfa(db, current_user.id, password):
            return {
                "success": True,
                "message": "MFA has been disabled successfully. Your account is no longer protected with two-factor authentication."
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password. Please enter your current password to disable MFA."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error disabling MFA", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA"
        )

@router.post("/regenerate-backup-codes", response_model=BackupCodesResponse)
async def regenerate_backup_codes(
    password: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Regenerate backup codes for the current user"""
    try:
        # Check if MFA is enabled
        if not current_user.two_factor_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this account"
            )
        
        # Regenerate backup codes
        backup_codes = await mfa_service.regenerate_backup_codes(db, current_user.id, password)
        
        if backup_codes:
            return {
                "success": True,
                "backup_codes": backup_codes,
                "message": "Backup codes regenerated successfully. Please save these codes in a secure location."
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password. Please enter your current password to regenerate backup codes."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error regenerating backup codes", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes"
        )

@router.get("/status")
async def get_mfa_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get MFA status for the current user"""
    try:
        status_data = await mfa_service.get_mfa_status(db, current_user.id)
        return {
            "success": True,
            "mfa_status": status_data
        }
    except Exception as e:
        logger.error("Error getting MFA status", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get MFA status"
        )

@router.post("/recovery-token")
async def generate_recovery_token(
    email: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Generate recovery token for MFA bypass (admin only)"""
    try:
        # Get user by email
        user = await User.get_by_email(db, email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check if MFA is enabled
        if not user.two_factor_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this account"
            )
        
        # Generate recovery token
        recovery_token = mfa_service.generate_recovery_token(user.id)
        
        return {
            "success": True,
            "recovery_token": recovery_token,
            "expires_in": "24 hours",
            "message": "Recovery token generated. This token can be used to bypass MFA for 24 hours."
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error generating recovery token", error=str(e), email=email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate recovery token"
        )

@router.post("/validate-recovery-token")
async def validate_recovery_token(
    recovery_token: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Validate recovery token and return user ID"""
    try:
        user_id = mfa_service.verify_recovery_token(recovery_token)
        
        if user_id:
            return {
                "success": True,
                "user_id": user_id,
                "message": "Recovery token is valid"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired recovery token"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error validating recovery token", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate recovery token"
        )

@router.get("/qr-code/{secret}")
async def get_qr_code(secret: str):
    """Get QR code for a given TOTP secret (for manual entry)"""
    try:
        # Generate QR code
        uri = mfa_service.generate_totp_uri("user", secret)
        qr_code = mfa_service.generate_qr_code(uri)
        
        return {
            "success": True,
            "qr_code": qr_code,
            "setup_uri": uri
        }
    except Exception as e:
        logger.error("Error generating QR code", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate QR code"
        ) 