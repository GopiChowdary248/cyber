import pyotp
import qrcode
import secrets
import hashlib
import base64
import io
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.user import User
from app.core.config import settings

logger = structlog.get_logger()

class MFAService:
    def __init__(self):
        self.backup_codes_count = 10
        self.backup_code_length = 8
        self.recovery_token_expiry = timedelta(hours=24)
    
    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_totp_uri(self, username: str, secret: str, issuer: str = "CyberShield") -> str:
        """Generate TOTP URI for QR code"""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
    
    def generate_qr_code(self, uri: str) -> str:
        """Generate QR code as base64 string"""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
        except Exception as e:
            logger.error("Error generating QR code", error=str(e))
            return ""
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception as e:
            logger.error("Error verifying TOTP", error=str(e))
            return False
    
    def generate_backup_codes(self) -> List[str]:
        """Generate backup codes for account recovery"""
        codes = []
        for _ in range(self.backup_codes_count):
            code = secrets.token_hex(self.backup_code_length // 2).upper()
            # Format as XXXX-XXXX for better readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes
    
    def verify_backup_code(self, provided_code: str, stored_codes: List[str]) -> Tuple[bool, List[str]]:
        """Verify backup code and return remaining codes"""
        # Normalize the provided code
        normalized_code = provided_code.replace('-', '').upper()
        
        for i, stored_code in enumerate(stored_codes):
            normalized_stored = stored_code.replace('-', '').upper()
            if normalized_code == normalized_stored:
                # Remove used code
                remaining_codes = stored_codes[:i] + stored_codes[i+1:]
                return True, remaining_codes
        
        return False, stored_codes
    
    def hash_backup_codes(self, codes: List[str]) -> List[str]:
        """Hash backup codes for secure storage"""
        return [hashlib.sha256(code.encode()).hexdigest() for code in codes]
    
    def generate_recovery_token(self, user_id: int) -> str:
        """Generate a recovery token for MFA bypass"""
        token_data = f"{user_id}:{datetime.utcnow().isoformat()}"
        return base64.b64encode(token_data.encode()).decode()
    
    def verify_recovery_token(self, token: str) -> Optional[int]:
        """Verify recovery token and return user ID if valid"""
        try:
            decoded = base64.b64decode(token.encode()).decode()
            user_id_str, timestamp_str = decoded.split(':', 1)
            timestamp = datetime.fromisoformat(timestamp_str)
            
            if datetime.utcnow() - timestamp > self.recovery_token_expiry:
                return None
            
            return int(user_id_str)
        except Exception as e:
            logger.error("Error verifying recovery token", error=str(e))
            return None
    
    async def setup_mfa(self, db: AsyncSession, user_id: int) -> Dict[str, any]:
        """Setup MFA for a user"""
        try:
            # Get user
            user = await User.get_by_id(db, user_id)
            if not user:
                raise ValueError("User not found")
            
            # Generate TOTP secret
            secret = self.generate_totp_secret()
            
            # Generate QR code
            uri = self.generate_totp_uri(user.username, secret)
            qr_code = self.generate_qr_code(uri)
            
            # Generate backup codes
            backup_codes = self.generate_backup_codes()
            hashed_codes = self.hash_backup_codes(backup_codes)
            
            # Update user with MFA secret (temporarily, until verified)
            await user.update(db, 
                two_factor_secret=secret,
                backup_codes=hashed_codes,
                mfa_setup_pending=True
            )
            
            return {
                "secret": secret,
                "qr_code": qr_code,
                "backup_codes": backup_codes,
                "setup_uri": uri
            }
        except Exception as e:
            logger.error("Error setting up MFA", error=str(e), user_id=user_id)
            raise
    
    async def verify_mfa_setup(self, db: AsyncSession, user_id: int, token: str) -> bool:
        """Verify MFA setup with first token"""
        try:
            user = await User.get_by_id(db, user_id)
            if not user or not user.two_factor_secret:
                return False
            
            # Verify the token
            if not self.verify_totp(user.two_factor_secret, token):
                return False
            
            # Mark MFA as active
            await user.update(db, 
                two_factor_enabled=True,
                mfa_setup_pending=False,
                mfa_enabled_at=datetime.utcnow()
            )
            
            logger.info("MFA setup verified", user_id=user_id)
            return True
        except Exception as e:
            logger.error("Error verifying MFA setup", error=str(e), user_id=user_id)
            return False
    
    async def verify_mfa_login(self, db: AsyncSession, user_id: int, token: str) -> bool:
        """Verify MFA token during login"""
        try:
            user = await User.get_by_id(db, user_id)
            if not user or not user.two_factor_enabled:
                return False
            
            # Check if it's a backup code
            if '-' in token:
                is_valid, remaining_codes = self.verify_backup_code(token, user.backup_codes or [])
                if is_valid:
                    # Update user with remaining backup codes
                    await user.update(db, backup_codes=remaining_codes)
                    logger.info("MFA login with backup code", user_id=user_id)
                    return True
                return False
            
            # Verify TOTP token
            if not self.verify_totp(user.two_factor_secret, token):
                return False
            
            logger.info("MFA login verified", user_id=user_id)
            return True
        except Exception as e:
            logger.error("Error verifying MFA login", error=str(e), user_id=user_id)
            return False
    
    async def disable_mfa(self, db: AsyncSession, user_id: int, password: str) -> bool:
        """Disable MFA for a user"""
        try:
            user = await User.get_by_id(db, user_id)
            if not user:
                return False
            
            # Verify password before disabling MFA
            if not user.verify_password(password):
                return False
            
            # Clear MFA data
            await user.update(db, 
                two_factor_enabled=False,
                two_factor_secret=None,
                backup_codes=None,
                mfa_setup_pending=False,
                mfa_disabled_at=datetime.utcnow()
            )
            
            logger.info("MFA disabled", user_id=user_id)
            return True
        except Exception as e:
            logger.error("Error disabling MFA", error=str(e), user_id=user_id)
            return False
    
    async def regenerate_backup_codes(self, db: AsyncSession, user_id: int, password: str) -> Optional[List[str]]:
        """Regenerate backup codes for a user"""
        try:
            user = await User.get_by_id(db, user_id)
            if not user or not user.two_factor_enabled:
                return None
            
            # Verify password
            if not user.verify_password(password):
                return None
            
            # Generate new backup codes
            backup_codes = self.generate_backup_codes()
            hashed_codes = self.hash_backup_codes(backup_codes)
            
            # Update user
            await user.update(db, backup_codes=hashed_codes)
            
            logger.info("Backup codes regenerated", user_id=user_id)
            return backup_codes
        except Exception as e:
            logger.error("Error regenerating backup codes", error=str(e), user_id=user_id)
            return None
    
    async def get_mfa_status(self, db: AsyncSession, user_id: int) -> Dict[str, any]:
        """Get MFA status for a user"""
        try:
            user = await User.get_by_id(db, user_id)
            if not user:
                return {"enabled": False}
            
            backup_codes_count = len(user.backup_codes) if user.backup_codes else 0
            
            return {
                "enabled": user.two_factor_enabled,
                "setup_pending": user.mfa_setup_pending,
                "backup_codes_remaining": backup_codes_count,
                "enabled_at": user.mfa_enabled_at.isoformat() if user.mfa_enabled_at else None,
                "last_used": user.last_login.isoformat() if user.last_login else None
            }
        except Exception as e:
            logger.error("Error getting MFA status", error=str(e), user_id=user_id)
            return {"enabled": False}
    
    def validate_token_format(self, token: str) -> bool:
        """Validate token format (6 digits for TOTP, XXXX-XXXX for backup codes)"""
        if '-' in token:
            # Backup code format: XXXX-XXXX
            parts = token.split('-')
            if len(parts) != 2 or len(parts[0]) != 4 or len(parts[1]) != 4:
                return False
            return all(part.isalnum() for part in parts)
        else:
            # TOTP format: 6 digits
            return len(token) == 6 and token.isdigit()

# Global MFA service instance
mfa_service = MFAService() 