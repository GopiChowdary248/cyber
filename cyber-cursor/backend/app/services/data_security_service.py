import os
import hashlib
import secrets
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import bcrypt
import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from app.models.data_security import (
    EncryptionKey, EncryptedAsset, DatabaseEncryption, DLPPolicy, DLPIncident,
    DataDiscovery, DatabaseConnection, DatabaseAuditLog, DatabaseAccessRequest,
    DatabaseVulnerability, DataMasking, DataTokenization, SecurityCompliance,
    SecurityReport
)
from app.core.config import settings
import structlog

logger = structlog.get_logger()

class EncryptionService:
    """Service for managing encryption keys and operations"""
    
    def __init__(self):
        # Generate a proper Fernet key from the secret key
        import base64
        import hashlib
        # Use SHA256 hash of the secret key to get 32 bytes
        key_bytes = hashlib.sha256(settings.security.SECRET_KEY.encode()).digest()
        self.master_key = base64.urlsafe_b64encode(key_bytes)
        self.fernet = Fernet(self.master_key)
    
    def generate_key_material(self, key_type: str, key_size: int) -> bytes:
        """Generate cryptographic key material"""
        if key_type == "AES":
            return secrets.token_bytes(key_size // 8)
        elif key_type == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
    
    def encrypt_key_material(self, key_material: bytes) -> str:
        """Encrypt key material for storage"""
        return self.fernet.encrypt(key_material).decode()
    
    def decrypt_key_material(self, encrypted_key: str) -> bytes:
        """Decrypt key material for use"""
        return self.fernet.decrypt(encrypted_key.encode())
    
    async def create_encryption_key(self, db: AsyncSession, key_data: Dict) -> EncryptionKey:
        """Create a new encryption key"""
        try:
            key_material = self.generate_key_material(key_data["key_type"], key_data["key_size"])
            encrypted_key = self.encrypt_key_material(key_material)
            
            db_key = EncryptionKey(
                key_name=key_data["key_name"],
                key_type=key_data["key_type"],
                key_size=key_data["key_size"],
                encrypted_key=encrypted_key,
                key_metadata=key_data.get("key_metadata"),
                expires_at=key_data.get("expires_at")
            )
            
            db.add(db_key)
            await db.commit()
            await db.refresh(db_key)
            
            logger.info("Created encryption key", key_id=db_key.key_id, key_name=db_key.key_name)
            return db_key
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to create encryption key", error=str(e))
            raise
    
    async def rotate_key(self, db: AsyncSession, key_id: int) -> bool:
        """Rotate an encryption key"""
        try:
            # Get existing key
            result = await db.execute(select(EncryptionKey).where(EncryptionKey.key_id == key_id))
            old_key = result.scalar_one_or_none()
            
            if not old_key:
                raise ValueError("Key not found")
            
            # Generate new key material
            new_key_material = self.generate_key_material(old_key.key_type, old_key.key_size)
            new_encrypted_key = self.encrypt_key_material(new_key_material)
            
            # Update key
            old_key.encrypted_key = new_encrypted_key
            old_key.updated_at = datetime.utcnow()
            
            await db.commit()
            
            logger.info("Rotated encryption key", key_id=key_id)
            return True
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to rotate encryption key", key_id=key_id, error=str(e))
            raise

class FileEncryptionService:
    """Service for file encryption operations"""
    
    def __init__(self, encryption_service: EncryptionService):
        self.encryption_service = encryption_service
    
    async def encrypt_file(self, db: AsyncSession, file_path: str, key_id: int) -> str:
        """Encrypt a file using the specified key"""
        try:
            # Get encryption key
            result = await db.execute(select(EncryptionKey).where(EncryptionKey.key_id == key_id))
            key = result.scalar_one_or_none()
            
            if not key:
                raise ValueError("Encryption key not found")
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Decrypt key material
            key_material = self.encryption_service.decrypt_key_material(key.encrypted_key)
            
            # Generate IV
            iv = secrets.token_bytes(16)
            
            # Encrypt file content
            cipher = Cipher(algorithms.AES(key_material), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_content = encryptor.update(file_content) + encryptor.finalize()
            
            # Combine IV, tag, and encrypted content
            encrypted_file_content = iv + encryptor.tag + encrypted_content
            
            # Write encrypted file
            encrypted_file_path = f"{file_path}.encrypted"
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_file_content)
            
            # Record encrypted asset
            asset = EncryptedAsset(
                asset_type="file",
                asset_path=encrypted_file_path,
                key_id=key_id,
                metadata={"original_path": file_path}
            )
            
            db.add(asset)
            await db.commit()
            
            logger.info("Encrypted file", file_path=file_path, encrypted_path=encrypted_file_path)
            return encrypted_file_path
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to encrypt file", file_path=file_path, error=str(e))
            raise

class DLPService:
    """Service for Data Loss Prevention operations"""
    
    def __init__(self):
        self.pii_patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        }
    
    async def create_dlp_policy(self, db: AsyncSession, policy_data: Dict) -> DLPPolicy:
        """Create a new DLP policy"""
        try:
            policy = DLPPolicy(
                policy_name=policy_data["policy_name"],
                policy_type=policy_data["policy_type"],
                policy_rules=policy_data["policy_rules"],
                enforcement_level=policy_data.get("enforcement_level", "monitor")
            )
            
            db.add(policy)
            await db.commit()
            await db.refresh(policy)
            
            logger.info("Created DLP policy", policy_id=policy.policy_id, policy_name=policy.policy_name)
            return policy
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to create DLP policy", error=str(e))
            raise
    
    def scan_content_for_pii(self, content: str) -> List[Dict]:
        """Scan content for PII patterns"""
        findings = []
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': pii_type,
                    'value': match.group(),
                    'position': match.span(),
                    'severity': 'high' if pii_type in ['ssn', 'credit_card'] else 'medium'
                })
        
        return findings
    
    async def evaluate_content(self, db: AsyncSession, content: str, policy_ids: List[int]) -> List[Dict]:
        """Evaluate content against DLP policies"""
        violations = []
        
        # Get policies
        result = await db.execute(
            select(DLPPolicy).where(DLPPolicy.policy_id.in_(policy_ids))
        )
        policies = result.scalars().all()
        
        for policy in policies:
            # Check for PII patterns
            pii_findings = self.scan_content_for_pii(content)
            
            if pii_findings:
                for finding in pii_findings:
                    violations.append({
                        'policy_id': policy.policy_id,
                        'policy_name': policy.policy_name,
                        'violation_type': f"PII_{finding['type'].upper()}",
                        'severity': finding['severity'],
                        'details': finding
                    })
        
        return violations
    
    async def create_incident(self, db: AsyncSession, incident_data: Dict) -> DLPIncident:
        """Create a DLP incident"""
        try:
            incident = DLPIncident(
                policy_id=incident_data["policy_id"],
                user_id=incident_data.get("user_id"),
                file_path=incident_data.get("file_path"),
                content_type=incident_data.get("content_type"),
                violation_type=incident_data["violation_type"],
                severity=incident_data.get("severity", "medium")
            )
            
            db.add(incident)
            await db.commit()
            await db.refresh(incident)
            
            logger.info("Created DLP incident", incident_id=incident.incident_id, violation_type=incident.violation_type)
            return incident
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to create DLP incident", error=str(e))
            raise

class DatabaseSecurityService:
    """Service for database security operations"""
    
    async def add_database_connection(self, db: AsyncSession, connection_data: Dict) -> DatabaseConnection:
        """Add a database for monitoring"""
        try:
            connection = DatabaseConnection(
                db_name=connection_data["db_name"],
                db_type=connection_data["db_type"],
                host=connection_data["host"],
                port=connection_data.get("port"),
                connection_string=connection_data.get("connection_string"),
                is_monitored=connection_data.get("is_monitored", True)
            )
            
            db.add(connection)
            await db.commit()
            await db.refresh(connection)
            
            logger.info("Added database connection", connection_id=connection.connection_id, db_name=connection.db_name)
            return connection
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to add database connection", error=str(e))
            raise
    
    async def log_database_activity(self, db: AsyncSession, activity_data: Dict) -> DatabaseAuditLog:
        """Log database activity"""
        try:
            log = DatabaseAuditLog(
                connection_id=activity_data["connection_id"],
                user_id=activity_data.get("user_id"),
                query_text=activity_data.get("query_text"),
                query_type=activity_data.get("query_type"),
                execution_time=activity_data.get("execution_time"),
                rows_affected=activity_data.get("rows_affected"),
                ip_address=activity_data.get("ip_address"),
                is_anomalous=activity_data.get("is_anomalous", False)
            )
            
            db.add(log)
            await db.commit()
            await db.refresh(log)
            
            return log
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to log database activity", error=str(e))
            raise
    
    async def request_database_access(self, db: AsyncSession, request_data: Dict) -> DatabaseAccessRequest:
        """Request database access"""
        try:
            request = DatabaseAccessRequest(
                user_id=request_data["user_id"],
                connection_id=request_data["connection_id"],
                access_type=request_data["access_type"],
                reason=request_data["reason"],
                requested_duration=request_data["requested_duration"]
            )
            
            db.add(request)
            await db.commit()
            await db.refresh(request)
            
            logger.info("Created database access request", request_id=request.request_id, user_id=request.user_id)
            return request
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to create database access request", error=str(e))
            raise
    
    async def approve_access_request(self, db: AsyncSession, request_id: int, approved_by: int) -> bool:
        """Approve a database access request"""
        try:
            result = await db.execute(
                select(DatabaseAccessRequest).where(DatabaseAccessRequest.request_id == request_id)
            )
            request = result.scalar_one_or_none()
            
            if not request:
                raise ValueError("Access request not found")
            
            request.status = "approved"
            request.approved_by = approved_by
            request.approved_at = datetime.utcnow()
            
            await db.commit()
            
            logger.info("Approved database access request", request_id=request_id, approved_by=approved_by)
            return True
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to approve access request", request_id=request_id, error=str(e))
            raise

class DataProtectionService:
    """Service for data protection operations"""
    
    async def mask_sensitive_data(self, db: AsyncSession, masking_data: Dict) -> DataMasking:
        """Configure data masking for a database column"""
        try:
            masking = DataMasking(
                connection_id=masking_data["connection_id"],
                table_name=masking_data["table_name"],
                column_name=masking_data["column_name"],
                masking_type=masking_data["masking_type"],
                masking_rules=masking_data.get("masking_rules")
            )
            
            db.add(masking)
            await db.commit()
            await db.refresh(masking)
            
            logger.info("Configured data masking", masking_id=masking.masking_id, table=masking.table_name)
            return masking
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to configure data masking", error=str(e))
            raise
    
    async def tokenize_data(self, db: AsyncSession, tokenization_data: Dict) -> DataTokenization:
        """Configure data tokenization for a database column"""
        try:
            tokenization = DataTokenization(
                connection_id=tokenization_data["connection_id"],
                table_name=tokenization_data["table_name"],
                column_name=tokenization_data["column_name"],
                token_type=tokenization_data["token_type"],
                token_format=tokenization_data.get("token_format")
            )
            
            db.add(tokenization)
            await db.commit()
            await db.refresh(tokenization)
            
            logger.info("Configured data tokenization", tokenization_id=tokenization.tokenization_id, table=tokenization.table_name)
            return tokenization
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to configure data tokenization", error=str(e))
            raise

class ComplianceService:
    """Service for compliance and reporting operations"""
    
    async def create_compliance_record(self, db: AsyncSession, compliance_data: Dict) -> SecurityCompliance:
        """Create a compliance record"""
        try:
            compliance = SecurityCompliance(
                framework=compliance_data["framework"],
                requirement=compliance_data["requirement"],
                status=compliance_data["status"],
                evidence=compliance_data.get("evidence"),
                next_assessment=compliance_data.get("next_assessment")
            )
            
            db.add(compliance)
            await db.commit()
            await db.refresh(compliance)
            
            logger.info("Created compliance record", compliance_id=compliance.compliance_id, framework=compliance.framework)
            return compliance
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to create compliance record", error=str(e))
            raise
    
    async def generate_security_report(self, db: AsyncSession, report_data: Dict) -> SecurityReport:
        """Generate a security report"""
        try:
            report = SecurityReport(
                report_type=report_data["report_type"],
                report_data=report_data["report_data"],
                generated_by=report_data.get("generated_by"),
                report_path=report_data.get("report_path")
            )
            
            db.add(report)
            await db.commit()
            await db.refresh(report)
            
            logger.info("Generated security report", report_id=report.report_id, report_type=report.report_type)
            return report
            
        except Exception as e:
            await db.rollback()
            logger.error("Failed to generate security report", error=str(e))
            raise

class DataSecurityService:
    """Main service orchestrating all data security operations"""
    
    def __init__(self):
        self.encryption_service = EncryptionService()
        self.file_encryption_service = FileEncryptionService(self.encryption_service)
        self.dlp_service = DLPService()
        self.database_security_service = DatabaseSecurityService()
        self.data_protection_service = DataProtectionService()
        self.compliance_service = ComplianceService()
    
    async def get_dashboard_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get comprehensive dashboard statistics"""
        try:
            # Encryption stats
            total_keys = await db.scalar(select(func.count(EncryptionKey.key_id)))
            active_keys = await db.scalar(select(func.count(EncryptionKey.key_id)).where(EncryptionKey.is_active == True))
            encrypted_assets = await db.scalar(select(func.count(EncryptedAsset.asset_id)))
            
            # DLP stats
            total_policies = await db.scalar(select(func.count(DLPPolicy.policy_id)))
            active_policies = await db.scalar(select(func.count(DLPPolicy.policy_id)).where(DLPPolicy.is_active == True))
            open_incidents = await db.scalar(select(func.count(DLPIncident.incident_id)).where(DLPIncident.status == "open"))
            
            # Database security stats
            monitored_databases = await db.scalar(select(func.count(DatabaseConnection.connection_id)).where(DatabaseConnection.is_monitored == True))
            total_audit_logs = await db.scalar(select(func.count(DatabaseAuditLog.log_id)))
            anomalous_activities = await db.scalar(select(func.count(DatabaseAuditLog.log_id)).where(DatabaseAuditLog.is_anomalous == True))
            pending_requests = await db.scalar(select(func.count(DatabaseAccessRequest.request_id)).where(DatabaseAccessRequest.status == "pending"))
            
            # Calculate security score
            security_score = self._calculate_security_score(
                encrypted_assets, open_incidents, anomalous_activities, pending_requests
            )
            
            return {
                "encryption": {
                    "total_keys": total_keys or 0,
                    "active_keys": active_keys or 0,
                    "encrypted_assets": encrypted_assets or 0
                },
                "dlp": {
                    "total_policies": total_policies or 0,
                    "active_policies": active_policies or 0,
                    "open_incidents": open_incidents or 0
                },
                "database_security": {
                    "monitored_databases": monitored_databases or 0,
                    "total_audit_logs": total_audit_logs or 0,
                    "anomalous_activities": anomalous_activities or 0,
                    "pending_requests": pending_requests or 0
                },
                "security_score": security_score
            }
            
        except Exception as e:
            logger.error("Failed to get dashboard stats", error=str(e))
            raise
    
    def _calculate_security_score(self, encrypted_assets: int, open_incidents: int, 
                                anomalous_activities: int, pending_requests: int) -> float:
        """Calculate overall security score (0-100)"""
        base_score = 100.0
        
        # Deduct points for security issues
        if open_incidents > 0:
            base_score -= min(open_incidents * 5, 30)  # Max 30 points deduction
        
        if anomalous_activities > 0:
            base_score -= min(anomalous_activities * 2, 20)  # Max 20 points deduction
        
        if pending_requests > 0:
            base_score -= min(pending_requests * 1, 10)  # Max 10 points deduction
        
        # Bonus for encrypted assets
        if encrypted_assets > 0:
            base_score += min(encrypted_assets * 0.5, 10)  # Max 10 points bonus
        
        return max(0.0, min(100.0, base_score))

# Global service instance
data_security_service = DataSecurityService() 