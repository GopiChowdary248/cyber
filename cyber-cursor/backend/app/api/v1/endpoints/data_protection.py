from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.services.data_protection_service import (
    data_protection_service,
    EncryptionKey,
    EncryptedData,
    DLPPolicy,
    DLPViolation,
    DatabaseActivity,
    DataProtectionSummary,
    EncryptionAlgorithm,
    DLPViolationType,
    DLPViolationSeverity,
    DLPViolationAction,
    DatabaseActivityType,
    DatabaseActivityRisk
)
from app.core.security import get_current_user

router = APIRouter()

# Encryption endpoints
@router.post("/encryption/keys", response_model=EncryptionKey)
async def create_encryption_key(
    name: str,
    algorithm: EncryptionAlgorithm,
    description: str = "",
    current_user: dict = Depends(get_current_user)
):
    """Create a new encryption key"""
    try:
        key = await data_protection_service.create_encryption_key(name, algorithm, description)
        return key
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create encryption key: {str(e)}")

@router.get("/encryption/keys", response_model=List[EncryptionKey])
async def get_encryption_keys(current_user: dict = Depends(get_current_user)):
    """Get all encryption keys"""
    try:
        keys = list(data_protection_service.encryption_keys.values())
        return keys
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve encryption keys: {str(e)}")

@router.post("/encryption/encrypt", response_model=EncryptedData)
async def encrypt_data(
    data: str,
    key_id: str,
    metadata: Optional[Dict[str, Any]] = None,
    current_user: dict = Depends(get_current_user)
):
    """Encrypt data using specified key"""
    try:
        encrypted_data = await data_protection_service.encrypt_data(data, key_id, metadata)
        return encrypted_data
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to encrypt data: {str(e)}")

@router.post("/encryption/decrypt")
async def decrypt_data(
    encrypted_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Decrypt data using the associated key"""
    try:
        decrypted_data = await data_protection_service.decrypt_data(encrypted_id)
        return {"decrypted_data": decrypted_data}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt data: {str(e)}")

@router.get("/encryption/data", response_model=List[EncryptedData])
async def get_encrypted_data(current_user: dict = Depends(get_current_user)):
    """Get all encrypted data records"""
    try:
        encrypted_data = list(data_protection_service.encrypted_data.values())
        return encrypted_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve encrypted data: {str(e)}")

# DLP endpoints
@router.post("/dlp/policies", response_model=DLPPolicy)
async def create_dlp_policy(
    name: str,
    description: str,
    patterns: List[str],
    violation_type: DLPViolationType,
    severity: DLPViolationSeverity,
    actions: List[DLPViolationAction],
    current_user: dict = Depends(get_current_user)
):
    """Create a new DLP policy"""
    try:
        policy = await data_protection_service.create_dlp_policy(
            name, description, patterns, violation_type, severity, actions
        )
        return policy
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create DLP policy: {str(e)}")

@router.get("/dlp/policies", response_model=List[DLPPolicy])
async def get_dlp_policies(current_user: dict = Depends(get_current_user)):
    """Get all DLP policies"""
    try:
        policies = list(data_protection_service.dlp_policies.values())
        return policies
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve DLP policies: {str(e)}")

@router.post("/dlp/scan", response_model=List[DLPViolation])
async def scan_content(
    content: str,
    source: str,
    current_user: dict = Depends(get_current_user)
):
    """Scan content for DLP violations"""
    try:
        violations = await data_protection_service.scan_content(content, source)
        return violations
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan content: {str(e)}")

@router.get("/dlp/violations", response_model=List[DLPViolation])
async def get_dlp_violations(
    status: Optional[str] = None,
    severity: Optional[DLPViolationSeverity] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get DLP violations with optional filtering"""
    try:
        violations = await data_protection_service.get_dlp_violations(status, severity)
        return violations
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve DLP violations: {str(e)}")

@router.put("/dlp/violations/{violation_id}/status")
async def update_violation_status(
    violation_id: str,
    status: str,
    current_user: dict = Depends(get_current_user)
):
    """Update DLP violation status"""
    try:
        if violation_id not in data_protection_service.dlp_violations:
            raise HTTPException(status_code=404, detail="Violation not found")
        
        violation = data_protection_service.dlp_violations[violation_id]
        violation.status = status
        if status == "resolved":
            violation.resolved_at = datetime.utcnow()
        
        return {"message": "Violation status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update violation status: {str(e)}")

# Database monitoring endpoints
@router.post("/database/activities", response_model=DatabaseActivity)
async def log_database_activity(
    database_name: str,
    table_name: str,
    activity_type: DatabaseActivityType,
    user: str,
    ip_address: str,
    query: str,
    current_user: dict = Depends(get_current_user)
):
    """Log database activity for monitoring"""
    try:
        activity = await data_protection_service.log_database_activity(
            database_name, table_name, activity_type, user, ip_address, query
        )
        return activity
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log database activity: {str(e)}")

@router.get("/database/activities", response_model=List[DatabaseActivity])
async def get_database_activities(
    risk_level: Optional[DatabaseActivityRisk] = None,
    is_suspicious: Optional[bool] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get database activities with optional filtering"""
    try:
        activities = await data_protection_service.get_database_activities(risk_level, is_suspicious)
        return activities
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve database activities: {str(e)}")

# Summary and reporting endpoints
@router.get("/summary", response_model=DataProtectionSummary)
async def get_data_protection_summary(current_user: dict = Depends(get_current_user)):
    """Get comprehensive data protection summary"""
    try:
        summary = await data_protection_service.get_data_protection_summary()
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve data protection summary: {str(e)}")

# Bulk operations
@router.post("/bulk/encrypt")
async def bulk_encrypt_data(
    data_list: List[Dict[str, Any]],
    key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Bulk encrypt multiple data items"""
    try:
        results = []
        for item in data_list:
            data = item.get("data", "")
            metadata = item.get("metadata")
            encrypted_data = await data_protection_service.encrypt_data(data, key_id, metadata)
            results.append(encrypted_data)
        return {"encrypted_items": results, "total_encrypted": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to bulk encrypt data: {str(e)}")

@router.post("/bulk/dlp-scan")
async def bulk_dlp_scan(
    content_list: List[Dict[str, str]],
    current_user: dict = Depends(get_current_user)
):
    """Bulk scan multiple content items for DLP violations"""
    try:
        all_violations = []
        for item in content_list:
            content = item.get("content", "")
            source = item.get("source", "unknown")
            violations = await data_protection_service.scan_content(content, source)
            all_violations.extend(violations)
        return {"violations": all_violations, "total_violations": len(all_violations)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to bulk scan content: {str(e)}")

# Health check
@router.get("/health")
async def data_protection_health(current_user: dict = Depends(get_current_user)):
    """Check data protection service health"""
    try:
        summary = await data_protection_service.get_data_protection_summary()
        return {
            "status": "healthy",
            "encryption": summary.encryption_health,
            "dlp": summary.dlp_health,
            "database_monitoring": summary.database_monitoring_health,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Data protection service health check failed: {str(e)}") 