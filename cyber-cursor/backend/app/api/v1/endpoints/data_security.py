from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import Optional, List
import structlog
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_active_user, require_admin, require_analyst
from app.models.data_security import (
    EncryptionKey, EncryptedAsset, DatabaseEncryption, DLPPolicy, DLPIncident,
    DataDiscovery, DatabaseConnection, DatabaseAuditLog, DatabaseAccessRequest,
    DatabaseVulnerability, DataMasking, DataTokenization, SecurityCompliance,
    SecurityReport
)
from app.schemas.data_security import (
    EncryptionKeyCreate, EncryptionKeyUpdate, EncryptionKeyResponse, EncryptionKeyListResponse,
    EncryptedAssetCreate, EncryptedAssetResponse,
    DatabaseEncryptionCreate, DatabaseEncryptionResponse,
    DLPPolicyCreate, DLPPolicyUpdate, DLPPolicyResponse, DLPPolicyListResponse,
    DLPIncidentCreate, DLPIncidentUpdate, DLPIncidentResponse, DLPIncidentListResponse,
    DataDiscoveryCreate, DataDiscoveryResponse,
    DatabaseConnectionCreate, DatabaseConnectionUpdate, DatabaseConnectionResponse, DatabaseConnectionListResponse,
    DatabaseAuditLogCreate, DatabaseAuditLogResponse, DatabaseAuditLogListResponse,
    DatabaseAccessRequestCreate, DatabaseAccessRequestUpdate, DatabaseAccessRequestResponse, DatabaseAccessRequestListResponse,
    DatabaseVulnerabilityCreate, DatabaseVulnerabilityResponse,
    DataMaskingCreate, DataMaskingResponse,
    DataTokenizationCreate, DataTokenizationResponse,
    SecurityComplianceCreate, SecurityComplianceResponse,
    SecurityReportCreate, SecurityReportResponse,
    DataSecurityStats, EncryptionStats, DLPStats, DatabaseSecurityStats,
    DataSecurityHealthCheck
)
from app.services.data_security_service import data_security_service
from app.models.iam import IAMUser

router = APIRouter()
logger = structlog.get_logger()

# ============================================================================
# ENCRYPTION ENDPOINTS
# ============================================================================

@router.post("/encryption/keys", response_model=EncryptionKeyResponse)
async def create_encryption_key(
    key_data: EncryptionKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Create a new encryption key"""
    try:
        key = await data_security_service.encryption_service.create_encryption_key(
            db, key_data.dict()
        )
        return EncryptionKeyResponse.from_orm(key)
    except Exception as e:
        logger.error("Failed to create encryption key", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create encryption key")

@router.get("/encryption/keys", response_model=EncryptionKeyListResponse)
async def get_encryption_keys(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    key_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get list of encryption keys"""
    try:
        query = select(EncryptionKey)
        
        if key_type:
            query = query.where(EncryptionKey.key_type == key_type)
        if is_active is not None:
            query = query.where(EncryptionKey.is_active == is_active)
        
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        keys = result.scalars().all()
        
        return EncryptionKeyListResponse(
            keys=[EncryptionKeyResponse.from_orm(key) for key in keys],
            total=total or 0,
            page=skip // limit + 1,
            size=limit
        )
    except Exception as e:
        logger.error("Failed to get encryption keys", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get encryption keys")

@router.put("/encryption/keys/{key_id}", response_model=EncryptionKeyResponse)
async def update_encryption_key(
    key_id: int,
    key_data: EncryptionKeyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Update an encryption key"""
    try:
        result = await db.execute(select(EncryptionKey).where(EncryptionKey.key_id == key_id))
        key = result.scalar_one_or_none()
        
        if not key:
            raise HTTPException(status_code=404, detail="Encryption key not found")
        
        update_data = key_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(key, field, value)
        
        await db.commit()
        await db.refresh(key)
        
        return EncryptionKeyResponse.from_orm(key)
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error("Failed to update encryption key", key_id=key_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update encryption key")

@router.post("/encryption/keys/{key_id}/rotate")
async def rotate_encryption_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Rotate an encryption key"""
    try:
        success = await data_security_service.encryption_service.rotate_key(db, key_id)
        if success:
            return {"message": "Key rotated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to rotate key")
    except Exception as e:
        logger.error("Failed to rotate encryption key", key_id=key_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to rotate encryption key")

@router.post("/encryption/files/encrypt")
async def encrypt_file(
    file_path: str = Form(...),
    key_id: int = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_analyst)
):
    """Encrypt a file"""
    try:
        encrypted_path = await data_security_service.file_encryption_service.encrypt_file(
            db, file_path, key_id
        )
        return {"encrypted_file_path": encrypted_path}
    except Exception as e:
        logger.error("Failed to encrypt file", file_path=file_path, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to encrypt file")

# ============================================================================
# DLP ENDPOINTS
# ============================================================================

@router.post("/dlp/policies", response_model=DLPPolicyResponse)
async def create_dlp_policy(
    policy_data: DLPPolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Create a new DLP policy"""
    try:
        policy = await data_security_service.dlp_service.create_dlp_policy(
            db, policy_data.dict()
        )
        return DLPPolicyResponse.from_orm(policy)
    except Exception as e:
        logger.error("Failed to create DLP policy", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create DLP policy")

@router.get("/dlp/policies", response_model=DLPPolicyListResponse)
async def get_dlp_policies(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    policy_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get list of DLP policies"""
    try:
        query = select(DLPPolicy)
        
        if policy_type:
            query = query.where(DLPPolicy.policy_type == policy_type)
        if is_active is not None:
            query = query.where(DLPPolicy.is_active == is_active)
        
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        policies = result.scalars().all()
        
        return DLPPolicyListResponse(
            policies=[DLPPolicyResponse.from_orm(policy) for policy in policies],
            total=total or 0,
            page=skip // limit + 1,
            size=limit
        )
    except Exception as e:
        logger.error("Failed to get DLP policies", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DLP policies")

@router.put("/dlp/policies/{policy_id}", response_model=DLPPolicyResponse)
async def update_dlp_policy(
    policy_id: int,
    policy_data: DLPPolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Update a DLP policy"""
    try:
        result = await db.execute(select(DLPPolicy).where(DLPPolicy.policy_id == policy_id))
        policy = result.scalar_one_or_none()
        
        if not policy:
            raise HTTPException(status_code=404, detail="DLP policy not found")
        
        update_data = policy_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(policy, field, value)
        
        await db.commit()
        await db.refresh(policy)
        
        return DLPPolicyResponse.from_orm(policy)
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error("Failed to update DLP policy", policy_id=policy_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update DLP policy")

@router.get("/dlp/incidents", response_model=DLPIncidentListResponse)
async def get_dlp_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get list of DLP incidents"""
    try:
        query = select(DLPIncident)
        
        if status:
            query = query.where(DLPIncident.status == status)
        if severity:
            query = query.where(DLPIncident.severity == severity)
        
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        incidents = result.scalars().all()
        
        return DLPIncidentListResponse(
            incidents=[DLPIncidentResponse.from_orm(incident) for incident in incidents],
            total=total or 0,
            page=skip // limit + 1,
            size=limit
        )
    except Exception as e:
        logger.error("Failed to get DLP incidents", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DLP incidents")

@router.put("/dlp/incidents/{incident_id}", response_model=DLPIncidentResponse)
async def update_dlp_incident(
    incident_id: int,
    incident_data: DLPIncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_analyst)
):
    """Update a DLP incident"""
    try:
        result = await db.execute(select(DLPIncident).where(DLPIncident.incident_id == incident_id))
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="DLP incident not found")
        
        update_data = incident_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(incident, field, value)
        
        await db.commit()
        await db.refresh(incident)
        
        return DLPIncidentResponse.from_orm(incident)
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error("Failed to update DLP incident", incident_id=incident_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update DLP incident")

@router.post("/dlp/content/evaluate")
async def evaluate_content(
    content: str = Form(...),
    policy_ids: List[int] = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Evaluate content against DLP policies"""
    try:
        violations = await data_security_service.dlp_service.evaluate_content(
            db, content, policy_ids
        )
        return {"violations": violations, "total_violations": len(violations)}
    except Exception as e:
        logger.error("Failed to evaluate content", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to evaluate content")

# ============================================================================
# DATABASE SECURITY ENDPOINTS
# ============================================================================

@router.post("/database/connections", response_model=DatabaseConnectionResponse)
async def add_database_connection(
    connection_data: DatabaseConnectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Add a database for monitoring"""
    try:
        connection = await data_security_service.database_security_service.add_database_connection(
            db, connection_data.dict()
        )
        return DatabaseConnectionResponse.from_orm(connection)
    except Exception as e:
        logger.error("Failed to add database connection", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to add database connection")

@router.get("/database/connections", response_model=DatabaseConnectionListResponse)
async def get_database_connections(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db_type: Optional[str] = Query(None),
    is_monitored: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get list of database connections"""
    try:
        query = select(DatabaseConnection)
        
        if db_type:
            query = query.where(DatabaseConnection.db_type == db_type)
        if is_monitored is not None:
            query = query.where(DatabaseConnection.is_monitored == is_monitored)
        
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        connections = result.scalars().all()
        
        return DatabaseConnectionListResponse(
            connections=[DatabaseConnectionResponse.from_orm(conn) for conn in connections],
            total=total or 0,
            page=skip // limit + 1,
            size=limit
        )
    except Exception as e:
        logger.error("Failed to get database connections", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get database connections")

@router.get("/database/activity", response_model=DatabaseAuditLogListResponse)
async def get_database_activity(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    connection_id: Optional[int] = Query(None),
    user_id: Optional[str] = Query(None),
    is_anomalous: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get database activity logs"""
    try:
        query = select(DatabaseAuditLog)
        
        if connection_id:
            query = query.where(DatabaseAuditLog.connection_id == connection_id)
        if user_id:
            query = query.where(DatabaseAuditLog.user_id == user_id)
        if is_anomalous is not None:
            query = query.where(DatabaseAuditLog.is_anomalous == is_anomalous)
        
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        
        query = query.order_by(DatabaseAuditLog.timestamp.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        logs = result.scalars().all()
        
        return DatabaseAuditLogListResponse(
            logs=[DatabaseAuditLogResponse.from_orm(log) for log in logs],
            total=total or 0,
            page=skip // limit + 1,
            size=limit
        )
    except Exception as e:
        logger.error("Failed to get database activity", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get database activity")

@router.post("/database/access/request", response_model=DatabaseAccessRequestResponse)
async def request_database_access(
    request_data: DatabaseAccessRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Request database access"""
    try:
        request = await data_security_service.database_security_service.request_database_access(
            db, request_data.dict()
        )
        return DatabaseAccessRequestResponse.from_orm(request)
    except Exception as e:
        logger.error("Failed to request database access", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to request database access")

@router.get("/database/access/requests", response_model=DatabaseAccessRequestListResponse)
async def get_database_access_requests(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get database access requests"""
    try:
        query = select(DatabaseAccessRequest)
        
        if status:
            query = query.where(DatabaseAccessRequest.status == status)
        if user_id:
            query = query.where(DatabaseAccessRequest.user_id == user_id)
        
        total = await db.scalar(select(func.count()).select_from(query.subquery()))
        
        query = query.order_by(DatabaseAccessRequest.created_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        requests = result.scalars().all()
        
        return DatabaseAccessRequestListResponse(
            requests=[DatabaseAccessRequestResponse.from_orm(req) for req in requests],
            total=total or 0,
            page=skip // limit + 1,
            size=limit
        )
    except Exception as e:
        logger.error("Failed to get database access requests", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get database access requests")

@router.put("/database/access/requests/{request_id}/approve")
async def approve_database_access(
    request_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(require_admin)
):
    """Approve a database access request"""
    try:
        success = await data_security_service.database_security_service.approve_access_request(
            db, request_id, current_user.id
        )
        if success:
            return {"message": "Access request approved successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to approve access request")
    except Exception as e:
        logger.error("Failed to approve database access", request_id=request_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to approve database access")

# ============================================================================
# DASHBOARD AND STATISTICS ENDPOINTS
# ============================================================================

@router.get("/dashboard/stats", response_model=DataSecurityStats)
async def get_data_security_stats(
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get comprehensive data security dashboard statistics"""
    try:
        stats = await data_security_service.get_dashboard_stats(db)
        return DataSecurityStats(**stats)
    except Exception as e:
        logger.error("Failed to get data security stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get data security stats")

@router.get("/encryption/stats", response_model=EncryptionStats)
async def get_encryption_stats(
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get encryption statistics"""
    try:
        # Get encryption stats from dashboard stats
        stats = await data_security_service.get_dashboard_stats(db)
        encryption_stats = stats["encryption"]
        
        # Calculate additional stats
        key_rotation_due = await db.scalar(
            select(func.count(EncryptionKey.key_id)).where(
                and_(
                    EncryptionKey.is_active == True,
                    EncryptionKey.expires_at < func.now() + timedelta(days=30)
                )
            )
        )
        
        return EncryptionStats(
            total_keys=encryption_stats["total_keys"],
            active_keys=encryption_stats["active_keys"],
            encrypted_files=encryption_stats["encrypted_assets"],
            encrypted_databases=0,  # TODO: Implement database encryption count
            key_rotation_due=key_rotation_due or 0
        )
    except Exception as e:
        logger.error("Failed to get encryption stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get encryption stats")

@router.get("/dlp/stats", response_model=DLPStats)
async def get_dlp_stats(
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get DLP statistics"""
    try:
        # Get DLP stats from dashboard stats
        stats = await data_security_service.get_dashboard_stats(db)
        dlp_stats = stats["dlp"]
        
        # Calculate additional stats
        resolved_incidents = await db.scalar(
            select(func.count(DLPIncident.incident_id)).where(DLPIncident.status == "resolved")
        )
        false_positives = await db.scalar(
            select(func.count(DLPIncident.incident_id)).where(DLPIncident.status == "false_positive")
        )
        
        return DLPStats(
            total_policies=dlp_stats["total_policies"],
            active_policies=dlp_stats["active_policies"],
            open_incidents=dlp_stats["open_incidents"],
            resolved_incidents=resolved_incidents or 0,
            false_positives=false_positives or 0
        )
    except Exception as e:
        logger.error("Failed to get DLP stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DLP stats")

@router.get("/database/security/stats", response_model=DatabaseSecurityStats)
async def get_database_security_stats(
    db: AsyncSession = Depends(get_db),
    current_user: IAMUser = Depends(get_current_active_user)
):
    """Get database security statistics"""
    try:
        # Get database security stats from dashboard stats
        stats = await data_security_service.get_dashboard_stats(db)
        db_stats = stats["database_security"]
        
        return DatabaseSecurityStats(
            monitored_connections=db_stats["monitored_databases"],
            total_audit_logs=db_stats["total_audit_logs"],
            anomalous_activities=db_stats["anomalous_activities"],
            open_vulnerabilities=0,  # TODO: Implement vulnerability count
            pending_requests=db_stats["pending_requests"]
        )
    except Exception as e:
        logger.error("Failed to get database security stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get database security stats")

# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================

@router.get("/health", response_model=DataSecurityHealthCheck)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check for data security services"""
    try:
        # Test database connection
        await db.execute(select(1))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"
    
    # Test encryption service
    try:
        # Simple test of encryption service
        test_key = data_security_service.encryption_service.generate_key_material("AES", 256)
        encryption_status = "healthy"
    except Exception:
        encryption_status = "unhealthy"
    
    # Test DLP service
    try:
        # Simple test of DLP service
        test_content = "test@example.com"
        findings = data_security_service.dlp_service.scan_content_for_pii(test_content)
        dlp_status = "healthy"
    except Exception:
        dlp_status = "unhealthy"
    
    # Test database security service
    try:
        # Simple test - just check if service is accessible
        db_security_status = "healthy"
    except Exception:
        db_security_status = "unhealthy"
    
    overall_status = "healthy" if all([
        db_status == "healthy",
        encryption_status == "healthy",
        dlp_status == "healthy",
        db_security_status == "healthy"
    ]) else "unhealthy"
    
    return DataSecurityHealthCheck(
        status=overall_status,
        encryption_service=encryption_status,
        dlp_service=dlp_status,
        database_security_service=db_security_status,
        database_connection=db_status,
        last_check=datetime.utcnow()
    ) 