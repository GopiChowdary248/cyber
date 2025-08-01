import asyncio
import structlog
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Optional, Any
import hashlib
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = structlog.get_logger()

class EncryptionAlgorithm(Enum):
    AES_256 = "aes_256"
    RSA_2048 = "rsa_2048"
    CHACHA20 = "chacha20"

class DLPViolationType(Enum):
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    API_KEY = "api_key"
    PASSWORD = "password"
    CUSTOM_PATTERN = "custom_pattern"

class DLPViolationSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DLPViolationAction(Enum):
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ENCRYPT = "encrypt"
    LOG = "log"
    NOTIFY = "notify"

class DatabaseActivityType(Enum):
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    DROP = "drop"
    ALTER = "alter"
    GRANT = "grant"
    REVOKE = "revoke"

class DatabaseActivityRisk(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class EncryptionKey:
    id: str
    name: str
    algorithm: EncryptionAlgorithm
    key_material: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool = True
    description: str = ""

@dataclass
class EncryptedData:
    id: str
    key_id: str
    algorithm: EncryptionAlgorithm
    encrypted_data: str
    iv: str
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DLPPolicy:
    id: str
    name: str
    description: str
    patterns: List[str]
    violation_type: DLPViolationType
    severity: DLPViolationSeverity
    actions: List[DLPViolationAction]
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class DLPViolation:
    id: str
    policy_id: str
    violation_type: DLPViolationType
    severity: DLPViolationSeverity
    detected_data: str
    source: str
    timestamp: datetime
    actions_taken: List[DLPViolationAction]
    status: str = "open"
    resolved_at: Optional[datetime] = None

@dataclass
class DatabaseActivity:
    id: str
    database_name: str
    table_name: str
    activity_type: DatabaseActivityType
    user: str
    ip_address: str
    query: str
    timestamp: datetime
    risk_level: DatabaseActivityRisk
    is_suspicious: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DataProtectionSummary:
    total_encrypted_files: int
    active_encryption_keys: int
    dlp_violations_today: int
    dlp_violations_week: int
    database_activities_today: int
    suspicious_activities: int
    encryption_health: str
    dlp_health: str
    database_monitoring_health: str

class DataProtectionService:
    def __init__(self):
        self.encryption_keys: Dict[str, EncryptionKey] = {}
        self.encrypted_data: Dict[str, EncryptedData] = {}
        self.dlp_policies: Dict[str, DLPPolicy] = {}
        self.dlp_violations: Dict[str, DLPViolation] = {}
        self.database_activities: Dict[str, DatabaseActivity] = {}
        self._encryption_worker_task: Optional[asyncio.Task] = None
        self._dlp_worker_task: Optional[asyncio.Task] = None
        self._database_monitoring_task: Optional[asyncio.Task] = None
        self._encryption_queue = asyncio.Queue()
        self._dlp_queue = asyncio.Queue()
        self._database_queue = asyncio.Queue()
        
        # Initialize sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize sample data for demonstration"""
        # Sample encryption keys
        key1 = EncryptionKey(
            id="key_001",
            name="Primary AES Key",
            algorithm=EncryptionAlgorithm.AES_256,
            key_material=base64.b64encode(Fernet.generate_key()).decode(),
            created_at=datetime.utcnow() - timedelta(days=30),
            description="Primary encryption key for sensitive data"
        )
        self.encryption_keys[key1.id] = key1
        
        # Sample DLP policies
        policy1 = DLPPolicy(
            id="dlp_001",
            name="Credit Card Detection",
            description="Detect and protect credit card numbers",
            patterns=[r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'],
            violation_type=DLPViolationType.CREDIT_CARD,
            severity=DLPViolationSeverity.HIGH,
            actions=[DLPViolationAction.BLOCK, DLPViolationAction.NOTIFY]
        )
        self.dlp_policies[policy1.id] = policy1
        
        policy2 = DLPPolicy(
            id="dlp_002",
            name="SSN Detection",
            description="Detect and protect Social Security Numbers",
            patterns=[r'\b\d{3}-\d{2}-\d{4}\b'],
            violation_type=DLPViolationType.SSN,
            severity=DLPViolationSeverity.CRITICAL,
            actions=[DLPViolationAction.QUARANTINE, DLPViolationAction.NOTIFY]
        )
        self.dlp_policies[policy2.id] = policy2
        
        # Sample DLP violations
        violation1 = DLPViolation(
            id="violation_001",
            policy_id="dlp_001",
            violation_type=DLPViolationType.CREDIT_CARD,
            severity=DLPViolationSeverity.HIGH,
            detected_data="****-****-****-1234",
            source="email_attachment.pdf",
            timestamp=datetime.utcnow() - timedelta(hours=2),
            actions_taken=[DLPViolationAction.BLOCK, DLPViolationAction.NOTIFY]
        )
        self.dlp_violations[violation1.id] = violation1
        
        # Sample database activities
        activity1 = DatabaseActivity(
            id="db_001",
            database_name="customer_db",
            table_name="users",
            activity_type=DatabaseActivityType.SELECT,
            user="admin",
            ip_address="192.168.1.100",
            query="SELECT * FROM users WHERE email = 'test@example.com'",
            timestamp=datetime.utcnow() - timedelta(minutes=30),
            risk_level=DatabaseActivityRisk.LOW
        )
        self.database_activities[activity1.id] = activity1
        
        activity2 = DatabaseActivity(
            id="db_002",
            database_name="customer_db",
            table_name="users",
            activity_type=DatabaseActivityType.UPDATE,
            user="unknown_user",
            ip_address="10.0.0.50",
            query="UPDATE users SET password = 'newpass' WHERE id = 1",
            timestamp=datetime.utcnow() - timedelta(minutes=15),
            risk_level=DatabaseActivityRisk.HIGH,
            is_suspicious=True
        )
        self.database_activities[activity2.id] = activity2
    
    async def start_data_protection_service(self):
        """Start the data protection service and background workers"""
        logger.info("Starting Data Protection Service")
        
        # Start background workers
        self._encryption_worker_task = asyncio.create_task(self._encryption_worker())
        self._dlp_worker_task = asyncio.create_task(self._dlp_worker())
        self._database_monitoring_task = asyncio.create_task(self._database_monitoring_worker())
        
        logger.info("Data Protection Service started successfully")
    
    async def stop_data_protection_service(self):
        """Stop the data protection service and background workers"""
        logger.info("Stopping Data Protection Service")
        
        if self._encryption_worker_task:
            self._encryption_worker_task.cancel()
        if self._dlp_worker_task:
            self._dlp_worker_task.cancel()
        if self._database_monitoring_task:
            self._database_monitoring_task.cancel()
        
        logger.info("Data Protection Service stopped")
    
    async def _encryption_worker(self):
        """Background worker for encryption operations"""
        while True:
            try:
                task = await self._encryption_queue.get()
                if task is None:
                    break
                
                operation, data = task
                if operation == "encrypt":
                    await self._process_encryption(data)
                elif operation == "decrypt":
                    await self._process_decryption(data)
                
                self._encryption_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Encryption worker error", error=str(e))
    
    async def _dlp_worker(self):
        """Background worker for DLP operations"""
        while True:
            try:
                task = await self._dlp_queue.get()
                if task is None:
                    break
                
                content, source = task
                await self._process_dlp_scan(content, source)
                
                self._dlp_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("DLP worker error", error=str(e))
    
    async def _database_monitoring_worker(self):
        """Background worker for database activity monitoring"""
        while True:
            try:
                activity = await self._database_queue.get()
                if activity is None:
                    break
                
                await self._process_database_activity(activity)
                
                self._database_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Database monitoring worker error", error=str(e))
    
    async def _process_encryption(self, data: Dict[str, Any]):
        """Process encryption operation"""
        await asyncio.sleep(1)  # Simulate processing time
        logger.info("Encryption processed", data_id=data.get("id"))
    
    async def _process_decryption(self, data: Dict[str, Any]):
        """Process decryption operation"""
        await asyncio.sleep(1)  # Simulate processing time
        logger.info("Decryption processed", data_id=data.get("id"))
    
    async def _process_dlp_scan(self, content: str, source: str):
        """Process DLP scan for violations"""
        await asyncio.sleep(0.5)  # Simulate processing time
        
        violations = []
        for policy in self.dlp_policies.values():
            if not policy.is_active:
                continue
            
            for pattern in policy.patterns:
                # Simple pattern matching simulation
                if any(pattern_type in content.lower() for pattern_type in ["credit", "card", "ssn", "social"]):
                    violation = DLPViolation(
                        id=f"violation_{len(self.dlp_violations) + 1}",
                        policy_id=policy.id,
                        violation_type=policy.violation_type,
                        severity=policy.severity,
                        detected_data=content[:50] + "..." if len(content) > 50 else content,
                        source=source,
                        timestamp=datetime.utcnow(),
                        actions_taken=policy.actions
                    )
                    violations.append(violation)
                    self.dlp_violations[violation.id] = violation
        
        if violations:
            logger.info("DLP violations detected", count=len(violations), source=source)
    
    async def _process_database_activity(self, activity: DatabaseActivity):
        """Process database activity for monitoring"""
        await asyncio.sleep(0.2)  # Simulate processing time
        
        # Risk assessment logic
        if activity.activity_type in [DatabaseActivityType.DELETE, DatabaseActivityType.DROP]:
            activity.risk_level = DatabaseActivityRisk.HIGH
        elif activity.activity_type == DatabaseActivityType.UPDATE and "password" in activity.query.lower():
            activity.risk_level = DatabaseActivityRisk.HIGH
            activity.is_suspicious = True
        
        self.database_activities[activity.id] = activity
        logger.info("Database activity processed", activity_id=activity.id, risk_level=activity.risk_level.value)
    
    # Encryption methods
    async def create_encryption_key(self, name: str, algorithm: EncryptionAlgorithm, description: str = "") -> EncryptionKey:
        """Create a new encryption key"""
        key_id = f"key_{len(self.encryption_keys) + 1:03d}"
        
        if algorithm == EncryptionAlgorithm.AES_256:
            key_material = base64.b64encode(Fernet.generate_key()).decode()
        else:
            # Simulate other algorithms
            key_material = base64.b64encode(hashlib.sha256(f"{name}_{datetime.utcnow()}".encode()).digest()).decode()
        
        key = EncryptionKey(
            id=key_id,
            name=name,
            algorithm=algorithm,
            key_material=key_material,
            created_at=datetime.utcnow(),
            description=description
        )
        
        self.encryption_keys[key_id] = key
        logger.info("Encryption key created", key_id=key_id, algorithm=algorithm.value)
        return key
    
    async def encrypt_data(self, data: str, key_id: str, metadata: Dict[str, Any] = None) -> EncryptedData:
        """Encrypt data using specified key"""
        if key_id not in self.encryption_keys:
            raise ValueError(f"Encryption key {key_id} not found")
        
        key = self.encryption_keys[key_id]
        
        # Simulate encryption
        encrypted_data = base64.b64encode(data.encode()).decode()
        iv = base64.b64encode(hashlib.md5(f"{key_id}_{datetime.utcnow()}".encode()).digest()).decode()
        
        encrypted_record = EncryptedData(
            id=f"enc_{len(self.encrypted_data) + 1:03d}",
            key_id=key_id,
            algorithm=key.algorithm,
            encrypted_data=encrypted_data,
            iv=iv,
            created_at=datetime.utcnow(),
            metadata=metadata or {}
        )
        
        self.encrypted_data[encrypted_record.id] = encrypted_record
        
        # Queue for background processing
        await self._encryption_queue.put(("encrypt", {"id": encrypted_record.id, "data": data}))
        
        logger.info("Data encrypted", encrypted_id=encrypted_record.id, key_id=key_id)
        return encrypted_record
    
    async def decrypt_data(self, encrypted_id: str) -> str:
        """Decrypt data using the associated key"""
        if encrypted_id not in self.encrypted_data:
            raise ValueError(f"Encrypted data {encrypted_id} not found")
        
        encrypted_record = self.encrypted_data[encrypted_id]
        
        # Simulate decryption
        decrypted_data = base64.b64decode(encrypted_record.encrypted_data).decode()
        
        # Queue for background processing
        await self._encryption_queue.put(("decrypt", {"id": encrypted_id, "data": decrypted_data}))
        
        logger.info("Data decrypted", encrypted_id=encrypted_id)
        return decrypted_data
    
    # DLP methods
    async def create_dlp_policy(self, name: str, description: str, patterns: List[str], 
                               violation_type: DLPViolationType, severity: DLPViolationSeverity,
                               actions: List[DLPViolationAction]) -> DLPPolicy:
        """Create a new DLP policy"""
        policy_id = f"dlp_{len(self.dlp_policies) + 1:03d}"
        
        policy = DLPPolicy(
            id=policy_id,
            name=name,
            description=description,
            patterns=patterns,
            violation_type=violation_type,
            severity=severity,
            actions=actions
        )
        
        self.dlp_policies[policy_id] = policy
        logger.info("DLP policy created", policy_id=policy_id, name=name)
        return policy
    
    async def scan_content(self, content: str, source: str) -> List[DLPViolation]:
        """Scan content for DLP violations"""
        # Queue for background processing
        await self._dlp_queue.put((content, source))
        
        # Return existing violations for this source
        violations = [v for v in self.dlp_violations.values() if v.source == source]
        return violations
    
    async def get_dlp_violations(self, status: str = None, severity: DLPViolationSeverity = None) -> List[DLPViolation]:
        """Get DLP violations with optional filtering"""
        violations = list(self.dlp_violations.values())
        
        if status:
            violations = [v for v in violations if v.status == status]
        if severity:
            violations = [v for v in violations if v.severity == severity]
        
        return sorted(violations, key=lambda x: x.timestamp, reverse=True)
    
    # Database monitoring methods
    async def log_database_activity(self, database_name: str, table_name: str, activity_type: DatabaseActivityType,
                                   user: str, ip_address: str, query: str) -> DatabaseActivity:
        """Log database activity for monitoring"""
        activity = DatabaseActivity(
            id=f"db_{len(self.database_activities) + 1:03d}",
            database_name=database_name,
            table_name=table_name,
            activity_type=activity_type,
            user=user,
            ip_address=ip_address,
            query=query,
            timestamp=datetime.utcnow(),
            risk_level=DatabaseActivityRisk.LOW
        )
        
        # Queue for background processing
        await self._database_queue.put(activity)
        
        logger.info("Database activity logged", activity_id=activity.id, activity_type=activity_type.value)
        return activity
    
    async def get_database_activities(self, risk_level: DatabaseActivityRisk = None, 
                                    is_suspicious: bool = None) -> List[DatabaseActivity]:
        """Get database activities with optional filtering"""
        activities = list(self.database_activities.values())
        
        if risk_level:
            activities = [a for a in activities if a.risk_level == risk_level]
        if is_suspicious is not None:
            activities = [a for a in activities if a.is_suspicious == is_suspicious]
        
        return sorted(activities, key=lambda x: x.timestamp, reverse=True)
    
    # Summary and reporting methods
    async def get_data_protection_summary(self) -> DataProtectionSummary:
        """Get comprehensive data protection summary"""
        now = datetime.utcnow()
        today = now.date()
        week_ago = now - timedelta(days=7)
        
        # Calculate metrics
        total_encrypted_files = len(self.encrypted_data)
        active_encryption_keys = len([k for k in self.encryption_keys.values() if k.is_active])
        
        dlp_violations_today = len([v for v in self.dlp_violations.values() 
                                   if v.timestamp.date() == today])
        dlp_violations_week = len([v for v in self.dlp_violations.values() 
                                  if v.timestamp >= week_ago])
        
        database_activities_today = len([a for a in self.database_activities.values() 
                                        if a.timestamp.date() == today])
        suspicious_activities = len([a for a in self.database_activities.values() 
                                   if a.is_suspicious])
        
        # Health status
        encryption_health = "healthy" if active_encryption_keys > 0 else "warning"
        dlp_health = "healthy" if len(self.dlp_policies) > 0 else "warning"
        database_monitoring_health = "healthy" if database_activities_today > 0 else "warning"
        
        return DataProtectionSummary(
            total_encrypted_files=total_encrypted_files,
            active_encryption_keys=active_encryption_keys,
            dlp_violations_today=dlp_violations_today,
            dlp_violations_week=dlp_violations_week,
            database_activities_today=database_activities_today,
            suspicious_activities=suspicious_activities,
            encryption_health=encryption_health,
            dlp_health=dlp_health,
            database_monitoring_health=database_monitoring_health
        )

# Global instance
data_protection_service = DataProtectionService() 