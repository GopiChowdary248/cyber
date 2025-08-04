from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON, Float, LargeBinary
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

# Encryption Management Models
class EncryptionKey(Base):
    __tablename__ = "encryption_keys"
    
    key_id = Column(Integer, primary_key=True, index=True)
    key_name = Column(String(255), nullable=False, unique=True)
    key_type = Column(String(50), nullable=False)  # AES, RSA, etc.
    key_size = Column(Integer, nullable=False)
    encrypted_key = Column(Text, nullable=False)  # Encrypted key material
    key_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    encrypted_assets = relationship("EncryptedAsset", back_populates="key")
    database_encryption = relationship("DatabaseEncryption", back_populates="key")

class EncryptedAsset(Base):
    __tablename__ = "encrypted_assets"
    
    asset_id = Column(Integer, primary_key=True, index=True)
    asset_type = Column(String(50), nullable=False)  # file, database, backup
    asset_path = Column(String(500), nullable=False)
    key_id = Column(Integer, ForeignKey("encryption_keys.key_id"), nullable=False)
    encryption_status = Column(String(50), default="encrypted")
    last_encrypted = Column(DateTime(timezone=True), server_default=func.now())
    asset_metadata = Column(JSON, nullable=True)
    
    # Relationships
    key = relationship("EncryptionKey", back_populates="encrypted_assets")

class DatabaseEncryption(Base):
    __tablename__ = "database_encryption"
    
    encryption_id = Column(Integer, primary_key=True, index=True)
    database_name = Column(String(255), nullable=False)
    table_name = Column(String(255), nullable=False)
    column_name = Column(String(255), nullable=False)
    key_id = Column(Integer, ForeignKey("encryption_keys.key_id"), nullable=False)
    encryption_type = Column(String(50), nullable=False)  # column, table, backup
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)
    
    # Relationships
    key = relationship("EncryptionKey", back_populates="database_encryption")

# DLP Management Models
class DLPPolicy(Base):
    __tablename__ = "dlp_policies"
    
    policy_id = Column(Integer, primary_key=True, index=True)
    policy_name = Column(String(255), nullable=False, unique=True)
    policy_type = Column(String(50), nullable=False)  # email, file, database, cloud
    policy_rules = Column(JSON, nullable=False)
    enforcement_level = Column(String(50), default="monitor")  # monitor, block, quarantine
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    incidents = relationship("DLPIncident", back_populates="policy")

class DLPIncident(Base):
    __tablename__ = "dlp_incidents"
    
    incident_id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("dlp_policies.policy_id"), nullable=False)
    user_id = Column(Integer, nullable=True)
    file_path = Column(String(500), nullable=True)
    content_type = Column(String(100), nullable=True)
    violation_type = Column(String(100), nullable=False)
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    status = Column(String(50), default="open")  # open, investigating, resolved, false_positive
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Relationships
    policy = relationship("DLPPolicy", back_populates="incidents")

class DataDiscovery(Base):
    __tablename__ = "data_discovery"
    
    discovery_id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)  # endpoint, cloud, database, email
    target_path = Column(String(500), nullable=False)
    discovered_data = Column(JSON, nullable=False)
    classification = Column(String(50), nullable=False)  # public, internal, confidential, restricted
    scan_date = Column(DateTime(timezone=True), server_default=func.now())
    is_processed = Column(Boolean, default=False)

# Database Security Models
class DatabaseConnection(Base):
    __tablename__ = "database_connections"
    
    connection_id = Column(Integer, primary_key=True, index=True)
    db_name = Column(String(255), nullable=False)
    db_type = Column(String(50), nullable=False)  # postgresql, mysql, oracle, sqlserver
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=True)
    connection_string = Column(Text, nullable=True)  # Encrypted connection string
    is_monitored = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    audit_logs = relationship("DatabaseAuditLog", back_populates="connection")
    access_requests = relationship("DatabaseAccessRequest", back_populates="connection")

class DatabaseAuditLog(Base):
    __tablename__ = "database_audit_logs"
    
    log_id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(Integer, ForeignKey("database_connections.connection_id"), nullable=False)
    user_id = Column(String(255), nullable=True)
    query_text = Column(Text, nullable=True)
    query_type = Column(String(50), nullable=True)  # SELECT, INSERT, UPDATE, DELETE, DDL
    execution_time = Column(Integer, nullable=True)  # milliseconds
    rows_affected = Column(Integer, nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    is_anomalous = Column(Boolean, default=False)
    
    # Relationships
    connection = relationship("DatabaseConnection", back_populates="audit_logs")

class DatabaseAccessRequest(Base):
    __tablename__ = "database_access_requests"
    
    request_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    connection_id = Column(Integer, ForeignKey("database_connections.connection_id"), nullable=False)
    access_type = Column(String(50), nullable=False)  # read, write, admin
    reason = Column(Text, nullable=False)
    requested_duration = Column(Integer, nullable=False)  # minutes
    status = Column(String(50), default="pending")  # pending, approved, denied, expired
    approved_by = Column(Integer, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    connection = relationship("DatabaseConnection", back_populates="access_requests")

class DatabaseVulnerability(Base):
    __tablename__ = "database_vulnerabilities"
    
    vulnerability_id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(Integer, ForeignKey("database_connections.connection_id"), nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    description = Column(Text, nullable=False)
    remediation_steps = Column(Text, nullable=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    is_resolved = Column(Boolean, default=False)

# Data Protection Models
class DataMasking(Base):
    __tablename__ = "data_masking"
    
    masking_id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(Integer, ForeignKey("database_connections.connection_id"), nullable=False)
    table_name = Column(String(255), nullable=False)
    column_name = Column(String(255), nullable=False)
    masking_type = Column(String(50), nullable=False)  # hash, random, fixed, custom
    masking_rules = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)

class DataTokenization(Base):
    __tablename__ = "data_tokenization"
    
    tokenization_id = Column(Integer, primary_key=True, index=True)
    connection_id = Column(Integer, ForeignKey("database_connections.connection_id"), nullable=False)
    table_name = Column(String(255), nullable=False)
    column_name = Column(String(255), nullable=False)
    token_type = Column(String(50), nullable=False)  # format_preserving, random, hash
    token_format = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)

# Compliance and Reporting Models
class SecurityCompliance(Base):
    __tablename__ = "security_compliance"
    
    compliance_id = Column(Integer, primary_key=True, index=True)
    framework = Column(String(50), nullable=False)  # pci_dss, hipaa, gdpr, sox, iso27001
    requirement = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)  # compliant, non_compliant, partial
    evidence = Column(Text, nullable=True)
    last_assessed = Column(DateTime(timezone=True), server_default=func.now())
    next_assessment = Column(DateTime(timezone=True), nullable=True)

class SecurityReport(Base):
    __tablename__ = "security_reports"
    
    report_id = Column(Integer, primary_key=True, index=True)
    report_type = Column(String(50), nullable=False)  # daily, weekly, monthly, compliance
    report_data = Column(JSON, nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    generated_by = Column(Integer, nullable=True)
    report_path = Column(String(500), nullable=True) 