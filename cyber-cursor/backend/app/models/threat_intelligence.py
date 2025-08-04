from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

Base = declarative_base()

class ThreatFeedType(enum.Enum):
    MISP = "misp"
    RECORDED_FUTURE = "recorded_future"
    ANOMALI = "anomali"
    IBM_XFORCE = "ibm_xforce"
    VIRUSTOTAL = "virustotal"
    CUSTOM = "custom"

class IoCType(enum.Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"

class ThreatLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FeedStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    feed_type = Column(Enum(ThreatFeedType), nullable=False)
    url = Column(String(500), nullable=False)
    api_key = Column(Text, nullable=True)  # Encrypted
    status = Column(Enum(FeedStatus), default=FeedStatus.INACTIVE)
    last_update = Column(DateTime(timezone=True), nullable=True)
    update_frequency = Column(Integer, default=3600)  # seconds
    description = Column(Text, nullable=True)
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    iocs = relationship("IoC", back_populates="feed")
    feed_logs = relationship("FeedLog", back_populates="feed")

class IoC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(1000), nullable=False, index=True)
    ioc_type = Column(Enum(IoCType), nullable=False)
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.MEDIUM)
    confidence_score = Column(Float, default=0.0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    feed_id = Column(Integer, ForeignKey("threat_feeds.id"))
    tags = Column(JSON, default=list)
    ioc_metadata = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    feed = relationship("ThreatFeed", back_populates="iocs")
    alerts = relationship("ThreatAlert", back_populates="ioc")
    correlations = relationship("IoCCorrelation", back_populates="ioc")

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"))
    threat_level = Column(Enum(ThreatLevel), nullable=False)
    source = Column(String(255), nullable=False)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(255), nullable=True)
    alert_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    ioc = relationship("IoC", back_populates="alerts")

class IoCCorrelation(Base):
    __tablename__ = "ioc_correlations"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"))
    correlated_ioc_id = Column(Integer, ForeignKey("iocs.id"))
    correlation_type = Column(String(100), nullable=False)  # "same_family", "related_attack", etc.
    confidence_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    ioc = relationship("IoC", back_populates="correlations")

class FeedLog(Base):
    __tablename__ = "feed_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id"))
    status = Column(String(50), nullable=False)  # "success", "error", "partial"
    message = Column(Text, nullable=True)
    iocs_added = Column(Integer, default=0)
    iocs_updated = Column(Integer, default=0)
    iocs_removed = Column(Integer, default=0)
    execution_time = Column(Float, nullable=True)  # seconds
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    feed = relationship("ThreatFeed", back_populates="feed_logs")

class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    integration_type = Column(String(100), nullable=False)  # "siem", "soar", "firewall", "edr"
    endpoint_url = Column(String(500), nullable=False)
    api_key = Column(Text, nullable=True)  # Encrypted
    credentials = Column(JSON, default=dict)  # Encrypted
    is_enabled = Column(Boolean, default=True)
    auto_block = Column(Boolean, default=False)
    block_threshold = Column(Enum(ThreatLevel), default=ThreatLevel.HIGH)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class ThreatReport(Base):
    __tablename__ = "threat_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(100), nullable=False)  # "daily", "weekly", "monthly", "custom"
    content = Column(JSON, nullable=False)
    generated_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    exports = relationship("ReportExport", back_populates="report")

class ReportExport(Base):
    __tablename__ = "report_exports"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("threat_reports.id"))
    export_format = Column(String(50), nullable=False)  # "pdf", "csv", "json"
    file_path = Column(String(500), nullable=True)
    exported_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    report = relationship("ThreatReport", back_populates="exports")

class ThreatIntelligenceStats(Base):
    __tablename__ = "threat_intelligence_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    date = Column(DateTime(timezone=True), nullable=False)
    total_iocs = Column(Integer, default=0)
    new_iocs = Column(Integer, default=0)
    active_feeds = Column(Integer, default=0)
    alerts_generated = Column(Integer, default=0)
    threats_blocked = Column(Integer, default=0)
    avg_confidence_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now()) 