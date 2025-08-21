from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum, UUID, SmallInteger, Numeric, BigInteger, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
import enum
import uuid

Base = declarative_base()

# Enums
class ThreatSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ThreatStatus(str, enum.Enum):
    ACTIVE = "active"
    MITIGATED = "mitigated"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"

class CVEStatus(str, enum.Enum):
    PUBLISHED = "published"
    MODIFIED = "modified"
    REJECTED = "rejected"

class ThreatFeedType(str, enum.Enum):
    CVE = "cve"
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    VULNERABILITY = "vulnerability"

# CVE Database Model
class CVE(Base):
    __tablename__ = "cves"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)  # e.g., "CVE-2024-1234"
    description = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    severity = Column(Enum(ThreatSeverity))
    status = Column(Enum(CVEStatus), default=CVEStatus.PUBLISHED)
    published_date = Column(DateTime(timezone=True))
    modified_date = Column(DateTime(timezone=True))
    references = Column(JSONB, default=[])  # URLs and references
    affected_products = Column(JSONB, default=[])  # Affected software/products
    exploitability = Column(JSONB, default={})  # Exploit details, PoC availability
    remediation = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    asset_vulnerabilities = relationship("AssetVulnerability", back_populates="cve")
    threat_indicators = relationship("ThreatIndicator", back_populates="cve")

# Asset-Vulnerability Mapping
class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    cve_id = Column(PGUUID(as_uuid=True), ForeignKey("cves.id"), nullable=False)
    status = Column(String(50), default="open")  # open, patched, false_positive
    detection_date = Column(DateTime(timezone=True), server_default=func.now())
    patch_date = Column(DateTime(timezone=True))
    risk_score = Column(Numeric(5, 2), default=0.0)
    exploitability_score = Column(Numeric(5, 2), default=0.0)
    business_impact = Column(Numeric(5, 2), default=0.0)
    evidence = Column(JSONB, default={})  # Detection evidence
    remediation_notes = Column(Text)
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")
    cve = relationship("CVE", back_populates="asset_vulnerabilities")

# Threat Intelligence Feeds
class ThreatFeed(Base):
    __tablename__ = "threat_feeds"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    feed_type = Column(Enum(ThreatFeedType), nullable=False)
    source_url = Column(String(500))
    api_key = Column(String(255))  # Encrypted
    last_updated = Column(DateTime(timezone=True))
    update_frequency = Column(Integer, default=3600)  # seconds
    enabled = Column(Boolean, default=True)
    config = Column(JSONB, default={})  # Feed-specific configuration
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    indicators = relationship("ThreatIndicator", back_populates="feed")

# Threat Indicators
class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    feed_id = Column(PGUUID(as_uuid=True), ForeignKey("threat_feeds.id"), nullable=False)
    cve_id = Column(PGUUID(as_uuid=True), ForeignKey("cves.id"))
    indicator_type = Column(String(100), nullable=False)  # IP, domain, hash, etc.
    indicator_value = Column(String(500), nullable=False)
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    threat_level = Column(Enum(ThreatSeverity))
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    tags = Column(JSONB, default=[])
    threat_metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    feed = relationship("ThreatFeed", back_populates="indicators")
    cve = relationship("CVE", back_populates="threat_indicators")

# Attack Path Analysis
class AttackPath(Base):
    __tablename__ = "attack_paths"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    source_asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"))
    target_asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"))
    path_steps = Column(JSONB, nullable=False)  # Array of attack path steps
    risk_score = Column(Numeric(5, 2), default=0.0)
    likelihood = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    impact = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    status = Column(String(50), default="active")  # active, mitigated, closed
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    source_asset = relationship("Asset", foreign_keys=[source_asset_id])
    target_asset = relationship("Asset", foreign_keys=[target_asset_id])

# Attack Path Steps
class AttackPathStep(Base):
    __tablename__ = "attack_path_steps"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_path_id = Column(PGUUID(as_uuid=True), ForeignKey("attack_paths.id"), nullable=False)
    step_number = Column(Integer, nullable=False)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"))
    vulnerability_id = Column(PGUUID(as_uuid=True), ForeignKey("asset_vulnerabilities.id"))
    attack_technique = Column(String(255))  # MITRE ATT&CK technique
    description = Column(Text)
    prerequisites = Column(JSONB, default=[])  # Required conditions
    mitigations = Column(JSONB, default=[])  # Available mitigations
    risk_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    attack_path = relationship("AttackPath")
    asset = relationship("Asset")
    vulnerability = relationship("AssetVulnerability")

# Threat Intelligence Alerts
class ThreatAlert(Base):
    __tablename__ = "threat_alerts"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    alert_type = Column(String(100), nullable=False)  # cve, threat_indicator, attack_path
    severity = Column(Enum(ThreatSeverity), nullable=False)
    status = Column(String(50), default="open")  # open, acknowledged, resolved
    source = Column(String(100))  # feed name, manual, automated
    affected_assets = Column(JSONB, default=[])  # Array of affected asset IDs
    threat_indicators = Column(JSONB, default=[])  # Related threat indicators
    cve_references = Column(JSONB, default=[])  # Related CVEs
    risk_score = Column(Numeric(5, 2), default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationships
    asset_alerts = relationship("AssetThreatAlert", back_populates="alert")

# Asset-Threat Alert Mapping
class AssetThreatAlert(Base):
    __tablename__ = "asset_threat_alerts"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    alert_id = Column(PGUUID(as_uuid=True), ForeignKey("threat_alerts.id"), nullable=False)
    status = Column(String(50), default="active")  # active, mitigated, false_positive
    risk_score = Column(Numeric(5, 2), default=0.0)
    mitigation_notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    asset = relationship("Asset")
    alert = relationship("ThreatAlert", back_populates="asset_alerts")

# Zero-day Detection Model
class ZeroDayDetection(Base):
    __tablename__ = "zero_day_detections"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    detection_type = Column(String(100), nullable=False)  # anomaly, behavior, pattern
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    anomaly_score = Column(Numeric(5, 2), default=0.0)
    behavior_pattern = Column(JSONB, default={})  # Detected behavior pattern
    baseline_comparison = Column(JSONB, default={})  # Comparison with baseline
    risk_assessment = Column(JSONB, default={})  # Risk factors and scoring
    mitigation_recommendations = Column(JSONB, default=[])
    status = Column(String(50), default="investigating")  # investigating, confirmed, false_positive
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    asset = relationship("Asset")

# Threat Intelligence Summary
class ThreatIntelligenceSummary(Base):
    __tablename__ = "threat_intelligence_summary"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    summary_date = Column(DateTime(timezone=True), nullable=False)
    total_cves = Column(Integer, default=0)
    critical_cves = Column(Integer, default=0)
    high_cves = Column(Integer, default=0)
    medium_cves = Column(Integer, default=0)
    low_cves = Column(Integer, default=0)
    total_threat_indicators = Column(Integer, default=0)
    active_attack_paths = Column(Integer, default=0)
    zero_day_detections = Column(Integer, default=0)
    overall_threat_score = Column(Numeric(5, 2), default=0.0)
    threat_trends = Column(JSONB, default={})  # Threat trend analysis
    top_threats = Column(JSONB, default=[])  # Top threats by risk score
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project")
