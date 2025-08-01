import asyncio
import json
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
import structlog

logger = structlog.get_logger()

class ThreatType(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    APT = "apt"
    BOTNET = "botnet"
    DDoS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

class IndicatorType(Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    USER_AGENT = "user_agent"

class HuntingStatus(Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SUSPENDED = "suspended"

class HuntingType(Enum):
    BEHAVIORAL = "behavioral"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    MEMORY = "memory"
    REGISTRY = "registry"
    FILE_SYSTEM = "file_system"

@dataclass
class ThreatIndicator:
    id: str
    indicator_type: IndicatorType
    value: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: ConfidenceLevel
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    description: str = ""

@dataclass
class ThreatCampaign:
    id: str
    name: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    first_seen: datetime
    last_seen: datetime
    indicators: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    attribution: Optional[str] = None
    status: str = "active"

@dataclass
class ThreatReport:
    id: str
    title: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    created_at: datetime
    updated_at: datetime
    author: str
    content: str
    indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    status: str = "draft"

@dataclass
class ThreatHunt:
    id: str
    name: str
    description: str
    hunt_type: HuntingType
    status: HuntingStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    analyst: str
    hypothesis: str
    scope: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    duration_minutes: Optional[int] = None

@dataclass
class HuntingQuery:
    id: str
    name: str
    description: str
    query_type: HuntingType
    query_string: str
    created_at: datetime
    created_by: str
    tags: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    usage_count: int = 0

@dataclass
class ThreatFeed:
    id: str
    name: str
    description: str
    url: str
    format: str  # json, csv, stix, etc.
    last_updated: datetime
    update_frequency: str  # hourly, daily, weekly
    enabled: bool = True
    indicators_count: int = 0
    last_sync: Optional[datetime] = None

@dataclass
class ThreatIntelligenceSummary:
    total_indicators: int
    active_campaigns: int
    recent_reports: int
    ongoing_hunts: int
    threat_feeds: int
    high_severity_threats: int
    new_indicators_24h: int
    last_updated: datetime

class ThreatIntelligenceService:
    def __init__(self):
        self.indicators: List[ThreatIndicator] = []
        self.campaigns: List[ThreatCampaign] = []
        self.reports: List[ThreatReport] = []
        self.hunts: List[ThreatHunt] = []
        self.queries: List[HuntingQuery] = []
        self.feeds: List[ThreatFeed] = []
        self.background_tasks: List[asyncio.Task] = []
        self._running = False
        
        # Initialize sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize sample data for demonstration"""
        # Sample threat indicators
        indicator_values = [
            "192.168.1.100", "malicious-domain.com", "http://evil.com/payload",
            "attacker@evil.com", "a1b2c3d4e5f6", "HKLM\\Software\\Evil",
            "C:\\Windows\\System32\\malware.exe", "Mozilla/5.0 (Evil Browser)"
        ]
        
        for i in range(50):
            self.indicators.append(ThreatIndicator(
                id=str(uuid.uuid4()),
                indicator_type=IndicatorType.IP_ADDRESS if i % 8 == 0 else IndicatorType.DOMAIN,
                value=indicator_values[i % len(indicator_values)],
                threat_type=ThreatType.MALWARE if i % 4 == 0 else ThreatType.PHISHING,
                severity=ThreatSeverity.HIGH if i % 5 == 0 else ThreatSeverity.MEDIUM,
                confidence=ConfidenceLevel.HIGH if i % 3 == 0 else ConfidenceLevel.MEDIUM,
                first_seen=datetime.utcnow() - timedelta(days=i),
                last_seen=datetime.utcnow() - timedelta(hours=i),
                tags=["malware", "apt"] if i % 2 == 0 else ["phishing", "credential_theft"],
                source=f"feed-{i % 5}",
                description=f"Threat indicator {i + 1}"
            ))
        
        # Sample threat campaigns
        campaign_names = ["APT29", "Lazarus Group", "Fancy Bear", "Cozy Bear", "Sandworm"]
        for i in range(8):
            self.campaigns.append(ThreatCampaign(
                id=str(uuid.uuid4()),
                name=campaign_names[i % len(campaign_names)],
                description=f"Advanced persistent threat campaign {i + 1}",
                threat_type=ThreatType.APT,
                severity=ThreatSeverity.HIGH if i % 2 == 0 else ThreatSeverity.CRITICAL,
                first_seen=datetime.utcnow() - timedelta(days=i * 30),
                last_seen=datetime.utcnow() - timedelta(days=i),
                indicators=[ind.id for ind in self.indicators[i*5:(i+1)*5]],
                targets=["government", "financial", "healthcare"],
                tactics=["initial_access", "persistence", "privilege_escalation"],
                techniques=["T1078", "T1055", "T1021"],
                attribution=f"attribution-{i}"
            ))
        
        # Sample threat reports
        for i in range(12):
            self.reports.append(ThreatReport(
                id=str(uuid.uuid4()),
                title=f"Threat Report {i + 1}: Emerging Malware Campaign",
                description=f"Analysis of emerging malware campaign {i + 1}",
                threat_type=ThreatType.MALWARE if i % 3 == 0 else ThreatType.RANSOMWARE,
                severity=ThreatSeverity.HIGH,
                created_at=datetime.utcnow() - timedelta(days=i * 7),
                updated_at=datetime.utcnow() - timedelta(days=i * 3),
                author=f"analyst-{i % 4}",
                content=f"Detailed analysis of threat campaign {i + 1}...",
                indicators=[ind.id for ind in self.indicators[i*3:(i+1)*3]],
                recommendations=["Update signatures", "Monitor network traffic", "Train users"],
                tags=["malware", "analysis", "recommendations"]
            ))
        
        # Sample threat hunts
        hunt_types = [HuntingType.BEHAVIORAL, HuntingType.NETWORK, HuntingType.ENDPOINT]
        for i in range(6):
            self.hunts.append(ThreatHunt(
                id=str(uuid.uuid4()),
                name=f"Threat Hunt {i + 1}: Suspicious Network Activity",
                description=f"Hunting for suspicious network activity {i + 1}",
                hunt_type=hunt_types[i % len(hunt_types)],
                status=HuntingStatus.COMPLETED if i < 4 else HuntingStatus.IN_PROGRESS,
                created_at=datetime.utcnow() - timedelta(days=i * 5),
                started_at=datetime.utcnow() - timedelta(days=i * 5, hours=1) if i < 4 else None,
                completed_at=datetime.utcnow() - timedelta(days=i * 5, hours=2) if i < 4 else None,
                analyst=f"hunter-{i % 3}",
                hypothesis=f"Hypothesis for hunt {i + 1}: Suspicious activity detected",
                scope={"networks": ["192.168.1.0/24"], "timeframe": "last_7_days"},
                findings=[{"finding": f"Finding {j + 1}", "severity": "medium"} for j in range(3)],
                tools_used=["YARA", "Sigma", "KQL"],
                duration_minutes=120 if i < 4 else None
            ))
        
        # Sample hunting queries
        query_templates = [
            "SELECT * FROM logs WHERE source_ip IN (SELECT ip FROM threat_indicators)",
            "event_type=process_start AND process_name IN (SELECT filename FROM malware_hashes)",
            "network_connection AND destination_domain IN (SELECT domain FROM malicious_domains)"
        ]
        
        for i in range(15):
            self.queries.append(HuntingQuery(
                id=str(uuid.uuid4()),
                name=f"Hunting Query {i + 1}",
                description=f"Query for detecting {ThreatType.MALWARE.value} activity",
                query_type=hunt_types[i % len(hunt_types)],
                query_string=query_templates[i % len(query_templates)],
                created_at=datetime.utcnow() - timedelta(days=i * 2),
                created_by=f"analyst-{i % 4}",
                tags=["malware", "network", "endpoint"],
                success_rate=0.75 + (i * 0.02),
                usage_count=i + 1
            ))
        
        # Sample threat feeds
        feed_names = ["AlienVault OTX", "MISP", "ThreatFox", "AbuseIPDB", "VirusTotal"]
        for i in range(8):
            self.feeds.append(ThreatFeed(
                id=str(uuid.uuid4()),
                name=feed_names[i % len(feed_names)],
                description=f"Threat intelligence feed {i + 1}",
                url=f"https://feed{i}.com/api/v1/indicators",
                format="json" if i % 2 == 0 else "stix",
                last_updated=datetime.utcnow() - timedelta(hours=i),
                update_frequency="hourly" if i % 3 == 0 else "daily",
                indicators_count=1000 + (i * 500),
                last_sync=datetime.utcnow() - timedelta(hours=i * 2)
            ))
    
    async def start_threat_intelligence_service(self):
        """Start the threat intelligence service"""
        if self._running:
            return
        
        self._running = True
        logger.info("Starting Threat Intelligence service")
        
        # Start background tasks
        self.background_tasks.extend([
            asyncio.create_task(self._feed_sync_worker()),
            asyncio.create_task(self._indicator_analysis_worker()),
            asyncio.create_task(self._campaign_correlation_worker()),
            asyncio.create_task(self._hunting_automation_worker())
        ])
        
        logger.info("Threat Intelligence service started successfully")
    
    async def stop_threat_intelligence_service(self):
        """Stop the threat intelligence service"""
        if not self._running:
            return
        
        self._running = False
        logger.info("Stopping Threat Intelligence service")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        self.background_tasks.clear()
        
        logger.info("Threat Intelligence service stopped")
    
    async def _feed_sync_worker(self):
        """Background task for syncing threat feeds"""
        while self._running:
            try:
                # Simulate feed synchronization
                await asyncio.sleep(300)  # 5 minutes
                logger.debug("Syncing threat feeds...")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in feed sync worker: {e}")
    
    async def _indicator_analysis_worker(self):
        """Background task for analyzing indicators"""
        while self._running:
            try:
                # Simulate indicator analysis
                await asyncio.sleep(600)  # 10 minutes
                logger.debug("Analyzing threat indicators...")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in indicator analysis worker: {e}")
    
    async def _campaign_correlation_worker(self):
        """Background task for correlating campaigns"""
        while self._running:
            try:
                # Simulate campaign correlation
                await asyncio.sleep(900)  # 15 minutes
                logger.debug("Correlating threat campaigns...")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in campaign correlation worker: {e}")
    
    async def _hunting_automation_worker(self):
        """Background task for automated hunting"""
        while self._running:
            try:
                # Simulate automated hunting
                await asyncio.sleep(1200)  # 20 minutes
                logger.debug("Running automated threat hunts...")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in hunting automation worker: {e}")
    
    # Threat Indicator Management
    async def add_indicator(self, indicator_type: IndicatorType, value: str, threat_type: ThreatType,
                           severity: ThreatSeverity, confidence: ConfidenceLevel, source: str,
                           description: str = "", tags: List[str] = None) -> ThreatIndicator:
        """Add a new threat indicator"""
        indicator = ThreatIndicator(
            id=str(uuid.uuid4()),
            indicator_type=indicator_type,
            value=value,
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            tags=tags or [],
            source=source,
            description=description
        )
        
        self.indicators.append(indicator)
        logger.info(f"Added threat indicator: {indicator.id}")
        return indicator
    
    async def get_indicators(self, indicator_type: IndicatorType = None, threat_type: ThreatType = None,
                           severity: ThreatSeverity = None, confidence: ConfidenceLevel = None,
                           source: str = None, limit: int = 100) -> List[ThreatIndicator]:
        """Get threat indicators with optional filtering"""
        filtered_indicators = self.indicators
        
        if indicator_type:
            filtered_indicators = [ind for ind in filtered_indicators if ind.indicator_type == indicator_type]
        if threat_type:
            filtered_indicators = [ind for ind in filtered_indicators if ind.threat_type == threat_type]
        if severity:
            filtered_indicators = [ind for ind in filtered_indicators if ind.severity == severity]
        if confidence:
            filtered_indicators = [ind for ind in filtered_indicators if ind.confidence == confidence]
        if source:
            filtered_indicators = [ind for ind in filtered_indicators if ind.source == source]
        
        return filtered_indicators[-limit:]
    
    async def search_indicators(self, query: str) -> List[ThreatIndicator]:
        """Search indicators by value, description, or tags"""
        query_lower = query.lower()
        results = []
        
        for indicator in self.indicators:
            if (query_lower in indicator.value.lower() or
                query_lower in indicator.description.lower() or
                any(query_lower in tag.lower() for tag in indicator.tags)):
                results.append(indicator)
        
        return results
    
    # Threat Campaign Management
    async def create_campaign(self, name: str, description: str, threat_type: ThreatType,
                             severity: ThreatSeverity, indicators: List[str] = None,
                             targets: List[str] = None, tactics: List[str] = None,
                             techniques: List[str] = None, attribution: str = None) -> ThreatCampaign:
        """Create a new threat campaign"""
        campaign = ThreatCampaign(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            threat_type=threat_type,
            severity=severity,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            indicators=indicators or [],
            targets=targets or [],
            tactics=tactics or [],
            techniques=techniques or [],
            attribution=attribution
        )
        
        self.campaigns.append(campaign)
        logger.info(f"Created threat campaign: {campaign.id}")
        return campaign
    
    async def get_campaigns(self, threat_type: ThreatType = None, severity: ThreatSeverity = None,
                           status: str = None, limit: int = 100) -> List[ThreatCampaign]:
        """Get threat campaigns with optional filtering"""
        filtered_campaigns = self.campaigns
        
        if threat_type:
            filtered_campaigns = [camp for camp in filtered_campaigns if camp.threat_type == threat_type]
        if severity:
            filtered_campaigns = [camp for camp in filtered_campaigns if camp.severity == severity]
        if status:
            filtered_campaigns = [camp for camp in filtered_campaigns if camp.status == status]
        
        return filtered_campaigns[-limit:]
    
    # Threat Report Management
    async def create_report(self, title: str, description: str, threat_type: ThreatType,
                           severity: ThreatSeverity, author: str, content: str,
                           indicators: List[str] = None, recommendations: List[str] = None,
                           tags: List[str] = None) -> ThreatReport:
        """Create a new threat report"""
        report = ThreatReport(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            threat_type=threat_type,
            severity=severity,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            author=author,
            content=content,
            indicators=indicators or [],
            recommendations=recommendations or [],
            tags=tags or []
        )
        
        self.reports.append(report)
        logger.info(f"Created threat report: {report.id}")
        return report
    
    async def get_reports(self, threat_type: ThreatType = None, severity: ThreatSeverity = None,
                         author: str = None, status: str = None, limit: int = 100) -> List[ThreatReport]:
        """Get threat reports with optional filtering"""
        filtered_reports = self.reports
        
        if threat_type:
            filtered_reports = [rep for rep in filtered_reports if rep.threat_type == threat_type]
        if severity:
            filtered_reports = [rep for rep in filtered_reports if rep.severity == severity]
        if author:
            filtered_reports = [rep for rep in filtered_reports if rep.author == author]
        if status:
            filtered_reports = [rep for rep in filtered_reports if rep.status == status]
        
        return filtered_reports[-limit:]
    
    # Threat Hunting Management
    async def create_hunt(self, name: str, description: str, hunt_type: HuntingType,
                         analyst: str, hypothesis: str, scope: Dict[str, Any] = None) -> ThreatHunt:
        """Create a new threat hunt"""
        hunt = ThreatHunt(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            hunt_type=hunt_type,
            status=HuntingStatus.PLANNED,
            created_at=datetime.utcnow(),
            analyst=analyst,
            hypothesis=hypothesis,
            scope=scope or {}
        )
        
        self.hunts.append(hunt)
        logger.info(f"Created threat hunt: {hunt.id}")
        return hunt
    
    async def start_hunt(self, hunt_id: str) -> Optional[ThreatHunt]:
        """Start a threat hunt"""
        for hunt in self.hunts:
            if hunt.id == hunt_id:
                hunt.status = HuntingStatus.IN_PROGRESS
                hunt.started_at = datetime.utcnow()
                logger.info(f"Started threat hunt: {hunt_id}")
                return hunt
        return None
    
    async def complete_hunt(self, hunt_id: str, findings: List[Dict[str, Any]] = None,
                           tools_used: List[str] = None) -> Optional[ThreatHunt]:
        """Complete a threat hunt"""
        for hunt in self.hunts:
            if hunt.id == hunt_id:
                hunt.status = HuntingStatus.COMPLETED
                hunt.completed_at = datetime.utcnow()
                if findings:
                    hunt.findings = findings
                if tools_used:
                    hunt.tools_used = tools_used
                if hunt.started_at:
                    hunt.duration_minutes = int((hunt.completed_at - hunt.started_at).total_seconds() / 60)
                logger.info(f"Completed threat hunt: {hunt_id}")
                return hunt
        return None
    
    async def get_hunts(self, hunt_type: HuntingType = None, status: HuntingStatus = None,
                       analyst: str = None, limit: int = 100) -> List[ThreatHunt]:
        """Get threat hunts with optional filtering"""
        filtered_hunts = self.hunts
        
        if hunt_type:
            filtered_hunts = [hunt for hunt in filtered_hunts if hunt.hunt_type == hunt_type]
        if status:
            filtered_hunts = [hunt for hunt in filtered_hunts if hunt.status == status]
        if analyst:
            filtered_hunts = [hunt for hunt in filtered_hunts if hunt.analyst == analyst]
        
        return filtered_hunts[-limit:]
    
    # Hunting Query Management
    async def create_hunting_query(self, name: str, description: str, query_type: HuntingType,
                                  query_string: str, created_by: str, tags: List[str] = None) -> HuntingQuery:
        """Create a new hunting query"""
        query = HuntingQuery(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            query_type=query_type,
            query_string=query_string,
            created_at=datetime.utcnow(),
            created_by=created_by,
            tags=tags or []
        )
        
        self.queries.append(query)
        logger.info(f"Created hunting query: {query.id}")
        return query
    
    async def get_queries(self, query_type: HuntingType = None, created_by: str = None,
                         limit: int = 100) -> List[HuntingQuery]:
        """Get hunting queries with optional filtering"""
        filtered_queries = self.queries
        
        if query_type:
            filtered_queries = [q for q in filtered_queries if q.query_type == query_type]
        if created_by:
            filtered_queries = [q for q in filtered_queries if q.created_by == created_by]
        
        return sorted(filtered_queries, key=lambda x: x.usage_count, reverse=True)[:limit]
    
    # Threat Feed Management
    async def add_feed(self, name: str, description: str, url: str, format: str,
                      update_frequency: str) -> ThreatFeed:
        """Add a new threat feed"""
        feed = ThreatFeed(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            url=url,
            format=format,
            last_updated=datetime.utcnow(),
            update_frequency=update_frequency
        )
        
        self.feeds.append(feed)
        logger.info(f"Added threat feed: {feed.id}")
        return feed
    
    async def sync_feed(self, feed_id: str) -> Optional[ThreatFeed]:
        """Sync a threat feed"""
        for feed in self.feeds:
            if feed.id == feed_id:
                feed.last_sync = datetime.utcnow()
                feed.last_updated = datetime.utcnow()
                logger.info(f"Synced threat feed: {feed_id}")
                return feed
        return None
    
    async def get_feeds(self, enabled: bool = None, format: str = None) -> List[ThreatFeed]:
        """Get threat feeds with optional filtering"""
        filtered_feeds = self.feeds
        
        if enabled is not None:
            filtered_feeds = [feed for feed in filtered_feeds if feed.enabled == enabled]
        if format:
            filtered_feeds = [feed for feed in filtered_feeds if feed.format == format]
        
        return filtered_feeds
    
    # Summary and Analytics
    async def get_threat_intelligence_summary(self) -> ThreatIntelligenceSummary:
        """Get threat intelligence summary statistics"""
        active_campaigns = len([camp for camp in self.campaigns if camp.status == "active"])
        recent_reports = len([rep for rep in self.reports 
                             if rep.created_at > datetime.utcnow() - timedelta(days=7)])
        ongoing_hunts = len([hunt for hunt in self.hunts if hunt.status == HuntingStatus.IN_PROGRESS])
        high_severity_threats = len([ind for ind in self.indicators 
                                   if ind.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]])
        new_indicators_24h = len([ind for ind in self.indicators 
                                 if ind.first_seen > datetime.utcnow() - timedelta(hours=24)])
        
        return ThreatIntelligenceSummary(
            total_indicators=len(self.indicators),
            active_campaigns=active_campaigns,
            recent_reports=recent_reports,
            ongoing_hunts=ongoing_hunts,
            threat_feeds=len([feed for feed in self.feeds if feed.enabled]),
            high_severity_threats=high_severity_threats,
            new_indicators_24h=new_indicators_24h,
            last_updated=datetime.utcnow()
        )

# Global service instance
threat_intelligence_service = ThreatIntelligenceService() 