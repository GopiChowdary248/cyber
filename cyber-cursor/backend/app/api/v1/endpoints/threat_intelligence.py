from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.threat_intelligence_service import (
    threat_intelligence_service,
    ThreatType, ThreatSeverity, ConfidenceLevel, IndicatorType, 
    HuntingStatus, HuntingType
)

router = APIRouter()

# Pydantic models for request/response
class ThreatIndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    value: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: ConfidenceLevel
    source: str
    description: Optional[str] = ""
    tags: Optional[List[str]] = None

class ThreatIndicatorResponse(BaseModel):
    id: str
    indicator_type: IndicatorType
    value: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: ConfidenceLevel
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    metadata: Dict[str, Any]
    source: str
    description: str

class ThreatCampaignCreate(BaseModel):
    name: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    indicators: Optional[List[str]] = None
    targets: Optional[List[str]] = None
    tactics: Optional[List[str]] = None
    techniques: Optional[List[str]] = None
    attribution: Optional[str] = None

class ThreatCampaignResponse(BaseModel):
    id: str
    name: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    first_seen: datetime
    last_seen: datetime
    indicators: List[str]
    targets: List[str]
    tactics: List[str]
    techniques: List[str]
    attribution: Optional[str]
    status: str

class ThreatReportCreate(BaseModel):
    title: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    author: str
    content: str
    indicators: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None
    tags: Optional[List[str]] = None

class ThreatReportResponse(BaseModel):
    id: str
    title: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    created_at: datetime
    updated_at: datetime
    author: str
    content: str
    indicators: List[str]
    recommendations: List[str]
    tags: List[str]
    status: str

class ThreatHuntCreate(BaseModel):
    name: str
    description: str
    hunt_type: HuntingType
    analyst: str
    hypothesis: str
    scope: Optional[Dict[str, Any]] = None

class ThreatHuntUpdate(BaseModel):
    findings: Optional[List[Dict[str, Any]]] = None
    tools_used: Optional[List[str]] = None

class ThreatHuntResponse(BaseModel):
    id: str
    name: str
    description: str
    hunt_type: HuntingType
    status: HuntingStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    analyst: str
    hypothesis: str
    scope: Dict[str, Any]
    findings: List[Dict[str, Any]]
    tools_used: List[str]
    duration_minutes: Optional[int]

class HuntingQueryCreate(BaseModel):
    name: str
    description: str
    query_type: HuntingType
    query_string: str
    created_by: str
    tags: Optional[List[str]] = None

class HuntingQueryResponse(BaseModel):
    id: str
    name: str
    description: str
    query_type: HuntingType
    query_string: str
    created_at: datetime
    created_by: str
    tags: List[str]
    success_rate: float
    usage_count: int

class ThreatFeedCreate(BaseModel):
    name: str
    description: str
    url: str
    format: str
    update_frequency: str

class ThreatFeedResponse(BaseModel):
    id: str
    name: str
    description: str
    url: str
    format: str
    last_updated: datetime
    update_frequency: str
    enabled: bool
    indicators_count: int
    last_sync: Optional[datetime]

class ThreatIntelligenceSummaryResponse(BaseModel):
    total_indicators: int
    active_campaigns: int
    recent_reports: int
    ongoing_hunts: int
    threat_feeds: int
    high_severity_threats: int
    new_indicators_24h: int
    last_updated: datetime

# Threat Indicator Management Endpoints
@router.post("/indicators", response_model=ThreatIndicatorResponse)
async def create_indicator(indicator_data: ThreatIndicatorCreate):
    """Create a new threat indicator"""
    try:
        indicator = await threat_intelligence_service.add_indicator(
            indicator_type=indicator_data.indicator_type,
            value=indicator_data.value,
            threat_type=indicator_data.threat_type,
            severity=indicator_data.severity,
            confidence=indicator_data.confidence,
            source=indicator_data.source,
            description=indicator_data.description,
            tags=indicator_data.tags
        )
        return indicator
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create threat indicator: {str(e)}")

@router.get("/indicators", response_model=List[ThreatIndicatorResponse])
async def get_indicators(
    indicator_type: Optional[IndicatorType] = Query(None, description="Filter by indicator type"),
    threat_type: Optional[ThreatType] = Query(None, description="Filter by threat type"),
    severity: Optional[ThreatSeverity] = Query(None, description="Filter by severity"),
    confidence: Optional[ConfidenceLevel] = Query(None, description="Filter by confidence level"),
    source: Optional[str] = Query(None, description="Filter by source"),
    limit: int = Query(100, description="Maximum number of indicators to return")
):
    """Get threat indicators with optional filtering"""
    try:
        indicators = await threat_intelligence_service.get_indicators(
            indicator_type=indicator_type,
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            source=source,
            limit=limit
        )
        return indicators
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat indicators: {str(e)}")

@router.get("/indicators/search", response_model=List[ThreatIndicatorResponse])
async def search_indicators(
    query: str = Query(..., description="Search query for indicators")
):
    """Search threat indicators by value, description, or tags"""
    try:
        indicators = await threat_intelligence_service.search_indicators(query)
        return indicators
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search threat indicators: {str(e)}")

# Threat Campaign Management Endpoints
@router.post("/campaigns", response_model=ThreatCampaignResponse)
async def create_campaign(campaign_data: ThreatCampaignCreate):
    """Create a new threat campaign"""
    try:
        campaign = await threat_intelligence_service.create_campaign(
            name=campaign_data.name,
            description=campaign_data.description,
            threat_type=campaign_data.threat_type,
            severity=campaign_data.severity,
            indicators=campaign_data.indicators,
            targets=campaign_data.targets,
            tactics=campaign_data.tactics,
            techniques=campaign_data.techniques,
            attribution=campaign_data.attribution
        )
        return campaign
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create threat campaign: {str(e)}")

@router.get("/campaigns", response_model=List[ThreatCampaignResponse])
async def get_campaigns(
    threat_type: Optional[ThreatType] = Query(None, description="Filter by threat type"),
    severity: Optional[ThreatSeverity] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Maximum number of campaigns to return")
):
    """Get threat campaigns with optional filtering"""
    try:
        campaigns = await threat_intelligence_service.get_campaigns(
            threat_type=threat_type,
            severity=severity,
            status=status,
            limit=limit
        )
        return campaigns
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat campaigns: {str(e)}")

# Threat Report Management Endpoints
@router.post("/reports", response_model=ThreatReportResponse)
async def create_report(report_data: ThreatReportCreate):
    """Create a new threat report"""
    try:
        report = await threat_intelligence_service.create_report(
            title=report_data.title,
            description=report_data.description,
            threat_type=report_data.threat_type,
            severity=report_data.severity,
            author=report_data.author,
            content=report_data.content,
            indicators=report_data.indicators,
            recommendations=report_data.recommendations,
            tags=report_data.tags
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create threat report: {str(e)}")

@router.get("/reports", response_model=List[ThreatReportResponse])
async def get_reports(
    threat_type: Optional[ThreatType] = Query(None, description="Filter by threat type"),
    severity: Optional[ThreatSeverity] = Query(None, description="Filter by severity"),
    author: Optional[str] = Query(None, description="Filter by author"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Maximum number of reports to return")
):
    """Get threat reports with optional filtering"""
    try:
        reports = await threat_intelligence_service.get_reports(
            threat_type=threat_type,
            severity=severity,
            author=author,
            status=status,
            limit=limit
        )
        return reports
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat reports: {str(e)}")

# Threat Hunting Management Endpoints
@router.post("/hunts", response_model=ThreatHuntResponse)
async def create_hunt(hunt_data: ThreatHuntCreate):
    """Create a new threat hunt"""
    try:
        hunt = await threat_intelligence_service.create_hunt(
            name=hunt_data.name,
            description=hunt_data.description,
            hunt_type=hunt_data.hunt_type,
            analyst=hunt_data.analyst,
            hypothesis=hunt_data.hypothesis,
            scope=hunt_data.scope
        )
        return hunt
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create threat hunt: {str(e)}")

@router.put("/hunts/{hunt_id}/start", response_model=ThreatHuntResponse)
async def start_hunt(hunt_id: str):
    """Start a threat hunt"""
    try:
        hunt = await threat_intelligence_service.start_hunt(hunt_id)
        if not hunt:
            raise HTTPException(status_code=404, detail="Threat hunt not found")
        return hunt
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start threat hunt: {str(e)}")

@router.put("/hunts/{hunt_id}/complete", response_model=ThreatHuntResponse)
async def complete_hunt(hunt_id: str, update_data: ThreatHuntUpdate):
    """Complete a threat hunt"""
    try:
        hunt = await threat_intelligence_service.complete_hunt(
            hunt_id=hunt_id,
            findings=update_data.findings,
            tools_used=update_data.tools_used
        )
        if not hunt:
            raise HTTPException(status_code=404, detail="Threat hunt not found")
        return hunt
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to complete threat hunt: {str(e)}")

@router.get("/hunts", response_model=List[ThreatHuntResponse])
async def get_hunts(
    hunt_type: Optional[HuntingType] = Query(None, description="Filter by hunt type"),
    status: Optional[HuntingStatus] = Query(None, description="Filter by status"),
    analyst: Optional[str] = Query(None, description="Filter by analyst"),
    limit: int = Query(100, description="Maximum number of hunts to return")
):
    """Get threat hunts with optional filtering"""
    try:
        hunts = await threat_intelligence_service.get_hunts(
            hunt_type=hunt_type,
            status=status,
            analyst=analyst,
            limit=limit
        )
        return hunts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat hunts: {str(e)}")

# Hunting Query Management Endpoints
@router.post("/queries", response_model=HuntingQueryResponse)
async def create_hunting_query(query_data: HuntingQueryCreate):
    """Create a new hunting query"""
    try:
        query = await threat_intelligence_service.create_hunting_query(
            name=query_data.name,
            description=query_data.description,
            query_type=query_data.query_type,
            query_string=query_data.query_string,
            created_by=query_data.created_by,
            tags=query_data.tags
        )
        return query
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create hunting query: {str(e)}")

@router.get("/queries", response_model=List[HuntingQueryResponse])
async def get_queries(
    query_type: Optional[HuntingType] = Query(None, description="Filter by query type"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    limit: int = Query(100, description="Maximum number of queries to return")
):
    """Get hunting queries with optional filtering"""
    try:
        queries = await threat_intelligence_service.get_queries(
            query_type=query_type,
            created_by=created_by,
            limit=limit
        )
        return queries
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve hunting queries: {str(e)}")

# Threat Feed Management Endpoints
@router.post("/feeds", response_model=ThreatFeedResponse)
async def add_feed(feed_data: ThreatFeedCreate):
    """Add a new threat feed"""
    try:
        feed = await threat_intelligence_service.add_feed(
            name=feed_data.name,
            description=feed_data.description,
            url=feed_data.url,
            format=feed_data.format,
            update_frequency=feed_data.update_frequency
        )
        return feed
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add threat feed: {str(e)}")

@router.put("/feeds/{feed_id}/sync", response_model=ThreatFeedResponse)
async def sync_feed(feed_id: str):
    """Sync a threat feed"""
    try:
        feed = await threat_intelligence_service.sync_feed(feed_id)
        if not feed:
            raise HTTPException(status_code=404, detail="Threat feed not found")
        return feed
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to sync threat feed: {str(e)}")

@router.get("/feeds", response_model=List[ThreatFeedResponse])
async def get_feeds(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    format: Optional[str] = Query(None, description="Filter by format")
):
    """Get threat feeds with optional filtering"""
    try:
        feeds = await threat_intelligence_service.get_feeds(enabled=enabled, format=format)
        return feeds
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat feeds: {str(e)}")

# Summary and Analytics Endpoints
@router.get("/summary", response_model=ThreatIntelligenceSummaryResponse)
async def get_threat_intelligence_summary():
    """Get threat intelligence summary statistics"""
    try:
        summary = await threat_intelligence_service.get_threat_intelligence_summary()
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat intelligence summary: {str(e)}")

# Bulk Operations
@router.post("/bulk/indicators")
async def bulk_create_indicators(indicators_data: List[ThreatIndicatorCreate]):
    """Create multiple threat indicators"""
    try:
        created_indicators = []
        for indicator_data in indicators_data:
            indicator = await threat_intelligence_service.add_indicator(
                indicator_type=indicator_data.indicator_type,
                value=indicator_data.value,
                threat_type=indicator_data.threat_type,
                severity=indicator_data.severity,
                confidence=indicator_data.confidence,
                source=indicator_data.source,
                description=indicator_data.description,
                tags=indicator_data.tags
            )
            created_indicators.append(indicator)
        return {"message": f"Created {len(created_indicators)} threat indicators", "indicators": created_indicators}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create bulk indicators: {str(e)}")

@router.post("/bulk/campaigns")
async def bulk_create_campaigns(campaigns_data: List[ThreatCampaignCreate]):
    """Create multiple threat campaigns"""
    try:
        created_campaigns = []
        for campaign_data in campaigns_data:
            campaign = await threat_intelligence_service.create_campaign(
                name=campaign_data.name,
                description=campaign_data.description,
                threat_type=campaign_data.threat_type,
                severity=campaign_data.severity,
                indicators=campaign_data.indicators,
                targets=campaign_data.targets,
                tactics=campaign_data.tactics,
                techniques=campaign_data.techniques,
                attribution=campaign_data.attribution
            )
            created_campaigns.append(campaign)
        return {"message": f"Created {len(created_campaigns)} threat campaigns", "campaigns": created_campaigns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create bulk campaigns: {str(e)}")

# Health Check
@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        summary = await threat_intelligence_service.get_threat_intelligence_summary()
        return {
            "status": "healthy",
            "service": "threat_intelligence",
            "summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service unhealthy: {str(e)}") 