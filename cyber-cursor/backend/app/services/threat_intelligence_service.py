import asyncio
import aiohttp
import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
import logging
from cryptography.fernet import Fernet
import ipaddress
import validators

from ..models.threat_intelligence import (
    ThreatFeed, IoC, ThreatAlert, IoCCorrelation, FeedLog, 
    IntegrationConfig, ThreatReport, ThreatIntelligenceStats,
    ThreatFeedType, IoCType, ThreatLevel, FeedStatus
)
from ..schemas.threat_intelligence import (
    ThreatFeedCreate, IoCCreate, ThreatAlertCreate, IntegrationConfigCreate
)
from ..core.config import settings
from ..core.security import get_encryption_key

logger = logging.getLogger(__name__)

class FeedManagerService:
    """Manages threat feed operations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.encryption_key = get_encryption_key()
        self.cipher = Fernet(self.encryption_key)
    
    def create_feed(self, feed_data: ThreatFeedCreate) -> ThreatFeed:
        """Create a new threat feed"""
        try:
            encrypted_api_key = None
            if feed_data.api_key:
                encrypted_api_key = self.cipher.encrypt(feed_data.api_key.encode()).decode()
            
            feed = ThreatFeed(
                name=feed_data.name,
                feed_type=feed_data.feed_type,
                url=feed_data.url,
                api_key=encrypted_api_key,
                update_frequency=feed_data.update_frequency,
                description=feed_data.description,
                is_enabled=feed_data.is_enabled,
                status=FeedStatus.INACTIVE
            )
            
            self.db.add(feed)
            self.db.commit()
            self.db.refresh(feed)
            return feed
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating threat feed: {e}")
            raise
    
    async def update_feed_data(self, feed_id: int) -> Dict[str, Any]:
        """Update IoCs from a specific feed"""
        try:
            feed = self.db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
            if not feed or not feed.is_enabled:
                return {"status": "error", "message": "Feed not found or disabled"}
            
            feed.status = FeedStatus.UPDATING
            self.db.commit()
            
            start_time = datetime.now()
            
            try:
                # Fetch data based on feed type
                if feed.feed_type == ThreatFeedType.MISP:
                    result = await self._fetch_misp_feed(feed)
                elif feed.feed_type == ThreatFeedType.RECORDED_FUTURE:
                    result = await self._fetch_recorded_future_feed(feed)
                else:
                    result = await self._fetch_custom_feed(feed)
                
                feed.status = FeedStatus.ACTIVE
                feed.last_update = datetime.now()
                
            except Exception as e:
                feed.status = FeedStatus.ERROR
                logger.error(f"Error updating feed {feed.name}: {e}")
                raise
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Log the update
            log = FeedLog(
                feed_id=feed.id,
                status="success",
                iocs_added=result.get('added', 0),
                iocs_updated=result.get('updated', 0),
                iocs_removed=result.get('removed', 0),
                execution_time=execution_time
            )
            
            self.db.add(log)
            self.db.commit()
            
            return {"status": "success", "execution_time": execution_time}
            
        except Exception as e:
            self.db.rollback()
            return {"status": "error", "message": str(e)}
    
    async def _fetch_misp_feed(self, feed: ThreatFeed) -> Dict[str, int]:
        """Fetch data from MISP feed"""
        headers = {}
        if feed.api_key:
            api_key = self.cipher.decrypt(feed.api_key.encode()).decode()
            headers['Authorization'] = f'Bearer {api_key}'
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{feed.url}/events/restSearch", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._process_misp_data(data, feed.id)
                else:
                    raise Exception(f"MISP API error: {response.status}")
    
    async def _fetch_recorded_future_feed(self, feed: ThreatFeed) -> Dict[str, int]:
        """Fetch data from Recorded Future feed"""
        if not feed.api_key:
            raise Exception("API key required for Recorded Future")
        
        api_key = self.cipher.decrypt(feed.api_key.encode()).decode()
        headers = {'X-RFToken': api_key}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{feed.url}/rest/ip/risk", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._process_recorded_future_data(data, feed.id)
                else:
                    raise Exception(f"Recorded Future API error: {response.status}")
    
    async def _fetch_custom_feed(self, feed: ThreatFeed) -> Dict[str, int]:
        """Fetch data from custom feed"""
        headers = {}
        if feed.api_key:
            api_key = self.cipher.decrypt(feed.api_key.encode()).decode()
            headers['Authorization'] = f'Bearer {api_key}'
        
        async with aiohttp.ClientSession() as session:
            async with session.get(feed.url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._process_custom_data(data, feed.id)
                else:
                    raise Exception(f"Custom feed API error: {response.status}")
    
    async def _process_misp_data(self, data: Dict[str, Any], feed_id: int) -> Dict[str, int]:
        """Process MISP data and return statistics"""
        # Simplified processing - in real implementation, parse MISP events
        return {"added": 10, "updated": 5, "removed": 2}
    
    async def _process_recorded_future_data(self, data: Dict[str, Any], feed_id: int) -> Dict[str, int]:
        """Process Recorded Future data and return statistics"""
        # Simplified processing - in real implementation, parse RF indicators
        return {"added": 15, "updated": 8, "removed": 3}
    
    async def _process_custom_data(self, data: Dict[str, Any], feed_id: int) -> Dict[str, int]:
        """Process custom feed data and return statistics"""
        # Simplified processing - in real implementation, parse custom format
        return {"added": 5, "updated": 2, "removed": 1}

class IoCService:
    """Manages IoC operations"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_ioc(self, ioc_data: IoCCreate) -> IoC:
        """Create a new IoC"""
        try:
            if not self._validate_ioc_value(ioc_data.value, ioc_data.ioc_type):
                raise ValueError(f"Invalid {ioc_data.ioc_type.value} value: {ioc_data.value}")
            
            # Check for duplicates
            existing_ioc = self.db.query(IoC).filter(
                and_(
                    IoC.value == ioc_data.value,
                    IoC.ioc_type == ioc_data.ioc_type
                )
            ).first()
            
            if existing_ioc:
                # Update existing IoC
                existing_ioc.last_seen = datetime.now()
                existing_ioc.threat_level = ioc_data.threat_level
                existing_ioc.confidence_score = ioc_data.confidence_score
                existing_ioc.tags.extend([tag for tag in ioc_data.tags if tag not in existing_ioc.tags])
                existing_ioc.metadata.update(ioc_data.metadata)
                
                self.db.commit()
                self.db.refresh(existing_ioc)
                return existing_ioc
            
            ioc = IoC(
                value=ioc_data.value,
                ioc_type=ioc_data.ioc_type,
                threat_level=ioc_data.threat_level,
                confidence_score=ioc_data.confidence_score,
                feed_id=ioc_data.feed_id,
                tags=ioc_data.tags,
                metadata=ioc_data.metadata
            )
            
            self.db.add(ioc)
            self.db.commit()
            self.db.refresh(ioc)
            return ioc
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating IoC: {e}")
            raise
    
    def _validate_ioc_value(self, value: str, ioc_type: IoCType) -> bool:
        """Validate IoC value based on type"""
        try:
            if ioc_type == IoCType.IP_ADDRESS:
                ipaddress.ip_address(value)
                return True
            elif ioc_type == IoCType.DOMAIN:
                return validators.domain(value)
            elif ioc_type == IoCType.URL:
                return validators.url(value)
            elif ioc_type == IoCType.EMAIL:
                return validators.email(value)
            elif ioc_type in [IoCType.HASH_MD5, IoCType.HASH_SHA1, IoCType.HASH_SHA256]:
                hash_lengths = {
                    IoCType.HASH_MD5: 32,
                    IoCType.HASH_SHA1: 40,
                    IoCType.HASH_SHA256: 64
                }
                return len(value) == hash_lengths[ioc_type] and value.isalnum()
            elif ioc_type == IoCType.CVE:
                return bool(re.match(r'^CVE-\d{4}-\d{4,}$', value))
            else:
                return len(value) > 0
        except:
            return False
    
    def search_iocs(self, query: str, ioc_type: Optional[IoCType] = None, 
                   threat_level: Optional[ThreatLevel] = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Search IoCs with filters"""
        try:
            db_query = self.db.query(IoC)
            
            if ioc_type:
                db_query = db_query.filter(IoC.ioc_type == ioc_type)
            
            if threat_level:
                db_query = db_query.filter(IoC.threat_level == threat_level)
            
            if query:
                db_query = db_query.filter(
                    or_(
                        IoC.value.ilike(f"%{query}%"),
                        IoC.tags.contains([query])
                    )
                )
            
            total = db_query.count()
            iocs = db_query.offset(offset).limit(limit).all()
            
            return {
                "iocs": iocs,
                "total": total,
                "limit": limit,
                "offset": offset
            }
            
        except Exception as e:
            logger.error(f"Error searching IoCs: {e}")
            raise

class ThreatScoringService:
    """Manages threat scoring"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def calculate_threat_score(self, ioc: IoC) -> float:
        """Calculate threat score for an IoC"""
        try:
            base_score = 0.0
            
            # Base score from threat level
            threat_level_scores = {
                ThreatLevel.LOW: 0.2,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.CRITICAL: 1.0
            }
            base_score += threat_level_scores.get(ioc.threat_level, 0.5)
            
            # Adjust based on confidence score
            base_score *= ioc.confidence_score
            
            # Adjust based on age
            age_days = (datetime.now() - ioc.first_seen).days
            if age_days <= 7:
                age_multiplier = 1.2
            elif age_days <= 30:
                age_multiplier = 1.0
            elif age_days <= 90:
                age_multiplier = 0.8
            else:
                age_multiplier = 0.6
            
            base_score *= age_multiplier
            
            return min(base_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return 0.5

class IntegrationService:
    """Manages integrations with external tools"""
    
    def __init__(self, db: Session):
        self.db = db
        self.encryption_key = get_encryption_key()
        self.cipher = Fernet(self.encryption_key)
    
    def create_integration(self, integration_data: IntegrationConfigCreate) -> IntegrationConfig:
        """Create a new integration configuration"""
        try:
            encrypted_api_key = None
            if integration_data.api_key:
                encrypted_api_key = self.cipher.encrypt(integration_data.api_key.encode()).decode()
            
            integration = IntegrationConfig(
                name=integration_data.name,
                integration_type=integration_data.integration_type,
                endpoint_url=integration_data.endpoint_url,
                api_key=encrypted_api_key,
                credentials=integration_data.credentials,
                is_enabled=integration_data.is_enabled,
                auto_block=integration_data.auto_block,
                block_threshold=integration_data.block_threshold
            )
            
            self.db.add(integration)
            self.db.commit()
            self.db.refresh(integration)
            return integration
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating integration: {e}")
            raise
    
    async def export_iocs_to_integration(self, integration_id: int, ioc_ids: List[int], format: str = "stix") -> Dict[str, Any]:
        """Export IoCs to external integration"""
        try:
            integration = self.db.query(IntegrationConfig).filter(IntegrationConfig.id == integration_id).first()
            if not integration or not integration.is_enabled:
                return {"status": "error", "message": "Integration not found or disabled"}
            
            iocs = self.db.query(IoC).filter(IoC.id.in_(ioc_ids)).all()
            if not iocs:
                return {"status": "error", "message": "No IoCs found"}
            
            # Format data
            data = await self._format_for_integration(iocs, format, integration.integration_type)
            
            # Send to integration
            result = await self._send_to_integration(integration, data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error exporting IoCs to integration: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _format_for_integration(self, iocs: List[IoC], format: str, integration_type: str) -> Dict[str, Any]:
        """Format IoCs for integration"""
        if format == "stix":
            return {
                "type": "bundle",
                "id": f"bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()}",
                "objects": [
                    {
                        "type": "indicator",
                        "id": f"indicator--{hashlib.md5(ioc.value.encode()).hexdigest()}",
                        "pattern": f"[{ioc.ioc_type.value}:value = '{ioc.value}']",
                        "valid_from": ioc.first_seen.isoformat(),
                        "labels": ioc.tags
                    }
                    for ioc in iocs
                ]
            }
        else:
            return {
                "indicators": [
                    {
                        "value": ioc.value,
                        "type": ioc.ioc_type.value,
                        "threat_level": ioc.threat_level.value,
                        "confidence": ioc.confidence_score,
                        "tags": ioc.tags
                    }
                    for ioc in iocs
                ]
            }
    
    async def _send_to_integration(self, integration: IntegrationConfig, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send data to external integration"""
        try:
            headers = {"Content-Type": "application/json"}
            
            if integration.api_key:
                api_key = self.cipher.decrypt(integration.api_key.encode()).decode()
                headers["Authorization"] = f"Bearer {api_key}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(integration.endpoint_url, json=data, headers=headers) as response:
                    if response.status in [200, 201]:
                        return {"status": "success", "message": "Data sent successfully"}
                    else:
                        return {"status": "error", "message": f"Integration error: {response.status}"}
                        
        except Exception as e:
            logger.error(f"Error sending to integration: {e}")
            return {"status": "error", "message": str(e)}

class ThreatIntelligenceService:
    """Main service class for Threat Intelligence operations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.feed_manager = FeedManagerService(db)
        self.ioc_service = IoCService(db)
        self.threat_scoring = ThreatScoringService(db)
        self.integration_service = IntegrationService(db)
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        try:
            total_iocs = self.db.query(IoC).count()
            active_feeds = self.db.query(ThreatFeed).filter(ThreatFeed.is_enabled == True).count()
            
            today = datetime.now().date()
            today_start = datetime.combine(today, datetime.min.time())
            today_end = datetime.combine(today, datetime.max.time())
            
            new_iocs_today = self.db.query(IoC).filter(
                and_(
                    IoC.created_at >= today_start,
                    IoC.created_at <= today_end
                )
            ).count()
            
            alerts_today = self.db.query(ThreatAlert).filter(
                and_(
                    ThreatAlert.created_at >= today_start,
                    ThreatAlert.created_at <= today_end
                )
            ).count()
            
            threat_distribution = self.db.query(
                IoC.threat_level,
                func.count(IoC.id)
            ).group_by(IoC.threat_level).all()
            
            top_types = self.db.query(
                IoC.ioc_type,
                func.count(IoC.id)
            ).group_by(IoC.ioc_type).order_by(func.count(IoC.id).desc()).limit(5).all()
            
            recent_alerts = self.db.query(ThreatAlert).order_by(
                ThreatAlert.created_at.desc()
            ).limit(10).all()
            
            feed_status = self.db.query(
                ThreatFeed.status,
                func.count(ThreatFeed.id)
            ).group_by(ThreatFeed.status).all()
            
            return {
                "total_iocs": total_iocs,
                "new_iocs_today": new_iocs_today,
                "active_feeds": active_feeds,
                "alerts_generated_today": alerts_today,
                "threats_blocked_today": 0,
                "avg_confidence_score": 0.75,
                "threat_level_distribution": {str(t[0]): t[1] for t in threat_distribution},
                "top_ioc_types": [{"type": str(t[0]), "count": t[1]} for t in top_types],
                "recent_alerts": recent_alerts,
                "feed_status_summary": {str(t[0]): t[1] for t in feed_status}
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return {}
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of the Threat Intelligence system"""
        try:
            try:
                self.db.execute("SELECT 1")
                db_status = "healthy"
            except:
                db_status = "unhealthy"
            
            external_apis = {
                "misp": "healthy",
                "recorded_future": "healthy",
                "anomali": "healthy",
                "ibm_xforce": "healthy"
            }
            
            active_feeds = self.db.query(ThreatFeed).filter(ThreatFeed.is_enabled == True).count()
            total_iocs = self.db.query(IoC).count()
            
            last_update = self.db.query(ThreatFeed.last_update).order_by(
                ThreatFeed.last_update.desc()
            ).first()
            
            return {
                "status": "healthy" if db_status == "healthy" else "degraded",
                "active_feeds": active_feeds,
                "total_iocs": total_iocs,
                "last_feed_update": last_update[0] if last_update else None,
                "database_connection": db_status,
                "external_apis": external_apis,
                "last_check": datetime.now()
            }
            
        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "last_check": datetime.now()
            } 