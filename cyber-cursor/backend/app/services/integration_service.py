import asyncio
import aiohttp
import json
import base64
import hmac
import hashlib
import time
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from enum import Enum
import structlog
from dataclasses import dataclass

from app.core.config import settings

logger = structlog.get_logger()

class IntegrationType(Enum):
    SIEM = "siem"
    EMAIL = "email"
    CLOUD = "cloud"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"

class SIEMProvider(Enum):
    SPLUNK = "splunk"
    QRADAR = "qradar"
    ELK = "elk"
    SENTINEL = "sentinel"
    CROWDSTRIKE = "crowdstrike"

class EmailProvider(Enum):
    OFFICE365 = "office365"
    GMAIL = "gmail"
    EXCHANGE = "exchange"
    SMTP = "smtp"

class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

@dataclass
class IntegrationConfig:
    id: str
    name: str
    type: IntegrationType
    provider: str
    config: Dict[str, Any]
    enabled: bool = True
    last_sync: Optional[datetime] = None
    status: str = "active"

class IntegrationService:
    def __init__(self):
        self.active_integrations: Dict[str, IntegrationConfig] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.sync_interval = 300  # 5 minutes
        
    async def initialize(self):
        """Initialize the integration service"""
        self.session = aiohttp.ClientSession()
        await self.load_integrations()
        asyncio.create_task(self._sync_loop())
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            
    async def load_integrations(self):
        """Load integration configurations from database"""
        # In a real implementation, this would load from database
        # For now, we'll use mock configurations
        self.active_integrations = {
            "splunk_main": IntegrationConfig(
                id="splunk_main",
                name="Main Splunk Instance",
                type=IntegrationType.SIEM,
                provider=SIEMProvider.SPLUNK.value,
                config={
                    "url": "https://splunk.company.com:8089",
                    "username": "cybershield_user",
                    "token": "splunk_token_here",
                    "index": "cybershield_events"
                }
            ),
            "office365_email": IntegrationConfig(
                id="office365_email",
                name="Office 365 Email",
                type=IntegrationType.EMAIL,
                provider=EmailProvider.OFFICE365.value,
                config={
                    "tenant_id": "tenant_id_here",
                    "client_id": "client_id_here",
                    "client_secret": "client_secret_here",
                    "mailbox": "security@company.com"
                }
            ),
            "aws_cloud": IntegrationConfig(
                id="aws_cloud",
                name="AWS Cloud Security",
                type=IntegrationType.CLOUD,
                provider=CloudProvider.AWS.value,
                config={
                    "access_key": "aws_access_key",
                    "secret_key": "aws_secret_key",
                    "region": "us-east-1",
                    "services": ["guardduty", "securityhub", "config"]
                }
            )
        }
        
    async def _sync_loop(self):
        """Background sync loop for integrations"""
        while True:
            try:
                await self.sync_all_integrations()
                await asyncio.sleep(self.sync_interval)
            except Exception as e:
                logger.error("Error in integration sync loop", error=str(e))
                await asyncio.sleep(60)  # Wait 1 minute on error
                
    async def sync_all_integrations(self):
        """Sync all active integrations"""
        for integration_id, config in self.active_integrations.items():
            if config.enabled:
                try:
                    await self.sync_integration(integration_id)
                except Exception as e:
                    logger.error(f"Error syncing integration {integration_id}", error=str(e))
                    
    async def sync_integration(self, integration_id: str):
        """Sync a specific integration"""
        config = self.active_integrations.get(integration_id)
        if not config:
            raise ValueError(f"Integration {integration_id} not found")
            
        if config.type == IntegrationType.SIEM:
            await self._sync_siem(config)
        elif config.type == IntegrationType.EMAIL:
            await self._sync_email(config)
        elif config.type == IntegrationType.CLOUD:
            await self._sync_cloud(config)
            
        # Update last sync time
        config.last_sync = datetime.utcnow()
        
    async def _sync_siem(self, config: IntegrationConfig):
        """Sync with SIEM system"""
        if config.provider == SIEMProvider.SPLUNK.value:
            await self._sync_splunk(config)
        elif config.provider == SIEMProvider.QRADAR.value:
            await self._sync_qradar(config)
        elif config.provider == SIEMProvider.ELK.value:
            await self._sync_elk(config)
        elif config.provider == SIEMProvider.SENTINEL.value:
            await self._sync_sentinel(config)
            
    async def _sync_splunk(self, config: IntegrationConfig):
        """Sync with Splunk"""
        try:
            # Get recent events from Splunk
            events = await self._get_splunk_events(config)
            
            # Process and store events
            for event in events:
                await self._process_siem_event(event, "splunk")
                
            logger.info("Splunk sync completed", events_count=len(events))
            
        except Exception as e:
            logger.error("Error syncing with Splunk", error=str(e))
            raise
            
    async def _get_splunk_events(self, config: IntegrationConfig) -> List[Dict]:
        """Get events from Splunk"""
        # Mock implementation - in real scenario, this would use Splunk REST API
        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "splunk",
                "event_type": "security_alert",
                "severity": "high",
                "message": "Suspicious login attempt detected",
                "raw_data": {"user": "test@company.com", "ip": "192.168.1.100"}
            }
        ]
        
    async def _sync_qradar(self, config: IntegrationConfig):
        """Sync with QRadar"""
        # Implementation for QRadar integration
        pass
        
    async def _sync_elk(self, config: IntegrationConfig):
        """Sync with ELK Stack"""
        # Implementation for ELK integration
        pass
        
    async def _sync_sentinel(self, config: IntegrationConfig):
        """Sync with Azure Sentinel"""
        # Implementation for Sentinel integration
        pass
        
    async def _sync_email(self, config: IntegrationConfig):
        """Sync with email provider"""
        if config.provider == EmailProvider.OFFICE365.value:
            await self._sync_office365(config)
        elif config.provider == EmailProvider.GMAIL.value:
            await self._sync_gmail(config)
            
    async def _sync_office365(self, config: IntegrationConfig):
        """Sync with Office 365"""
        try:
            # Get recent emails from Office 365
            emails = await self._get_office365_emails(config)
            
            # Process emails for security threats
            for email in emails:
                await self._process_email(email, "office365")
                
            logger.info("Office 365 sync completed", emails_count=len(emails))
            
        except Exception as e:
            logger.error("Error syncing with Office 365", error=str(e))
            raise
            
    async def _get_office365_emails(self, config: IntegrationConfig) -> List[Dict]:
        """Get emails from Office 365"""
        # Mock implementation - in real scenario, this would use Microsoft Graph API
        return [
            {
                "id": "email_123",
                "subject": "Suspicious Activity Detected",
                "from": "security@company.com",
                "to": ["admin@company.com"],
                "body": "Potential security threat detected...",
                "received_time": datetime.utcnow().isoformat(),
                "attachments": []
            }
        ]
        
    async def _sync_gmail(self, config: IntegrationConfig):
        """Sync with Gmail"""
        # Implementation for Gmail integration
        pass
        
    async def _sync_cloud(self, config: IntegrationConfig):
        """Sync with cloud provider"""
        if config.provider == CloudProvider.AWS.value:
            await self._sync_aws(config)
        elif config.provider == CloudProvider.AZURE.value:
            await self._sync_azure(config)
        elif config.provider == CloudProvider.GCP.value:
            await self._sync_gcp(config)
            
    async def _sync_aws(self, config: IntegrationConfig):
        """Sync with AWS security services"""
        try:
            # Get security findings from AWS
            findings = await self._get_aws_findings(config)
            
            # Process findings
            for finding in findings:
                await self._process_cloud_finding(finding, "aws")
                
            logger.info("AWS sync completed", findings_count=len(findings))
            
        except Exception as e:
            logger.error("Error syncing with AWS", error=str(e))
            raise
            
    async def _get_aws_findings(self, config: IntegrationConfig) -> List[Dict]:
        """Get security findings from AWS"""
        # Mock implementation - in real scenario, this would use AWS SDK
        return [
            {
                "id": "finding_123",
                "service": "guardduty",
                "severity": "high",
                "title": "Suspicious IAM activity detected",
                "description": "Unusual IAM user activity detected...",
                "timestamp": datetime.utcnow().isoformat(),
                "region": "us-east-1"
            }
        ]
        
    async def _sync_azure(self, config: IntegrationConfig):
        """Sync with Azure security services"""
        # Implementation for Azure integration
        pass
        
    async def _sync_gcp(self, config: IntegrationConfig):
        """Sync with GCP security services"""
        # Implementation for GCP integration
        pass
        
    async def _process_siem_event(self, event: Dict, source: str):
        """Process SIEM event and create incident if needed"""
        # Check if event should create an incident
        if event.get("severity") in ["high", "critical"]:
            # Create incident from SIEM event
            incident_data = {
                "title": f"SIEM Alert: {event.get('message', 'Security Event')}",
                "description": f"Event from {source}: {event.get('message')}",
                "severity": event.get("severity", "medium"),
                "source": source,
                "external_id": event.get("id"),
                "raw_data": event
            }
            
            # In real implementation, this would create an incident
            logger.info("Creating incident from SIEM event", incident_data=incident_data)
            
    async def _process_email(self, email: Dict, source: str):
        """Process email for security threats"""
        # Analyze email content for threats
        threat_score = await self._analyze_email_threat(email)
        
        if threat_score > 0.7:  # High threat threshold
            incident_data = {
                "title": f"Email Threat: {email.get('subject', 'Suspicious Email')}",
                "description": f"High-threat email detected from {source}",
                "severity": "high",
                "source": source,
                "external_id": email.get("id"),
                "raw_data": email
            }
            
            logger.info("Creating incident from email threat", incident_data=incident_data)
            
    async def _process_cloud_finding(self, finding: Dict, source: str):
        """Process cloud security finding"""
        # Create incident from cloud finding
        incident_data = {
            "title": f"Cloud Security: {finding.get('title', 'Security Finding')}",
            "description": f"Security finding from {source}: {finding.get('description')}",
            "severity": finding.get("severity", "medium"),
            "source": source,
            "external_id": finding.get("id"),
            "raw_data": finding
        }
        
        logger.info("Creating incident from cloud finding", incident_data=incident_data)
        
    async def _analyze_email_threat(self, email: Dict) -> float:
        """Analyze email for threat indicators"""
        # Mock threat analysis - in real implementation, this would use AI/ML
        threat_indicators = [
            "suspicious", "urgent", "password", "login", "verify",
            "account", "security", "breach", "compromise"
        ]
        
        content = f"{email.get('subject', '')} {email.get('body', '')}".lower()
        threat_score = sum(1 for indicator in threat_indicators if indicator in content)
        
        return min(threat_score / len(threat_indicators), 1.0)
        
    async def send_incident_to_siem(self, incident: Dict, integration_id: str):
        """Send incident to SIEM system"""
        config = self.active_integrations.get(integration_id)
        if not config or config.type != IntegrationType.SIEM:
            raise ValueError(f"Invalid SIEM integration: {integration_id}")
            
        if config.provider == SIEMProvider.SPLUNK.value:
            await self._send_to_splunk(incident, config)
        elif config.provider == SIEMProvider.QRADAR.value:
            await self._send_to_qradar(incident, config)
            
    async def _send_to_splunk(self, incident: Dict, config: IntegrationConfig):
        """Send incident to Splunk"""
        try:
            event_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "cybershield",
                "event_type": "incident",
                "severity": incident.get("severity"),
                "title": incident.get("title"),
                "description": incident.get("description"),
                "incident_id": incident.get("id"),
                "raw_data": incident
            }
            
            # In real implementation, this would send to Splunk HTTP Event Collector
            logger.info("Sending incident to Splunk", event_data=event_data)
            
        except Exception as e:
            logger.error("Error sending to Splunk", error=str(e))
            raise
            
    async def _send_to_qradar(self, incident: Dict, config: IntegrationConfig):
        """Send incident to QRadar"""
        # Implementation for QRadar integration
        pass
        
    async def send_notification_to_slack(self, message: str, channel: str = "#security"):
        """Send notification to Slack"""
        try:
            webhook_url = settings.SLACK_WEBHOOK_URL
            if not webhook_url:
                logger.warning("Slack webhook URL not configured")
                return
                
            payload = {
                "channel": channel,
                "text": message,
                "username": "CyberShield",
                "icon_emoji": ":shield:"
            }
            
            if self.session:
                async with self.session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info("Slack notification sent successfully")
                    else:
                        logger.error("Failed to send Slack notification", status=response.status)
                        
        except Exception as e:
            logger.error("Error sending Slack notification", error=str(e))
            
    async def send_notification_to_teams(self, message: str, webhook_url: str):
        """Send notification to Microsoft Teams"""
        try:
            payload = {
                "text": message,
                "themeColor": "0076D7"
            }
            
            if self.session:
                async with self.session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info("Teams notification sent successfully")
                    else:
                        logger.error("Failed to send Teams notification", status=response.status)
                        
        except Exception as e:
            logger.error("Error sending Teams notification", error=str(e))
            
    async def test_integration(self, integration_id: str) -> Dict[str, Any]:
        """Test integration connectivity"""
        config = self.active_integrations.get(integration_id)
        if not config:
            raise ValueError(f"Integration {integration_id} not found")
            
        try:
            if config.type == IntegrationType.SIEM:
                return await self._test_siem_connection(config)
            elif config.type == IntegrationType.EMAIL:
                return await self._test_email_connection(config)
            elif config.type == IntegrationType.CLOUD:
                return await self._test_cloud_connection(config)
            else:
                return {"success": False, "error": "Unsupported integration type"}
                
        except Exception as e:
            logger.error(f"Error testing integration {integration_id}", error=str(e))
            return {"success": False, "error": str(e)}
            
    async def _test_siem_connection(self, config: IntegrationConfig) -> Dict[str, Any]:
        """Test SIEM connection"""
        # Mock connection test
        return {
            "success": True,
            "message": f"Successfully connected to {config.provider}",
            "details": {
                "provider": config.provider,
                "url": config.config.get("url", "N/A"),
                "status": "connected"
            }
        }
        
    async def _test_email_connection(self, config: IntegrationConfig) -> Dict[str, Any]:
        """Test email connection"""
        return {
            "success": True,
            "message": f"Successfully connected to {config.provider}",
            "details": {
                "provider": config.provider,
                "mailbox": config.config.get("mailbox", "N/A"),
                "status": "connected"
            }
        }
        
    async def _test_cloud_connection(self, config: IntegrationConfig) -> Dict[str, Any]:
        """Test cloud connection"""
        return {
            "success": True,
            "message": f"Successfully connected to {config.provider}",
            "details": {
                "provider": config.provider,
                "region": config.config.get("region", "N/A"),
                "status": "connected"
            }
        }
        
    async def get_integration_status(self) -> Dict[str, Any]:
        """Get status of all integrations"""
        status = {}
        for integration_id, config in self.active_integrations.items():
            status[integration_id] = {
                "name": config.name,
                "type": config.type.value,
                "provider": config.provider,
                "enabled": config.enabled,
                "status": config.status,
                "last_sync": config.last_sync.isoformat() if config.last_sync else None
            }
        return status

# Global integration service instance
integration_service = IntegrationService() 