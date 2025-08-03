"""
RASP (Runtime Application Self-Protection) Service
Business logic layer for RASP functionality including:
- Agent management and monitoring
- Attack detection and logging
- Rule management and validation
- Vulnerability tracking
- Virtual patching
- Telemetry and alerts
- SIEM/SOAR integrations
"""
import asyncio
import logging
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from app.models.rasp import (
    RASPAgent, RASPAttack, RASPRule, RASPVulnerability, RASPVirtualPatch,
    RASPTelemetry, RASPAlert, RASPIntegration,
    AgentStatus, AttackSeverity, VulnerabilityStatus, AlertStatus, PatchStatus
)
from app.schemas.rasp import (
    AgentCreate, AgentUpdate, AttackCreate, RuleCreate, RuleUpdate,
    VulnerabilityUpdate, VirtualPatchCreate, AlertUpdate, IntegrationCreate
)

logger = logging.getLogger(__name__)


class RASPService:
    """Service class for RASP operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db

    # Agent Management Methods
    async def get_agents(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        status: Optional[str] = None, 
        language: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get agents with optional filtering"""
        try:
            query = select(RASPAgent)
            
            if status:
                query = query.where(RASPAgent.status == status)
            if language:
                query = query.where(RASPAgent.language == language)
                
            query = query.offset(skip).limit(limit)
            result = await self.db.execute(query)
            agents = result.scalars().all()
            
            return [self._agent_to_dict(agent) for agent in agents]
        except Exception as e:
            logger.error(f"Error getting agents: {e}")
            raise

    async def get_agent(self, agent_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific agent by ID"""
        try:
            result = await self.db.execute(
                select(RASPAgent).where(RASPAgent.agent_id == agent_id)
            )
            agent = result.scalar_one_or_none()
            return self._agent_to_dict(agent) if agent else None
        except Exception as e:
            logger.error(f"Error getting agent {agent_id}: {e}")
            raise

    async def create_agent(self, agent_data: AgentCreate) -> Dict[str, Any]:
        """Create a new agent"""
        try:
            agent = RASPAgent(
                app_name=agent_data.app_name,
                language=agent_data.language,
                version=agent_data.version,
                config=agent_data.config
            )
            self.db.add(agent)
            await self.db.commit()
            await self.db.refresh(agent)
            return self._agent_to_dict(agent)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating agent: {e}")
            raise

    async def update_agent(self, agent_id: int, agent_data: AgentUpdate) -> Optional[Dict[str, Any]]:
        """Update an existing agent"""
        try:
            result = await self.db.execute(
                select(RASPAgent).where(RASPAgent.agent_id == agent_id)
            )
            agent = result.scalar_one_or_none()
            if not agent:
                return None

            update_data = agent_data.dict(exclude_unset=True)
            for field, value in update_data.items():
                setattr(agent, field, value)
            
            agent.updated_at = datetime.utcnow()
            await self.db.commit()
            await self.db.refresh(agent)
            return self._agent_to_dict(agent)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating agent {agent_id}: {e}")
            raise

    async def delete_agent(self, agent_id: int) -> bool:
        """Delete an agent"""
        try:
            result = await self.db.execute(
                select(RASPAgent).where(RASPAgent.agent_id == agent_id)
            )
            agent = result.scalar_one_or_none()
            if not agent:
                return False

            await self.db.delete(agent)
            await self.db.commit()
            return True
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error deleting agent {agent_id}: {e}")
            raise

    async def update_agent_heartbeat(self, agent_id: int, heartbeat_data: Dict[str, Any]) -> bool:
        """Update agent heartbeat and telemetry"""
        try:
            result = await self.db.execute(
                select(RASPAgent).where(RASPAgent.agent_id == agent_id)
            )
            agent = result.scalar_one_or_none()
            if not agent:
                return False

            # Update agent heartbeat
            agent.last_seen = datetime.utcnow()
            if 'status' in heartbeat_data:
                agent.status = heartbeat_data['status']
            if 'config' in heartbeat_data:
                agent.config.update(heartbeat_data['config'])

            # Store telemetry data
            if 'telemetry' in heartbeat_data:
                for telemetry_item in heartbeat_data['telemetry']:
                    telemetry = RASPTelemetry(
                        agent_id=agent_id,
                        metric_name=telemetry_item.get('metric_name'),
                        metric_value=telemetry_item.get('metric_value'),
                        metric_data=telemetry_item.get('metric_data', {})
                    )
                    self.db.add(telemetry)

            await self.db.commit()
            return True
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating agent heartbeat {agent_id}: {e}")
            raise

    # Attack Management Methods
    async def get_attacks(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        agent_id: Optional[int] = None,
        vuln_type: Optional[str] = None,
        severity: Optional[str] = None,
        blocked: Optional[bool] = None,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get attacks with optional filtering"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            query = select(RASPAttack).where(RASPAttack.timestamp >= cutoff_time)
            
            if agent_id:
                query = query.where(RASPAttack.agent_id == agent_id)
            if vuln_type:
                query = query.where(RASPAttack.vuln_type == vuln_type)
            if severity:
                query = query.where(RASPAttack.severity == severity)
            if blocked is not None:
                query = query.where(RASPAttack.blocked == blocked)
                
            query = query.order_by(RASPAttack.timestamp.desc()).offset(skip).limit(limit)
            result = await self.db.execute(query)
            attacks = result.scalars().all()
            
            return [self._attack_to_dict(attack) for attack in attacks]
        except Exception as e:
            logger.error(f"Error getting attacks: {e}")
            raise

    async def get_attack(self, attack_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific attack by ID"""
        try:
            result = await self.db.execute(
                select(RASPAttack).where(RASPAttack.attack_id == attack_id)
            )
            attack = result.scalar_one_or_none()
            return self._attack_to_dict(attack) if attack else None
        except Exception as e:
            logger.error(f"Error getting attack {attack_id}: {e}")
            raise

    async def create_attack(self, attack_data: AttackCreate) -> Dict[str, Any]:
        """Create a new attack record"""
        try:
            attack = RASPAttack(
                agent_id=attack_data.agent_id,
                source_ip=attack_data.source_ip,
                url=attack_data.url,
                payload=attack_data.payload,
                vuln_type=attack_data.vuln_type,
                severity=attack_data.severity,
                stack_trace=attack_data.stack_trace,
                blocked=attack_data.blocked,
                context=attack_data.context,
                request_data=attack_data.request_data,
                response_data=attack_data.response_data
            )
            self.db.add(attack)
            await self.db.commit()
            await self.db.refresh(attack)
            
            # Create alert for the attack
            await self._create_attack_alert(attack)
            
            return self._attack_to_dict(attack)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating attack: {e}")
            raise

    # Rule Management Methods
    async def get_rules(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        language: Optional[str] = None,
        vuln_type: Optional[str] = None,
        enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Get rules with optional filtering"""
        try:
            query = select(RASPRule)
            
            if language:
                query = query.where(RASPRule.language == language)
            if vuln_type:
                query = query.where(RASPRule.vuln_type == vuln_type)
            if enabled is not None:
                query = query.where(RASPRule.enabled == enabled)
                
            query = query.offset(skip).limit(limit)
            result = await self.db.execute(query)
            rules = result.scalars().all()
            
            return [self._rule_to_dict(rule) for rule in rules]
        except Exception as e:
            logger.error(f"Error getting rules: {e}")
            raise

    async def get_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID"""
        try:
            result = await self.db.execute(
                select(RASPRule).where(RASPRule.rule_id == rule_id)
            )
            rule = result.scalar_one_or_none()
            return self._rule_to_dict(rule) if rule else None
        except Exception as e:
            logger.error(f"Error getting rule {rule_id}: {e}")
            raise

    async def create_rule(self, rule_data: RuleCreate) -> Dict[str, Any]:
        """Create a new rule"""
        try:
            rule = RASPRule(
                vuln_type=rule_data.vuln_type,
                language=rule_data.language,
                pattern=rule_data.pattern,
                severity=rule_data.severity,
                auto_block=rule_data.auto_block,
                description=rule_data.description
            )
            self.db.add(rule)
            await self.db.commit()
            await self.db.refresh(rule)
            return self._rule_to_dict(rule)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating rule: {e}")
            raise

    async def update_rule(self, rule_id: int, rule_data: RuleUpdate) -> Optional[Dict[str, Any]]:
        """Update an existing rule"""
        try:
            result = await self.db.execute(
                select(RASPRule).where(RASPRule.rule_id == rule_id)
            )
            rule = result.scalar_one_or_none()
            if not rule:
                return None

            update_data = rule_data.dict(exclude_unset=True)
            for field, value in update_data.items():
                setattr(rule, field, value)
            
            rule.updated_at = datetime.utcnow()
            await self.db.commit()
            await self.db.refresh(rule)
            return self._rule_to_dict(rule)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating rule {rule_id}: {e}")
            raise

    async def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule"""
        try:
            result = await self.db.execute(
                select(RASPRule).where(RASPRule.rule_id == rule_id)
            )
            rule = result.scalar_one_or_none()
            if not rule:
                return False

            await self.db.delete(rule)
            await self.db.commit()
            return True
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error deleting rule {rule_id}: {e}")
            raise

    async def validate_payload(self, payload: str, language: str) -> List[Dict[str, Any]]:
        """Validate payload against enabled rules"""
        try:
            result = await self.db.execute(
                select(RASPRule).where(
                    and_(
                        RASPRule.language == language,
                        RASPRule.enabled == True
                    )
                )
            )
            rules = result.scalars().all()
            
            matches = []
            for rule in rules:
                try:
                    if re.search(rule.pattern, payload, re.IGNORECASE):
                        matches.append({
                            'rule_id': rule.rule_id,
                            'vuln_type': rule.vuln_type,
                            'severity': rule.severity,
                            'auto_block': rule.auto_block,
                            'description': rule.description
                        })
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in rule {rule.rule_id}: {e}")
            
            return matches
        except Exception as e:
            logger.error(f"Error validating payload: {e}")
            raise

    # Vulnerability Management Methods
    async def get_vulnerabilities(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        agent_id: Optional[int] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities with optional filtering"""
        try:
            query = select(RASPVulnerability)
            
            if agent_id:
                query = query.where(RASPVulnerability.agent_id == agent_id)
            if status:
                query = query.where(RASPVulnerability.status == status)
            if severity:
                query = query.where(RASPVulnerability.severity == severity)
            if vuln_type:
                query = query.where(RASPVulnerability.vuln_type == vuln_type)
                
            query = query.order_by(RASPVulnerability.created_at.desc()).offset(skip).limit(limit)
            result = await self.db.execute(query)
            vulnerabilities = result.scalars().all()
            
            return [self._vulnerability_to_dict(vuln) for vuln in vulnerabilities]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {e}")
            raise

    async def get_vulnerability(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific vulnerability by ID"""
        try:
            result = await self.db.execute(
                select(RASPVulnerability).where(RASPVulnerability.vuln_id == vuln_id)
            )
            vulnerability = result.scalar_one_or_none()
            return self._vulnerability_to_dict(vulnerability) if vulnerability else None
        except Exception as e:
            logger.error(f"Error getting vulnerability {vuln_id}: {e}")
            raise

    async def update_vulnerability(self, vuln_id: int, vuln_data: VulnerabilityUpdate) -> Optional[Dict[str, Any]]:
        """Update vulnerability status and details"""
        try:
            result = await self.db.execute(
                select(RASPVulnerability).where(RASPVulnerability.vuln_id == vuln_id)
            )
            vulnerability = result.scalar_one_or_none()
            if not vulnerability:
                return None

            update_data = vuln_data.dict(exclude_unset=True)
            for field, value in update_data.items():
                setattr(vulnerability, field, value)
            
            vulnerability.updated_at = datetime.utcnow()
            await self.db.commit()
            await self.db.refresh(vulnerability)
            return self._vulnerability_to_dict(vulnerability)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating vulnerability {vuln_id}: {e}")
            raise

    # Virtual Patching Methods
    async def get_virtual_patches(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        agent_id: Optional[int] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get virtual patches with optional filtering"""
        try:
            query = select(RASPVirtualPatch)
            
            if agent_id:
                query = query.where(RASPVirtualPatch.agent_id == agent_id)
            if status:
                query = query.where(RASPVirtualPatch.status == status)
                
            query = query.order_by(RASPVirtualPatch.created_at.desc()).offset(skip).limit(limit)
            result = await self.db.execute(query)
            patches = result.scalars().all()
            
            return [self._virtual_patch_to_dict(patch) for patch in patches]
        except Exception as e:
            logger.error(f"Error getting virtual patches: {e}")
            raise

    async def create_virtual_patch(self, patch_data: VirtualPatchCreate) -> Dict[str, Any]:
        """Create a new virtual patch"""
        try:
            patch = RASPVirtualPatch(
                vuln_id=patch_data.vuln_id,
                agent_id=patch_data.agent_id,
                patch_type=patch_data.patch_type,
                patch_config=patch_data.patch_config,
                expires_at=patch_data.expires_at
            )
            self.db.add(patch)
            await self.db.commit()
            await self.db.refresh(patch)
            return self._virtual_patch_to_dict(patch)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating virtual patch: {e}")
            raise

    # Alert Management Methods
    async def get_alerts(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        agent_id: Optional[int] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering"""
        try:
            query = select(RASPAlert)
            
            if agent_id:
                query = query.where(RASPAlert.agent_id == agent_id)
            if status:
                query = query.where(RASPAlert.status == status)
            if severity:
                query = query.where(RASPAlert.severity == severity)
                
            query = query.order_by(RASPAlert.created_at.desc()).offset(skip).limit(limit)
            result = await self.db.execute(query)
            alerts = result.scalars().all()
            
            return [self._alert_to_dict(alert) for alert in alerts]
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            raise

    async def update_alert(self, alert_id: int, alert_data: AlertUpdate) -> Optional[Dict[str, Any]]:
        """Update alert status"""
        try:
            result = await self.db.execute(
                select(RASPAlert).where(RASPAlert.alert_id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if not alert:
                return None

            update_data = alert_data.dict(exclude_unset=True)
            for field, value in update_data.items():
                setattr(alert, field, value)
            
            if 'status' in update_data and update_data['status'] == AlertStatus.ACKNOWLEDGED:
                alert.acknowledged_at = datetime.utcnow()
            
            await self.db.commit()
            await self.db.refresh(alert)
            return self._alert_to_dict(alert)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating alert {alert_id}: {e}")
            raise

    # Integration Methods
    async def get_integrations(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        integration_type: Optional[str] = None,
        enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Get integrations with optional filtering"""
        try:
            query = select(RASPIntegration)
            
            if integration_type:
                query = query.where(RASPIntegration.integration_type == integration_type)
            if enabled is not None:
                query = query.where(RASPIntegration.enabled == enabled)
                
            query = query.offset(skip).limit(limit)
            result = await self.db.execute(query)
            integrations = result.scalars().all()
            
            return [self._integration_to_dict(integration) for integration in integrations]
        except Exception as e:
            logger.error(f"Error getting integrations: {e}")
            raise

    async def create_integration(self, integration_data: IntegrationCreate) -> Dict[str, Any]:
        """Create a new integration"""
        try:
            integration = RASPIntegration(
                integration_type=integration_data.integration_type,
                name=integration_data.name,
                config=integration_data.config
            )
            self.db.add(integration)
            await self.db.commit()
            await self.db.refresh(integration)
            return self._integration_to_dict(integration)
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating integration: {e}")
            raise

    # Dashboard Methods
    async def get_dashboard_overview(self) -> Dict[str, Any]:
        """Get dashboard overview with key metrics"""
        try:
            # Get agent counts
            total_agents_result = await self.db.execute(select(func.count(RASPAgent.agent_id)))
            total_agents = total_agents_result.scalar()
            
            active_agents_result = await self.db.execute(
                select(func.count(RASPAgent.agent_id)).where(RASPAgent.status == AgentStatus.ACTIVE)
            )
            active_agents = active_agents_result.scalar()

            # Get attack counts (last 24 hours)
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            total_attacks_result = await self.db.execute(
                select(func.count(RASPAttack.attack_id)).where(RASPAttack.timestamp >= cutoff_time)
            )
            total_attacks = total_attacks_result.scalar()
            
            blocked_attacks_result = await self.db.execute(
                select(func.count(RASPAttack.attack_id)).where(
                    and_(RASPAttack.timestamp >= cutoff_time, RASPAttack.blocked == True)
                )
            )
            blocked_attacks = blocked_attacks_result.scalar()

            # Get vulnerability counts
            total_vulns_result = await self.db.execute(select(func.count(RASPVulnerability.vuln_id)))
            total_vulns = total_vulns_result.scalar()
            
            open_vulns_result = await self.db.execute(
                select(func.count(RASPVulnerability.vuln_id)).where(RASPVulnerability.status == VulnerabilityStatus.OPEN)
            )
            open_vulns = open_vulns_result.scalar()

            # Get alert counts
            total_alerts_result = await self.db.execute(select(func.count(RASPAlert.alert_id)))
            total_alerts = total_alerts_result.scalar()
            
            new_alerts_result = await self.db.execute(
                select(func.count(RASPAlert.alert_id)).where(RASPAlert.status == AlertStatus.NEW)
            )
            new_alerts = new_alerts_result.scalar()

            # Get recent attacks by type
            recent_attacks_by_type_result = await self.db.execute(
                select(RASPAttack.vuln_type, func.count(RASPAttack.attack_id))
                .where(RASPAttack.timestamp >= cutoff_time)
                .group_by(RASPAttack.vuln_type)
            )
            recent_attacks_by_type = dict(recent_attacks_by_type_result.all())

            # Get recent attacks by severity
            recent_attacks_by_severity_result = await self.db.execute(
                select(RASPAttack.severity, func.count(RASPAttack.attack_id))
                .where(RASPAttack.timestamp >= cutoff_time)
                .group_by(RASPAttack.severity)
            )
            recent_attacks_by_severity = dict(recent_attacks_by_severity_result.all())

            return {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'total_attacks': total_attacks,
                'blocked_attacks': blocked_attacks,
                'total_vulnerabilities': total_vulns,
                'open_vulnerabilities': open_vulns,
                'total_alerts': total_alerts,
                'new_alerts': new_alerts,
                'recent_attacks_by_type': recent_attacks_by_type,
                'recent_attacks_by_severity': recent_attacks_by_severity
            }
        except Exception as e:
            logger.error(f"Error getting dashboard overview: {e}")
            raise

    async def get_attack_summary(self, hours: int = 24, agent_id: Optional[int] = None) -> Dict[str, Any]:
        """Get attack summary statistics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            query = select(RASPAttack).where(RASPAttack.timestamp >= cutoff_time)
            
            if agent_id:
                query = query.where(RASPAttack.agent_id == agent_id)
            
            result = await self.db.execute(query)
            attacks = result.scalars().all()
            
            total_attacks = len(attacks)
            blocked_attacks = sum(1 for attack in attacks if attack.blocked)
            successful_attacks = total_attacks - blocked_attacks
            
            # Group by type
            attacks_by_type = {}
            for attack in attacks:
                attacks_by_type[attack.vuln_type] = attacks_by_type.get(attack.vuln_type, 0) + 1
            
            # Group by severity
            attacks_by_severity = {}
            for attack in attacks:
                attacks_by_severity[attack.severity] = attacks_by_severity.get(attack.severity, 0) + 1
            
            # Group by agent
            attacks_by_agent = {}
            for attack in attacks:
                agent_name = f"Agent {attack.agent_id}"
                attacks_by_agent[agent_name] = attacks_by_agent.get(agent_name, 0) + 1
            
            return {
                'total_attacks': total_attacks,
                'blocked_attacks': blocked_attacks,
                'successful_attacks': successful_attacks,
                'attacks_by_type': attacks_by_type,
                'attacks_by_severity': attacks_by_severity,
                'attacks_by_agent': attacks_by_agent,
                'recent_trend': []  # TODO: Implement trend analysis
            }
        except Exception as e:
            logger.error(f"Error getting attack summary: {e}")
            raise

    async def get_agent_status(self) -> List[Dict[str, Any]]:
        """Get agent status and health information"""
        try:
            result = await self.db.execute(select(RASPAgent))
            agents = result.scalars().all()
            
            agent_status_list = []
            for agent in agents:
                # Calculate connection status
                time_diff = datetime.utcnow() - agent.last_seen
                if time_diff.total_seconds() < 300:  # 5 minutes
                    connection_status = 'online'
                elif time_diff.total_seconds() < 3600:  # 1 hour
                    connection_status = 'recent'
                else:
                    connection_status = 'offline'
                
                # Get recent attacks count
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                recent_attacks_result = await self.db.execute(
                    select(func.count(RASPAttack.attack_id))
                    .where(and_(RASPAttack.agent_id == agent.agent_id, RASPAttack.timestamp >= cutoff_time))
                )
                recent_attacks = recent_attacks_result.scalar()
                
                # Get open vulnerabilities count
                open_vulns_result = await self.db.execute(
                    select(func.count(RASPVulnerability.vuln_id))
                    .where(and_(RASPVulnerability.agent_id == agent.agent_id, RASPVulnerability.status == VulnerabilityStatus.OPEN))
                )
                open_vulnerabilities = open_vulns_result.scalar()
                
                agent_status_list.append({
                    'agent_id': agent.agent_id,
                    'app_name': agent.app_name,
                    'language': agent.language,
                    'version': agent.version,
                    'status': agent.status,
                    'last_seen': agent.last_seen,
                    'connection_status': connection_status,
                    'recent_attacks': recent_attacks,
                    'open_vulnerabilities': open_vulnerabilities
                })
            
            return agent_status_list
        except Exception as e:
            logger.error(f"Error getting agent status: {e}")
            raise

    # Webhook Processing
    async def process_webhook(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process webhook data from external integrations"""
        try:
            event_type = webhook_data.get('event_type')
            timestamp = webhook_data.get('timestamp', datetime.utcnow())
            data = webhook_data.get('data', {})
            source = webhook_data.get('source')
            
            # Process based on event type
            if event_type == 'attack_detected':
                # Create attack record from webhook
                attack_data = AttackCreate(
                    agent_id=data.get('agent_id'),
                    source_ip=data.get('source_ip'),
                    url=data.get('url'),
                    payload=data.get('payload'),
                    vuln_type=data.get('vuln_type'),
                    severity=data.get('severity', AttackSeverity.MEDIUM),
                    blocked=data.get('blocked', False),
                    context=data.get('context', {}),
                    request_data=data.get('request_data', {}),
                    response_data=data.get('response_data', {})
                )
                await self.create_attack(attack_data)
            
            elif event_type == 'vulnerability_found':
                # Create vulnerability record from webhook
                # Implementation depends on vulnerability schema
                pass
            
            elif event_type == 'agent_status':
                # Update agent status from webhook
                agent_id = data.get('agent_id')
                if agent_id:
                    await self.update_agent_heartbeat(agent_id, data)
            
            return {
                'status': 'processed',
                'event_type': event_type,
                'timestamp': timestamp,
                'source': source
            }
        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            raise

    # Helper Methods
    async def _create_attack_alert(self, attack: RASPAttack):
        """Create alert for detected attack"""
        try:
            alert = RASPAlert(
                agent_id=attack.agent_id,
                attack_id=attack.attack_id,
                alert_type='attack_detected',
                severity=attack.severity,
                message=f"Attack detected: {attack.vuln_type} from {attack.source_ip}"
            )
            self.db.add(alert)
            await self.db.commit()
        except Exception as e:
            logger.error(f"Error creating attack alert: {e}")

    def _agent_to_dict(self, agent: RASPAgent) -> Dict[str, Any]:
        """Convert agent model to dictionary"""
        return {
            'agent_id': agent.agent_id,
            'app_name': agent.app_name,
            'language': agent.language,
            'version': agent.version,
            'status': agent.status,
            'last_seen': agent.last_seen,
            'config': agent.config,
            'created_at': agent.created_at,
            'updated_at': agent.updated_at
        }

    def _attack_to_dict(self, attack: RASPAttack) -> Dict[str, Any]:
        """Convert attack model to dictionary"""
        return {
            'attack_id': attack.attack_id,
            'agent_id': attack.agent_id,
            'timestamp': attack.timestamp,
            'source_ip': attack.source_ip,
            'url': attack.url,
            'payload': attack.payload,
            'vuln_type': attack.vuln_type,
            'severity': attack.severity,
            'stack_trace': attack.stack_trace,
            'blocked': attack.blocked,
            'context': attack.context,
            'request_data': attack.request_data,
            'response_data': attack.response_data,
            'created_at': attack.created_at
        }

    def _rule_to_dict(self, rule: RASPRule) -> Dict[str, Any]:
        """Convert rule model to dictionary"""
        return {
            'rule_id': rule.rule_id,
            'vuln_type': rule.vuln_type,
            'language': rule.language,
            'pattern': rule.pattern,
            'severity': rule.severity,
            'auto_block': rule.auto_block,
            'description': rule.description,
            'enabled': rule.enabled,
            'created_at': rule.created_at,
            'updated_at': rule.updated_at
        }

    def _vulnerability_to_dict(self, vuln: RASPVulnerability) -> Dict[str, Any]:
        """Convert vulnerability model to dictionary"""
        return {
            'vuln_id': vuln.vuln_id,
            'agent_id': vuln.agent_id,
            'vuln_type': vuln.vuln_type,
            'severity': vuln.severity,
            'status': vuln.status,
            'description': vuln.description,
            'affected_file': vuln.affected_file,
            'affected_line': vuln.affected_line,
            'affected_method': vuln.affected_method,
            'cwe_id': vuln.cwe_id,
            'owasp_category': vuln.owasp_category,
            'evidence': vuln.evidence,
            'remediation': vuln.remediation,
            'created_at': vuln.created_at,
            'updated_at': vuln.updated_at
        }

    def _virtual_patch_to_dict(self, patch: RASPVirtualPatch) -> Dict[str, Any]:
        """Convert virtual patch model to dictionary"""
        return {
            'patch_id': patch.patch_id,
            'vuln_id': patch.vuln_id,
            'agent_id': patch.agent_id,
            'patch_type': patch.patch_type,
            'patch_config': patch.patch_config,
            'status': patch.status,
            'created_at': patch.created_at,
            'expires_at': patch.expires_at,
            'created_by': patch.created_by
        }

    def _alert_to_dict(self, alert: RASPAlert) -> Dict[str, Any]:
        """Convert alert model to dictionary"""
        return {
            'alert_id': alert.alert_id,
            'agent_id': alert.agent_id,
            'attack_id': alert.attack_id,
            'alert_type': alert.alert_type,
            'severity': alert.severity,
            'message': alert.message,
            'status': alert.status,
            'acknowledged_by': alert.acknowledged_by,
            'acknowledged_at': alert.acknowledged_at,
            'created_at': alert.created_at
        }

    def _integration_to_dict(self, integration: RASPIntegration) -> Dict[str, Any]:
        """Convert integration model to dictionary"""
        return {
            'integration_id': integration.integration_id,
            'integration_type': integration.integration_type,
            'name': integration.name,
            'config': integration.config,
            'enabled': integration.enabled,
            'last_sync': integration.last_sync,
            'created_at': integration.created_at,
            'updated_at': integration.updated_at
        } 