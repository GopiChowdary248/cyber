from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import uuid
import json
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc
import boto3
import azure.mgmt.resource
import google.cloud.resourcemanager

from app.models.cspm_models import *
from app.schemas.cspm_schemas import *

logger = logging.getLogger(__name__)

class CSPMService:
    """Service layer for CSPM operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    # ============================================================================
    # Risk Scoring & Assessment
    # ============================================================================
    
    async def calculate_asset_risk_score(self, asset: Asset) -> float:
        """Calculate comprehensive risk score for an asset"""
        try:
            base_score = 0.0
            
            # Factor 1: Findings severity (50% weight)
            findings_query = select(Finding).where(Finding.asset_id == asset.id)
            findings_result = await self.db.execute(findings_query)
            findings = findings_result.scalars().all()
            
            severity_scores = {
                FindingSeverity.CRITICAL: 100,
                FindingSeverity.HIGH: 75,
                FindingSeverity.MEDIUM: 50,
                FindingSeverity.LOW: 25,
                FindingSeverity.INFO: 10
            }
            
            if findings:
                severity_score = sum(severity_scores.get(f.severity, 0) for f in findings) / len(findings)
                base_score += severity_score * 0.5
            
            # Factor 2: Exposure level (20% weight)
            exposure_score = await self._calculate_exposure_score(asset)
            base_score += exposure_score * 0.2
            
            # Factor 3: Asset criticality (15% weight)
            criticality_score = await self._calculate_criticality_score(asset)
            base_score += criticality_score * 0.15
            
            # Factor 4: Exploitability (15% weight)
            exploitability_score = await self._calculate_exploitability_score(asset)
            base_score += exploitability_score * 0.15
            
            # Normalize to 0-100 range
            risk_score = min(100.0, max(0.0, base_score))
            
            return round(risk_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating risk score for asset {asset.id}: {str(e)}")
            return 0.0
    
    async def _calculate_exposure_score(self, asset: Asset) -> float:
        """Calculate exposure score based on network configuration"""
        try:
            exposure_score = 0.0
            
            # Check if asset is publicly accessible
            if asset.metadata:
                # AWS S3 bucket public access
                if asset.resource_type == "s3" and asset.metadata.get("public_access_block"):
                    if not asset.metadata["public_access_block"].get("block_public_acls"):
                        exposure_score += 50
                
                # EC2 instance with public IP
                if asset.resource_type == "ec2" and asset.metadata.get("public_ip_address"):
                    exposure_score += 40
                
                # RDS with public accessibility
                if asset.resource_type == "rds" and asset.metadata.get("publicly_accessible"):
                    exposure_score += 60
                
                # Load balancer with public access
                if asset.resource_type in ["elb", "alb", "nlb"] and asset.metadata.get("scheme") == "internet-facing":
                    exposure_score += 45
            
            return min(100.0, exposure_score)
            
        except Exception as e:
            logger.error(f"Error calculating exposure score: {str(e)}")
            return 0.0
    
    async def _calculate_criticality_score(self, asset: Asset) -> float:
        """Calculate asset criticality based on tags and metadata"""
        try:
            criticality_score = 50.0  # Default medium criticality
        
            if asset.tags:
                # Check for criticality tags
                criticality_tags = {
                    "production": 90,
                    "prod": 90,
                    "critical": 95,
                    "high": 80,
                    "medium": 50,
                    "low": 20,
                    "dev": 30,
                    "test": 20
                }
                
                for tag_key, tag_value in asset.tags.items():
                    tag_lower = str(tag_value).lower()
                    if tag_lower in criticality_tags:
                        criticality_score = criticality_tags[tag_lower]
                        break
                
                # Check for business critical indicators
                business_critical_indicators = [
                    "database", "db", "payment", "financial", "customer", "user"
                ]
                
                for indicator in business_critical_indicators:
                    if any(indicator in str(v).lower() for v in asset.tags.values()):
                        criticality_score = min(100.0, criticality_score + 20)
                        break
            
            return criticality_score
            
        except Exception as e:
            logger.error(f"Error calculating criticality score: {str(e)}")
            return 50.0
    
    async def _calculate_exploitability_score(self, asset: Asset) -> float:
        """Calculate exploitability score based on vulnerabilities and configuration"""
        try:
            exploitability_score = 0.0
            
            # Check for known vulnerabilities
            findings_query = select(Finding).where(
                and_(
                    Finding.asset_id == asset.id,
                    Finding.severity.in_([FindingSeverity.CRITICAL, FindingSeverity.HIGH])
                )
            )
            findings_result = await self.db.execute(findings_query)
            critical_high_findings = findings_result.scalars().all()
            
            if critical_high_findings:
                exploitability_score += min(100.0, len(critical_high_findings) * 25)
            
            # Check for weak configurations
            if asset.metadata:
                # Weak IAM policies
                if asset.resource_type == "iam" and asset.metadata.get("policy_document"):
                    if self._has_weak_iam_policy(asset.metadata["policy_document"]):
                        exploitability_score += 30
                
                # Unencrypted resources
                if asset.metadata.get("encrypted") == False:
                    exploitability_score += 25
                
                # Outdated software versions
                if asset.metadata.get("version"):
                    if self._is_outdated_version(asset.metadata["version"]):
                        exploitability_score += 20
            
            return min(100.0, exploitability_score)
            
        except Exception as e:
            logger.error(f"Error calculating exploitability score: {str(e)}")
            return 0.0
    
    def _has_weak_iam_policy(self, policy_document: Dict[str, Any]) -> bool:
        """Check if IAM policy has weak permissions"""
        try:
            if not policy_document or "Statement" not in policy_document:
                return False
            
            weak_actions = [
                "*",  # Wildcard permissions
                "iam:*",
                "s3:*",
                "ec2:*",
                "rds:*",
                "lambda:*"
            ]
            
            for statement in policy_document["Statement"]:
                if "Action" in statement:
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        if any(action.startswith(weak) for weak in weak_actions):
                            return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking IAM policy: {str(e)}")
            return False
    
    def _is_outdated_version(self, version: str) -> bool:
        """Check if software version is outdated"""
        try:
            # This is a simplified check - in production you'd want more sophisticated version comparison
            if not version:
                return False
            
            # Check for very old version patterns
            old_patterns = ["1.0", "2.0", "2018", "2019", "2020"]
            return any(pattern in str(version) for pattern in old_patterns)
            
        except Exception as e:
            logger.error(f"Error checking version: {str(e)}")
            return False
    
    # ============================================================================
    # Policy Evaluation
    # ============================================================================
    
    async def evaluate_policy_against_asset(self, policy: Policy, asset: Asset) -> Optional[Finding]:
        """Evaluate a single policy against a single asset"""
        try:
            # Skip disabled policies
            if not policy.enabled:
                return None
            
            # Evaluate policy rule
            evaluation_result = await self._evaluate_policy_rule(policy.rule, asset)
            
            if evaluation_result.get("violation"):
                # Create finding
                finding = Finding(
                    asset_id=asset.id,
                    policy_id=policy.id,
                    severity=policy.severity,
                    status=FindingStatus.OPEN,
                    title=policy.name,
                    description=policy.description or f"Policy violation: {policy.name}",
                    evidence=evaluation_result.get("evidence", {}),
                    risk_score=await self.calculate_asset_risk_score(asset)
                )
                
                return finding
            
            return None
            
        except Exception as e:
            logger.error(f"Error evaluating policy {policy.id} against asset {asset.id}: {str(e)}")
            return None
    
    async def _evaluate_policy_rule(self, rule: Dict[str, Any], asset: Asset) -> Dict[str, Any]:
        """Evaluate policy rule against asset metadata"""
        try:
            rule_type = rule.get("type", "simple")
            
            if rule_type == "simple":
                return await self._evaluate_simple_rule(rule, asset)
            elif rule_type == "rego":
                return await self._evaluate_rego_rule(rule, asset)
            elif rule_type == "cel":
                return await self._evaluate_cel_rule(rule, asset)
            else:
                logger.warning(f"Unknown rule type: {rule_type}")
                return {"violation": False}
                
        except Exception as e:
            logger.error(f"Error evaluating rule: {str(e)}")
            return {"violation": False}
    
    async def _evaluate_simple_rule(self, rule: Dict[str, Any], asset: Asset) -> Dict[str, Any]:
        """Evaluate simple JSON-based rule"""
        try:
            conditions = rule.get("conditions", [])
            violation = False
            evidence = {}
            
            for condition in conditions:
                field = condition.get("field")
                operator = condition.get("operator")
                value = condition.get("value")
                
                if not all([field, operator, value]):
                    continue
                
                # Get field value from asset
                field_value = self._get_nested_field_value(asset, field)
                
                # Apply operator
                condition_result = self._apply_operator(field_value, operator, value)
                
                if not condition_result:
                    violation = True
                    evidence[field] = {
                        "expected": value,
                        "actual": field_value,
                        "operator": operator
                    }
            
            return {
                "violation": violation,
                "evidence": evidence
            }
            
        except Exception as e:
            logger.error(f"Error evaluating simple rule: {str(e)}")
            return {"violation": False}
    
    def _get_nested_field_value(self, asset: Asset, field_path: str) -> Any:
        """Get nested field value from asset using dot notation"""
        try:
            if "." in field_path:
                # Handle nested fields like "metadata.security_groups"
                parts = field_path.split(".")
                current = asset
                
                for part in parts:
                    if hasattr(current, part):
                        current = getattr(current, part)
                    elif isinstance(current, dict):
                        current = current.get(part)
                    else:
                        return None
                
                return current
            else:
                # Direct attribute
                if hasattr(asset, field_path):
                    return getattr(asset, field_path)
                elif isinstance(asset.metadata, dict):
                    return asset.metadata.get(field_path)
                else:
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting field value for {field_path}: {str(e)}")
            return None
    
    def _apply_operator(self, actual_value: Any, operator: str, expected_value: Any) -> bool:
        """Apply comparison operator"""
        try:
            if operator == "equals":
                return actual_value == expected_value
            elif operator == "not_equals":
                return actual_value != expected_value
            elif operator == "contains":
                return expected_value in str(actual_value)
            elif operator == "not_contains":
                return expected_value not in str(actual_value)
            elif operator == "greater_than":
                return float(actual_value or 0) > float(expected_value)
            elif operator == "less_than":
                return float(actual_value or 0) < float(expected_value)
            elif operator == "exists":
                return actual_value is not None
            elif operator == "not_exists":
                return actual_value is None
            else:
                logger.warning(f"Unknown operator: {operator}")
                return True
                
        except Exception as e:
            logger.error(f"Error applying operator {operator}: {str(e)}")
            return True
    
    async def _evaluate_rego_rule(self, rule: Dict[str, Any], asset: Asset) -> Dict[str, Any]:
        """Evaluate Rego-based rule (placeholder for OPA integration)"""
        # TODO: Implement OPA/Rego evaluation
        logger.info("Rego rule evaluation not yet implemented")
        return {"violation": False}
    
    async def _evaluate_cel_rule(self, rule: Dict[str, Any], asset: Asset) -> Dict[str, Any]:
        """Evaluate CEL-based rule (placeholder for CEL integration)"""
        # TODO: Implement CEL evaluation
        logger.info("CEL rule evaluation not yet implemented")
        return {"violation": False}
    
    # ============================================================================
    # Asset Management
    # ============================================================================
    
    async def sync_cloud_assets(self, connector: Connector) -> Dict[str, Any]:
        """Sync assets from cloud provider"""
        try:
            if connector.type == CloudProvider.AWS:
                return await self._sync_aws_assets(connector)
            elif connector.type == CloudProvider.AZURE:
                return await self._sync_azure_assets(connector)
            elif connector.type == CloudProvider.GCP:
                return await self._sync_gcp_assets(connector)
            else:
                logger.warning(f"Unsupported cloud provider: {connector.type}")
                return {"success": False, "error": f"Unsupported provider: {connector.type}"}
                
        except Exception as e:
            logger.error(f"Error syncing assets for connector {connector.id}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _sync_aws_assets(self, connector: Connector) -> Dict[str, Any]:
        """Sync AWS assets using boto3"""
        try:
            # Extract AWS credentials from connector config
            config = connector.config
            aws_access_key = config.get("access_key_id")
            aws_secret_key = config.get("secret_access_key")
            aws_region = config.get("region", "us-east-1")
            
            if not (aws_access_key and aws_secret_key):
                return {"success": False, "error": "Missing AWS credentials"}
            
            # Initialize AWS clients
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            
            # Sync different resource types
            synced_assets = []
            
            # EC2 instances
            ec2_client = session.client('ec2')
            ec2_response = ec2_client.describe_instances()
            for reservation in ec2_response['Reservations']:
                for instance in reservation['Instances']:
                    asset = await self._create_aws_asset(
                        connector, "ec2", instance['InstanceId'], instance, ec2_client
                    )
                    if asset:
                        synced_assets.append(asset)
            
            # S3 buckets
            s3_client = session.client('s3')
            s3_response = s3_client.list_buckets()
            for bucket in s3_response['Buckets']:
                asset = await self._create_aws_asset(
                    connector, "s3", bucket['Name'], bucket, s3_client
                )
                if asset:
                    synced_assets.append(asset)
            
            # RDS instances
            rds_client = session.client('rds')
            rds_response = rds_client.describe_db_instances()
            for db_instance in rds_response['DBInstances']:
                asset = await self._create_aws_asset(
                    connector, "rds", db_instance['DBInstanceIdentifier'], db_instance, rds_client
                )
                if asset:
                    synced_assets.append(asset)
            
            return {
                "success": True,
                "synced_assets": len(synced_assets),
                "details": f"Synced {len(synced_assets)} assets from AWS"
            }
            
        except Exception as e:
            logger.error(f"Error syncing AWS assets: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _create_aws_asset(
        self, 
        connector: Connector, 
        resource_type: str, 
        resource_id: str, 
        resource_data: Dict[str, Any],
        client: Any
    ) -> Optional[Asset]:
        """Create AWS asset from resource data"""
        try:
            # Check if asset already exists
            existing_query = select(Asset).where(
                and_(
                    Asset.connector_id == connector.id,
                    Asset.resource_id == resource_id
                )
            )
            existing_result = await self.db.execute(existing_query)
            existing_asset = existing_result.scalar_one_or_none()
            
            # Prepare asset data
            asset_data = {
                "connector_id": connector.id,
                "project_id": connector.project_id,
                "cloud": CloudProvider.AWS,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "metadata": resource_data,
                "last_seen": datetime.utcnow()
            }
            
            # Extract name and tags
            if resource_type == "ec2":
                asset_data["name"] = self._extract_ec2_name(resource_data)
                asset_data["region"] = resource_data.get("Placement", {}).get("AvailabilityZone", "")
                asset_data["tags"] = self._extract_aws_tags(resource_data.get("Tags", []))
            elif resource_type == "s3":
                asset_data["name"] = resource_id
                asset_data["tags"] = self._extract_aws_tags(resource_data.get("Tags", []))
            elif resource_type == "rds":
                asset_data["name"] = resource_id
                asset_data["region"] = resource_data.get("AvailabilityZone", "")
                asset_data["tags"] = self._extract_aws_tags(resource_data.get("TagList", []))
            
            if existing_asset:
                # Update existing asset
                for key, value in asset_data.items():
                    if key != "id":
                        setattr(existing_asset, key, value)
                existing_asset.last_seen = datetime.utcnow()
                await self.db.commit()
                return existing_asset
            else:
                # Create new asset
                asset_data["first_seen"] = datetime.utcnow()
                new_asset = Asset(**asset_data)
                self.db.add(new_asset)
                await self.db.commit()
                await self.db.refresh(new_asset)
                return new_asset
                
        except Exception as e:
            logger.error(f"Error creating AWS asset {resource_id}: {str(e)}")
            return None
    
    def _extract_ec2_name(self, instance_data: Dict[str, Any]) -> str:
        """Extract EC2 instance name from tags"""
        try:
            tags = instance_data.get("Tags", [])
            for tag in tags:
                if tag.get("Key") == "Name":
                    return tag.get("Value", "Unknown")
            return f"i-{instance_data.get('InstanceId', 'unknown')}"
        except Exception:
            return "Unknown"
    
    def _extract_aws_tags(self, tags: List[Dict[str, str]]) -> Dict[str, str]:
        """Extract AWS tags into key-value dictionary"""
        try:
            return {tag["Key"]: tag["Value"] for tag in tags if "Key" in tag and "Value" in tag}
        except Exception:
            return {}
    
    async def _sync_azure_assets(self, connector: Connector) -> Dict[str, Any]:
        """Sync Azure assets (placeholder)"""
        # TODO: Implement Azure asset sync
        logger.info("Azure asset sync not yet implemented")
        return {"success": False, "error": "Azure sync not implemented"}
    
    async def _sync_gcp_assets(self, connector: Connector) -> Dict[str, Any]:
        """Sync GCP assets (placeholder)"""
        # TODO: Implement GCP asset sync
        logger.info("GCP asset sync not yet implemented")
        return {"success": False, "error": "GCP sync not implemented"}
    
    # ============================================================================
    # Compliance & Reporting
    # ============================================================================
    
    async def generate_compliance_report(self, framework_id: uuid.UUID, project_id: uuid.UUID) -> Dict[str, Any]:
        """Generate compliance report for a specific framework"""
        try:
            # Get framework details
            framework_query = select(ComplianceFramework).where(ComplianceFramework.id == framework_id)
            framework_result = await self.db.execute(framework_query)
            framework = framework_result.scalar_one_or_none()
            
            if not framework:
                return {"success": False, "error": "Framework not found"}
            
            # Get project assets
            assets_query = select(Asset).where(Asset.project_id == project_id)
            assets_result = await self.db.execute(assets_query)
            assets = assets_result.scalars().all()
            
            # Get policies for this framework
            policies_query = select(Policy).where(
                and_(
                    Policy.framework == framework.name,
                    Policy.enabled == True
                )
            )
            policies_result = await self.db.execute(policies_query)
            policies = policies_result.scalars().all()
            
            # Evaluate compliance
            total_controls = len(policies)
            passed_controls = 0
            failed_controls = 0
            compliance_details = []
            
            for policy in policies:
                policy_violations = 0
                for asset in assets:
                    finding = await self.evaluate_policy_against_asset(policy, asset)
                    if finding:
                        policy_violations += 1
                
                if policy_violations == 0:
                    passed_controls += 1
                    compliance_details.append({
                        "policy": policy.name,
                        "status": "passed",
                        "violations": 0
                    })
                else:
                    failed_controls += 1
                    compliance_details.append({
                        "policy": policy.name,
                        "status": "failed",
                        "violations": policy_violations
                    })
            
            # Calculate compliance score
            compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 100
            
            return {
                "success": True,
                "framework": framework.name,
                "total_controls": total_controls,
                "passed_controls": passed_controls,
                "failed_controls": failed_controls,
                "compliance_score": round(compliance_score, 2),
                "details": compliance_details
            }
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # ============================================================================
    # Dashboard & Analytics
    # ============================================================================
    
    async def get_dashboard_metrics(self, project_id: Optional[uuid.UUID] = None) -> Dict[str, Any]:
        """Get comprehensive dashboard metrics"""
        try:
            base_filters = []
            if project_id:
                base_filters.append(Asset.project_id == project_id)
            
            # Asset counts by type
            asset_type_query = select(
                Asset.resource_type,
                func.count(Asset.id).label("count")
            ).select_from(Asset)
            
            if base_filters:
                asset_type_query = asset_type_query.where(and_(*base_filters))
            
            asset_type_query = asset_type_query.group_by(Asset.resource_type)
            asset_type_result = await self.db.execute(asset_type_query)
            assets_by_type = {row.resource_type: row.count for row in asset_type_result}
            
            # Risk distribution
            risk_distribution_query = select(
                func.count(Asset.id).filter(Asset.risk_score >= 80).label("critical"),
                func.count(Asset.id).filter(and_(Asset.risk_score >= 60, Asset.risk_score < 80)).label("high"),
                func.count(Asset.id).filter(and_(Asset.risk_score >= 40, Asset.risk_score < 60)).label("medium"),
                func.count(Asset.id).filter(and_(Asset.risk_score >= 20, Asset.risk_score < 40)).label("low"),
                func.count(Asset.id).filter(Asset.risk_score < 20).label("minimal")
            ).select_from(Asset)
            
            if base_filters:
                risk_distribution_query = risk_distribution_query.where(and_(*base_filters))
            
            risk_distribution_result = await self.db.execute(risk_distribution_query)
            risk_distribution = risk_distribution_result.first()
            
            # Recent findings
            recent_findings_query = select(
                Finding.id, Finding.title, Finding.severity, Finding.created_at,
                Asset.name.label("asset_name"), Asset.resource_type
            ).select_from(Finding).join(Asset, Finding.asset_id == Asset.id)
            
            if base_filters:
                recent_findings_query = recent_findings_query.where(and_(*base_filters))
            
            recent_findings_query = recent_findings_query.order_by(desc(Finding.created_at)).limit(10)
            recent_findings_result = await self.db.execute(recent_findings_query)
            recent_findings = []
            
            for row in recent_findings_result:
                recent_findings.append({
                    "id": str(row.id),
                    "title": row.title,
                    "severity": row.severity,
                    "created_at": row.created_at.isoformat(),
                    "asset_name": row.asset_name or "Unknown",
                    "resource_type": row.resource_type
                })
            
            return {
                "success": True,
                "assets_by_type": assets_by_type,
                "risk_distribution": {
                    "critical": risk_distribution.critical or 0,
                    "high": risk_distribution.high or 0,
                    "medium": risk_distribution.medium or 0,
                    "low": risk_distribution.low or 0,
                    "minimal": risk_distribution.minimal or 0
                },
                "recent_findings": recent_findings
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard metrics: {str(e)}")
            return {"success": False, "error": str(e)}
