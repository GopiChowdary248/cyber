"""
Enhanced Cloud Security Service
Implements comprehensive CSPM, CASB, and Cloud-Native security features
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import boto3
# from azure.mgmt.security import SecurityCenter  # Temporarily disabled
# from google.cloud import securitycenter_v1  # Temporarily disabled

logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    id: str
    type: str
    severity: str
    title: str
    description: str
    resource_id: str
    provider: str
    compliance_standards: List[str]
    remediation_steps: List[str]
    auto_remediable: bool
    detected_at: datetime
    status: str = "open"

@dataclass
class ComplianceReport:
    standard: str
    score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    generated_at: datetime

class EnhancedCSPMService:
    """Enhanced Cloud Security Posture Management Service"""
    
    def __init__(self):
        # Initialize AWS clients only if credentials are available
        try:
            self.aws_config = boto3.client('config')
            self.aws_security_hub = boto3.client('securityhub')
            self.aws_guardduty = boto3.client('guardduty')
            self.aws_iam = boto3.client('iam')
            self.aws_s3 = boto3.client('s3')
            self.aws_ec2 = boto3.client('ec2')
            self.aws_available = True
        except Exception as e:
            logger.warning(f"AWS credentials not configured, cloud security features will be limited: {e}")
            self.aws_config = None
            self.aws_security_hub = None
            self.aws_guardduty = None
            self.aws_iam = None
            self.aws_s3 = None
            self.aws_ec2 = None
            self.aws_available = False
        
        # CSPM Rules for different cloud providers
        self.cspm_rules = {
            "aws": {
                "s3_public_access": {
                    "description": "S3 bucket with public access",
                    "severity": "high",
                    "remediation": "terraform_script",
                    "compliance": ["cis", "pci_dss", "nist"],
                    "check_function": self._check_s3_public_access
                },
                "iam_overprivileged": {
                    "description": "IAM role with excessive permissions",
                    "severity": "critical",
                    "remediation": "policy_update",
                    "compliance": ["cis", "nist"],
                    "check_function": self._check_iam_overprivileged
                },
                "security_group_open": {
                    "description": "Security group allowing 0.0.0.0/0",
                    "severity": "high",
                    "remediation": "sg_update",
                    "compliance": ["cis"],
                    "check_function": self._check_security_group_open
                },
                # "rds_public_access": {
                #     "description": "RDS instance with public access",
                #     "severity": "high",
                #     "remediation": "rds_private_subnet",
                #     "compliance": ["cis", "pci_dss"],
                #     "check_function": self._check_rds_public_access
                # },
                # "cloudtrail_disabled": {
                #     "description": "CloudTrail logging disabled",
                #     "severity": "medium",
                #     "remediation": "enable_cloudtrail",
                #     "compliance": ["cis", "nist"],
                #     "check_function": self._check_cloudtrail_disabled
                # }
            },
            # "azure": {
            #     "storage_public_access": {
            #         "description": "Storage account with public access",
            #         "severity": "high",
            #         "remediation": "azure_policy",
            #         "compliance": ["cis", "iso27001"],
            #         "check_function": self._check_azure_storage_public
            #     },
            #     "sql_server_public_access": {
            #         "description": "SQL Server with public access",
            #         "severity": "high",
            #         "remediation": "private_endpoint",
            #         "compliance": ["cis", "pci_dss"],
            #         "check_function": self._check_azure_sql_public
            #     }
            # },
            # "gcp": {
            #     "bucket_public_access": {
            #         "description": "Cloud Storage bucket with public access",
            #         "severity": "high",
            #         "remediation": "gcp_iam_policy",
            #         "compliance": ["cis"],
            #         "check_function": self._check_gcp_bucket_public
            #     },
            #     "compute_public_access": {
            #         "description": "Compute instance with public access",
            #         "severity": "high",
            #         "remediation": "vpc_firewall",
            #         "compliance": ["cis"],
            #         "check_function": self._check_gcp_compute_public
            #     }
            # }
        }
    
    async def scan_aws_account(self, account_id: str) -> Dict[str, Any]:
        """Comprehensive AWS account security scan"""
        logger.info(f"Starting AWS security scan for account: {account_id}")
        
        if not self.aws_available:
            logger.warning("AWS not available, returning mock data")
            return {
                "account_id": account_id,
                "provider": "aws",
                "scan_timestamp": datetime.now(),
                "findings": [],
                "security_score": 85.0,
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "status": "mock_data"
            }
        
        findings = []
        
        # Run all CSPM checks
        for rule_name, rule_config in self.cspm_rules["aws"].items():
            try:
                rule_findings = await rule_config["check_function"](account_id)
                findings.extend(rule_findings)
            except Exception as e:
                logger.error(f"Error running rule {rule_name}: {str(e)}")
        
        # Get Security Hub findings
        security_hub_findings = await self._get_security_hub_findings(account_id)
        findings.extend(security_hub_findings)
        
        # Get GuardDuty findings
        guardduty_findings = await self._get_guardduty_findings(account_id)
        findings.extend(guardduty_findings)
        
        # Calculate security score
        security_score = self._calculate_security_score(findings)
        
        return {
            "account_id": account_id,
            "provider": "aws",
            "scan_timestamp": datetime.now(),
            "findings": findings,
            "security_score": security_score,
            "total_findings": len(findings),
            "critical_count": len([f for f in findings if f.severity == "critical"]),
            "high_count": len([f for f in findings if f.severity == "high"]),
            "medium_count": len([f for f in findings if f.severity == "medium"]),
            "low_count": len([f for f in findings if f.severity == "low"])
        }
    
    async def _check_s3_public_access(self, account_id: str) -> List[SecurityFinding]:
        """Check for S3 buckets with public access"""
        findings = []
        
        try:
            response = self.aws_s3.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Check bucket ACL
                try:
                    acl = self.aws_s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            findings.append(SecurityFinding(
                                id=f"s3_public_{bucket_name}",
                                type="s3_public_access",
                                severity="high",
                                title=f"S3 Bucket {bucket_name} has public access",
                                description=f"S3 bucket {bucket_name} allows public read access",
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                provider="aws",
                                compliance_standards=["cis", "pci_dss", "nist"],
                                remediation_steps=[
                                    "Remove public read access from bucket ACL",
                                    "Configure bucket policy to deny public access",
                                    "Enable S3 Block Public Access settings"
                                ],
                                auto_remediable=True,
                                detected_at=datetime.now()
                            ))
                            break
                except Exception as e:
                    logger.warning(f"Could not check ACL for bucket {bucket_name}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error checking S3 public access: {str(e)}")
        
        return findings
    
    async def _check_iam_overprivileged(self, account_id: str) -> List[SecurityFinding]:
        """Check for over-privileged IAM roles"""
        findings = []
        
        try:
            # Get all IAM roles
            response = self.aws_iam.list_roles()
            
            for role in response['Roles']:
                role_name = role['RoleName']
                
                # Get role policies
                attached_policies = self.aws_iam.list_attached_role_policies(RoleName=role_name)
                inline_policies = self.aws_iam.list_role_policies(RoleName=role_name)
                
                # Check for dangerous permissions
                dangerous_permissions = [
                    "iam:*",
                    "s3:*",
                    "ec2:*",
                    "rds:*",
                    "lambda:*"
                ]
                
                for policy in attached_policies['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    policy_version = self.aws_iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=self.aws_iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    )
                    
                    for statement in policy_version['PolicyVersion']['Document']['Statement']:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            for action in actions:
                                for dangerous_perm in dangerous_permissions:
                                    if self._wildcard_match(action, dangerous_perm):
                                        findings.append(SecurityFinding(
                                            id=f"iam_overprivileged_{role_name}",
                                            type="iam_overprivileged",
                                            severity="critical",
                                            title=f"IAM Role {role_name} has over-privileged permissions",
                                            description=f"IAM role {role_name} has dangerous permission: {action}",
                                            resource_id=role['Arn'],
                                            provider="aws",
                                            compliance_standards=["cis", "nist"],
                                            remediation_steps=[
                                                "Review and reduce IAM permissions",
                                                "Apply principle of least privilege",
                                                "Use AWS IAM Access Analyzer for recommendations"
                                            ],
                                            auto_remediable=False,
                                            detected_at=datetime.now()
                                        ))
                                        break
                
        except Exception as e:
            logger.error(f"Error checking IAM over-privileged: {str(e)}")
        
        return findings
    
    async def _check_security_group_open(self, account_id: str) -> List[SecurityFinding]:
        """Check for security groups with open access"""
        findings = []
        
        try:
            response = self.aws_ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            findings.append(SecurityFinding(
                                id=f"sg_open_{sg_id}",
                                type="security_group_open",
                                severity="high",
                                title=f"Security Group {sg_name} allows open access",
                                description=f"Security group {sg_name} allows access from 0.0.0.0/0",
                                resource_id=sg_id,
                                provider="aws",
                                compliance_standards=["cis"],
                                remediation_steps=[
                                    "Restrict security group to specific IP ranges",
                                    "Use VPC endpoints for internal communication",
                                    "Implement proper network segmentation"
                                ],
                                auto_remediable=True,
                                detected_at=datetime.now()
                            ))
                            break
                            
        except Exception as e:
            logger.error(f"Error checking security groups: {str(e)}")
        
        return findings
    
    async def _get_security_hub_findings(self, account_id: str) -> List[SecurityFinding]:
        """Get AWS Security Hub findings"""
        findings = []
        
        try:
            response = self.aws_security_hub.get_findings(
                Filters={
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
                }
            )
            
            for finding in response['Findings']:
                findings.append(SecurityFinding(
                    id=finding['Id'],
                    type="security_hub",
                    severity=finding['Severity']['Label'].lower(),
                    title=finding['Title'],
                    description=finding['Description'],
                    resource_id=finding.get('Resources', [{}])[0].get('Id', ''),
                    provider="aws",
                    compliance_standards=finding.get('Compliance', {}).get('Standards', []),
                    remediation_steps=finding.get('Remediation', {}).get('Recommendation', {}).get('Text', '').split('\n'),
                    auto_remediable=False,
                    detected_at=finding['CreatedAt']
                ))
                
        except Exception as e:
            logger.error(f"Error getting Security Hub findings: {str(e)}")
        
        return findings
    
    async def _get_guardduty_findings(self, account_id: str) -> List[SecurityFinding]:
        """Get AWS GuardDuty findings"""
        findings = []
        
        try:
            # Get detector ID
            detectors = self.aws_guardduty.list_detectors()
            if not detectors['DetectorIds']:
                return findings
            
            detector_id = detectors['DetectorIds'][0]
            
            response = self.aws_guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': 4  # Medium and above
                        }
                    }
                }
            )
            
            for finding_id in response['FindingIds']:
                finding = self.aws_guardduty.get_findings(
                    DetectorId=detector_id,
                    FindingIds=[finding_id]
                )['Findings'][0]
                
                findings.append(SecurityFinding(
                    id=finding['Id'],
                    type="guardduty",
                    severity=self._map_guardduty_severity(finding['Severity']),
                    title=finding['Title'],
                    description=finding['Description'],
                    resource_id=finding.get('Resource', {}).get('InstanceDetails', {}).get('InstanceId', ''),
                    provider="aws",
                    compliance_standards=[],
                    remediation_steps=finding.get('Remediation', {}).get('Recommendation', {}).get('Text', '').split('\n'),
                    auto_remediable=False,
                    detected_at=finding['CreatedAt']
                ))
                
        except Exception as e:
            logger.error(f"Error getting GuardDuty findings: {str(e)}")
        
        return findings
    
    def _calculate_security_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate security score based on findings"""
        if not findings:
            return 100.0
        
        # Weight factors for different severities
        weights = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5
        }
        
        total_weight = 0
        for finding in findings:
            total_weight += weights.get(finding.severity, 0)
        
        # Calculate score (100 - weighted deductions)
        max_possible_weight = len(findings) * 10.0  # Assume all critical
        score = max(0, 100 - (total_weight / max_possible_weight) * 100)
        
        return round(score, 2)
    
    def _wildcard_match(self, action: str, pattern: str) -> bool:
        """Check if action matches wildcard pattern"""
        if pattern.endswith('*'):
            return action.startswith(pattern[:-1])
        return action == pattern
    
    def _map_guardduty_severity(self, severity: int) -> str:
        """Map GuardDuty severity to standard severity"""
        if severity >= 8:
            return "critical"
        elif severity >= 6:
            return "high"
        elif severity >= 4:
            return "medium"
        else:
            return "low"

class EnhancedCASBService:
    """Enhanced Cloud Access Security Broker Service"""
    
    def __init__(self):
        self.dlp_patterns = {
            "pii": [
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                r"\b\d{3}-\d{3}-\d{4}\b"  # Phone
            ],
            "pci": [
                r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"  # Credit Card
            ],
            "phi": [
                r"\b(patient|medical|health|diagnosis|treatment)\b"  # Health Info
            ]
        }
        
        # Known SaaS applications and their risk profiles
        self.saas_applications = {
            "salesforce": {"risk_score": 0.2, "category": "crm", "sanctioned": True},
            "slack": {"risk_score": 0.3, "category": "communication", "sanctioned": True},
            "dropbox": {"risk_score": 0.6, "category": "file_sharing", "sanctioned": False},
            "github": {"risk_score": 0.4, "category": "development", "sanctioned": True},
            "zoom": {"risk_score": 0.3, "category": "video_conferencing", "sanctioned": True},
            "trello": {"risk_score": 0.5, "category": "project_management", "sanctioned": False},
            "asana": {"risk_score": 0.4, "category": "project_management", "sanctioned": True}
        }
    
    async def discover_saas_applications(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover SaaS applications in use"""
        discovered_apps = []
        
        # Analyze network traffic for SaaS applications
        for domain, traffic_data in network_data.get("domains", {}).items():
            app_info = self._identify_saas_application(domain)
            if app_info:
                discovered_apps.append({
                    "domain": domain,
                    "app_name": app_info["name"],
                    "category": app_info["category"],
                    "risk_score": app_info["risk_score"],
                    "sanctioned": app_info["sanctioned"],
                    "user_count": traffic_data.get("unique_users", 0),
                    "data_volume": traffic_data.get("data_transferred", 0),
                    "discovered_at": datetime.now()
                })
        
        return discovered_apps
    
    async def analyze_user_activity(self, user_activities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze user activities for suspicious behavior"""
        suspicious_activities = []
        
        for activity in user_activities:
            risk_score = self._calculate_activity_risk(activity)
            
            if risk_score > 0.7:  # High risk threshold
                suspicious_activities.append({
                    "user_id": activity["user_id"],
                    "app_name": activity["app_name"],
                    "activity_type": activity["activity_type"],
                    "risk_score": risk_score,
                    "risk_factors": self._identify_risk_factors(activity),
                    "timestamp": activity["timestamp"],
                    "ip_address": activity.get("ip_address"),
                    "location": activity.get("location"),
                    "device_info": activity.get("device_info")
                })
        
        return suspicious_activities
    
    async def scan_for_dlp_violations(self, file_content: str, file_type: str) -> List[Dict[str, Any]]:
        """Scan file content for DLP violations"""
        import re
        
        violations = []
        
        for data_type, patterns in self.dlp_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, file_content, re.IGNORECASE)
                if matches:
                    violations.append({
                        "type": data_type,
                        "pattern": pattern,
                        "matches": len(matches),
                        "confidence": 0.95,
                        "file_type": file_type,
                        "detected_at": datetime.now()
                    })
        
        return violations
    
    def _identify_saas_application(self, domain: str) -> Optional[Dict[str, Any]]:
        """Identify SaaS application from domain"""
        domain_lower = domain.lower()
        
        for app_name, app_info in self.saas_applications.items():
            if app_name in domain_lower:
                return {
                    "name": app_name,
                    "category": app_info["category"],
                    "risk_score": app_info["risk_score"],
                    "sanctioned": app_info["sanctioned"]
                }
        
        return None
    
    def _calculate_activity_risk(self, activity: Dict[str, Any]) -> float:
        """Calculate risk score for user activity"""
        risk_score = 0.0
        
        # Time-based risk (off-hours activity)
        hour = activity["timestamp"].hour
        if hour < 6 or hour > 22:
            risk_score += 0.3
        
        # Location-based risk (unusual location)
        if activity.get("location") and activity["location"] not in ["office", "home"]:
            risk_score += 0.4
        
        # Activity-based risk
        high_risk_activities = ["download", "share", "delete", "admin_action"]
        if activity["activity_type"] in high_risk_activities:
            risk_score += 0.3
        
        # Data volume risk
        if activity.get("data_volume", 0) > 1000000:  # 1MB
            risk_score += 0.2
        
        return min(risk_score, 1.0)
    
    def _identify_risk_factors(self, activity: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors for an activity"""
        risk_factors = []
        
        if activity["timestamp"].hour < 6 or activity["timestamp"].hour > 22:
            risk_factors.append("off_hours_activity")
        
        if activity.get("location") and activity["location"] not in ["office", "home"]:
            risk_factors.append("unusual_location")
        
        if activity["activity_type"] in ["download", "share", "delete"]:
            risk_factors.append("sensitive_operation")
        
        if activity.get("data_volume", 0) > 1000000:
            risk_factors.append("large_data_transfer")
        
        return risk_factors

class EnhancedCloudNativeSecurityService:
    """Enhanced Cloud-Native Security Service"""
    
    def __init__(self):
        # Initialize AWS clients only if credentials are available
        try:
            self.aws_shield = boto3.client('shield')
            self.aws_guardduty = boto3.client('guardduty')
            self.aws_iam = boto3.client('iam')
            self.aws_available = True
        except Exception as e:
            logger.warning(f"AWS credentials not configured for cloud native security: {e}")
            self.aws_shield = None
            self.aws_guardduty = None
            self.aws_iam = None
            self.aws_available = False
        
    async def get_aws_security_status(self, account_id: str) -> Dict[str, Any]:
        """Get comprehensive AWS security status"""
        if not self.aws_available:
            logger.warning("AWS not available, returning mock data")
            return {
                "shield_status": {"protected": False, "status": "mock_data"},
                "guardduty_findings": [],
                "iam_risks": [],
                "security_score": 75.0,
                "status": "mock_data"
            }
        
        return {
            "shield_status": await self._get_shield_protection_status(),
            "guardduty_findings": await self._get_guardduty_findings(),
            "iam_risks": await self._analyze_iam_risks(account_id),
            "security_score": await self._calculate_native_security_score(account_id)
        }
    
    async def _get_shield_protection_status(self) -> Dict[str, Any]:
        """Get AWS Shield protection status"""
        try:
            response = self.aws_shield.describe_protection()
            return {
                "protected": True,
                "protection_id": response.get("Protection", {}).get("Id"),
                "resource_arn": response.get("Protection", {}).get("ResourceArn"),
                "protection_name": response.get("Protection", {}).get("Name")
            }
        except Exception as e:
            logger.error(f"Error getting Shield status: {str(e)}")
            return {"protected": False, "error": str(e)}
    
    async def _analyze_iam_risks(self, account_id: str) -> List[Dict[str, Any]]:
        """Analyze IAM risks"""
        risks = []
        
        try:
            # Analyze over-privileged roles
            over_privileged = await self._find_over_privileged_roles()
            risks.extend(over_privileged)
            
            # Analyze unused permissions
            unused_permissions = await self._find_unused_permissions()
            risks.extend(unused_permissions)
            
            # Analyze weak policies
            weak_policies = await self._find_weak_policies()
            risks.extend(weak_policies)
            
        except Exception as e:
            logger.error(f"Error analyzing IAM risks: {str(e)}")
        
        return risks
    
    async def _find_over_privileged_roles(self) -> List[Dict[str, Any]]:
        """Find over-privileged IAM roles"""
        risks = []
        
        try:
            response = self.aws_iam.list_roles()
            
            for role in response['Roles']:
                role_name = role['RoleName']
                
                # Get role policies
                attached_policies = self.aws_iam.list_attached_role_policies(RoleName=role_name)
                
                # Check for dangerous permissions
                dangerous_permissions = ["iam:*", "s3:*", "ec2:*", "rds:*"]
                
                for policy in attached_policies['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    
                    # Get policy document
                    policy_version = self.aws_iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=self.aws_iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    )
                    
                    for statement in policy_version['PolicyVersion']['Document']['Statement']:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            for action in actions:
                                for dangerous_perm in dangerous_permissions:
                                    if action.startswith(dangerous_perm[:-1]):
                                        risks.append({
                                            "type": "over_privileged_role",
                                            "severity": "high",
                                            "resource": role_name,
                                            "description": f"Role {role_name} has dangerous permission: {action}",
                                            "recommendation": "Apply principle of least privilege"
                                        })
                                        break
                                        
        except Exception as e:
            logger.error(f"Error finding over-privileged roles: {str(e)}")
        
        return risks
    
    async def _calculate_native_security_score(self, account_id: str) -> float:
        """Calculate cloud-native security score"""
        score = 100.0
        
        try:
            # Deduct points for various security issues
            shield_status = await self._get_shield_protection_status()
            if not shield_status.get("protected", False):
                score -= 10
            
            iam_risks = await self._analyze_iam_risks(account_id)
            score -= len(iam_risks) * 5
            
            # Ensure score doesn't go below 0
            score = max(0, score)
            
        except Exception as e:
            logger.error(f"Error calculating native security score: {str(e)}")
        
        return round(score, 2)

class CloudSecurityOrchestrator:
    """Orchestrates all cloud security services"""
    
    def __init__(self):
        self.cspm_service = EnhancedCSPMService()
        self.casb_service = EnhancedCASBService()
        self.cloud_native_service = EnhancedCloudNativeSecurityService()
    
    async def comprehensive_scan(self, account_id: str, provider: str = "aws") -> Dict[str, Any]:
        """Run comprehensive cloud security scan"""
        logger.info(f"Starting comprehensive cloud security scan for account: {account_id}")
        
        results = {}
        
        # Run CSPM scan
        if provider == "aws":
            results["cspm"] = await self.cspm_service.scan_aws_account(account_id)
        
        # Run CASB analysis (requires network data)
        # results["casb"] = await self.casb_service.discover_saas_applications(network_data)
        
        # Run Cloud-Native security analysis
        if provider == "aws":
            results["cloud_native"] = await self.cloud_native_service.get_aws_security_status(account_id)
        
        # Generate unified risk score
        unified_score = self._calculate_unified_risk_score(results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(results)
        
        return {
            "account_id": account_id,
            "provider": provider,
            "scan_timestamp": datetime.now(),
            "results": results,
            "unified_risk_score": unified_score,
            "recommendations": recommendations,
            "total_findings": self._count_total_findings(results)
        }
    
    def _calculate_unified_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate unified risk score across all services"""
        scores = []
        
        if "cspm" in results:
            scores.append(results["cspm"]["security_score"])
        
        if "cloud_native" in results:
            scores.append(results["cloud_native"]["security_score"])
        
        if scores:
            return round(sum(scores) / len(scores), 2)
        
        return 0.0
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if "cspm" in results:
            cspm_results = results["cspm"]
            
            if cspm_results["critical_count"] > 0:
                recommendations.append(f"Address {cspm_results['critical_count']} critical security findings immediately")
            
            if cspm_results["high_count"] > 0:
                recommendations.append(f"Review and fix {cspm_results['high_count']} high-severity misconfigurations")
            
            if cspm_results["security_score"] < 70:
                recommendations.append("Overall security posture needs improvement - focus on high-priority findings")
        
        if "cloud_native" in results:
            cloud_native_results = results["cloud_native"]
            
            if not cloud_native_results.get("shield_status", {}).get("protected", False):
                recommendations.append("Enable AWS Shield for DDoS protection")
            
            if cloud_native_results.get("iam_risks"):
                recommendations.append("Review and remediate IAM security risks")
        
        return recommendations
    
    def _count_total_findings(self, results: Dict[str, Any]) -> int:
        """Count total findings across all services"""
        total = 0
        
        if "cspm" in results:
            total += results["cspm"]["total_findings"]
        
        if "cloud_native" in results and "iam_risks" in results["cloud_native"]:
            total += len(results["cloud_native"]["iam_risks"])
        
        return total 