import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import security
from google.cloud import storage
from typing import Dict, List, Optional, Any
import structlog
from datetime import datetime
import asyncio

from app.core.config import settings
from app.models.cloud_security import CloudProvider, ResourceType, SeverityLevel
from app.services.ai_service import ai_service

logger = structlog.get_logger()

class CloudSecurityService:
    def __init__(self):
        self.aws_session = None
        self.azure_client = None
        self.gcp_client = None
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize cloud provider clients"""
        try:
            # Initialize AWS client
            if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
                self.aws_session = boto3.Session(
                    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                    region_name=settings.AWS_REGION
                )
                logger.info("AWS client initialized")
            
            # Initialize Azure client
            if settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET:
                self.azure_client = ResourceManagementClient(
                    credential=DefaultAzureCredential(),
                    subscription_id=settings.AZURE_TENANT_ID
                )
                logger.info("Azure client initialized")
            
            # Initialize GCP client
            if settings.GCP_PROJECT_ID:
                self.gcp_client = security.SecurityCenterClient()
                logger.info("GCP client initialized")
                
        except Exception as e:
            logger.error("Failed to initialize cloud clients", error=str(e))
    
    async def scan_aws_resources(self) -> List[Dict[str, Any]]:
        """Scan AWS resources for security misconfigurations"""
        misconfigurations = []
        
        if not self.aws_session:
            logger.warning("AWS client not configured")
            return misconfigurations
        
        try:
            # Scan S3 buckets
            s3_client = self.aws_session.client('s3')
            buckets = await self._get_aws_s3_buckets(s3_client)
            
            for bucket in buckets:
                bucket_misconfigs = await self._check_s3_bucket_security(s3_client, bucket)
                misconfigurations.extend(bucket_misconfigs)
            
            # Scan EC2 instances
            ec2_client = self.aws_session.client('ec2')
            instances = await self._get_aws_ec2_instances(ec2_client)
            
            for instance in instances:
                instance_misconfigs = await self._check_ec2_instance_security(ec2_client, instance)
                misconfigurations.extend(instance_misconfigs)
            
            # Scan IAM roles and users
            iam_client = self.aws_session.client('iam')
            iam_misconfigs = await self._check_aws_iam_security(iam_client)
            misconfigurations.extend(iam_misconfigs)
            
            # Scan Security Groups
            sg_misconfigs = await self._check_aws_security_groups(ec2_client)
            misconfigurations.extend(sg_misconfigs)
            
            logger.info("AWS security scan completed", 
                       resources_scanned=len(buckets) + len(instances),
                       misconfigurations_found=len(misconfigurations))
            
        except Exception as e:
            logger.error("AWS security scan failed", error=str(e))
        
        return misconfigurations
    
    async def scan_azure_resources(self) -> List[Dict[str, Any]]:
        """Scan Azure resources for security misconfigurations"""
        misconfigurations = []
        
        if not self.azure_client:
            logger.warning("Azure client not configured")
            return misconfigurations
        
        try:
            # Scan Storage Accounts
            storage_misconfigs = await self._check_azure_storage_security()
            misconfigurations.extend(storage_misconfigs)
            
            # Scan Virtual Machines
            vm_misconfigs = await self._check_azure_vm_security()
            misconfigurations.extend(vm_misconfigs)
            
            # Scan Network Security Groups
            nsg_misconfigs = await self._check_azure_nsg_security()
            misconfigurations.extend(nsg_misconfigs)
            
            # Scan Key Vaults
            kv_misconfigs = await self._check_azure_keyvault_security()
            misconfigurations.extend(kv_misconfigs)
            
            logger.info("Azure security scan completed", 
                       misconfigurations_found=len(misconfigurations))
            
        except Exception as e:
            logger.error("Azure security scan failed", error=str(e))
        
        return misconfigurations
    
    async def scan_gcp_resources(self) -> List[Dict[str, Any]]:
        """Scan GCP resources for security misconfigurations"""
        misconfigurations = []
        
        if not self.gcp_client:
            logger.warning("GCP client not configured")
            return misconfigurations
        
        try:
            # Scan Cloud Storage buckets
            storage_misconfigs = await self._check_gcp_storage_security()
            misconfigurations.extend(storage_misconfigs)
            
            # Scan Compute instances
            compute_misconfigs = await self._check_gcp_compute_security()
            misconfigurations.extend(compute_misconfigs)
            
            # Scan IAM policies
            iam_misconfigs = await self._check_gcp_iam_security()
            misconfigurations.extend(iam_misconfigs)
            
            logger.info("GCP security scan completed", 
                       misconfigurations_found=len(misconfigurations))
            
        except Exception as e:
            logger.error("GCP security scan failed", error=str(e))
        
        return misconfigurations
    
    async def _get_aws_s3_buckets(self, s3_client) -> List[Dict[str, Any]]:
        """Get list of S3 buckets"""
        try:
            response = s3_client.list_buckets()
            return [{"name": bucket["Name"], "created": bucket["CreationDate"]} 
                   for bucket in response["Buckets"]]
        except Exception as e:
            logger.error("Failed to get S3 buckets", error=str(e))
            return []
    
    async def _check_s3_bucket_security(self, s3_client, bucket: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check S3 bucket security configurations"""
        misconfigurations = []
        bucket_name = bucket["name"]
        
        try:
            # Check bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                if not encryption.get("ServerSideEncryptionConfiguration"):
                    misconfigurations.append({
                        "resource_id": bucket_name,
                        "resource_type": ResourceType.S3_BUCKET,
                        "provider": CloudProvider.AWS,
                        "title": "S3 Bucket Not Encrypted",
                        "description": f"S3 bucket {bucket_name} is not encrypted",
                        "severity": SeverityLevel.HIGH,
                        "rule_id": "S3_ENCRYPTION",
                        "current_value": "No encryption",
                        "expected_value": "Server-side encryption enabled",
                        "remediation_steps": "Enable server-side encryption for the S3 bucket"
                    })
            except s3_client.exceptions.NoSuchEncryptionConfiguration:
                misconfigurations.append({
                    "resource_id": bucket_name,
                    "resource_type": ResourceType.S3_BUCKET,
                    "provider": CloudProvider.AWS,
                    "title": "S3 Bucket Not Encrypted",
                    "description": f"S3 bucket {bucket_name} is not encrypted",
                    "severity": SeverityLevel.HIGH,
                    "rule_id": "S3_ENCRYPTION",
                    "current_value": "No encryption",
                    "expected_value": "Server-side encryption enabled",
                    "remediation_steps": "Enable server-side encryption for the S3 bucket"
                })
            
            # Check bucket versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    misconfigurations.append({
                        "resource_id": bucket_name,
                        "resource_type": ResourceType.S3_BUCKET,
                        "provider": CloudProvider.AWS,
                        "title": "S3 Bucket Versioning Disabled",
                        "description": f"S3 bucket {bucket_name} versioning is not enabled",
                        "severity": SeverityLevel.MEDIUM,
                        "rule_id": "S3_VERSIONING",
                        "current_value": "Versioning disabled",
                        "expected_value": "Versioning enabled",
                        "remediation_steps": "Enable versioning for the S3 bucket"
                    })
            except Exception:
                pass
            
            # Check bucket access logging
            try:
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                if not logging.get("LoggingEnabled"):
                    misconfigurations.append({
                        "resource_id": bucket_name,
                        "resource_type": ResourceType.S3_BUCKET,
                        "provider": CloudProvider.AWS,
                        "title": "S3 Bucket Access Logging Disabled",
                        "description": f"S3 bucket {bucket_name} access logging is not enabled",
                        "severity": SeverityLevel.MEDIUM,
                        "rule_id": "S3_LOGGING",
                        "current_value": "Logging disabled",
                        "expected_value": "Access logging enabled",
                        "remediation_steps": "Enable access logging for the S3 bucket"
                    })
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f"Failed to check S3 bucket security for {bucket_name}", error=str(e))
        
        return misconfigurations
    
    async def _get_aws_ec2_instances(self, ec2_client) -> List[Dict[str, Any]]:
        """Get list of EC2 instances"""
        try:
            response = ec2_client.describe_instances()
            instances = []
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    instances.append({
                        "id": instance["InstanceId"],
                        "type": instance["InstanceType"],
                        "state": instance["State"]["Name"],
                        "launch_time": instance["LaunchTime"]
                    })
            return instances
        except Exception as e:
            logger.error("Failed to get EC2 instances", error=str(e))
            return []
    
    async def _check_ec2_instance_security(self, ec2_client, instance: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check EC2 instance security configurations"""
        misconfigurations = []
        instance_id = instance["id"]
        
        try:
            # Check if instance has public IP
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance_data = response["Reservations"][0]["Instances"][0]
            
            if instance_data.get("PublicIpAddress"):
                misconfigurations.append({
                    "resource_id": instance_id,
                    "resource_type": ResourceType.EC2_INSTANCE,
                    "provider": CloudProvider.AWS,
                    "title": "EC2 Instance Has Public IP",
                    "description": f"EC2 instance {instance_id} has a public IP address",
                    "severity": SeverityLevel.MEDIUM,
                    "rule_id": "EC2_PUBLIC_IP",
                    "current_value": "Public IP assigned",
                    "expected_value": "Private IP only",
                    "remediation_steps": "Remove public IP or place instance in private subnet"
                })
            
            # Check security groups
            for sg in instance_data.get("SecurityGroups", []):
                sg_misconfigs = await self._check_security_group_rules(ec2_client, sg["GroupId"])
                misconfigurations.extend(sg_misconfigs)
            
        except Exception as e:
            logger.error(f"Failed to check EC2 instance security for {instance_id}", error=str(e))
        
        return misconfigurations
    
    async def _check_aws_iam_security(self, iam_client) -> List[Dict[str, Any]]:
        """Check IAM security configurations"""
        misconfigurations = []
        
        try:
            # Check for users with console access
            users = iam_client.list_users()
            for user in users["Users"]:
                try:
                    login_profile = iam_client.get_login_profile(UserName=user["UserName"])
                    misconfigurations.append({
                        "resource_id": user["UserName"],
                        "resource_type": ResourceType.IAM_USER,
                        "provider": CloudProvider.AWS,
                        "title": "IAM User Has Console Access",
                        "description": f"IAM user {user['UserName']} has console access enabled",
                        "severity": SeverityLevel.MEDIUM,
                        "rule_id": "IAM_CONSOLE_ACCESS",
                        "current_value": "Console access enabled",
                        "expected_value": "Console access disabled",
                        "remediation_steps": "Disable console access for IAM user"
                    })
                except iam_client.exceptions.NoSuchEntityException:
                    pass
            
            # Check for unused IAM roles
            roles = iam_client.list_roles()
            for role in roles["Roles"]:
                try:
                    # Check if role has been used recently
                    # This is a simplified check - in production, you'd check CloudTrail logs
                    pass
                except Exception:
                    pass
            
        except Exception as e:
            logger.error("Failed to check IAM security", error=str(e))
        
        return misconfigurations
    
    async def _check_aws_security_groups(self, ec2_client) -> List[Dict[str, Any]]:
        """Check security group configurations"""
        misconfigurations = []
        
        try:
            security_groups = ec2_client.describe_security_groups()
            for sg in security_groups["SecurityGroups"]:
                sg_misconfigs = await self._check_security_group_rules(ec2_client, sg["GroupId"])
                misconfigurations.extend(sg_misconfigs)
        except Exception as e:
            logger.error("Failed to check security groups", error=str(e))
        
        return misconfigurations
    
    async def _check_security_group_rules(self, ec2_client, sg_id: str) -> List[Dict[str, Any]]:
        """Check individual security group rules"""
        misconfigurations = []
        
        try:
            response = ec2_client.describe_security_group_rules(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )
            
            for rule in response["SecurityGroupRules"]:
                # Check for overly permissive rules
                if rule.get("IpProtocol") == "-1":  # All traffic
                    misconfigurations.append({
                        "resource_id": sg_id,
                        "resource_type": ResourceType.SECURITY_GROUP,
                        "provider": CloudProvider.AWS,
                        "title": "Overly Permissive Security Group Rule",
                        "description": f"Security group {sg_id} allows all traffic",
                        "severity": SeverityLevel.HIGH,
                        "rule_id": "SG_ALL_TRAFFIC",
                        "current_value": "All traffic allowed",
                        "expected_value": "Specific ports only",
                        "remediation_steps": "Restrict security group rules to specific ports and sources"
                    })
                
                # Check for 0.0.0.0/0 (any IP)
                if rule.get("CidrIpv4") == "0.0.0.0/0":
                    misconfigurations.append({
                        "resource_id": sg_id,
                        "resource_type": ResourceType.SECURITY_GROUP,
                        "provider": CloudProvider.AWS,
                        "title": "Security Group Allows Any IP",
                        "description": f"Security group {sg_id} allows traffic from any IP",
                        "severity": SeverityLevel.HIGH,
                        "rule_id": "SG_ANY_IP",
                        "current_value": "0.0.0.0/0",
                        "expected_value": "Specific IP ranges",
                        "remediation_steps": "Restrict security group to specific IP ranges"
                    })
        
        except Exception as e:
            logger.error(f"Failed to check security group rules for {sg_id}", error=str(e))
        
        return misconfigurations
    
    async def _check_azure_storage_security(self) -> List[Dict[str, Any]]:
        """Check Azure storage account security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual Azure storage checks
            # You would use the Azure SDK to check storage account configurations
            pass
        except Exception as e:
            logger.error("Failed to check Azure storage security", error=str(e))
        
        return misconfigurations
    
    async def _check_azure_vm_security(self) -> List[Dict[str, Any]]:
        """Check Azure virtual machine security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual Azure VM checks
            pass
        except Exception as e:
            logger.error("Failed to check Azure VM security", error=str(e))
        
        return misconfigurations
    
    async def _check_azure_nsg_security(self) -> List[Dict[str, Any]]:
        """Check Azure network security group security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual Azure NSG checks
            pass
        except Exception as e:
            logger.error("Failed to check Azure NSG security", error=str(e))
        
        return misconfigurations
    
    async def _check_azure_keyvault_security(self) -> List[Dict[str, Any]]:
        """Check Azure Key Vault security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual Azure Key Vault checks
            pass
        except Exception as e:
            logger.error("Failed to check Azure Key Vault security", error=str(e))
        
        return misconfigurations
    
    async def _check_gcp_storage_security(self) -> List[Dict[str, Any]]:
        """Check GCP Cloud Storage security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual GCP storage checks
            pass
        except Exception as e:
            logger.error("Failed to check GCP storage security", error=str(e))
        
        return misconfigurations
    
    async def _check_gcp_compute_security(self) -> List[Dict[str, Any]]:
        """Check GCP Compute Engine security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual GCP compute checks
            pass
        except Exception as e:
            logger.error("Failed to check GCP compute security", error=str(e))
        
        return misconfigurations
    
    async def _check_gcp_iam_security(self) -> List[Dict[str, Any]]:
        """Check GCP IAM security"""
        misconfigurations = []
        
        try:
            # This is a placeholder - implement actual GCP IAM checks
            pass
        except Exception as e:
            logger.error("Failed to check GCP IAM security", error=str(e))
        
        return misconfigurations
    
    async def generate_compliance_report(
        self, 
        provider: CloudProvider, 
        framework: str
    ) -> Dict[str, Any]:
        """Generate compliance report for cloud provider"""
        try:
            # Get misconfigurations for the provider
            if provider == CloudProvider.AWS:
                misconfigurations = await self.scan_aws_resources()
            elif provider == CloudProvider.AZURE:
                misconfigurations = await self.scan_azure_resources()
            elif provider == CloudProvider.GCP:
                misconfigurations = await self.scan_gcp_resources()
            else:
                return {"error": "Unsupported cloud provider"}
            
            # Generate compliance report using AI
            report_data = {
                "provider": provider,
                "framework": framework,
                "misconfigurations": misconfigurations,
                "total_issues": len(misconfigurations),
                "critical_issues": len([m for m in misconfigurations if m["severity"] == SeverityLevel.CRITICAL]),
                "high_issues": len([m for m in misconfigurations if m["severity"] == SeverityLevel.HIGH]),
                "medium_issues": len([m for m in misconfigurations if m["severity"] == SeverityLevel.MEDIUM]),
                "low_issues": len([m for m in misconfigurations if m["severity"] == SeverityLevel.LOW])
            }
            
            # Calculate compliance score
            total_checks = 100  # This would be based on the framework
            failed_checks = len(misconfigurations)
            compliance_score = max(0, ((total_checks - failed_checks) / total_checks) * 100)
            
            report_data["compliance_score"] = compliance_score
            report_data["passed_checks"] = total_checks - failed_checks
            report_data["failed_checks"] = failed_checks
            
            logger.info("Compliance report generated", 
                       provider=provider,
                       framework=framework,
                       compliance_score=compliance_score)
            
            return report_data
            
        except Exception as e:
            logger.error("Failed to generate compliance report", error=str(e))
            return {"error": str(e)}

# Create global cloud security service instance
cloud_security_service = CloudSecurityService() 