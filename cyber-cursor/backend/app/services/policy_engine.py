"""
Policy Engine Service using OPA (Open Policy Agent) and Rego
"""

import json
import logging
import subprocess
import tempfile
import os
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import asyncio
import aiohttp
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class PolicyResult(Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"

@dataclass
class PolicyEvaluation:
    result: PolicyResult
    evidence: Dict[str, Any]
    execution_time_ms: float
    policy_id: str
    asset_id: str
    rule_name: str
    message: str

class PolicyEngine:
    """
    Policy Engine using OPA for advanced policy evaluation
    """
    
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url
        self.policies_dir = Path("policies")
        self.policies_dir.mkdir(exist_ok=True)
        
    async def evaluate_policy(
        self, 
        policy_id: str, 
        asset_data: Dict[str, Any], 
        policy_rule: str,
        rule_name: str = "main"
    ) -> PolicyEvaluation:
        """
        Evaluate a policy against asset data using OPA
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Create temporary policy file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as f:
                f.write(policy_rule)
                policy_file = f.name
            
            try:
                # Evaluate using OPA CLI
                result = await self._evaluate_with_opa_cli(
                    policy_file, asset_data, rule_name
                )
                
                execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
                
                return PolicyEvaluation(
                    result=PolicyResult.ALLOW if result.get('allow', False) else PolicyResult.DENY,
                    evidence=result,
                    execution_time_ms=execution_time,
                    policy_id=policy_id,
                    asset_id=asset_data.get('id', 'unknown'),
                    rule_name=rule_name,
                    message=result.get('message', 'Policy evaluation completed')
                )
                
            finally:
                # Clean up temporary file
                os.unlink(policy_file)
                
        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
            
            return PolicyEvaluation(
                result=PolicyResult.UNKNOWN,
                evidence={'error': str(e)},
                execution_time_ms=execution_time,
                policy_id=policy_id,
                asset_id=asset_data.get('id', 'unknown'),
                rule_name=rule_name,
                message=f"Policy evaluation failed: {str(e)}"
            )
    
    async def _evaluate_with_opa_cli(
        self, 
        policy_file: str, 
        input_data: Dict[str, Any], 
        rule_name: str
    ) -> Dict[str, Any]:
        """
        Evaluate policy using OPA CLI
        """
        try:
            # Create temporary input file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(input_data, f)
                input_file = f.name
            
            try:
                # Run OPA eval command
                cmd = [
                    'opa', 'eval',
                    '--data', policy_file,
                    '--input', input_file,
                    f'data.{rule_name}'
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise Exception(f"OPA evaluation failed: {result.stderr}")
                
                # Parse OPA output
                output_lines = result.stdout.strip().split('\n')
                if output_lines:
                    try:
                        # OPA outputs JSON lines, take the last one
                        last_line = output_lines[-1]
                        if last_line.startswith('{'):
                            return json.loads(last_line)
                    except json.JSONDecodeError:
                        pass
                
                # Fallback parsing
                return self._parse_opa_output(result.stdout)
                
            finally:
                os.unlink(input_file)
                
        except subprocess.TimeoutExpired:
            raise Exception("OPA evaluation timed out")
        except Exception as e:
            raise Exception(f"OPA CLI execution failed: {str(e)}")
    
    def _parse_opa_output(self, output: str) -> Dict[str, Any]:
        """
        Parse OPA CLI output
        """
        try:
            # Look for JSON in output
            lines = output.split('\n')
            for line in lines:
                if line.strip().startswith('{') and line.strip().endswith('}'):
                    return json.loads(line.strip())
            
            # If no JSON found, create a simple result
            return {
                'allow': False,
                'message': 'Unable to parse OPA output',
                'raw_output': output
            }
        except Exception:
            return {
                'allow': False,
                'message': 'Failed to parse OPA output',
                'raw_output': output
            }
    
    async def evaluate_policy_http(
        self, 
        policy_id: str, 
        asset_data: Dict[str, Any], 
        policy_rule: str,
        rule_name: str = "main"
    ) -> PolicyEvaluation:
        """
        Evaluate policy using OPA HTTP API
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Create policy document
            policy_doc = {
                "policy": policy_rule,
                "data": asset_data
            }
            
            # Send to OPA HTTP API
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.opa_url}/v1/data/{rule_name}",
                    json=policy_doc,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    if response.status != 200:
                        raise Exception(f"OPA HTTP API error: {response.status}")
                    
                    result = await response.json()
                    
                    execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
                    
                    return PolicyEvaluation(
                        result=PolicyResult.ALLOW if result.get('result', {}).get('allow', False) else PolicyResult.DENY,
                        evidence=result.get('result', {}),
                        execution_time_ms=execution_time,
                        policy_id=policy_id,
                        asset_id=asset_data.get('id', 'unknown'),
                        rule_name=rule_name,
                        message=result.get('result', {}).get('message', 'Policy evaluation completed')
                    )
                    
        except Exception as e:
            logger.error(f"Policy evaluation via HTTP failed: {e}")
            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
            
            return PolicyEvaluation(
                result=PolicyResult.UNKNOWN,
                evidence={'error': str(e)},
                execution_time_ms=execution_time,
                policy_id=policy_id,
                asset_id=asset_data.get('id', 'unknown'),
                rule_name=rule_name,
                message=f"Policy evaluation failed: {str(e)}"
            )
    
    def load_policy_from_file(self, policy_path: str) -> str:
        """
        Load policy rule from file
        """
        try:
            with open(policy_path, 'r') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to load policy from {policy_path}: {str(e)}")
    
    def save_policy_to_file(self, policy_id: str, policy_rule: str) -> str:
        """
        Save policy rule to file
        """
        try:
            policy_file = self.policies_dir / f"{policy_id}.rego"
            with open(policy_file, 'w') as f:
                f.write(policy_rule)
            return str(policy_file)
        except Exception as e:
            raise Exception(f"Failed to save policy {policy_id}: {str(e)}")
    
    async def validate_policy_syntax(self, policy_rule: str) -> bool:
        """
        Validate Rego policy syntax
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as f:
                f.write(policy_rule)
                policy_file = f.name
            
            try:
                # Check syntax with OPA
                cmd = ['opa', 'check', policy_file]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                return result.returncode == 0
                
            finally:
                os.unlink(policy_file)
                
        except Exception as e:
            logger.error(f"Policy syntax validation failed: {e}")
            return False

class BuiltinPolicies:
    """
    Built-in policy templates for common security checks
    """
    
    @staticmethod
    def get_aws_s3_public_access_policy() -> str:
        """Policy to check for public S3 bucket access"""
        return """
package s3.public_access

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_acls == false
    msg := sprintf("S3 bucket %v has public ACLs enabled", [input.bucket_name])
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_policy == false
    msg := sprintf("S3 bucket %v has public policy enabled", [input.bucket_name])
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.restrict_public_buckets == false
    msg := sprintf("S3 bucket %v has public bucket access enabled", [input.bucket_name])
}
"""
    
    @staticmethod
    def get_aws_ec2_security_group_policy() -> str:
        """Policy to check for overly permissive security groups"""
        return """
package ec2.security_groups

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.ingress_rules[_]
    rule.from_port == 0
    rule.to_port == 65535
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group %v allows all traffic from anywhere", [input.group_name])
}

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.ingress_rules[_]
    rule.from_port == 22
    rule.to_port == 22
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group %v allows SSH access from anywhere", [input.group_name])
}

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.ingress_rules[_]
    rule.from_port == 3389
    rule.to_port == 3389
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group %v allows RDP access from anywhere", [input.group_name])
}
"""
    
    @staticmethod
    def get_aws_iam_user_policy() -> str:
        """Policy to check for IAM user security best practices"""
        return """
package iam.users

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_iam_user"
    input.access_keys[_].status == "Active"
    input.access_keys[_].last_used_date == null
    msg := sprintf("IAM user %v has unused access keys", [input.user_name])
}

deny[msg] {
    input.resource_type == "aws_iam_user"
    input.mfa_devices == []
    msg := sprintf("IAM user %v does not have MFA enabled", [input.user_name])
}

deny[msg] {
    input.resource_type == "aws_iam_user"
    input.attached_policies[_].policy_name == "AdministratorAccess"
    msg := sprintf("IAM user %v has AdministratorAccess policy", [input.user_name])
}
"""
    
    @staticmethod
    def get_compliance_cis_aws_policy() -> str:
        """CIS AWS Foundations Benchmark compliance policy"""
        return """
package compliance.cis_aws

import future.keywords.if
import future.keywords.in

# CIS 1.1: Avoid the use of the "root" account
deny[msg] {
    input.resource_type == "aws_iam_user"
    input.user_name == "root"
    msg := "CIS 1.1: Root account should not be used for daily operations"
}

# CIS 1.2: Ensure multi-factor authentication (MFA) is enabled for all IAM users
deny[msg] {
    input.resource_type == "aws_iam_user"
    input.mfa_devices == []
    msg := sprintf("CIS 1.2: IAM user %v does not have MFA enabled", [input.user_name])
}

# CIS 1.3: Ensure credentials unused for 90 days or greater are disabled
deny[msg] {
    input.resource_type == "aws_iam_user"
    input.access_keys[_].status == "Active"
    input.access_keys[_].last_used_date != null
    days_since_use := time.diff(time.now(), input.access_keys[_].last_used_date, "days")
    days_since_use > 90
    msg := sprintf("CIS 1.3: IAM user %v has access keys unused for more than 90 days", [input.user_name])
}
"""

# Global policy engine instance
policy_engine = PolicyEngine()

async def evaluate_policy_with_opa(
    policy_id: str,
    asset_data: Dict[str, Any],
    policy_rule: str,
    rule_name: str = "main"
) -> PolicyEvaluation:
    """
    Convenience function to evaluate policy using the global policy engine
    """
    return await policy_engine.evaluate_policy(
        policy_id, asset_data, policy_rule, rule_name
    )

def get_builtin_policy(policy_type: str) -> str:
    """
    Get a built-in policy template
    """
    policies = {
        'aws_s3_public_access': BuiltinPolicies.get_aws_s3_public_access_policy,
        'aws_ec2_security_groups': BuiltinPolicies.get_aws_ec2_security_group_policy,
        'aws_iam_users': BuiltinPolicies.get_aws_iam_user_policy,
        'cis_aws_foundations': BuiltinPolicies.get_compliance_cis_aws_policy,
    }
    
    if policy_type in policies:
        return policies[policy_type]()
    else:
        raise ValueError(f"Unknown policy type: {policy_type}")
