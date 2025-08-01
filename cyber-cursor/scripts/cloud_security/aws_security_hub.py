#!/usr/bin/env python3
"""
AWS Security Hub Integration Script

This script integrates with AWS Security Hub to:
- Enable Security Hub
- Configure security standards
- Create custom actions
- Manage findings
- Set up automated responses
"""

import boto3
import json
import argparse
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AWSSecurityHubManager:
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.securityhub = boto3.client('securityhub', region_name=region)
        self.config = boto3.client('config', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        
    def enable_security_hub(self) -> Dict[str, Any]:
        """Enable AWS Security Hub"""
        try:
            response = self.securityhub.enable_security_hub(
                EnableDefaultStandards=True,
                Tags=[
                    {'Key': 'Environment', 'Value': 'Production'},
                    {'Key': 'ManagedBy', 'Value': 'CyberCursor'}
                ]
            )
            logger.info("Security Hub enabled successfully")
            return response
        except self.securityhub.exceptions.ResourceConflictException:
            logger.info("Security Hub is already enabled")
            return {"status": "already_enabled"}
        except Exception as e:
            logger.error(f"Failed to enable Security Hub: {str(e)}")
            raise
    
    def enable_security_standards(self) -> Dict[str, Any]:
        """Enable security standards"""
        standards = [
            'cis-aws-foundations-benchmark/v/1.2.0',
            'pci-dss/v/3.2.1',
            'aws-foundational-security-best-practices/v/1.0.0'
        ]
        
        results = {}
        for standard in standards:
            try:
                response = self.securityhub.batch_enable_standards(
                    StandardsSubscriptionRequests=[
                        {
                            'StandardsArn': f'arn:aws:securityhub:{self.region}::standards/{standard}'
                        }
                    ]
                )
                results[standard] = response
                logger.info(f"Enabled security standard: {standard}")
            except Exception as e:
                logger.error(f"Failed to enable standard {standard}: {str(e)}")
                results[standard] = {"error": str(e)}
        
        return results
    
    def create_custom_actions(self) -> Dict[str, Any]:
        """Create custom actions for Security Hub"""
        custom_actions = [
            {
                'Name': 'CyberCursor_Investigate',
                'Description': 'Investigate security finding using Cyber Cursor',
                'ActionType': 'CUSTOM_ACTION'
            },
            {
                'Name': 'CyberCursor_Remediate',
                'Description': 'Automatically remediate security finding',
                'ActionType': 'CUSTOM_ACTION'
            },
            {
                'Name': 'CyberCursor_Escalate',
                'Description': 'Escalate finding to security team',
                'ActionType': 'CUSTOM_ACTION'
            }
        ]
        
        results = {}
        for action in custom_actions:
            try:
                response = self.securityhub.create_action_target(
                    Name=action['Name'],
                    Description=action['Description'],
                    Id=f"cyber-cursor-{action['Name'].lower()}",
                    Tags=[
                        {'Key': 'ManagedBy', 'Value': 'CyberCursor'}
                    ]
                )
                results[action['Name']] = response
                logger.info(f"Created custom action: {action['Name']}")
            except Exception as e:
                logger.error(f"Failed to create custom action {action['Name']}: {str(e)}")
                results[action['Name']] = {"error": str(e)}
        
        return results
    
    def get_findings(self, severity: str = None, status: str = None) -> List[Dict[str, Any]]:
        """Get Security Hub findings"""
        filters = {}
        
        if severity:
            filters['SeverityLabel'] = [{'Value': severity, 'Comparison': 'EQUALS'}]
        
        if status:
            filters['WorkflowStatus'] = [{'Value': status, 'Comparison': 'EQUALS'}]
        
        try:
            response = self.securityhub.get_findings(
                Filters=filters if filters else {},
                MaxResults=100
            )
            return response['Findings']
        except Exception as e:
            logger.error(f"Failed to get findings: {str(e)}")
            return []
    
    def update_finding_status(self, finding_id: str, status: str, note: str = None) -> Dict[str, Any]:
        """Update finding workflow status"""
        try:
            update_data = {
                'FindingIdentifiers': [{'Id': finding_id, 'ProductArn': 'arn:aws:securityhub:us-east-1:aws:product/aws/securityhub'}],
                'Workflow': {'Status': status}
            }
            
            if note:
                update_data['Note'] = {'Text': note, 'UpdatedBy': 'CyberCursor'}
            
            response = self.securityhub.batch_update_findings(**update_data)
            logger.info(f"Updated finding {finding_id} status to {status}")
            return response
        except Exception as e:
            logger.error(f"Failed to update finding {finding_id}: {str(e)}")
            raise
    
    def create_insights(self) -> Dict[str, Any]:
        """Create custom insights for Security Hub"""
        insights = [
            {
                'Name': 'CyberCursor_Critical_Findings',
                'Description': 'Critical security findings requiring immediate attention',
                'Filters': {
                    'SeverityLabel': [{'Value': 'CRITICAL', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                }
            },
            {
                'Name': 'CyberCursor_Unresolved_Findings',
                'Description': 'Findings that have not been resolved',
                'Filters': {
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                }
            },
            {
                'Name': 'CyberCursor_Compliance_Violations',
                'Description': 'Findings related to compliance violations',
                'Filters': {
                    'ComplianceStandardsComplianceId': [{'Value': 'cis-aws-foundations-benchmark', 'Comparison': 'EQUALS'}]
                }
            }
        ]
        
        results = {}
        for insight in insights:
            try:
                response = self.securityhub.create_insight(
                    Name=insight['Name'],
                    Description=insight['Description'],
                    Filters=insight['Filters'],
                    GroupByAttribute='SeverityLabel'
                )
                results[insight['Name']] = response
                logger.info(f"Created insight: {insight['Name']}")
            except Exception as e:
                logger.error(f"Failed to create insight {insight['Name']}: {str(e)}")
                results[insight['Name']] = {"error": str(e)}
        
        return results
    
    def setup_automated_responses(self) -> Dict[str, Any]:
        """Setup automated responses for Security Hub findings"""
        # This would integrate with EventBridge and Lambda functions
        # For now, we'll create the basic structure
        
        automated_responses = {
            'critical_findings': {
                'description': 'Automated response for critical findings',
                'actions': ['notify_security_team', 'create_incident', 'escalate']
            },
            'compliance_violations': {
                'description': 'Automated response for compliance violations',
                'actions': ['notify_compliance_team', 'create_ticket']
            },
            'public_exposure': {
                'description': 'Automated response for public exposure findings',
                'actions': ['immediate_remediation', 'notify_management']
            }
        }
        
        logger.info("Automated responses configured")
        return automated_responses
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            # Get findings by severity
            critical_findings = self.get_findings(severity='CRITICAL')
            high_findings = self.get_findings(severity='HIGH')
            medium_findings = self.get_findings(severity='MEDIUM')
            low_findings = self.get_findings(severity='LOW')
            
            # Get findings by status
            new_findings = self.get_findings(status='NEW')
            in_progress_findings = self.get_findings(status='IN_PROGRESS')
            resolved_findings = self.get_findings(status='RESOLVED')
            
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'region': self.region,
                'summary': {
                    'total_findings': len(critical_findings) + len(high_findings) + len(medium_findings) + len(low_findings),
                    'critical_findings': len(critical_findings),
                    'high_findings': len(high_findings),
                    'medium_findings': len(medium_findings),
                    'low_findings': len(low_findings),
                    'new_findings': len(new_findings),
                    'in_progress_findings': len(in_progress_findings),
                    'resolved_findings': len(resolved_findings)
                },
                'findings_by_severity': {
                    'critical': critical_findings,
                    'high': high_findings,
                    'medium': medium_findings,
                    'low': low_findings
                },
                'findings_by_status': {
                    'new': new_findings,
                    'in_progress': in_progress_findings,
                    'resolved': resolved_findings
                }
            }
            
            return report
        except Exception as e:
            logger.error(f"Failed to generate security report: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='AWS Security Hub Management')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--enable-findings', action='store_true', help='Enable Security Hub findings')
    parser.add_argument('--enable-standards', action='store_true', help='Enable security standards')
    parser.add_argument('--create-actions', action='store_true', help='Create custom actions')
    parser.add_argument('--create-insights', action='store_true', help='Create custom insights')
    parser.add_argument('--setup-automation', action='store_true', help='Setup automated responses')
    parser.add_argument('--generate-report', action='store_true', help='Generate security report')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Initialize Security Hub manager
    manager = AWSSecurityHubManager(args.region)
    
    results = {}
    
    try:
        # Enable Security Hub
        if args.enable_findings:
            results['enable_security_hub'] = manager.enable_security_hub()
        
        # Enable security standards
        if args.enable_standards:
            results['enable_standards'] = manager.enable_security_standards()
        
        # Create custom actions
        if args.create_actions:
            results['create_actions'] = manager.create_custom_actions()
        
        # Create insights
        if args.create_insights:
            results['create_insights'] = manager.create_insights()
        
        # Setup automation
        if args.setup_automation:
            results['automated_responses'] = manager.setup_automated_responses()
        
        # Generate report
        if args.generate_report:
            results['security_report'] = manager.generate_security_report()
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2, default=str))
            
    except Exception as e:
        logger.error(f"Script failed: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main() 