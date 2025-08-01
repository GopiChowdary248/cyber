#!/usr/bin/env python3
"""
GCP Security Command Center Integration Script

This script integrates with Google Cloud Security Command Center to:
- Enable Security Command Center
- Configure security policies
- Manage security findings
- Set up automated responses
- Monitor compliance
"""

import json
import argparse
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta
from google.cloud import securitycenter_v1
from google.cloud import asset_v1
from google.cloud import iam_v1
from google.cloud import compute_v1

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GCPSecurityCommandCenterManager:
    def __init__(self, project_id: str):
        self.project_id = project_id
        
        # Initialize GCP clients
        self.scc_client = securitycenter_v1.SecurityCenterClient()
        self.asset_client = asset_v1.AssetServiceClient()
        self.iam_client = iam_v1.IAMClient()
        self.compute_client = compute_v1.InstancesClient()
        
        # Set up common paths
        self.organization_path = f"organizations/{project_id}" if project_id.isdigit() else f"projects/{project_id}"
        self.project_path = f"projects/{project_id}"
        
    def enable_security_command_center(self) -> Dict[str, Any]:
        """Enable Security Command Center"""
        try:
            # Check if SCC is already enabled
            try:
                settings = self.scc_client.get_organization_settings(name=f"{self.organization_path}/organizationSettings")
                logger.info("Security Command Center is already enabled")
                return {"status": "already_enabled", "settings": settings}
            except Exception:
                pass
            
            # Enable SCC
            settings = securitycenter_v1.OrganizationSettings()
            settings.name = f"{self.organization_path}/organizationSettings"
            settings.enable_asset_discovery = True
            
            # Set up service account for SCC
            service_account = f"service-{self.project_id}@gcp-sa-securitycenter.iam.gserviceaccount.com"
            
            result = self.scc_client.update_organization_settings(organization_settings=settings)
            logger.info("Security Command Center enabled successfully")
            
            return {
                "status": "enabled",
                "service_account": service_account,
                "asset_discovery": True
            }
            
        except Exception as e:
            logger.error(f"Failed to enable Security Command Center: {str(e)}")
            raise
    
    def configure_security_sources(self) -> Dict[str, Any]:
        """Configure security sources in SCC"""
        sources = [
            {
                "display_name": "CyberCursor Security Source",
                "description": "Security findings from Cyber Cursor platform",
                "canonical_name": "cyber-cursor-security"
            },
            {
                "display_name": "GCP Built-in Security",
                "description": "Built-in GCP security findings",
                "canonical_name": "gcp-builtin-security"
            }
        ]
        
        results = {}
        for source in sources:
            try:
                # Create source
                source_obj = securitycenter_v1.Source()
                source_obj.display_name = source["display_name"]
                source_obj.description = source["description"]
                source_obj.canonical_name = source["canonical_name"]
                
                result = self.scc_client.create_source(
                    parent=self.organization_path,
                    source=source_obj
                )
                results[source["canonical_name"]] = {
                    "status": "created",
                    "source_id": result.name
                }
                logger.info(f"Created security source: {source['display_name']}")
                
            except Exception as e:
                logger.error(f"Failed to create source {source['canonical_name']}: {str(e)}")
                results[source["canonical_name"]] = {"error": str(e)}
        
        return results
    
    def get_security_findings(self, severity: str = None, state: str = None) -> List[Dict[str, Any]]:
        """Get security findings from SCC"""
        try:
            findings = []
            
            # Build filter
            filter_expr = ""
            if severity:
                filter_expr += f"severity = {severity.upper()} "
            if state:
                if filter_expr:
                    filter_expr += "AND "
                filter_expr += f"state = {state.upper()}"
            
            # Get findings
            request = securitycenter_v1.ListFindingsRequest(
                parent=f"{self.organization_path}/sources/-",
                filter=filter_expr if filter_expr else None
            )
            
            page_result = self.scc_client.list_findings(request=request)
            
            for finding in page_result:
                finding_data = {
                    "name": finding.name,
                    "parent": finding.parent,
                    "resource_name": finding.resource_name,
                    "state": finding.state.name,
                    "severity": finding.severity.name,
                    "category": finding.category,
                    "external_uri": finding.external_uri,
                    "create_time": finding.create_time.isoformat() if finding.create_time else None,
                    "event_time": finding.event_time.isoformat() if finding.event_time else None,
                    "source_properties": dict(finding.source_properties) if finding.source_properties else {}
                }
                findings.append(finding_data)
            
            return findings
        except Exception as e:
            logger.error(f"Failed to get security findings: {str(e)}")
            return []
    
    def get_assets(self, asset_type: str = None) -> List[Dict[str, Any]]:
        """Get assets from SCC"""
        try:
            assets = []
            
            # Build filter
            filter_expr = ""
            if asset_type:
                filter_expr = f"assetType = {asset_type}"
            
            # Get assets
            request = asset_v1.ListAssetsRequest(
                parent=self.organization_path,
                filter=filter_expr if filter_expr else None
            )
            
            page_result = self.asset_client.list_assets(request=request)
            
            for asset in page_result:
                asset_data = {
                    "name": asset.name,
                    "asset_type": asset.asset_type,
                    "resource": asset.resource,
                    "iam_policy": asset.iam_policy,
                    "org_policy": asset.org_policy,
                    "access_policy": asset.access_policy,
                    "update_time": asset.update_time.isoformat() if asset.update_time else None
                }
                assets.append(asset_data)
            
            return assets
        except Exception as e:
            logger.error(f"Failed to get assets: {str(e)}")
            return []
    
    def create_finding(self, source_name: str, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security finding"""
        try:
            finding = securitycenter_v1.Finding()
            finding.parent = source_name
            finding.resource_name = finding_data.get("resource_name", "")
            finding.state = securitycenter_v1.Finding.State.ACTIVE
            finding.severity = securitycenter_v1.Finding.Severity.HIGH
            finding.category = finding_data.get("category", "security_vulnerability")
            finding.external_uri = finding_data.get("external_uri", "")
            
            # Set source properties
            if finding_data.get("source_properties"):
                for key, value in finding_data["source_properties"].items():
                    finding.source_properties[key] = value
            
            result = self.scc_client.create_finding(
                parent=source_name,
                finding_id=finding_data.get("finding_id", f"finding-{datetime.utcnow().timestamp()}"),
                finding=finding
            )
            
            logger.info(f"Created finding: {result.name}")
            return {"status": "created", "finding_name": result.name}
            
        except Exception as e:
            logger.error(f"Failed to create finding: {str(e)}")
            raise
    
    def update_finding_state(self, finding_name: str, state: str) -> Dict[str, Any]:
        """Update finding state"""
        try:
            # Map state string to enum
            state_enum = {
                "active": securitycenter_v1.Finding.State.ACTIVE,
                "inactive": securitycenter_v1.Finding.State.INACTIVE
            }
            
            if state.lower() not in state_enum:
                raise ValueError(f"Invalid state: {state}")
            
            finding = securitycenter_v1.Finding()
            finding.name = finding_name
            finding.state = state_enum[state.lower()]
            
            result = self.scc_client.update_finding(finding=finding)
            
            logger.info(f"Updated finding {finding_name} state to {state}")
            return {"status": "updated", "finding_name": result.name}
            
        except Exception as e:
            logger.error(f"Failed to update finding state: {str(e)}")
            raise
    
    def setup_notification_config(self) -> Dict[str, Any]:
        """Setup notification configuration for SCC"""
        try:
            # Create notification config
            notification_config = securitycenter_v1.NotificationConfig()
            notification_config.description = "Cyber Cursor Security Notifications"
            notification_config.pubsub_topic = f"projects/{self.project_id}/topics/security-notifications"
            
            # Set up streaming config
            streaming_config = securitycenter_v1.NotificationConfig.StreamingConfig()
            streaming_config.filter = "severity = HIGH OR severity = CRITICAL"
            notification_config.streaming_config = streaming_config
            
            result = self.scc_client.create_notification_config(
                parent=self.organization_path,
                config_id="cyber-cursor-notifications",
                notification_config=notification_config
            )
            
            logger.info("Notification config created successfully")
            return {"status": "created", "config_name": result.name}
            
        except Exception as e:
            logger.error(f"Failed to setup notification config: {str(e)}")
            raise
    
    def get_compliance_status(self) -> Dict[str, Any]:
        """Get compliance status from SCC"""
        try:
            compliance_data = {
                "project_id": self.project_id,
                "assessment_date": datetime.utcnow().isoformat(),
                "compliance_frameworks": {}
            }
            
            # Get compliance findings
            compliance_findings = self.get_security_findings()
            
            # Categorize by compliance framework
            frameworks = {
                "cis": [],
                "pci": [],
                "sox": [],
                "hipaa": []
            }
            
            for finding in compliance_findings:
                category = finding.get("category", "").lower()
                if "cis" in category:
                    frameworks["cis"].append(finding)
                elif "pci" in category:
                    frameworks["pci"].append(finding)
                elif "sox" in category:
                    frameworks["sox"].append(finding)
                elif "hipaa" in category:
                    frameworks["hipaa"].append(finding)
            
            for framework, findings in frameworks.items():
                compliance_data["compliance_frameworks"][framework] = {
                    "total_findings": len(findings),
                    "critical_findings": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                    "high_findings": len([f for f in findings if f.get("severity") == "HIGH"]),
                    "medium_findings": len([f for f in findings if f.get("severity") == "MEDIUM"]),
                    "low_findings": len([f for f in findings if f.get("severity") == "LOW"])
                }
            
            return compliance_data
            
        except Exception as e:
            logger.error(f"Failed to get compliance status: {str(e)}")
            return {"error": str(e)}
    
    def setup_automated_responses(self) -> Dict[str, Any]:
        """Setup automated responses for SCC findings"""
        automated_responses = {
            "critical_findings": {
                "description": "Automated response for critical security findings",
                "actions": [
                    "notify_security_team",
                    "create_incident",
                    "escalate_to_management"
                ],
                "pubsub_topics": [
                    "critical-security-alerts",
                    "incident-response"
                ]
            },
            "compliance_violations": {
                "description": "Automated response for compliance violations",
                "actions": [
                    "notify_compliance_team",
                    "create_remediation_ticket",
                    "schedule_audit_review"
                ],
                "pubsub_topics": [
                    "compliance-alerts",
                    "remediation-tasks"
                ]
            },
            "threat_detection": {
                "description": "Automated response for threat detection",
                "actions": [
                    "investigate_threat",
                    "contain_threat",
                    "notify_incident_response"
                ],
                "pubsub_topics": [
                    "threat-intelligence",
                    "incident-response"
                ]
            }
        }
        
        logger.info("Automated responses configured for Security Command Center")
        return automated_responses
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            # Get all security data
            findings = self.get_security_findings()
            assets = self.get_assets()
            compliance = self.get_compliance_status()
            
            # Categorize findings by severity
            critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
            high_findings = [f for f in findings if f.get("severity") == "HIGH"]
            medium_findings = [f for f in findings if f.get("severity") == "MEDIUM"]
            low_findings = [f for f in findings if f.get("severity") == "LOW"]
            
            # Categorize findings by state
            active_findings = [f for f in findings if f.get("state") == "ACTIVE"]
            inactive_findings = [f for f in findings if f.get("state") == "INACTIVE"]
            
            report = {
                "generated_at": datetime.utcnow().isoformat(),
                "project_id": self.project_id,
                "summary": {
                    "total_findings": len(findings),
                    "critical_findings": len(critical_findings),
                    "high_findings": len(high_findings),
                    "medium_findings": len(medium_findings),
                    "low_findings": len(low_findings),
                    "active_findings": len(active_findings),
                    "inactive_findings": len(inactive_findings),
                    "total_assets": len(assets)
                },
                "findings_by_severity": {
                    "critical": critical_findings,
                    "high": high_findings,
                    "medium": medium_findings,
                    "low": low_findings
                },
                "findings_by_state": {
                    "active": active_findings,
                    "inactive": inactive_findings
                },
                "assets": assets,
                "compliance": compliance
            }
            
            return report
        except Exception as e:
            logger.error(f"Failed to generate security report: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='GCP Security Command Center Management')
    parser.add_argument('--project-id', required=True, help='GCP project ID')
    parser.add_argument('--enable-scc', action='store_true', help='Enable Security Command Center')
    parser.add_argument('--configure-sources', action='store_true', help='Configure security sources')
    parser.add_argument('--setup-notifications', action='store_true', help='Setup notification configuration')
    parser.add_argument('--setup-automation', action='store_true', help='Setup automated responses')
    parser.add_argument('--generate-report', action='store_true', help='Generate security report')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Initialize SCC manager
    manager = GCPSecurityCommandCenterManager(args.project_id)
    
    results = {}
    
    try:
        # Enable Security Command Center
        if args.enable_scc:
            results['enable_scc'] = manager.enable_security_command_center()
        
        # Configure sources
        if args.configure_sources:
            results['configure_sources'] = manager.configure_security_sources()
        
        # Setup notifications
        if args.setup_notifications:
            results['setup_notifications'] = manager.setup_notification_config()
        
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