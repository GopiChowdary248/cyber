#!/usr/bin/env python3
"""
DevSecOps Integration Components
Supports GitHub, GitLab, Jenkins, and CI/CD pipeline integration
"""

import os
import json
import hmac
import hashlib
import requests
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging
from enum import Enum

logger = logging.getLogger(__name__)

class IntegrationType(Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"

@dataclass
class WebhookEvent:
    """Represents a webhook event from CI/CD systems"""
    event_type: str
    repository: str
    branch: str
    commit_sha: str
    pull_request_id: Optional[str]
    user: str
    timestamp: datetime
    payload: Dict[str, Any]

class GitHubIntegration:
    """GitHub integration for DevSecOps"""
    
    def __init__(self, access_token: str, webhook_secret: Optional[str] = None):
        self.access_token = access_token
        self.webhook_secret = webhook_secret
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature"""
        if not self.webhook_secret:
            return True
        
        expected_signature = "sha256=" + hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def parse_webhook_event(self, event_type: str, payload: Dict[str, Any]) -> WebhookEvent:
        """Parse GitHub webhook event"""
        if event_type == "push":
            return WebhookEvent(
                event_type="push",
                repository=payload["repository"]["full_name"],
                branch=payload["ref"].replace("refs/heads/", ""),
                commit_sha=payload["after"],
                pull_request_id=None,
                user=payload["pusher"]["name"],
                timestamp=datetime.fromisoformat(payload["head_commit"]["timestamp"].replace("Z", "+00:00")),
                payload=payload
            )
        elif event_type == "pull_request":
            return WebhookEvent(
                event_type="pull_request",
                repository=payload["repository"]["full_name"],
                branch=payload["pull_request"]["head"]["ref"],
                commit_sha=payload["pull_request"]["head"]["sha"],
                pull_request_id=str(payload["pull_request"]["number"]),
                user=payload["pull_request"]["user"]["login"],
                timestamp=datetime.fromisoformat(payload["pull_request"]["updated_at"].replace("Z", "+00:00")),
                payload=payload
            )
        else:
            raise ValueError(f"Unsupported event type: {event_type}")
    
    async def create_check_run(self, repository: str, commit_sha: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create GitHub check run for SAST results"""
        try:
            # Determine check status based on scan results
            critical_count = scan_results.get("critical_count", 0)
            high_count = scan_results.get("high_count", 0)
            
            if critical_count > 0:
                conclusion = "failure"
                status = "completed"
            elif high_count > 0:
                conclusion = "neutral"
                status = "completed"
            else:
                conclusion = "success"
                status = "completed"
            
            # Create check run
            check_run_data = {
                "name": "SAST Security Scan",
                "head_sha": commit_sha,
                "status": status,
                "conclusion": conclusion,
                "output": {
                    "title": f"Found {scan_results.get('total_vulnerabilities', 0)} security vulnerabilities",
                    "summary": self._generate_check_summary(scan_results),
                    "text": self._generate_check_details(scan_results)
                },
                "annotations": self._generate_annotations(scan_results.get("vulnerabilities", []))
            }
            
            response = requests.post(
                f"{self.api_base}/repos/{repository}/check-runs",
                headers=self.headers,
                json=check_run_data
            )
            
            if response.status_code == 201:
                return response.json()
            else:
                logger.error(f"Failed to create check run: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating GitHub check run: {e}")
            return None
    
    async def create_issue(self, repository: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Create GitHub issue for critical vulnerability"""
        try:
            issue_data = {
                "title": f"Security Vulnerability: {vulnerability.get('vulnerability_type', 'Unknown')}",
                "body": self._generate_issue_body(vulnerability),
                "labels": ["security", "sast", vulnerability.get("severity", "medium")],
                "assignees": [vulnerability.get("assigned_to")] if vulnerability.get("assigned_to") else []
            }
            
            response = requests.post(
                f"{self.api_base}/repos/{repository}/issues",
                headers=self.headers,
                json=issue_data
            )
            
            if response.status_code == 201:
                return response.json()["html_url"]
            else:
                logger.error(f"Failed to create issue: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating GitHub issue: {e}")
            return None
    
    def _generate_check_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate summary for GitHub check run"""
        total = scan_results.get("total_vulnerabilities", 0)
        critical = scan_results.get("critical_count", 0)
        high = scan_results.get("high_count", 0)
        medium = scan_results.get("medium_count", 0)
        low = scan_results.get("low_count", 0)
        
        return f"""
## SAST Security Scan Results

- **Total Vulnerabilities**: {total}
- **Critical**: {critical}
- **High**: {high}
- **Medium**: {medium}
- **Low**: {low}

{'🚨 **Critical vulnerabilities found!**' if critical > 0 else '✅ No critical vulnerabilities found.'}
        """.strip()
    
    def _generate_check_details(self, scan_results: Dict[str, Any]) -> str:
        """Generate detailed report for GitHub check run"""
        details = ["## Detailed Vulnerability Report\n"]
        
        for vuln in scan_results.get("vulnerabilities", []):
            details.append(f"""
### {vuln.get('vulnerability_type', 'Unknown')} - {vuln.get('severity', 'Unknown').upper()}
- **File**: {vuln.get('file_name', 'Unknown')}:{vuln.get('line_number', 'Unknown')}
- **Description**: {vuln.get('description', 'No description')}
- **Tool**: {vuln.get('tool', 'Unknown')}
- **Recommendation**: {vuln.get('recommendation', 'No recommendation')}
            """.strip())
        
        return "\n".join(details)
    
    def _generate_annotations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate GitHub annotations for vulnerabilities"""
        annotations = []
        
        for vuln in vulnerabilities:
            annotation = {
                "path": vuln.get("file_name", ""),
                "start_line": vuln.get("line_number", 1),
                "end_line": vuln.get("line_number", 1),
                "annotation_level": self._map_severity_to_level(vuln.get("severity", "medium")),
                "message": vuln.get("description", ""),
                "title": f"{vuln.get('vulnerability_type', 'Security Issue')} - {vuln.get('severity', 'medium').upper()}"
            }
            annotations.append(annotation)
        
        return annotations
    
    def _map_severity_to_level(self, severity: str) -> str:
        """Map vulnerability severity to GitHub annotation level"""
        mapping = {
            "critical": "failure",
            "high": "warning",
            "medium": "notice",
            "low": "notice"
        }
        return mapping.get(severity.lower(), "notice")
    
    def _generate_issue_body(self, vulnerability: Dict[str, Any]) -> str:
        """Generate issue body for GitHub issue"""
        return f"""
## Security Vulnerability Detected

**Type**: {vulnerability.get('vulnerability_type', 'Unknown')}
**Severity**: {vulnerability.get('severity', 'Unknown').upper()}
**File**: {vulnerability.get('file_name', 'Unknown')}
**Line**: {vulnerability.get('line_number', 'Unknown')}
**Tool**: {vulnerability.get('tool', 'Unknown')}

### Description
{vulnerability.get('description', 'No description provided')}

### Recommendation
{vulnerability.get('recommendation', 'No recommendation provided')}

### Code Snippet
```{self._get_file_extension(vulnerability.get('file_name', ''))}
{vulnerability.get('code_snippet', 'No code snippet available')}
```

### Risk Score
{vulnerability.get('risk_score', 'Not calculated')}

---
*This issue was automatically created by the SAST security scanner.*
        """.strip()
    
    def _get_file_extension(self, filename: str) -> str:
        """Get file extension for syntax highlighting"""
        ext = filename.split('.')[-1].lower()
        mapping = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'java': 'java',
            'php': 'php',
            'go': 'go',
            'cs': 'csharp',
            'rb': 'ruby'
        }
        return mapping.get(ext, 'text')

class GitLabIntegration:
    """GitLab integration for DevSecOps"""
    
    def __init__(self, access_token: str, webhook_secret: Optional[str] = None):
        self.access_token = access_token
        self.webhook_secret = webhook_secret
        self.api_base = "https://gitlab.com/api/v4"
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
    
    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitLab webhook signature"""
        if not self.webhook_secret:
            return True
        
        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def parse_webhook_event(self, event_type: str, payload: Dict[str, Any]) -> WebhookEvent:
        """Parse GitLab webhook event"""
        if event_type == "Push Hook":
            return WebhookEvent(
                event_type="push",
                repository=payload["project"]["path_with_namespace"],
                branch=payload["ref"].replace("refs/heads/", ""),
                commit_sha=payload["after"],
                pull_request_id=None,
                user=payload["user_name"],
                timestamp=datetime.fromisoformat(payload["commits"][0]["timestamp"]),
                payload=payload
            )
        elif event_type == "Merge Request Hook":
            return WebhookEvent(
                event_type="merge_request",
                repository=payload["project"]["path_with_namespace"],
                branch=payload["object_attributes"]["source_branch"],
                commit_sha=payload["object_attributes"]["last_commit"]["id"],
                pull_request_id=str(payload["object_attributes"]["iid"]),
                user=payload["user"]["name"],
                timestamp=datetime.fromisoformat(payload["object_attributes"]["updated_at"]),
                payload=payload
            )
        else:
            raise ValueError(f"Unsupported event type: {event_type}")
    
    async def create_pipeline_job(self, project_id: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create GitLab pipeline job for SAST results"""
        try:
            # Create job data
            job_data = {
                "name": "SAST Security Scan",
                "stage": "security",
                "script": [
                    "echo 'SAST scan completed'",
                    f"echo 'Total vulnerabilities: {scan_results.get('total_vulnerabilities', 0)}'",
                    f"echo 'Critical: {scan_results.get('critical_count', 0)}'",
                    f"echo 'High: {scan_results.get('high_count', 0)}'"
                ],
                "artifacts": {
                    "reports": {
                        "sast": "sast-report.json"
                    }
                }
            }
            
            # Determine job status
            critical_count = scan_results.get("critical_count", 0)
            if critical_count > 0:
                job_data["script"].append("exit 1")  # Fail the job
            
            return job_data
            
        except Exception as e:
            logger.error(f"Error creating GitLab pipeline job: {e}")
            return None
    
    async def create_issue(self, project_id: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Create GitLab issue for critical vulnerability"""
        try:
            issue_data = {
                "title": f"Security Vulnerability: {vulnerability.get('vulnerability_type', 'Unknown')}",
                "description": self._generate_gitlab_issue_body(vulnerability),
                "labels": "security,sast," + vulnerability.get("severity", "medium"),
                "assignee_id": vulnerability.get("assigned_to")
            }
            
            response = requests.post(
                f"{self.api_base}/projects/{project_id}/issues",
                headers=self.headers,
                json=issue_data
            )
            
            if response.status_code == 201:
                return response.json()["web_url"]
            else:
                logger.error(f"Failed to create GitLab issue: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating GitLab issue: {e}")
            return None
    
    def _generate_gitlab_issue_body(self, vulnerability: Dict[str, Any]) -> str:
        """Generate issue body for GitLab issue"""
        return f"""
## Security Vulnerability Detected

**Type**: {vulnerability.get('vulnerability_type', 'Unknown')}
**Severity**: {vulnerability.get('severity', 'Unknown').upper()}
**File**: {vulnerability.get('file_name', 'Unknown')}
**Line**: {vulnerability.get('line_number', 'Unknown')}
**Tool**: {vulnerability.get('tool', 'Unknown')}

### Description
{vulnerability.get('description', 'No description provided')}

### Recommendation
{vulnerability.get('recommendation', 'No recommendation provided')}

### Code Snippet
```{self._get_file_extension(vulnerability.get('file_name', ''))}
{vulnerability.get('code_snippet', 'No code snippet available')}
```

---
*This issue was automatically created by the SAST security scanner.*
        """.strip()
    
    def _get_file_extension(self, filename: str) -> str:
        """Get file extension for syntax highlighting"""
        ext = filename.split('.')[-1].lower()
        mapping = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'java': 'java',
            'php': 'php',
            'go': 'go',
            'cs': 'csharp',
            'rb': 'ruby'
        }
        return mapping.get(ext, 'text')

class JenkinsIntegration:
    """Jenkins integration for DevSecOps"""
    
    def __init__(self, jenkins_url: str, username: str, api_token: str):
        self.jenkins_url = jenkins_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.auth = (username, api_token)
    
    async def trigger_build(self, job_name: str, parameters: Dict[str, str] = None) -> Optional[str]:
        """Trigger Jenkins build"""
        try:
            url = f"{self.jenkins_url}/job/{job_name}/build"
            
            if parameters:
                # Build with parameters
                url = f"{self.jenkins_url}/job/{job_name}/buildWithParameters"
                response = requests.post(url, auth=self.auth, params=parameters)
            else:
                # Simple build
                response = requests.post(url, auth=self.auth)
            
            if response.status_code in [200, 201]:
                # Extract build number from response headers
                location = response.headers.get('Location', '')
                if location:
                    return location.split('/')[-2]  # Extract build number
                return "triggered"
            else:
                logger.error(f"Failed to trigger Jenkins build: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error triggering Jenkins build: {e}")
            return None
    
    async def get_build_status(self, job_name: str, build_number: str) -> Optional[Dict[str, Any]]:
        """Get Jenkins build status"""
        try:
            url = f"{self.jenkins_url}/job/{job_name}/{build_number}/api/json"
            response = requests.get(url, auth=self.auth)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get build status: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting Jenkins build status: {e}")
            return None
    
    async def create_sast_job(self, job_name: str, scan_config: Dict[str, Any]) -> bool:
        """Create Jenkins job for SAST scanning"""
        try:
            # Generate Jenkins job XML configuration
            job_xml = self._generate_jenkins_job_xml(job_name, scan_config)
            
            url = f"{self.jenkins_url}/createItem"
            headers = {"Content-Type": "application/xml"}
            
            response = requests.post(
                url,
                auth=self.auth,
                headers=headers,
                data=job_xml,
                params={"name": job_name}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully created Jenkins job: {job_name}")
                return True
            else:
                logger.error(f"Failed to create Jenkins job: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating Jenkins job: {e}")
            return False
    
    def _generate_jenkins_job_xml(self, job_name: str, scan_config: Dict[str, Any]) -> str:
        """Generate Jenkins job XML configuration"""
        return f"""<?xml version='1.1' encoding='UTF-8'?>
<project>
    <description>SAST Security Scan Job</description>
    <keepDependencies>false</keepDependencies>
    <properties/>
    <scm class="hudson.plugins.git.GitSCM" plugin="git@4.10.2">
        <configVersion>2</configVersion>
        <userRemoteConfigs>
            <hudson.plugins.git.UserRemoteConfig>
                <url>{scan_config.get('repository_url', '')}</url>
            </hudson.plugins.git.UserRemoteConfig>
        </userRemoteConfigs>
        <branches>
            <hudson.plugins.git.BranchSpec>
                <name>{scan_config.get('branch', 'main')}</name>
            </hudson.plugins.git.BranchSpec>
        </branches>
    </scm>
    <canRoam>true</canRoam>
    <disabled>false</disabled>
    <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
    <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
    <triggers>
        <hudson.triggers.SCMTrigger>
            <spec>H/5 * * * *</spec>
        </hudson.triggers.SCMTrigger>
    </triggers>
    <concurrentBuild>false</concurrentBuild>
    <builders>
        <hudson.tasks.Shell>
            <command>
                # Install SAST tools
                pip install bandit pylint semgrep
                
                # Run SAST scan
                python -m bandit -r . -f json -o bandit-report.json
                python -m pylint --output-format=json . > pylint-report.json
                semgrep scan --config=auto --json --output=semgrep-report.json .
                
                # Send results to SAST API
                curl -X POST http://localhost:8000/api/v1/sast/scan \\
                    -H "Content-Type: application/json" \\
                    -H "Authorization: Bearer $SAST_API_TOKEN" \\
                    -d '{{"project_name": "{job_name}", "project_path": ".", "scan_config": {json.dumps(scan_config)}}}'
            </command>
        </hudson.tasks.Shell>
    </builders>
    <publishers>
        <hudson.plugins.junit.JUnitResultArchiver plugin="junit@1.53">
            <testResults>**/test-results/*.xml</testResults>
            <keepLongStdio>false</keepLongStdio>
            <healthScaleFactor>1.0</healthScaleFactor>
            <allowEmptyResults>false</allowEmptyResults>
        </hudson.plugins.junit.JUnitResultArchiver>
    </publishers>
    <buildWrappers/>
</project>"""

class DevSecOpsManager:
    """Main DevSecOps integration manager"""
    
    def __init__(self):
        self.integrations = {}
        self.webhook_handlers = {}
    
    def register_integration(self, integration_type: IntegrationType, config: Dict[str, Any]):
        """Register a new integration"""
        try:
            if integration_type == IntegrationType.GITHUB:
                integration = GitHubIntegration(
                    access_token=config["access_token"],
                    webhook_secret=config.get("webhook_secret")
                )
            elif integration_type == IntegrationType.GITLAB:
                integration = GitLabIntegration(
                    access_token=config["access_token"],
                    webhook_secret=config.get("webhook_secret")
                )
            elif integration_type == IntegrationType.JENKINS:
                integration = JenkinsIntegration(
                    jenkins_url=config["jenkins_url"],
                    username=config["username"],
                    api_token=config["api_token"]
                )
            else:
                raise ValueError(f"Unsupported integration type: {integration_type}")
            
            self.integrations[integration_type] = integration
            logger.info(f"Registered {integration_type.value} integration")
            
        except Exception as e:
            logger.error(f"Failed to register {integration_type.value} integration: {e}")
    
    async def handle_webhook(self, integration_type: IntegrationType, event_type: str, payload: Dict[str, Any], signature: str = None) -> Optional[WebhookEvent]:
        """Handle webhook from CI/CD systems"""
        try:
            integration = self.integrations.get(integration_type)
            if not integration:
                raise ValueError(f"No integration registered for {integration_type.value}")
            
            # Verify webhook signature if provided
            if signature and hasattr(integration, 'verify_webhook_signature'):
                if not integration.verify_webhook_signature(json.dumps(payload).encode(), signature):
                    raise ValueError("Invalid webhook signature")
            
            # Parse webhook event
            webhook_event = integration.parse_webhook_event(event_type, payload)
            
            # Store webhook event for processing
            self.webhook_handlers[webhook_event.commit_sha] = webhook_event
            
            logger.info(f"Processed webhook event: {webhook_event.event_type} for {webhook_event.repository}")
            return webhook_event
            
        except Exception as e:
            logger.error(f"Error handling webhook: {e}")
            return None
    
    async def trigger_sast_scan_on_webhook(self, webhook_event: WebhookEvent, scan_config: Dict[str, Any]) -> Optional[str]:
        """Trigger SAST scan based on webhook event"""
        try:
            # This would integrate with the SAST scanning system
            # For now, return a mock scan ID
            scan_id = f"sast_webhook_{webhook_event.commit_sha[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            logger.info(f"Triggered SAST scan {scan_id} for {webhook_event.repository}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Error triggering SAST scan: {e}")
            return None
    
    async def post_scan_results(self, integration_type: IntegrationType, scan_results: Dict[str, Any], webhook_event: WebhookEvent):
        """Post scan results back to CI/CD system"""
        try:
            integration = self.integrations.get(integration_type)
            if not integration:
                raise ValueError(f"No integration registered for {integration_type.value}")
            
            if integration_type == IntegrationType.GITHUB:
                await integration.create_check_run(
                    webhook_event.repository,
                    webhook_event.commit_sha,
                    scan_results
                )
            elif integration_type == IntegrationType.GITLAB:
                # Extract project ID from repository path
                project_id = webhook_event.repository.replace('/', '%2F')
                await integration.create_pipeline_job(project_id, scan_results)
            
            logger.info(f"Posted scan results to {integration_type.value}")
            
        except Exception as e:
            logger.error(f"Error posting scan results: {e}")
    
    async def create_vulnerability_issues(self, integration_type: IntegrationType, vulnerabilities: List[Dict[str, Any]], webhook_event: WebhookEvent):
        """Create issues for critical vulnerabilities"""
        try:
            integration = self.integrations.get(integration_type)
            if not integration:
                raise ValueError(f"No integration registered for {integration_type.value}")
            
            created_issues = []
            
            for vuln in vulnerabilities:
                if vuln.get("severity") in ["critical", "high"]:
                    if integration_type == IntegrationType.GITHUB:
                        issue_url = await integration.create_issue(webhook_event.repository, vuln)
                    elif integration_type == IntegrationType.GITLAB:
                        project_id = webhook_event.repository.replace('/', '%2F')
                        issue_url = await integration.create_issue(project_id, vuln)
                    else:
                        continue
                    
                    if issue_url:
                        created_issues.append(issue_url)
            
            logger.info(f"Created {len(created_issues)} issues for {integration_type.value}")
            return created_issues
            
        except Exception as e:
            logger.error(f"Error creating vulnerability issues: {e}")
            return [] 