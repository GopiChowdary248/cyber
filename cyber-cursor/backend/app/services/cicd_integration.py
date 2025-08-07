import os
import json
import asyncio
import aiohttp
import subprocess
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
from enum import Enum

logger = logging.getLogger(__name__)

class CICDPlatform(str, Enum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    CIRCLE_CI = "circle_ci"
    TRAVIS_CI = "travis_ci"

class CICDIntegration:
    """CI/CD Integration service for automated security scanning"""
    
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.gitlab_token = os.getenv("GITLAB_TOKEN")
        self.azure_token = os.getenv("AZURE_DEVOPS_TOKEN")
        self.jenkins_url = os.getenv("JENKINS_URL")
        self.jenkins_user = os.getenv("JENKINS_USER")
        self.jenkins_token = os.getenv("JENKINS_TOKEN")
    
    async def create_github_workflow(self, project_key: str, repo_name: str, branch: str = "main") -> Dict[str, Any]:
        """Create GitHub Actions workflow for automated SAST scanning"""
        workflow_content = f"""name: SAST Security Scan

on:
  push:
    branches: [ {branch} ]
  pull_request:
    branches: [ {branch} ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install bandit safety semgrep
        
    - name: Run Bandit SAST scan
      run: |
        bandit -r . -f json -o bandit-report.json || true
        
    - name: Run Safety check
      run: |
        safety check --json --output safety-report.json || true
        
    - name: Run Semgrep scan
      run: |
        semgrep scan --config auto --json --output semgrep-report.json || true
        
    - name: Upload scan results to CyberShield
      run: |
        curl -X POST "http://localhost:8000/api/v1/projects/{project_key}/upload" \\
          -H "Authorization: Bearer ${{{{ secrets.CYBERSHIELD_TOKEN }}}}" \\
          -F "upload_type=zip" \\
          -F "file=@scan-results.zip" \\
          -F "scan_after_upload=true"
          
    - name: Comment PR with results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          let comment = '## Security Scan Results\\n\\n';
          
          if (fs.existsSync('bandit-report.json')) {{
            const banditResults = JSON.parse(fs.readFileSync('bandit-report.json', 'utf8'));
            comment += `**Bandit Issues:** ${{banditResults.results.length}}\\n`;
          }}
          
          if (fs.existsSync('safety-report.json')) {{
            const safetyResults = JSON.parse(fs.readFileSync('safety-report.json', 'utf8'));
            comment += `**Safety Issues:** ${{safetyResults.length}}\\n`;
          }}
          
          github.rest.issues.createComment({{
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          }});
"""
        
        return {
            "platform": CICDPlatform.GITHUB_ACTIONS,
            "workflow_content": workflow_content,
            "file_path": ".github/workflows/sast-scan.yml",
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def create_gitlab_ci_config(self, project_key: str) -> Dict[str, Any]:
        """Create GitLab CI configuration for automated SAST scanning"""
        gitlab_ci_content = f"""stages:
  - security

variables:
  CYBERSHIELD_PROJECT_KEY: "{project_key}"

sast-scan:
  stage: security
  image: python:3.9-slim
  before_script:
    - pip install bandit safety semgrep
  script:
    - echo "Running SAST security scan..."
    - bandit -r . -f json -o bandit-report.json || true
    - safety check --json --output safety-report.json || true
    - semgrep scan --config auto --json --output semgrep-report.json || true
    - |
      # Create scan results archive
      zip -r scan-results.zip bandit-report.json safety-report.json semgrep-report.json
    - |
      # Upload to CyberShield
      curl -X POST "http://localhost:8000/api/v1/projects/{project_key}/upload" \\
        -H "Authorization: Bearer $CYBERSHIELD_TOKEN" \\
        -F "upload_type=zip" \\
        -F "file=@scan-results.zip" \\
        -F "scan_after_upload=true"
  artifacts:
    reports:
      security: semgrep-report.json
    paths:
      - bandit-report.json
      - safety-report.json
      - semgrep-report.json
    expire_in: 1 week
  only:
    - merge_requests
    - main
    - develop
"""
        
        return {
            "platform": CICDPlatform.GITLAB_CI,
            "config_content": gitlab_ci_content,
            "file_path": ".gitlab-ci.yml",
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def create_jenkins_pipeline(self, project_key: str, repo_url: str) -> Dict[str, Any]:
        """Create Jenkins pipeline for automated SAST scanning"""
        jenkinsfile_content = f"""pipeline {{
    agent any
    
    environment {{
        CYBERSHIELD_PROJECT_KEY = '{project_key}'
        REPO_URL = '{repo_url}'
    }}
    
    stages {{
        stage('Checkout') {{
            steps {{
                checkout scm
            }}
        }}
        
        stage('Setup Tools') {{
            steps {{
                sh '''
                    pip install bandit safety semgrep
                '''
            }}
        }}
        
        stage('SAST Scan') {{
            steps {{
                sh '''
                    echo "Running SAST security scan..."
                    bandit -r . -f json -o bandit-report.json || true
                    safety check --json --output safety-report.json || true
                    semgrep scan --config auto --json --output semgrep-report.json || true
                '''
            }}
        }}
        
        stage('Upload Results') {{
            steps {{
                sh '''
                    zip -r scan-results.zip bandit-report.json safety-report.json semgrep-report.json
                    curl -X POST "http://localhost:8000/api/v1/projects/{project_key}/upload" \\
                        -H "Authorization: Bearer $CYBERSHIELD_TOKEN" \\
                        -F "upload_type=zip" \\
                        -F "file=@scan-results.zip" \\
                        -F "scan_after_upload=true"
                '''
            }}
        }}
    }}
    
    post {{
        always {{
            archiveArtifacts artifacts: '*.json', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'semgrep-report.json',
                reportName: 'SAST Report'
            ])
        }}
    }}
}}
"""
        
        return {
            "platform": CICDPlatform.JENKINS,
            "pipeline_content": jenkinsfile_content,
            "file_path": "Jenkinsfile",
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def create_azure_devops_pipeline(self, project_key: str) -> Dict[str, Any]:
        """Create Azure DevOps pipeline for automated SAST scanning"""
        azure_pipeline_content = f"""trigger:
  branches:
    include:
    - main
    - develop
  paths:
    include:
    - '**/*.py'
    - '**/*.js'
    - '**/*.java'
    - '**/*.cs'

pool:
  vmImage: 'ubuntu-latest'

variables:
  CYBERSHIELD_PROJECT_KEY: '{project_key}'

stages:
- stage: Security
  displayName: 'Security Scan'
  jobs:
  - job: SASTScan
    displayName: 'SAST Security Scan'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.9'
        
    - script: |
        pip install bandit safety semgrep
      displayName: 'Install Security Tools'
      
    - script: |
        echo "Running Bandit SAST scan..."
        bandit -r . -f json -o bandit-report.json || true
      displayName: 'Run Bandit Scan'
      
    - script: |
        echo "Running Safety check..."
        safety check --json --output safety-report.json || true
      displayName: 'Run Safety Check'
      
    - script: |
        echo "Running Semgrep scan..."
        semgrep scan --config auto --json --output semgrep-report.json || true
      displayName: 'Run Semgrep Scan'
      
    - script: |
        echo "Uploading results to CyberShield..."
        zip -r scan-results.zip bandit-report.json safety-report.json semgrep-report.json
        curl -X POST "http://localhost:8000/api/v1/projects/{project_key}/upload" \\
          -H "Authorization: Bearer $(CYBERSHIELD_TOKEN)" \\
          -F "upload_type=zip" \\
          -F "file=@scan-results.zip" \\
          -F "scan_after_upload=true"
      displayName: 'Upload to CyberShield'
      
    - task: PublishTestResults@2
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: '**/semgrep-report.json'
        mergeTestResults: true
        testRunTitle: 'SAST Security Scan'
      condition: succeededOrFailed()
      
    - task: PublishBuildArtifacts@1
      inputs:
        PathtoPublish: '$(System.DefaultWorkingDirectory)'
        ArtifactName: 'SAST-Reports'
        publishLocation: 'Container'
      condition: succeededOrFailed()
"""
        
        return {
            "platform": CICDPlatform.AZURE_DEVOPS,
            "pipeline_content": azure_pipeline_content,
            "file_path": "azure-pipelines.yml",
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def create_circle_ci_config(self, project_key: str) -> Dict[str, Any]:
        """Create CircleCI configuration for automated SAST scanning"""
        circle_ci_content = f"""version: 2.1

orbs:
  python: circleci/python@2.0

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.9
    steps:
      - checkout
      - python/install-packages:
          pkg-manager: pip
          app-dir: ./
      - run:
          name: Install security tools
          command: |
            pip install bandit safety semgrep
      - run:
          name: Run Bandit SAST scan
          command: |
            bandit -r . -f json -o bandit-report.json || true
      - run:
          name: Run Safety check
          command: |
            safety check --json --output safety-report.json || true
      - run:
          name: Run Semgrep scan
          command: |
            semgrep scan --config auto --json --output semgrep-report.json || true
      - run:
          name: Upload results to CyberShield
          command: |
            zip -r scan-results.zip bandit-report.json safety-report.json semgrep-report.json
            curl -X POST "http://localhost:8000/api/v1/projects/{project_key}/upload" \\
              -H "Authorization: Bearer $CYBERSHIELD_TOKEN" \\
              -F "upload_type=zip" \\
              -F "file=@scan-results.zip" \\
              -F "scan_after_upload=true"
      - store_artifacts:
          path: ./
          destination: security-reports

workflows:
  version: 2
  security:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop
"""
        
        return {
            "platform": CICDPlatform.CIRCLE_CI,
            "config_content": circle_ci_content,
            "file_path": ".circleci/config.yml",
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def create_travis_ci_config(self, project_key: str) -> Dict[str, Any]:
        """Create Travis CI configuration for automated SAST scanning"""
        travis_ci_content = f"""language: python
python:
  - "3.9"

branches:
  only:
    - main
    - develop

before_install:
  - pip install bandit safety semgrep

script:
  - echo "Running SAST security scan..."
  - bandit -r . -f json -o bandit-report.json || true
  - safety check --json --output safety-report.json || true
  - semgrep scan --config auto --json --output semgrep-report.json || true

after_success:
  - |
    zip -r scan-results.zip bandit-report.json safety-report.json semgrep-report.json
    curl -X POST "http://localhost:8000/api/v1/projects/{project_key}/upload" \\
      -H "Authorization: Bearer $CYBERSHIELD_TOKEN" \\
      -F "upload_type=zip" \\
      -F "file=@scan-results.zip" \\
      -F "scan_after_upload=true"

after_script:
  - echo "Security scan completed"

env:
  global:
    - CYBERSHIELD_PROJECT_KEY={project_key}
"""
        
        return {
            "platform": CICDPlatform.TRAVIS_CI,
            "config_content": travis_ci_content,
            "file_path": ".travis.yml",
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def generate_cicd_config(self, platform: CICDPlatform, project_key: str, **kwargs) -> Dict[str, Any]:
        """Generate CI/CD configuration for specified platform"""
        try:
            if platform == CICDPlatform.GITHUB_ACTIONS:
                repo_name = kwargs.get('repo_name', '')
                branch = kwargs.get('branch', 'main')
                return await self.create_github_workflow(project_key, repo_name, branch)
            
            elif platform == CICDPlatform.GITLAB_CI:
                return await self.create_gitlab_ci_config(project_key)
            
            elif platform == CICDPlatform.JENKINS:
                repo_url = kwargs.get('repo_url', '')
                return await self.create_jenkins_pipeline(project_key, repo_url)
            
            elif platform == CICDPlatform.AZURE_DEVOPS:
                return await self.create_azure_devops_pipeline(project_key)
            
            elif platform == CICDPlatform.CIRCLE_CI:
                return await self.create_circle_ci_config(project_key)
            
            elif platform == CICDPlatform.TRAVIS_CI:
                return await self.create_travis_ci_config(project_key)
            
            else:
                raise ValueError(f"Unsupported CI/CD platform: {platform}")
                
        except Exception as e:
            logger.error(f"Error generating CI/CD config for {platform}: {e}")
            raise
    
    async def test_github_integration(self, repo_owner: str, repo_name: str) -> Dict[str, Any]:
        """Test GitHub integration and get repository information"""
        if not self.github_token:
            raise ValueError("GitHub token not configured")
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Get repository information
            repo_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
            async with session.get(repo_url, headers=headers) as response:
                if response.status == 200:
                    repo_data = await response.json()
                    
                    # Get recent commits
                    commits_url = f"{repo_url}/commits"
                    async with session.get(commits_url, headers=headers) as commits_response:
                        commits_data = await commits_response.json() if commits_response.status == 200 else []
                    
                    return {
                        "success": True,
                        "repository": {
                            "name": repo_data["name"],
                            "full_name": repo_data["full_name"],
                            "description": repo_data["description"],
                            "language": repo_data["language"],
                            "default_branch": repo_data["default_branch"],
                            "created_at": repo_data["created_at"],
                            "updated_at": repo_data["updated_at"],
                            "stars": repo_data["stargazers_count"],
                            "forks": repo_data["forks_count"]
                        },
                        "recent_commits": len(commits_data),
                        "last_commit": commits_data[0] if commits_data else None
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Failed to fetch repository: {response.status}"
                    }
    
    async def test_gitlab_integration(self, project_id: str) -> Dict[str, Any]:
        """Test GitLab integration and get project information"""
        if not self.gitlab_token:
            raise ValueError("GitLab token not configured")
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "PRIVATE-TOKEN": self.gitlab_token,
                "Content-Type": "application/json"
            }
            
            # Get project information
            project_url = f"https://gitlab.com/api/v4/projects/{project_id}"
            async with session.get(project_url, headers=headers) as response:
                if response.status == 200:
                    project_data = await response.json()
                    
                    return {
                        "success": True,
                        "project": {
                            "id": project_data["id"],
                            "name": project_data["name"],
                            "path": project_data["path"],
                            "description": project_data["description"],
                            "created_at": project_data["created_at"],
                            "last_activity_at": project_data["last_activity_at"],
                            "star_count": project_data["star_count"],
                            "fork_count": project_data["forks_count"]
                        }
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Failed to fetch project: {response.status}"
                    }
    
    async def get_available_platforms(self) -> List[Dict[str, Any]]:
        """Get list of available CI/CD platforms with their status"""
        platforms = []
        
        # Check GitHub
        github_status = {
            "platform": CICDPlatform.GITHUB_ACTIONS,
            "name": "GitHub Actions",
            "available": bool(self.github_token),
            "configured": bool(self.github_token)
        }
        platforms.append(github_status)
        
        # Check GitLab
        gitlab_status = {
            "platform": CICDPlatform.GITLAB_CI,
            "name": "GitLab CI",
            "available": bool(self.gitlab_token),
            "configured": bool(self.gitlab_token)
        }
        platforms.append(gitlab_status)
        
        # Check Jenkins
        jenkins_status = {
            "platform": CICDPlatform.JENKINS,
            "name": "Jenkins",
            "available": bool(self.jenkins_url and self.jenkins_user and self.jenkins_token),
            "configured": bool(self.jenkins_url and self.jenkins_user and self.jenkins_token)
        }
        platforms.append(jenkins_status)
        
        # Check Azure DevOps
        azure_status = {
            "platform": CICDPlatform.AZURE_DEVOPS,
            "name": "Azure DevOps",
            "available": bool(self.azure_token),
            "configured": bool(self.azure_token)
        }
        platforms.append(azure_status)
        
        # CircleCI and Travis CI are always available (no tokens required)
        platforms.extend([
            {
                "platform": CICDPlatform.CIRCLE_CI,
                "name": "CircleCI",
                "available": True,
                "configured": True
            },
            {
                "platform": CICDPlatform.TRAVIS_CI,
                "name": "Travis CI",
                "available": True,
                "configured": True
            }
        ])
        
        return platforms 