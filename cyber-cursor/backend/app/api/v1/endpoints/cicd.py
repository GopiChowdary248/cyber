from fastapi import APIRouter, Depends, HTTPException, status, Query, Form
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models.project import Project
from app.schemas.auth import User as UserSchema
from app.services.cicd_integration import CICDIntegration, CICDPlatform

router = APIRouter()

# ============================================================================
# CI/CD Integration Endpoints
# ============================================================================

@router.get("/platforms")
async def get_available_platforms(
    current_user: UserSchema = Depends(get_current_user)
):
    """Get list of available CI/CD platforms and their configuration status"""
    try:
        cicd_service = CICDIntegration()
        platforms = await cicd_service.get_available_platforms()
        
        return {
            "platforms": platforms,
            "total_platforms": len(platforms),
            "configured_platforms": len([p for p in platforms if p["configured"]]),
            "available_platforms": len([p for p in platforms if p["available"]])
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get CI/CD platforms: {str(e)}"
        )

@router.post("/generate/{project_id}")
async def generate_cicd_config(
    project_id: int,
    platform: CICDPlatform = Form(...),
    repo_name: Optional[str] = Form(None),
    repo_url: Optional[str] = Form(None),
    branch: Optional[str] = Form("main"),
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate CI/CD configuration for a project"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check user permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Generate CI/CD configuration
        cicd_service = CICDIntegration()
        
        kwargs = {}
        if platform == CICDPlatform.GITHUB_ACTIONS:
            if not repo_name:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Repository name is required for GitHub Actions"
                )
            kwargs["repo_name"] = repo_name
            kwargs["branch"] = branch
        
        elif platform == CICDPlatform.JENKINS:
            if not repo_url:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Repository URL is required for Jenkins"
                )
            kwargs["repo_url"] = repo_url
        
        config = await cicd_service.generate_cicd_config(platform, project.key, **kwargs)
        
        return {
            "project_id": project_id,
            "project_key": project.key,
            "config": config,
            "instructions": get_setup_instructions(platform, config)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate CI/CD config: {str(e)}"
        )

@router.post("/test/github")
async def test_github_integration(
    repo_owner: str = Form(...),
    repo_name: str = Form(...),
    current_user: UserSchema = Depends(get_current_user)
):
    """Test GitHub integration and get repository information"""
    try:
        cicd_service = CICDIntegration()
        result = await cicd_service.test_github_integration(repo_owner, repo_name)
        
        return result
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to test GitHub integration: {str(e)}"
        )

@router.post("/test/gitlab")
async def test_gitlab_integration(
    project_id: str = Form(...),
    current_user: UserSchema = Depends(get_current_user)
):
    """Test GitLab integration and get project information"""
    try:
        cicd_service = CICDIntegration()
        result = await cicd_service.test_gitlab_integration(project_id)
        
        return result
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to test GitLab integration: {str(e)}"
        )

@router.get("/webhooks/{project_id}")
async def get_webhook_config(
    project_id: int,
    platform: CICDPlatform = Query(...),
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get webhook configuration for CI/CD integration"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check user permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        webhook_url = f"http://localhost:8000/api/v1/cicd/webhooks/{project.key}"
        
        webhook_config = {
            "project_id": project_id,
            "project_key": project.key,
            "webhook_url": webhook_url,
            "platform": platform,
            "secret": f"cybershield_{project.key}_secret",
            "events": get_webhook_events(platform),
            "headers": get_webhook_headers(platform)
        }
        
        return webhook_config
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get webhook config: {str(e)}"
        )

@router.post("/webhooks/{project_key}")
async def handle_webhook(
    project_key: str,
    platform: CICDPlatform = Query(...),
    db: AsyncSession = Depends(get_db)
):
    """Handle webhook events from CI/CD platforms"""
    try:
        # Verify project exists
        project = await Project.get_by_key(db, project_key)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # In a real implementation, this would:
        # 1. Verify webhook signature
        # 2. Parse the webhook payload
        # 3. Trigger appropriate actions based on the event
        
        return {
            "status": "success",
            "message": f"Webhook received for project {project_key} from {platform}",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to handle webhook: {str(e)}"
        )

@router.get("/status/{project_id}")
async def get_cicd_status(
    project_id: int,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get CI/CD integration status for a project"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check user permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get available platforms
        cicd_service = CICDIntegration()
        platforms = await cicd_service.get_available_platforms()
        
        # Mock CI/CD status (in real implementation, this would check actual integrations)
        cicd_status = {
            "project_id": project_id,
            "project_key": project.key,
            "integrations": [],
            "last_scan_triggered": None,
            "webhooks_configured": False,
            "automated_scans_enabled": False
        }
        
        # Add platform-specific status
        for platform in platforms:
            if platform["available"]:
                cicd_status["integrations"].append({
                    "platform": platform["platform"],
                    "name": platform["name"],
                    "configured": platform["configured"],
                    "status": "available" if platform["configured"] else "not_configured"
                })
        
        return cicd_status
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get CI/CD status: {str(e)}"
        )

def get_setup_instructions(platform: CICDPlatform, config: Dict[str, Any]) -> List[str]:
    """Get setup instructions for CI/CD platform"""
    instructions = []
    
    if platform == CICDPlatform.GITHUB_ACTIONS:
        instructions = [
            "1. Create the file .github/workflows/sast-scan.yml in your repository",
            "2. Copy the generated workflow content into the file",
            "3. Add CYBERSHIELD_TOKEN to your repository secrets",
            "4. Commit and push the changes to trigger the workflow",
            "5. The workflow will run on every push and pull request"
        ]
    
    elif platform == CICDPlatform.GITLAB_CI:
        instructions = [
            "1. Create the file .gitlab-ci.yml in your repository",
            "2. Copy the generated configuration content into the file",
            "3. Add CYBERSHIELD_TOKEN to your GitLab CI/CD variables",
            "4. Commit and push the changes to trigger the pipeline",
            "5. The pipeline will run on merge requests and main branch"
        ]
    
    elif platform == CICDPlatform.JENKINS:
        instructions = [
            "1. Create a new Jenkins pipeline job",
            "2. Set the pipeline definition to 'Pipeline script from SCM'",
            "3. Configure your Git repository",
            "4. Set the script path to 'Jenkinsfile'",
            "5. Add CYBERSHIELD_TOKEN as a Jenkins credential",
            "6. The pipeline will run on every build"
        ]
    
    elif platform == CICDPlatform.AZURE_DEVOPS:
        instructions = [
            "1. Create the file azure-pipelines.yml in your repository",
            "2. Copy the generated pipeline content into the file",
            "3. Add CYBERSHIELD_TOKEN to your Azure DevOps variables",
            "4. Create a new pipeline in Azure DevOps",
            "5. The pipeline will run on every push to main/develop"
        ]
    
    elif platform == CICDPlatform.CIRCLE_CI:
        instructions = [
            "1. Create the file .circleci/config.yml in your repository",
            "2. Copy the generated configuration content into the file",
            "3. Add CYBERSHIELD_TOKEN to your CircleCI environment variables",
            "4. Commit and push the changes to trigger the workflow",
            "5. The workflow will run on every push to main/develop"
        ]
    
    elif platform == CICDPlatform.TRAVIS_CI:
        instructions = [
            "1. Create the file .travis.yml in your repository",
            "2. Copy the generated configuration content into the file",
            "3. Add CYBERSHIELD_TOKEN to your Travis CI environment variables",
            "4. Commit and push the changes to trigger the build",
            "5. The build will run on every push to main/develop"
        ]
    
    return instructions

def get_webhook_events(platform: CICDPlatform) -> List[str]:
    """Get supported webhook events for platform"""
    if platform == CICDPlatform.GITHUB_ACTIONS:
        return ["push", "pull_request", "release"]
    elif platform == CICDPlatform.GITLAB_CI:
        return ["push", "merge_request", "tag_push"]
    elif platform == CICDPlatform.JENKINS:
        return ["build_started", "build_completed", "build_failed"]
    elif platform == CICDPlatform.AZURE_DEVOPS:
        return ["git.push", "git.pullrequest.created", "git.pullrequest.updated"]
    else:
        return ["push", "build"]

def get_webhook_headers(platform: CICDPlatform) -> Dict[str, str]:
    """Get required webhook headers for platform"""
    if platform == CICDPlatform.GITHUB_ACTIONS:
        return {
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=..."
        }
    elif platform == CICDPlatform.GITLAB_CI:
        return {
            "Content-Type": "application/json",
            "X-Gitlab-Event": "Push Hook",
            "X-Gitlab-Token": "..."
        }
    else:
        return {
            "Content-Type": "application/json"
        } 