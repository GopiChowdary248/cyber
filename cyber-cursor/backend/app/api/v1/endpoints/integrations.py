from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List, Any, Optional
import structlog

from app.core.database import get_db
from app.core.security import get_current_user, RoleChecker
from app.models.user import User
from app.services.integration_service import integration_service, IntegrationType, SIEMProvider, EmailProvider, CloudProvider
from app.schemas.integrations import (
    IntegrationCreate, IntegrationUpdate, IntegrationResponse, 
    IntegrationTestResponse, IntegrationStatusResponse, SyncResponse
)

logger = structlog.get_logger()
router = APIRouter()

# Role-based access control
admin_only = RoleChecker(["admin"])

@router.get("/", response_model=List[IntegrationResponse])
async def get_integrations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all integrations"""
    try:
        status_data = await integration_service.get_integration_status()
        integrations = []
        
        for integration_id, data in status_data.items():
            integrations.append({
                "id": integration_id,
                "name": data["name"],
                "type": data["type"],
                "provider": data["provider"],
                "enabled": data["enabled"],
                "status": data["status"],
                "last_sync": data["last_sync"]
            })
            
        return integrations
    except Exception as e:
        logger.error("Error getting integrations", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get integrations"
        )

@router.post("/", response_model=IntegrationResponse)
async def create_integration(
    integration: IntegrationCreate,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Create a new integration"""
    try:
        # Validate integration type and provider
        if integration.type == "siem" and integration.provider not in [p.value for p in SIEMProvider]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid SIEM provider. Supported: {[p.value for p in SIEMProvider]}"
            )
        elif integration.type == "email" and integration.provider not in [p.value for p in EmailProvider]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid email provider. Supported: {[p.value for p in EmailProvider]}"
            )
        elif integration.type == "cloud" and integration.provider not in [p.value for p in CloudProvider]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid cloud provider. Supported: {[p.value for p in CloudProvider]}"
            )
        
        # In a real implementation, this would save to database
        # For now, we'll return a mock response
        integration_id = f"{integration.provider}_{integration.name.lower().replace(' ', '_')}"
        
        return {
            "id": integration_id,
            "name": integration.name,
            "type": integration.type,
            "provider": integration.provider,
            "enabled": True,
            "status": "active",
            "last_sync": None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error creating integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create integration"
        )

@router.get("/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific integration"""
    try:
        status_data = await integration_service.get_integration_status()
        if integration_id not in status_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
            
        data = status_data[integration_id]
        return {
            "id": integration_id,
            "name": data["name"],
            "type": data["type"],
            "provider": data["provider"],
            "enabled": data["enabled"],
            "status": data["status"],
            "last_sync": data["last_sync"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get integration"
        )

@router.put("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: str,
    integration: IntegrationUpdate,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Update an integration"""
    try:
        status_data = await integration_service.get_integration_status()
        if integration_id not in status_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
            
        # In a real implementation, this would update the database
        # For now, we'll return the updated data
        data = status_data[integration_id]
        return {
            "id": integration_id,
            "name": integration.name or data["name"],
            "type": data["type"],
            "provider": data["provider"],
            "enabled": integration.enabled if integration.enabled is not None else data["enabled"],
            "status": data["status"],
            "last_sync": data["last_sync"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update integration"
        )

@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: str,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Delete an integration"""
    try:
        status_data = await integration_service.get_integration_status()
        if integration_id not in status_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
            
        # In a real implementation, this would delete from database
        logger.info("Integration deleted", integration_id=integration_id, user_id=current_user.id)
        
        return {"message": "Integration deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete integration"
        )

@router.post("/{integration_id}/test", response_model=IntegrationTestResponse)
async def test_integration(
    integration_id: str,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Test integration connectivity"""
    try:
        result = await integration_service.test_integration(integration_id)
        return result
    except Exception as e:
        logger.error("Error testing integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test integration"
        )

@router.post("/{integration_id}/sync", response_model=SyncResponse)
async def sync_integration(
    integration_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Manually sync an integration"""
    try:
        # Add sync task to background
        background_tasks.add_task(integration_service.sync_integration, integration_id)
        
        return {
            "success": True,
            "message": f"Sync started for integration {integration_id}",
            "integration_id": integration_id
        }
    except Exception as e:
        logger.error("Error starting integration sync", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start integration sync"
        )

@router.post("/sync-all", response_model=SyncResponse)
async def sync_all_integrations(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Manually sync all integrations"""
    try:
        # Add sync task to background
        background_tasks.add_task(integration_service.sync_all_integrations)
        
        return {
            "success": True,
            "message": "Sync started for all integrations",
            "integration_id": "all"
        }
    except Exception as e:
        logger.error("Error starting all integrations sync", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start integrations sync"
        )

@router.get("/status/overview", response_model=IntegrationStatusResponse)
async def get_integration_status_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get integration status overview"""
    try:
        status_data = await integration_service.get_integration_status()
        
        # Calculate statistics
        total_integrations = len(status_data)
        enabled_integrations = sum(1 for data in status_data.values() if data["enabled"])
        active_integrations = sum(1 for data in status_data.values() if data["status"] == "active")
        
        # Group by type
        type_stats = {}
        for data in status_data.values():
            integration_type = data["type"]
            if integration_type not in type_stats:
                type_stats[integration_type] = {"total": 0, "enabled": 0, "active": 0}
            type_stats[integration_type]["total"] += 1
            if data["enabled"]:
                type_stats[integration_type]["enabled"] += 1
            if data["status"] == "active":
                type_stats[integration_type]["active"] += 1
        
        return {
            "total_integrations": total_integrations,
            "enabled_integrations": enabled_integrations,
            "active_integrations": active_integrations,
            "type_statistics": type_stats,
            "recent_syncs": [
                {
                    "integration_id": integration_id,
                    "last_sync": data["last_sync"]
                }
                for integration_id, data in status_data.items()
                if data["last_sync"]
            ][:5]  # Last 5 syncs
        }
    except Exception as e:
        logger.error("Error getting integration status overview", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get integration status overview"
        )

@router.post("/{integration_id}/enable")
async def enable_integration(
    integration_id: str,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Enable an integration"""
    try:
        status_data = await integration_service.get_integration_status()
        if integration_id not in status_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
            
        # In a real implementation, this would update the database
        logger.info("Integration enabled", integration_id=integration_id, user_id=current_user.id)
        
        return {"message": "Integration enabled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error enabling integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable integration"
        )

@router.post("/{integration_id}/disable")
async def disable_integration(
    integration_id: str,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Disable an integration"""
    try:
        status_data = await integration_service.get_integration_status()
        if integration_id not in status_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
            
        # In a real implementation, this would update the database
        logger.info("Integration disabled", integration_id=integration_id, user_id=current_user.id)
        
        return {"message": "Integration disabled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error disabling integration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable integration"
        )

@router.get("/providers/supported")
async def get_supported_providers(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get list of supported integration providers"""
    return {
        "siem": {
            "splunk": {
                "name": "Splunk",
                "description": "Enterprise SIEM platform",
                "capabilities": ["event_collection", "incident_creation", "alert_forwarding"]
            },
            "qradar": {
                "name": "IBM QRadar",
                "description": "Enterprise security intelligence platform",
                "capabilities": ["event_collection", "incident_creation", "alert_forwarding"]
            },
            "elk": {
                "name": "ELK Stack",
                "description": "Elasticsearch, Logstash, Kibana stack",
                "capabilities": ["event_collection", "log_analysis"]
            },
            "sentinel": {
                "name": "Azure Sentinel",
                "description": "Microsoft's cloud-native SIEM",
                "capabilities": ["event_collection", "incident_creation", "alert_forwarding"]
            },
            "crowdstrike": {
                "name": "CrowdStrike Falcon",
                "description": "Cloud-native endpoint protection platform",
                "capabilities": ["threat_detection", "incident_creation"]
            }
        },
        "email": {
            "office365": {
                "name": "Office 365",
                "description": "Microsoft Office 365 email services",
                "capabilities": ["email_analysis", "threat_detection", "quarantine"]
            },
            "gmail": {
                "name": "Gmail",
                "description": "Google Workspace email services",
                "capabilities": ["email_analysis", "threat_detection"]
            },
            "exchange": {
                "name": "Microsoft Exchange",
                "description": "On-premises Exchange server",
                "capabilities": ["email_analysis", "threat_detection"]
            },
            "smtp": {
                "name": "SMTP",
                "description": "Standard SMTP email server",
                "capabilities": ["email_analysis"]
            }
        },
        "cloud": {
            "aws": {
                "name": "Amazon Web Services",
                "description": "AWS security services",
                "capabilities": ["guardduty", "securityhub", "config", "cloudtrail"]
            },
            "azure": {
                "name": "Microsoft Azure",
                "description": "Azure security services",
                "capabilities": ["sentinel", "defender", "security_center"]
            },
            "gcp": {
                "name": "Google Cloud Platform",
                "description": "GCP security services",
                "capabilities": ["security_command_center", "chronicle"]
            }
        }
    }

@router.post("/notifications/slack")
async def send_slack_notification(
    message: str,
    channel: str = "#security",
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Send notification to Slack"""
    try:
        await integration_service.send_notification_to_slack(message, channel)
        return {"message": "Slack notification sent successfully"}
    except Exception as e:
        logger.error("Error sending Slack notification", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send Slack notification"
        )

@router.post("/notifications/teams")
async def send_teams_notification(
    message: str,
    webhook_url: str,
    current_user: User = Depends(admin_only),
    db: AsyncSession = Depends(get_db)
):
    """Send notification to Microsoft Teams"""
    try:
        await integration_service.send_notification_to_teams(message, webhook_url)
        return {"message": "Teams notification sent successfully"}
    except Exception as e:
        logger.error("Error sending Teams notification", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send Teams notification"
        ) 