"""
Background tasks for CSPM operations
"""

from celery import shared_task
from app.core.celery_app import celery_app
from app.models.cspm_models import (
    Asset, Policy, Finding, ComplianceFramework, 
    ComplianceControl, PolicyEvaluationResult, RiskAssessment
)
from app.core.database import get_db
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json

logger = logging.getLogger(__name__)

@shared_task(bind=True, name='app.services.cspm_tasks.run_compliance_check')
def run_compliance_check(self):
    """
    Run compliance check across all assets and policies
    """
    try:
        logger.info("Starting compliance check task")
        
        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_run_compliance_check_async())
        loop.close()
        
        logger.info("Compliance check task completed successfully")
        return result
        
    except Exception as exc:
        logger.error(f"Compliance check task failed: {exc}")
        self.retry(countdown=60, max_retries=3)

async def _run_compliance_check_async():
    """Async implementation of compliance check"""
    async for db in get_db():
        try:
            # Get all assets
            assets_result = await db.execute(select(Asset))
            assets = assets_result.scalars().all()
            
            # Get all policies
            policies_result = await db.execute(select(Policy))
            policies = policies_result.scalars().all()
            
            compliance_results = []
            
            for asset in assets:
                for policy in policies:
                    # Evaluate policy against asset
                    result = await evaluate_policy_async(policy, asset, db)
                    compliance_results.append(result)
            
            # Update compliance scores
            await update_compliance_scores(assets, compliance_results, db)
            
            return {
                'status': 'success',
                'assets_checked': len(assets),
                'policies_evaluated': len(policies),
                'results_count': len(compliance_results)
            }
            
        except Exception as e:
            logger.error(f"Error in compliance check: {e}")
            raise
        finally:
            await db.close()

@shared_task(bind=True, name='app.services.cspm_tasks.update_risk_assessments')
def update_risk_assessments(self):
    """
    Update risk assessments for all assets based on findings and policy violations
    """
    try:
        logger.info("Starting risk assessment update task")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_update_risk_assessments_async())
        loop.close()
        
        logger.info("Risk assessment update task completed successfully")
        return result
        
    except Exception as exc:
        logger.error(f"Risk assessment update task failed: {exc}")
        self.retry(countdown=120, max_retries=3)

async def _update_risk_assessments_async():
    """Async implementation of risk assessment update"""
    async for db in get_db():
        try:
            # Get all assets with their findings
            assets_result = await db.execute(
                select(Asset).outerjoin(Finding, Asset.id == Finding.asset_id)
            )
            assets = assets_result.scalars().all()
            
            updated_assessments = []
            
            for asset in assets:
                # Calculate new risk score
                risk_score = await calculate_asset_risk_score(asset, db)
                
                # Create or update risk assessment
                assessment = await create_or_update_risk_assessment(
                    asset.id, risk_score, db
                )
                updated_assessments.append(assessment)
            
            return {
                'status': 'success',
                'assessments_updated': len(updated_assessments)
            }
            
        except Exception as e:
            logger.error(f"Error in risk assessment update: {e}")
            raise
        finally:
            await db.close()

@shared_task(bind=True, name='app.services.cspm_tasks.evaluate_policy_batch')
def evaluate_policy_batch(self, policy_ids: List[str], asset_ids: List[str]):
    """
    Evaluate multiple policies against multiple assets in batch
    """
    try:
        logger.info(f"Starting batch policy evaluation for {len(policy_ids)} policies and {len(asset_ids)} assets")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_evaluate_policy_batch_async(policy_ids, asset_ids))
        loop.close()
        
        logger.info("Batch policy evaluation completed successfully")
        return result
        
    except Exception as exc:
        logger.error(f"Batch policy evaluation failed: {exc}")
        self.retry(countdown=60, max_retries=3)

async def _evaluate_policy_batch_async(policy_ids: List[str], asset_ids: List[str]):
    """Async implementation of batch policy evaluation"""
    async for db in get_db():
        try:
            # Get policies and assets
            policies_result = await db.execute(
                select(Policy).where(Policy.id.in_(policy_ids))
            )
            policies = policies_result.scalars().all()
            
            assets_result = await db.execute(
                select(Asset).where(Asset.id.in_(asset_ids))
            )
            assets = assets_result.scalars().all()
            
            evaluation_results = []
            
            for policy in policies:
                for asset in assets:
                    result = await evaluate_policy_async(policy, asset, db)
                    evaluation_results.append(result)
            
            return {
                'status': 'success',
                'evaluations_performed': len(evaluation_results)
            }
            
        except Exception as e:
            logger.error(f"Error in batch policy evaluation: {e}")
            raise
        finally:
            await db.close()

@shared_task(bind=True, name='app.services.cspm_tasks.sync_cloud_inventory')
def sync_cloud_inventory(self, cloud_provider: str, credentials: Dict[str, Any]):
    """
    Sync cloud inventory from specified provider
    """
    try:
        logger.info(f"Starting cloud inventory sync for {cloud_provider}")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_sync_cloud_inventory_async(cloud_provider, credentials))
        loop.close()
        
        logger.info(f"Cloud inventory sync for {cloud_provider} completed successfully")
        return result
        
    except Exception as exc:
        logger.error(f"Cloud inventory sync for {cloud_provider} failed: {exc}")
        self.retry(countdown=300, max_retries=3)

async def _sync_cloud_inventory_async(cloud_provider: str, credentials: Dict[str, Any]):
    """Async implementation of cloud inventory sync"""
    async for db in get_db():
        try:
            # This would integrate with actual cloud provider APIs
            # For now, we'll simulate the process
            
            if cloud_provider == 'aws':
                assets = await sync_aws_inventory(credentials, db)
            elif cloud_provider == 'azure':
                assets = await sync_azure_inventory(credentials, db)
            elif cloud_provider == 'gcp':
                assets = await sync_gcp_inventory(credentials, db)
            else:
                raise ValueError(f"Unsupported cloud provider: {cloud_provider}")
            
            return {
                'status': 'success',
                'cloud_provider': cloud_provider,
                'assets_synced': len(assets)
            }
            
        except Exception as e:
            logger.error(f"Error in cloud inventory sync: {e}")
            raise
        finally:
            await db.close()

# Helper functions
async def evaluate_policy_async(policy: Policy, asset: Asset, db: AsyncSession) -> Dict[str, Any]:
    """Evaluate a single policy against a single asset"""
    try:
        # Simple policy evaluation logic
        # In production, this would use a proper policy engine (OPA/Rego)
        
        evaluation_result = {
            'asset_id': asset.id,
            'policy_id': policy.id,
            'result': True,  # Default to passing
            'evidence': {},
            'execution_time_ms': 0
        }
        
        # Check if asset has required tags
        if policy.rule and 'required_tags' in policy.rule:
            required_tags = policy.rule['required_tags']
            asset_tags = asset.tags or {}
            
            for tag_key, tag_value in required_tags.items():
                if tag_key not in asset_tags or asset_tags[tag_key] != tag_value:
                    evaluation_result['result'] = False
                    evaluation_result['evidence'] = {
                        'missing_tag': tag_key,
                        'expected_value': tag_value,
                        'actual_value': asset_tags.get(tag_key)
                    }
                    break
        
        # Save evaluation result
        db_result = PolicyEvaluationResult(
            asset_id=asset.id,
            policy_id=policy.id,
            result=evaluation_result['result'],
            evidence=evaluation_result['evidence'],
            execution_time_ms=evaluation_result['execution_time_ms']
        )
        
        db.add(db_result)
        await db.commit()
        
        return evaluation_result
        
    except Exception as e:
        logger.error(f"Error evaluating policy {policy.id} against asset {asset.id}: {e}")
        return {
            'asset_id': asset.id,
            'policy_id': policy.id,
            'result': False,
            'evidence': {'error': str(e)},
            'execution_time_ms': 0
        }

async def calculate_asset_risk_score(asset: Asset, db: AsyncSession) -> float:
    """Calculate risk score for an asset based on findings and policy violations"""
    try:
        base_score = 0.0
        
        # Get asset findings
        findings_result = await db.execute(
            select(Finding).where(Finding.asset_id == asset.id)
        )
        findings = findings_result.scalars().all()
        
        # Calculate score based on findings severity
        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0,
            'info': 0.0
        }
        
        for finding in findings:
            weight = severity_weights.get(finding.severity, 0.0)
            base_score += weight
        
        # Normalize score to 0-100 range
        risk_score = min(100.0, base_score * 2.5)  # Scale factor
        
        return round(risk_score, 2)
        
    except Exception as e:
        logger.error(f"Error calculating risk score for asset {asset.id}: {e}")
        return 50.0  # Default medium risk

async def create_or_update_risk_assessment(asset_id: str, risk_score: float, db: AsyncSession) -> RiskAssessment:
    """Create or update risk assessment for an asset"""
    try:
        # Check if assessment exists
        existing_result = await db.execute(
            select(RiskAssessment).where(RiskAssessment.asset_id == asset_id)
        )
        existing = existing_result.scalar_one_or_none()
        
        if existing:
            # Update existing assessment
            existing.overall_score = risk_score
            existing.assessment_date = datetime.utcnow()
            await db.commit()
            return existing
        else:
            # Create new assessment
            new_assessment = RiskAssessment(
                asset_id=asset_id,
                overall_score=risk_score,
                factors={},
                recommendations=[]
            )
            db.add(new_assessment)
            await db.commit()
            await db.refresh(new_assessment)
            return new_assessment
            
    except Exception as e:
        logger.error(f"Error creating/updating risk assessment for asset {asset_id}: {e}")
        raise

async def update_compliance_scores(assets: List[Asset], compliance_results: List[Dict], db: AsyncSession):
    """Update compliance scores for assets based on evaluation results"""
    try:
        for asset in assets:
            # Calculate compliance score based on results
            asset_results = [r for r in compliance_results if r['asset_id'] == asset.id]
            
            if asset_results:
                passed_count = sum(1 for r in asset_results if r['result'])
                total_count = len(asset_results)
                compliance_score = (passed_count / total_count) * 100
                
                # Update asset compliance score
                await db.execute(
                    update(Asset)
                    .where(Asset.id == asset.id)
                    .values(compliance_score=round(compliance_score, 2))
                )
        
        await db.commit()
        
    except Exception as e:
        logger.error(f"Error updating compliance scores: {e}")
        raise

# Cloud provider sync functions (placeholder implementations)
async def sync_aws_inventory(credentials: Dict[str, Any], db: AsyncSession) -> List[Asset]:
    """Sync AWS inventory"""
    # This would integrate with AWS SDK (boto3)
    logger.info("AWS inventory sync not yet implemented")
    return []

async def sync_azure_inventory(credentials: Dict[str, Any], db: AsyncSession) -> List[Asset]:
    """Sync Azure inventory"""
    # This would integrate with Azure SDK
    logger.info("Azure inventory sync not yet implemented")
    return []

async def sync_gcp_inventory(credentials: Dict[str, Any], db: AsyncSession) -> List[Asset]:
    """Sync GCP inventory"""
    # This would integrate with GCP SDK
    logger.info("GCP inventory sync not yet implemented")
    return []
