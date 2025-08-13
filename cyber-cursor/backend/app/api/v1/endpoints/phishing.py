from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models.phishing import EmailAnalysis, EmailAttachment, EmailResponse, PhishingTemplate, ThreatIntelligence
from app.schemas.phishing import (
    EmailAnalysisCreate, EmailAnalysisResponse, EmailAttachmentResponse,
    EmailResponseCreate, EmailResponseResponse, PhishingTemplateCreate,
    PhishingTemplateResponse, ThreatIntelligenceResponse, PhishingStats
)
from app.schemas.auth import User
from app.services.ai_service import ai_service

router = APIRouter()

@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(
    email_data: EmailAnalysisCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Analyze email for phishing indicators"""
    # Use AI to analyze the email
    analysis_result = await ai_service.analyze_email_content(
        subject=email_data.subject,
        body_text=email_data.body_text,
        body_html=email_data.body_html,
        sender=email_data.sender,
        attachments=email_data.attachments
    )
    
    # Create email analysis record
    analysis_data = email_data.dict()
    analysis_data["analyzed_by"] = current_user.id
    analysis_data["threat_level"] = analysis_result.get("threat_level", "safe")
    analysis_data["email_type"] = analysis_result.get("email_type", "legitimate")
    analysis_data["confidence_score"] = analysis_result.get("confidence_score", 0)
    analysis_data["ai_analysis"] = analysis_result
    
    email_analysis = await EmailAnalysis.create_analysis(db, **analysis_data)
    return email_analysis

@router.post("/analyze/file")
async def analyze_email_file(
    file: UploadFile = File(...),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Analyze email from uploaded file (EML, MSG, etc.)"""
    # Parse email file and extract content
    email_content = await parse_email_file(file)
    
    # Analyze the email
    analysis_result = await ai_service.analyze_email_content(
        subject=email_content.get("subject", ""),
        body_text=email_content.get("body_text", ""),
        body_html=email_content.get("body_html", ""),
        sender=email_content.get("sender", ""),
        attachments=email_content.get("attachments", [])
    )
    
    # Create analysis record
    analysis_data = {
        "subject": email_content.get("subject", ""),
        "body_text": email_content.get("body_text", ""),
        "body_html": email_content.get("body_html", ""),
        "sender": email_content.get("sender", ""),
        "recipients": email_content.get("recipients", []),
        "analyzed_by": current_user.id,
        "threat_level": analysis_result.get("threat_level", "safe"),
        "email_type": analysis_result.get("email_type", "legitimate"),
        "confidence_score": analysis_result.get("confidence_score", 0),
        "ai_analysis": analysis_result
    }
    
    email_analysis = await EmailAnalysis.create_analysis(db, **analysis_data)
    return email_analysis

@router.get("/analyses", response_model=List[EmailAnalysisResponse])
async def get_email_analyses(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    threat_level: Optional[str] = None,
    email_type: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get email analyses with filtering"""
    analyses = await EmailAnalysis.get_analyses(
        db, skip=skip, limit=limit, threat_level=threat_level,
        email_type=email_type, date_from=date_from, date_to=date_to
    )
    return analyses

@router.get("/analyses/{analysis_id}", response_model=EmailAnalysisResponse)
async def get_email_analysis(
    analysis_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get email analysis by ID"""
    analysis = await EmailAnalysis.get_by_id(db, analysis_id=analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email analysis not found"
        )
    return analysis

@router.post("/analyses/{analysis_id}/response", response_model=EmailResponseResponse)
async def create_email_response(
    analysis_id: int,
    response_data: EmailResponseCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Create automated response for email threat"""
    analysis = await EmailAnalysis.get_by_id(db, analysis_id=analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email analysis not found"
        )
    
    # Generate automated response if not provided
    if not response_data.response_type:
        auto_response = await ai_service.generate_auto_response(
            analysis.email_type,
            analysis.threat_level,
            analysis.ai_analysis
        )
        response_data.response_type = auto_response.get("response_type", "monitor")
        response_data.subject = auto_response.get("subject", "")
        response_data.message = auto_response.get("message", "")
    
    response_data.analysis_id = analysis_id
    response_data.created_by = current_user.id
    
    email_response = await EmailResponse.create_response(db, **response_data.dict())
    return email_response

@router.get("/templates", response_model=List[PhishingTemplateResponse])
async def get_phishing_templates(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get phishing email templates"""
    templates = await PhishingTemplate.get_all(db)
    return templates

@router.post("/templates", response_model=PhishingTemplateResponse)
async def create_phishing_template(
    template_data: PhishingTemplateCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Create a new phishing email template"""
    template_data.created_by = current_user.id
    template = await PhishingTemplate.create_template(db, **template_data.dict())
    return template

@router.get("/threat-intelligence", response_model=List[ThreatIntelligenceResponse])
async def get_threat_intelligence(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    threat_type: Optional[str] = None,
    source: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get threat intelligence data"""
    threats = await ThreatIntelligence.get_threats(
        db, skip=skip, limit=limit, threat_type=threat_type, source=source
    )
    return threats

@router.get("/stats/overview", response_model=PhishingStats)
async def get_phishing_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get phishing detection statistics"""
    stats = await EmailAnalysis.get_stats(db)
    return stats

@router.post("/bulk-analyze")
async def bulk_analyze_emails(
    emails: List[EmailAnalysisCreate],
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Bulk analyze multiple emails"""
    results = []
    for email_data in emails:
        try:
            analysis_result = await ai_service.analyze_email_content(
                subject=email_data.subject,
                body_text=email_data.body_text,
                body_html=email_data.body_html,
                sender=email_data.sender,
                attachments=email_data.attachments
            )
            
            analysis_data = email_data.dict()
            analysis_data["analyzed_by"] = current_user.id
            analysis_data["threat_level"] = analysis_result.get("threat_level", "safe")
            analysis_data["email_type"] = analysis_result.get("email_type", "legitimate")
            analysis_data["confidence_score"] = analysis_result.get("confidence_score", 0)
            analysis_data["ai_analysis"] = analysis_result
            
            email_analysis = await EmailAnalysis.create_analysis(db, **analysis_data)
            results.append(email_analysis)
        except Exception as e:
            results.append({"error": str(e), "email": email_data.subject})
    
    return {"results": results, "total_processed": len(emails)}

async def parse_email_file(file: UploadFile) -> dict:
    """Parse email file and extract content"""
    # This is a placeholder - implement actual email parsing logic
    # For now, return basic structure
    return {
        "subject": "Sample Email Subject",
        "body_text": "Sample email body text",
        "body_html": "<p>Sample email HTML body</p>",
        "sender": "sender@example.com",
        "recipients": ["recipient@example.com"],
        "attachments": []
    } 