"""
Threat Correlation Engine Routes (Milestone 12)

Provides endpoints to identify relationships between incidents and detect coordinated campaigns:
1. GET  /api/correlation/incident/{analysis_id} -> Correlates a stored incident against all history
2. GET  /api/correlation/campaigns              -> Detects and groups incidents into active campaigns
3. POST /api/correlation/analyze                -> Correlates a live email payload against historical records
"""

from fastapi import APIRouter, HTTPException
from models.schemas import (
    IncidentCorrelationReport,
    CampaignDetectionResponse,
    EmailAnalysisRequest
)
from database.mongodb import db_manager
from services.correlation_service import correlation_service
from services.phishing_detector import detector
from services.url_analyzer import url_analyzer
from services.attachment_analyzer import attachment_analyzer
from services.header_analyzer import header_analyzer
from services.scoring import risk_scorer
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/correlation", tags=["Threat Correlation Engine"])


# ─────────────────────────────────────────────
# 1. CORRELATE STORED INCIDENT BY ID
# ─────────────────────────────────────────────

@router.get(
    "/incident/{analysis_id}",
    response_model=IncidentCorrelationReport,
    summary="Correlate a stored security incident against history",
    description="Analyzes relationships between the specified incident and all historical events in MongoDB, returning shared indicators, matching artifacts, and confidence tiers."
)
async def correlate_incident_by_id(analysis_id: str):
    target = await db_manager.get_analysis_by_id(analysis_id)
    if not target:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis record '{analysis_id}' not found. Cannot correlate."
        )

    try:
        all_records = await db_manager.get_analyses(limit=250)
        report = correlation_service.correlate_incident(target, all_records)
        return report
    except Exception as e:
        logger.error(f"Correlation failed for {analysis_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Correlation engine error: {str(e)}")


# ─────────────────────────────────────────────
# 2. DETECT AND CLUSTER ALL CAMPAIGNS
# ─────────────────────────────────────────────

@router.get(
    "/campaigns",
    response_model=CampaignDetectionResponse,
    summary="Detect and cluster active threat campaigns",
    description="Groups historical incidents into multi-incident attack campaigns using infrastructure, lure patterns, and behavioral similarity graphs."
)
async def detect_all_campaigns():
    try:
        all_records = await db_manager.get_analyses(limit=250)
        campaign_response = correlation_service.cluster_campaigns(all_records)
        return campaign_response
    except Exception as e:
        logger.error(f"Campaign detection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Campaign clustering error: {str(e)}")


# ─────────────────────────────────────────────
# 3. LIVE CORRELATION ANALYSIS
# ─────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=IncidentCorrelationReport,
    summary="Correlate live email against historical threats",
    description="Executes live multi-vector threat detection on a raw email payload and correlates it on-the-fly with historical incidents without requiring prior storage."
)
async def correlate_live_incident(request: EmailAnalysisRequest):
    try:
        # Run static detection
        indicators = detector.analyze(sender=request.sender, subject=request.subject, body=request.body)
        urls_found, url_details = url_analyzer.analyze_all(request.body)
        attachments_found, attachment_details = attachment_analyzer.analyze_all(request.attachments or [])
        header_detail = header_analyzer.analyze_headers(request.raw_headers) if request.raw_headers else None

        risk_score, risk_level, verdict, breakdown = risk_scorer.calculate_score(
            indicators=indicators,
            url_details=url_details,
            attachment_details=attachment_details,
            header_detail=header_detail
        )

        live_data = {
            "analysis_id": "LIVE_EVALUATION",
            "analyzed_at": datetime.utcnow(),
            "sender": request.sender,
            "subject": request.subject,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "verdict": verdict,
            "indicators": [ind.model_dump() for ind in indicators],
            "urls_found": urls_found,
            "url_analysis": [u.model_dump() for u in url_details],
            "attachments_found": attachments_found,
            "attachment_analysis": [a.model_dump() for a in attachment_details],
            "header_analysis": header_detail.model_dump() if header_detail else None,
            "score_breakdown": breakdown.model_dump()
        }

        all_records = await db_manager.get_analyses(limit=250)
        report = correlation_service.correlate_incident(live_data, all_records)
        return report

    except Exception as e:
        logger.error(f"Live correlation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Live correlation error: {str(e)}")
