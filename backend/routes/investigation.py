"""
Threat Investigation Center Routes

Provides forensic dossier retrieval:
1. GET  /api/investigation/{analysis_id} -> Full SOC Dossier for a stored analysis
2. POST /api/investigation/live          -> Generate on-the-fly SOC Dossier from direct input
"""

from fastapi import APIRouter, HTTPException
from models.schemas import ThreatInvestigationDossier, EmailAnalysisRequest
from database.mongodb import db_manager
from services.investigation_service import investigation_service
from services.correlation_service import correlation_service
from services.phishing_detector import detector
from services.url_analyzer import url_analyzer
from services.attachment_analyzer import attachment_analyzer
from services.header_analyzer import header_analyzer
from services.scoring import risk_scorer
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/investigation", tags=["Threat Investigation Center"])


# ─────────────────────────────────────────────
# 1. RETRIEVE INVESTIGATION DOSSIER BY ID
# ─────────────────────────────────────────────

@router.get(
    "/{analysis_id}",
    response_model=ThreatInvestigationDossier,
    summary="Get detailed SOC Threat Investigation Dossier",
    description="Transforms a stored MongoDB email analysis into a comprehensive forensic investigation report with remediation steps and threat correlation."
)
async def get_investigation_dossier(analysis_id: str):
    record = await db_manager.get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis record '{analysis_id}' not found. Run an email analysis first."
        )

    try:
        # Fetch historical records for correlation
        all_records = await db_manager.get_analyses(limit=250)
        correlated_report = correlation_service.correlate_incident(record, all_records)
        
        dossier = investigation_service.generate_dossier(record, correlated_threats=correlated_report)
        return dossier
    except Exception as e:
        logger.error(f"Failed to generate investigation dossier: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Investigation engine error: {str(e)}")


# ─────────────────────────────────────────────
# 2. LIVE ON-THE-FLY INVESTIGATION
# ─────────────────────────────────────────────

@router.post(
    "/live",
    response_model=ThreatInvestigationDossier,
    summary="Generate a live SOC Investigation Dossier without database lookup",
    description="Runs live multi-vector threat detection and produces a full forensic dossier, correlation findings, and remediation playbook immediately."
)
async def generate_live_investigation(request: EmailAnalysisRequest):
    try:
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

        analysis_data = {
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

        # Correlate live payload against historical records
        all_records = await db_manager.get_analyses(limit=250)
        correlated_report = correlation_service.correlate_incident(analysis_data, all_records)

        dossier = investigation_service.generate_dossier(analysis_data, correlated_threats=correlated_report)
        return dossier

    except Exception as e:
        logger.error(f"Live investigation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Live investigation engine error: {str(e)}")