"""
Analysis Routes

Handles:
  - POST   /api/analyze-email   -> Run multi-vector analysis (Text, Sender, URLs, Attachments, Headers) & save to MongoDB
  - GET    /api/analyses        -> List analysis history
  - GET    /api/analyses/{id}   -> Fetch single past analysis
  - DELETE /api/analyses/{id}   -> Delete an analysis record
"""

from fastapi import APIRouter, HTTPException, Query
from models.schemas import EmailAnalysisRequest, EmailAnalysisResponse
from services.phishing_detector import detector
from services.url_analyzer import url_analyzer
from services.attachment_analyzer import attachment_analyzer
from services.header_analyzer import header_analyzer
from services.scoring import risk_scorer
from services.ai_analyzer import ai_service
from database.mongodb import db_manager
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Email Threat Analyzer & History"])


def _generate_recommendations(risk_level: str, indicators: list, url_details: list, attachment_details: list, header_detail) -> list[str]:
    recs = []

    if risk_level == "low":
        recs.append("This email appears safe, but continue exercising standard security caution.")
        recs.append("Verify any unexpected requests directly with the sender via a known trusted channel.")
    elif risk_level == "medium":
        recs.append("Exercise caution. Avoid clicking links or opening attachments until sender is confirmed.")
        recs.append("Inspect the sender's full email address and look for subtle spelling mismatches.")
    elif risk_level == "high":
        recs.append("Do NOT click any links, download attachments, or reply to this email.")
        recs.append("Report this message to your organization's IT or security department.")
        recs.append("If you have entered information or downloaded files, disconnect from network and scan your device.")
    else:  # critical
        recs.append("CRITICAL: Do not interact with this email in any way. Delete or isolate immediately.")
        recs.append("Never execute attachments or enter credentials on unverified websites.")
        recs.append("If an attachment was opened, alert your security administrator immediately to isolate the endpoint.")

    ind_keys = {ind.indicator for ind in indicators}
    if "credential_request" in ind_keys:
        recs.append("Security Rule: Legitimate companies and universities never ask for your password via email.")
    if "otp_request" in ind_keys:
        recs.append("Security Rule: OTP codes are secret authentication keys. Sharing them gives attackers full access.")
    if "financial_request" in ind_keys:
        recs.append("Financial Rule: Always verify payment or invoice change requests via an out-of-band phone call.")
    if "free_email_impersonation" in ind_keys:
        recs.append("Identity Rule: Official institutions send emails from their registered corporate domain, not free webmail.")

    if any(u.is_suspicious for u in url_details):
        recs.append("URL Rule: Never log into an account through links sent in unsolicited emails.")

    if any(a.is_suspicious for a in attachment_details):
        recs.append("Attachment Rule: Never open macro-enabled (.xlsm/.docm) or double-extension (.pdf.exe) attachments.")

    if header_detail and header_detail.is_suspicious:
        recs.append("Header Rule: Technical authentication (SPF/DKIM/DMARC) failed. The sender's identity is forged.")

    return recs


# ─────────────────────────────────────────────
# 1. ANALYZE AND SAVE ENDPOINT
# ─────────────────────────────────────────────

@router.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    summary="Analyze email, attachments & headers, save to MongoDB",
    description="Performs multi-signal analysis across email text, sender identity, static URLs, attachment metadata, and RFC 822 headers."
)
async def analyze_email(request: EmailAnalysisRequest):
    try:
        logger.info(f"Received analysis request for sender: {request.sender}")

        # ── Step 1: Content & Sender Analysis ──
        indicators = detector.analyze(
            sender=request.sender,
            subject=request.subject,
            body=request.body,
        )

        # ── Step 2: Static URL Analysis ──
        urls_found, url_details = url_analyzer.analyze_all(request.body)

        # ── Step 3: Attachment Metadata Analysis ──
        attachments_found, attachment_details = attachment_analyzer.analyze_all(request.attachments or [])

        # ── Step 4: Email Header Analysis (Milestone 9) ──
        header_detail = None
        if request.raw_headers:
            header_detail = header_analyzer.analyze_headers(request.raw_headers)

        # ── Step 5: Centralized Weighted Risk Scoring ──
        risk_score, risk_level, verdict, breakdown = risk_scorer.calculate_score(
            indicators=indicators,
            url_details=url_details,
            attachment_details=attachment_details,
            header_detail=header_detail
        )

        # ── Step 6: AI Explanation Layer ──
        ai_explanation = await ai_service.generate_explanation(
            sender=request.sender,
            subject=request.subject,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            indicators=indicators,
            url_details=url_details
        )

        # ── Step 7: Tailored Recommendations ──
        recommendations = _generate_recommendations(risk_level, indicators, url_details, attachment_details, header_detail)

        # ── Step 8: Assemble Response Object ──
        response_obj = EmailAnalysisResponse(
            sender=request.sender,
            subject=request.subject,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            indicators=indicators,
            urls_found=urls_found,
            url_analysis=url_details,
            attachments_found=attachments_found,
            attachment_analysis=attachment_details,
            header_analysis=header_detail,
            score_breakdown=breakdown,
            ai_explanation=ai_explanation,
            recommendations=recommendations,
            analyzed_at=datetime.utcnow()
        )

        # ── Step 9: Persist to MongoDB ──
        doc_data = response_obj.model_dump()
        doc_data["body"] = request.body
        doc_data["raw_headers"] = request.raw_headers
        analysis_id = await db_manager.save_analysis(doc_data)
        response_obj.analysis_id = analysis_id

        return response_obj

    except Exception as e:
        logger.error(f"Analysis endpoint failure: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")


# ─────────────────────────────────────────────
# 2. GET ANALYSIS HISTORY
# ─────────────────────────────────────────────

@router.get(
    "/analyses",
    summary="Get analysis history",
    description="Fetches past email analysis records sorted by most recent first."
)
async def get_analyses_history(
    limit: int = Query(default=20, ge=1, le=100, description="Max records to return"),
    skip: int = Query(default=0, ge=0, description="Number of records to skip for pagination")
):
    try:
        history = await db_manager.get_analyses(limit=limit, skip=skip)
        return {
            "total": len(history),
            "records": history
        }
    except Exception as e:
        logger.error(f"Failed to retrieve history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analysis history.")


# ─────────────────────────────────────────────
# 3. GET SINGLE ANALYSIS RECORD
# ─────────────────────────────────────────────

@router.get(
    "/analyses/{analysis_id}",
    summary="Get a single analysis by ID",
    description="Retrieves full details of a specific past email analysis."
)
async def get_analysis_by_id(analysis_id: str):
    record = await db_manager.get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return record


# ─────────────────────────────────────────────
# 4. DELETE ANALYSIS RECORD
# ─────────────────────────────────────────────

@router.delete(
    "/analyses/{analysis_id}",
    summary="Delete an analysis record",
    description="Removes an analysis record from the database."
)
async def delete_analysis_by_id(analysis_id: str):
    success = await db_manager.delete_analysis_by_id(analysis_id)
    if not success:
        raise HTTPException(status_code=404, detail="Analysis record not found or could not be deleted.")
    return {"status": "success", "message": f"Analysis {analysis_id} successfully deleted."}