"""
Email Integration Routes

Provides endpoints to:
1. Check email provider readiness (GET /api/integration/providers)
2. List inbox summaries (GET /api/integration/inbox)
3. Select and analyze a specific email (POST /api/integration/analyze-selected)
"""

from fastapi import APIRouter, HTTPException, Query
from models.schemas import (
    InboxListResponse,
    AnalyzeSelectedEmailRequest,
    EmailAnalysisResponse,
    AttachmentMetadata
)
from services.email_integration import email_service
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

router = APIRouter(prefix="/api/integration", tags=["Email Inbox Integration"])


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
# 1. PROVIDER STATUS
# ─────────────────────────────────────────────

@router.get(
    "/providers",
    summary="Get status of supported email providers",
    description="Returns configuration status for Gmail, Outlook, and the Simulated Security Inbox."
)
async def get_providers():
    return email_service.get_provider_status()


# ─────────────────────────────────────────────
# 2. INBOX LISTING
# ─────────────────────────────────────────────

@router.get(
    "/inbox",
    response_model=InboxListResponse,
    summary="Fetch inbox email summaries",
    description="Retrieves a list of recent email headers/snippets for the user to review. Does NOT scan entire inbox."
)
async def get_inbox_messages(provider: str = Query(default="simulated", description="'simulated', 'gmail', or 'outlook'")):
    messages = email_service.list_inbox_messages(provider)
    return InboxListResponse(
        provider=provider,
        total_messages=len(messages),
        messages=messages
    )


# ─────────────────────────────────────────────
# 3. ANALYZE SELECTED EMAIL
# ─────────────────────────────────────────────

@router.post(
    "/analyze-selected",
    response_model=EmailAnalysisResponse,
    summary="Analyze a specific email selected from inbox",
    description="Fetches full body, headers, and attachments for the chosen message and runs the complete threat detection pipeline."
)
async def analyze_selected_email(request: AnalyzeSelectedEmailRequest):
    # ── Step 1: Fetch Message Content from Provider ──
    raw_email = email_service.fetch_email_content(request.message_id, request.provider)
    if not raw_email:
        raise HTTPException(
            status_code=404,
            detail=f"Message '{request.message_id}' not found in provider '{request.provider}'."
        )

    sender = raw_email.get("sender", "")
    subject = raw_email.get("subject", "")
    body = raw_email.get("body", "")
    raw_headers = raw_email.get("raw_headers", "")
    attachments_raw = raw_email.get("attachments", [])

    attachments = [
        AttachmentMetadata(
            filename=a["filename"],
            file_size_bytes=a.get("file_size_bytes"),
            content_type=a.get("content_type")
        ) for a in attachments_raw
    ]

    try:
        # ── Step 2: Content & Sender Analysis ──
        indicators = detector.analyze(sender=sender, subject=subject, body=body)

        # ── Step 3: Static URL Analysis ──
        urls_found, url_details = url_analyzer.analyze_all(body)

        # ── Step 4: Attachment Analysis ──
        attachments_found, attachment_details = attachment_analyzer.analyze_all(attachments)

        # ── Step 5: Email Header Analysis ──
        header_detail = header_analyzer.analyze_headers(raw_headers) if raw_headers else None

        # ── Step 6: Risk Scoring ──
        risk_score, risk_level, verdict, breakdown = risk_scorer.calculate_score(
            indicators=indicators,
            url_details=url_details,
            attachment_details=attachment_details,
            header_detail=header_detail
        )

        # ── Step 7: AI Explanation ──
        ai_explanation = await ai_service.generate_explanation(
            sender=sender,
            subject=subject,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            indicators=indicators,
            url_details=url_details
        )

        # ── Step 8: Recommendations ──
        recommendations = _generate_recommendations(risk_level, indicators, url_details, attachment_details, header_detail)

        # ── Step 9: Assemble Response & Persist to DB ──
        response_obj = EmailAnalysisResponse(
            sender=sender,
            subject=subject,
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

        doc_data = response_obj.model_dump()
        doc_data["body"] = body
        doc_data["raw_headers"] = raw_headers
        doc_data["source_provider"] = request.provider
        doc_data["source_message_id"] = request.message_id
        analysis_id = await db_manager.save_analysis(doc_data)
        response_obj.analysis_id = analysis_id

        return response_obj

    except Exception as e:
        logger.error(f"Failed to analyze selected email: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Email analysis pipeline failure: {str(e)}")