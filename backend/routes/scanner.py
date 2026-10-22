"""
Threat Artifact Scanner Routes

Provides standalone scanning APIs for:
1. Arbitrary URLs (POST /api/scan/url)
2. Attachment Metadata (POST /api/scan/attachment)
3. Email Headers & SPF/DKIM/DMARC (POST /api/scan/headers)
"""

from fastapi import APIRouter, HTTPException
from models.schemas import (
    URLScanRequest, URLScanResponse,
    AttachmentScanRequest, AttachmentScanResponse,
    HeaderScanRequest, HeaderScanResponse
)
from services.url_analyzer import url_analyzer
from services.attachment_analyzer import attachment_analyzer
from services.header_analyzer import header_analyzer
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["Threat Artifact Scanner"])


# ─────────────────────────────────────────────
# 1. STANDALONE URL SCANNER
# ─────────────────────────────────────────────

@router.post(
    "/url",
    response_model=URLScanResponse,
    summary="Scan an arbitrary URL statically",
    description="Analyzes a single URL string for phishing domains, IP addresses, shorteners, and disguised paths."
)
async def scan_url(request: URLScanRequest):
    try:
        url_detail = url_analyzer.analyze_single_url(request.url)
        normalized_score = min(int((url_detail.score_contribution / 35) * 100), 100)
        
        if normalized_score <= 20:
            verdict = "Likely Safe — No suspicious domain or structure anomalies found."
        elif normalized_score <= 50:
            verdict = "Suspicious Link — Unencrypted or contains structural risk patterns."
        elif normalized_score <= 80:
            verdict = "High Risk URL — Strong indicators of brand impersonation or phishing."
        else:
            verdict = "Critical Malicious Link — IP hostname, abusive TLD, or credential harvesting path."

        return URLScanResponse(
            url=request.url,
            is_suspicious=url_detail.is_suspicious,
            risk_score=normalized_score,
            risk_level=url_detail.risk_level,
            verdict=verdict,
            reasons=url_detail.reasons,
            details=url_detail,
            scanned_at=datetime.utcnow()
        )
    except Exception as e:
        logger.error(f"URL scanner failure: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"URL scanning error: {str(e)}")


# ─────────────────────────────────────────────
# 2. STANDALONE ATTACHMENT METADATA SCANNER
# ─────────────────────────────────────────────

@router.post(
    "/attachment",
    response_model=AttachmentScanResponse,
    summary="Scan file attachment metadata",
    description="Inspects filename, double extensions, macro documents, and script payloads without executing the file."
)
async def scan_attachment(request: AttachmentScanRequest):
    try:
        att_detail = attachment_analyzer.analyze_single(
            filename=request.filename,
            file_size_bytes=request.file_size_bytes,
            content_type=request.content_type
        )

        normalized_score = min(int((att_detail.score_contribution / 40) * 100), 100)

        if normalized_score == 0:
            verdict = "Safe Document Format — No dangerous executable extensions or macro risks."
        elif normalized_score <= 50:
            verdict = "Potentially Risky Container / Macro Document — Exercise caution before opening."
        elif normalized_score <= 80:
            verdict = "High Risk Attachment — Script or macro-enabled format with high exploitation risk."
        else:
            verdict = "Critical Threat Payload — Deceptive double extension or dangerous executable script."

        return AttachmentScanResponse(
            filename=request.filename,
            is_suspicious=att_detail.is_suspicious,
            risk_score=normalized_score,
            risk_level=att_detail.risk_level,
            verdict=verdict,
            threat_category=att_detail.threat_category,
            reasons=att_detail.reasons,
            details=att_detail,
            scanned_at=datetime.utcnow()
        )
    except Exception as e:
        logger.error(f"Attachment scanner failure: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Attachment scanning error: {str(e)}")


# ─────────────────────────────────────────────
# 3. STANDALONE EMAIL HEADER SCANNER (Milestone 9)
# ─────────────────────────────────────────────

@router.post(
    "/headers",
    response_model=HeaderScanResponse,
    summary="Scan raw RFC 822 email headers",
    description="Inspects SPF, DKIM, DMARC, Return-Path, and Reply-To alignment to detect forged origins and spoofing."
)
async def scan_headers(request: HeaderScanRequest):
    try:
        header_detail = header_analyzer.analyze_headers(request.raw_headers)
        normalized_score = min(int((header_detail.score_contribution / 40) * 100), 100)

        if normalized_score == 0:
            verdict = "Headers Authenticated & Aligned — No technical spoofing indicators found."
        elif normalized_score <= 45:
            verdict = "Header Discrepancies Detected — Mild SPF softfail or minor routing anomalies."
        elif normalized_score <= 75:
            verdict = "High Risk Header Forgery — SPF/DKIM verification failed or Return-Path was redirected."
        else:
            verdict = "Critical Email Forgery — Complete SPF, DKIM, and DMARC authentication failure."

        sender_alignment = {
            "from": header_detail.from_header,
            "return_path": header_detail.return_path,
            "reply_to": header_detail.reply_to,
            "has_return_path_mismatch": header_detail.has_sender_mismatch,
            "has_reply_to_mismatch": header_detail.has_reply_to_mismatch
        }

        return HeaderScanResponse(
            is_suspicious=header_detail.is_suspicious,
            risk_score=normalized_score,
            risk_level=header_detail.risk_level,
            verdict=verdict,
            spf_status=header_detail.spf_status,
            dkim_status=header_detail.dkim_status,
            dmarc_status=header_detail.dmarc_status,
            sender_alignment=sender_alignment,
            reasons=header_detail.reasons,
            details=header_detail,
            scanned_at=datetime.utcnow()
        )
    except Exception as e:
        logger.error(f"Header scanner failure: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Header scanning error: {str(e)}")