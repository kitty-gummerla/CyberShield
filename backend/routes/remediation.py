"""
Autonomous Remediation Engine Routes (Milestone 13)

Provides endpoints for AI-driven autonomous threat remediation:
1. POST /api/remediation/execute/{analysis_id}  -> Execute remediation for a stored incident
2. POST /api/remediation/execute-live            -> Detect + remediate a live email payload
3. POST /api/remediation/dry-run                 -> Simulate remediation without executing
4. GET  /api/remediation/audit-log               -> Retrieve history of all remediation actions
"""

from fastapi import APIRouter, HTTPException, Query
from models.schemas import (
    RemediationExecutionRequest,
    RemediationExecutionResult,
    RemediationAuditLogResponse
)
from database.mongodb import db_manager
from services.remediation_engine import remediation_engine
from services.correlation_service import correlation_service
from services.phishing_detector import detector
from services.url_analyzer import url_analyzer
from services.attachment_analyzer import attachment_analyzer
from services.header_analyzer import header_analyzer
from services.scoring import risk_scorer
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/remediation", tags=["Autonomous Remediation Engine"])


# ─────────────────────────────────────────────
# HELPER: Run full detection pipeline on raw email
# ─────────────────────────────────────────────

def _run_detection_pipeline(request: RemediationExecutionRequest) -> dict:
    """Runs the complete multi-vector detection pipeline and returns analysis data."""
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

    return {
        "analysis_id": "LIVE_REMEDIATION",
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


# ─────────────────────────────────────────────
# 1. EXECUTE REMEDIATION FOR STORED INCIDENT
# ─────────────────────────────────────────────

@router.post(
    "/execute/{analysis_id}",
    response_model=RemediationExecutionResult,
    summary="Execute autonomous remediation for a stored incident",
    description="Fetches a stored analysis from MongoDB, runs AI decision logic, and executes safe remediation actions."
)
async def execute_remediation_by_id(analysis_id: str, dry_run: bool = Query(default=False)):
    record = await db_manager.get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis record '{analysis_id}' not found."
        )

    try:
        # Get correlation context
        all_records = await db_manager.get_analyses(limit=250)
        correlation_report = correlation_service.correlate_incident(record, all_records)

        # AI Decision: determine remediation plan
        actions = remediation_engine.decide_remediation_plan(record, correlation_report)

        # Execute remediation
        result = remediation_engine.execute_remediation(
            analysis_data=record,
            actions=actions,
            dry_run=dry_run,
            correlation_report=correlation_report
        )

        # Save audit record to MongoDB
        await db_manager.save_remediation(result.model_dump(mode="json"))

        return result
    except Exception as e:
        logger.error(f"Remediation failed for {analysis_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Remediation engine error: {str(e)}")


# ─────────────────────────────────────────────
# 2. EXECUTE LIVE REMEDIATION (Detect + Remediate)
# ─────────────────────────────────────────────

@router.post(
    "/execute-live",
    response_model=RemediationExecutionResult,
    summary="Detect threats in a live email and execute autonomous remediation",
    description="Runs full multi-vector detection, correlation, AI decision, and remediation execution on a raw email payload."
)
async def execute_live_remediation(request: RemediationExecutionRequest):
    try:
        # Step 1: Run detection pipeline
        analysis_data = _run_detection_pipeline(request)

        # Step 2: Correlate against history
        all_records = await db_manager.get_analyses(limit=250)
        correlation_report = correlation_service.correlate_incident(analysis_data, all_records)

        # Step 3: AI Decision
        actions = remediation_engine.decide_remediation_plan(analysis_data, correlation_report)

        # Step 4: Execute
        result = remediation_engine.execute_remediation(
            analysis_data=analysis_data,
            actions=actions,
            dry_run=request.dry_run,
            correlation_report=correlation_report
        )

        # Step 5: Save audit trail
        await db_manager.save_remediation(result.model_dump(mode="json"))

        return result
    except Exception as e:
        logger.error(f"Live remediation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Live remediation error: {str(e)}")


# ─────────────────────────────────────────────
# 3. DRY RUN (Simulate Only)
# ─────────────────────────────────────────────

@router.post(
    "/dry-run",
    response_model=RemediationExecutionResult,
    summary="Simulate remediation actions without executing",
    description="Runs full threat detection and AI decision logic, but marks all actions as 'simulated'. No changes are applied."
)
async def dry_run_remediation(request: RemediationExecutionRequest):
    try:
        analysis_data = _run_detection_pipeline(request)

        all_records = await db_manager.get_analyses(limit=250)
        correlation_report = correlation_service.correlate_incident(analysis_data, all_records)

        actions = remediation_engine.decide_remediation_plan(analysis_data, correlation_report)

        # Force dry_run regardless of request setting
        result = remediation_engine.execute_remediation(
            analysis_data=analysis_data,
            actions=actions,
            dry_run=True,
            correlation_report=correlation_report
        )

        await db_manager.save_remediation(result.model_dump(mode="json"))

        return result
    except Exception as e:
        logger.error(f"Dry-run remediation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Dry-run error: {str(e)}")


# ─────────────────────────────────────────────
# 4. AUDIT LOG (History of all remediation actions)
# ─────────────────────────────────────────────

@router.get(
    "/audit-log",
    response_model=RemediationAuditLogResponse,
    summary="Retrieve remediation audit log",
    description="Returns a paginated history of all autonomous remediation actions taken by the platform."
)
async def get_audit_log(limit: int = Query(default=50, ge=1, le=200), skip: int = Query(default=0, ge=0)):
    try:
        records = await db_manager.get_remediations(limit=limit, skip=skip)
        return RemediationAuditLogResponse(
            total_records=len(records),
            records=records
        )
    except Exception as e:
        logger.error(f"Audit log retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Audit log error: {str(e)}")