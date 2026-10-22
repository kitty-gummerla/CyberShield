"""
Remediation Verification & Risk Reassessment Routes (Milestone 14)

Endpoints:
1. POST /api/verification/verify-remediation/{remediation_id} -> Verify a stored remediation record
2. POST /api/verification/verify-live                        -> Verify a remediation result object directly
"""

from fastapi import APIRouter, HTTPException
from models.schemas import (
    RiskReassessmentReport,
    RemediationExecutionResult,
    VerificationRequest
)
from database.mongodb import db_manager
from services.verification_service import verification_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/verification", tags=["Remediation Verification & Reassessment"])


# ─────────────────────────────────────────────
# 1. VERIFY STORED REMEDIATION BY ID
# ─────────────────────────────────────────────

@router.post(
    "/verify-remediation/{remediation_id}",
    response_model=RiskReassessmentReport,
    summary="Verify executed remediation record and recalculate residual risk",
    description="Loads a past remediation record from MongoDB, verifies all security controls, and produces a post-incident risk reassessment."
)
async def verify_stored_remediation(remediation_id: str):
    record = await db_manager.get_remediation_by_id(remediation_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Remediation record '{remediation_id}' not found."
        )

    try:
        remediation_obj = RemediationExecutionResult(**record)
        report = verification_service.verify_and_reassess(remediation_obj)
        return report
    except Exception as e:
        logger.error(f"Verification failed for {remediation_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Verification engine error: {str(e)}")


# ─────────────────────────────────────────────
# 2. VERIFY LIVE REMEDIATION RESULT DIRECTLY
# ─────────────────────────────────────────────

@router.post(
    "/verify-live",
    response_model=RiskReassessmentReport,
    summary="Verify a remediation result directly on-the-fly",
    description="Accepts a RemediationExecutionResult payload directly, verifies controls, and returns residual risk metrics."
)
async def verify_live_remediation(result: RemediationExecutionResult):
    try:
        report = verification_service.verify_and_reassess(result)
        return report
    except Exception as e:
        logger.error(f"Live verification failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Live verification error: {str(e)}")