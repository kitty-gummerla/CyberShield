"""
Autonomous Notification & Incident Reporting Routes (Milestone 15)

Endpoints:
1. GET  /api/notifications               -> Retrieve list of all security alerts
2. POST /api/notifications/dispatch-live -> Trigger notifications for a completed remediation & verification
3. PATCH /api/notifications/{id}/read    -> Mark an alert as read
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from models.schemas import (
    NotificationListResponse,
    IncidentNotificationDispatch,
    RemediationExecutionResult,
    RiskReassessmentReport
)
from services.notification_service import notification_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["Security Notifications & Alerts"])


class LiveDispatchPayload(BaseModel):
    remediation_result: RemediationExecutionResult
    reassessment_report: RiskReassessmentReport
    target_user_email: Optional[str] = "victim@organization.com"


# ─────────────────────────────────────────────
# 1. GET ALL NOTIFICATIONS
# ─────────────────────────────────────────────

@router.get(
    "",
    response_model=NotificationListResponse,
    summary="Get all security notifications and alerts",
    description="Returns notifications filtered by recipient type (user/admin) and read status."
)
async def get_notifications(
    recipient_type: Optional[str] = Query(default=None, description="user / admin"),
    unread_only: bool = Query(default=False)
):
    items = notification_service.get_all_notifications(
        recipient_type=recipient_type,
        unread_only=unread_only
    )
    unread_count = sum(1 for n in items if not n.is_read)
    return NotificationListResponse(
        total_notifications=len(items),
        unread_count=unread_count,
        notifications=items
    )


# ─────────────────────────────────────────────
# 2. DISPATCH NOTIFICATIONS FOR AN INCIDENT
# ─────────────────────────────────────────────

@router.post(
    "/dispatch-live",
    response_model=IncidentNotificationDispatch,
    summary="Dispatch notifications for a resolved and verified incident",
    description="Generates both user and admin alerts from a remediation and verification result."
)
async def dispatch_live_notification(payload: LiveDispatchPayload):
    try:
        dispatch = notification_service.dispatch_incident_notifications(
            remediation_result=payload.remediation_result,
            reassessment_report=payload.reassessment_report,
            target_user_email=payload.target_user_email
        )
        return dispatch
    except Exception as e:
        logger.error(f"Notification dispatch failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Notification error: {str(e)}")


# ─────────────────────────────────────────────
# 3. MARK NOTIFICATION AS READ
# ─────────────────────────────────────────────

@router.patch(
    "/{notification_id}/read",
    summary="Mark a notification as read",
    description="Updates the is_read status of a specific security alert."
)
async def mark_notification_read(notification_id: str):
    success = notification_service.mark_as_read(notification_id)
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found.")
    return {"status": "ok", "message": f"Notification '{notification_id}' marked as read."}