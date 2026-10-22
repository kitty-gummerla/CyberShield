"""
Autonomous Notification & Incident Reporting Service (Milestone 15)

Generates tailored security notifications for affected users and SOC administrators
after an incident has been autonomously resolved and verified.
"""

import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from models.schemas import (
    SecurityNotificationItem,
    IncidentNotificationDispatch,
    RiskReassessmentReport,
    RemediationExecutionResult
)

logger = logging.getLogger(__name__)


class AutonomousNotificationService:
    """
    Synthesizes incident details into user-friendly and admin-grade security alerts,
    and maintains an in-memory alert inbox.
    """

    def __init__(self):
        # In-memory storage for notification items
        self._notifications: List[SecurityNotificationItem] = []

    def dispatch_incident_notifications(
        self,
        remediation_result: RemediationExecutionResult,
        reassessment_report: RiskReassessmentReport,
        target_user_email: Optional[str] = None
    ) -> IncidentNotificationDispatch:
        """
        Creates and dispatches tailored alerts for both the affected user and the SOC administrator.
        """
        dispatch_id = f"DSP-{uuid.uuid4().hex[:8].upper()}"
        incident_id = remediation_result.analysis_id
        user_email = target_user_email or "recipient@company.com"

        actions_taken = [
            f"{action.action_type.replace('_', ' ').title()}: {action.target}"
            for action in remediation_result.executed_actions
        ]

        # 1. Generate Employee / User Notification (Clear, reassuring, zero jargon)
        user_notif = self._build_user_notification(
            incident_id=incident_id,
            user_email=user_email,
            remediation_result=remediation_result,
            reassessment_report=reassessment_report,
            actions_taken=actions_taken
        )

        # 2. Generate SOC Admin Notification (Technical, actionable, metrics-heavy)
        admin_notif = self._build_admin_notification(
            incident_id=incident_id,
            remediation_result=remediation_result,
            reassessment_report=reassessment_report,
            actions_taken=actions_taken
        )

        # 3. Store notifications in memory inbox
        self._notifications.insert(0, user_notif)
        self._notifications.insert(0, admin_notif)

        # 4. Simulated delivery channels
        channels = ["in_app_banner", "email_dispatch_simulation", "soc_webhook_stream"]
        logger.info(f"Dispatched incident notifications for {incident_id} across {channels}")

        return IncidentNotificationDispatch(
            dispatch_id=dispatch_id,
            incident_id=incident_id,
            user_notification=user_notif,
            admin_notification=admin_notif,
            channels_delivered=channels
        )

    def get_all_notifications(
        self,
        recipient_type: Optional[str] = None,
        unread_only: bool = False
    ) -> List[SecurityNotificationItem]:
        """Returns filtered notifications sorted newest first."""
        items = self._notifications
        if recipient_type:
            items = [n for n in items if n.recipient_type == recipient_type]
        if unread_only:
            items = [n for n in items if not n.is_read]
        return items

    def mark_as_read(self, notification_id: str) -> bool:
        """Marks a notification as read."""
        for n in self._notifications:
            if n.notification_id == notification_id:
                n.is_read = True
                return True
        return False

    def clear_all(self):
        """Clears notification queue (primarily for testing)."""
        self._notifications.clear()

    # ─────────────────────────────────────────────
    # BUILDERS
    # ─────────────────────────────────────────────

    def _build_user_notification(
        self,
        incident_id: str,
        user_email: str,
        remediation_result: RemediationExecutionResult,
        reassessment_report: RiskReassessmentReport,
        actions_taken: List[str]
    ) -> SecurityNotificationItem:
        subject = "🛡️ Security Action Taken: Threat Neutralized Automatically"
        message = (
            f"Hello,\n\n"
            f"Our autonomous security system intercepted and safely resolved a suspicious email targeting your inbox.\n\n"
            f"• What happened: A deceptive message was identified and quarantined before it could cause harm.\n"
            f"• Actions taken: Malicious links and attachments were blocked across company defenses.\n"
            f"• Status: {reassessment_report.containment_status.replace('_', ' ').title()}\n\n"
            f"You do NOT need to take any action. Your account remains secure."
        )

        return SecurityNotificationItem(
            notification_id=f"NOTIF-USR-{uuid.uuid4().hex[:6].upper()}",
            recipient_type="user",
            recipient=user_email,
            subject=subject,
            message=message,
            threat_level=remediation_result.threat_level,
            initial_risk_score=remediation_result.risk_score,
            residual_risk_score=reassessment_report.residual_risk_score,
            containment_status=reassessment_report.containment_status,
            actions_summary=actions_taken[:3]
        )

    def _build_admin_notification(
        self,
        incident_id: str,
        remediation_result: RemediationExecutionResult,
        reassessment_report: RiskReassessmentReport,
        actions_taken: List[str]
    ) -> SecurityNotificationItem:
        subject = f"[SOC ALERT] Autonomous Remediation Executed: {remediation_result.threat_level} Incident ({incident_id})"
        message = (
            f"INCIDENT RESOLUTION REPORT\n"
            f"Incident ID:         {incident_id}\n"
            f"Remediation ID:      {remediation_result.remediation_id}\n"
            f"Initial Risk Score:  {remediation_result.risk_score}/100 ({remediation_result.threat_level})\n"
            f"Residual Risk Score: {reassessment_report.residual_risk_score}/100 ({reassessment_report.residual_threat_level})\n"
            f"Risk Reduction:      {reassessment_report.risk_reduction_percentage}%\n"
            f"Containment Status:  {reassessment_report.containment_status}\n\n"
            f"Verified Defense Controls:\n"
            + "\n".join(f"  • {a}" for a in actions_taken) + "\n\n"
            f"Recommended Next Steps: {', '.join(reassessment_report.next_recommended_steps)}"
        )

        return SecurityNotificationItem(
            notification_id=f"NOTIF-ADM-{uuid.uuid4().hex[:6].upper()}",
            recipient_type="admin",
            recipient="soc-team@organization.com",
            subject=subject,
            message=message,
            threat_level=remediation_result.threat_level,
            initial_risk_score=remediation_result.risk_score,
            residual_risk_score=reassessment_report.residual_risk_score,
            containment_status=reassessment_report.containment_status,
            actions_summary=actions_taken
        )


# Global instance
notification_service = AutonomousNotificationService()