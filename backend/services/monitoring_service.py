"""
Continuous Monitoring Engine (Milestone 16)

Autonomous background service that:
1. Periodically polls email inboxes (Simulated Threat Lab or live OAuth providers).
2. Prevents duplicate inspections of already analyzed messages.
3. Automatically triggers the full threat detection & scoring pipeline.
4. If risk >= 60, autonomously orchestrates:
     Remediation (M13) -> Verification (M14) -> Notification (M15)
5. Maintains real-time operational status, cycle metrics, and telemetry events.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

from models.schemas import (
    MonitoringStatus,
    MonitoringCycleResult,
    MonitoringEvent,
    EmailAnalysisResponse,
    AttachmentMetadata
)
from services.email_integration import email_service
from services.phishing_detector import detector
from services.url_analyzer import url_analyzer
from services.attachment_analyzer import attachment_analyzer
from services.header_analyzer import header_analyzer
from services.scoring import risk_scorer
from services.remediation_engine import remediation_engine
from services.verification_service import verification_service
from services.notification_service import notification_service
from database.mongodb import db_manager

logger = logging.getLogger(__name__)


class ContinuousMonitoringService:
    """
    Autonomous engine for continuous threat monitoring and automated incident response.
    """

    def __init__(self):
        self.is_running: bool = False
        self.poll_interval_seconds: int = 15
        self.auto_remediate: bool = True
        self.active_provider: str = "simulated"

        # Background task handle
        self._background_task: Optional[asyncio.Task] = None

        # Tracking state & metrics
        self.total_cycles_completed: int = 0
        self.total_emails_scanned: int = 0
        self.threats_detected: int = 0
        self.remediations_triggered: int = 0
        self.notifications_dispatched: int = 0
        self.last_poll_time: Optional[datetime] = None

        # Deduplication memory (tracks message IDs processed this session)
        self._processed_message_ids: Set[str] = set()

        # Telemetry event log (keeps recent 50 events)
        self._event_log: List[MonitoringEvent] = []

    def _log_event(self, event_type: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Appends a telemetry event to the bounded event log."""
        event = MonitoringEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow(),
            event_type=event_type,
            message=message,
            details=details or {}
        )
        self._event_log.insert(0, event)
        if len(self._event_log) > 50:
            self._event_log.pop()
        logger.info(f"[MONITORING] [{event_type}] {message}")

    def get_status(self) -> MonitoringStatus:
        """Returns the current operational status and metrics of the monitoring engine."""
        return MonitoringStatus(
            is_running=self.is_running,
            status="running" if self.is_running else "idle",
            poll_interval_seconds=self.poll_interval_seconds,
            total_cycles_completed=self.total_cycles_completed,
            total_emails_scanned=self.total_emails_scanned,
            threats_detected=self.threats_detected,
            remediations_triggered=self.remediations_triggered,
            notifications_dispatched=self.notifications_dispatched,
            last_poll_time=self.last_poll_time,
            active_provider=self.active_provider,
            recent_events=self._event_log[:15]
        )

    def get_events(self, limit: int = 20) -> List[MonitoringEvent]:
        """Returns recent telemetry events."""
        return self._event_log[:limit]

    def reset_processed_cache(self):
        """Clears the deduplication set so all inbox messages can be re-evaluated."""
        self._processed_message_ids.clear()
        self._log_event("cache_reset", "Processed messages deduplication cache cleared.")

    async def run_single_cycle(self) -> MonitoringCycleResult:
        """
        Executes a single end-to-end evaluation cycle across the configured email provider.
        Evaluates new messages, detects threats, and triggers autonomous remediation/notification.
        """
        cycle_id = f"CYCLE-{uuid.uuid4().hex[:8].upper()}"
        started_at = datetime.utcnow()
        self.last_poll_time = started_at

        self._log_event(
            "cycle_start",
            f"Started monitoring evaluation cycle {cycle_id} on '{self.active_provider}'",
            {"cycle_id": cycle_id, "provider": self.active_provider}
        )

        # 1. Fetch available messages from inbox provider
        inbox_summaries = email_service.list_inbox_messages(provider=self.active_provider)

        cycle_details: List[Dict[str, Any]] = []
        new_threats_found = 0
        remediations_in_cycle = 0

        for summary in inbox_summaries:
            msg_id = summary.id

            # Skip already analyzed messages (Deduplication)
            if msg_id in self._processed_message_ids:
                continue

            # Mark as processed
            self._processed_message_ids.add(msg_id)
            self.total_emails_scanned += 1

            # 2. Fetch full message content
            content = email_service.fetch_email_content(msg_id, provider=self.active_provider)
            if not content:
                continue

            # 3. Execute Detection Pipeline
            sender = content.get("sender", "")
            subject = content.get("subject", "")
            body = content.get("body", "")
            raw_headers = content.get("raw_headers", "")
            attachments_raw = content.get("attachments", [])
            attachments = [
                AttachmentMetadata(
                    filename=a["filename"],
                    file_size_bytes=a.get("file_size_bytes"),
                    content_type=a.get("content_type")
                ) if isinstance(a, dict) else a
                for a in attachments_raw
            ]

            indicators = detector.analyze(sender=sender, subject=subject, body=body)
            urls_found, url_details = url_analyzer.analyze_all(body)
            attachments_found, attachment_details = attachment_analyzer.analyze_all(attachments)
            header_detail = None
            if raw_headers:
                header_detail = header_analyzer.analyze_headers(raw_headers)

            risk_score, risk_level, verdict, breakdown = risk_scorer.calculate_score(
                indicators=indicators,
                url_details=url_details,
                attachment_details=attachment_details,
                header_detail=header_detail
            )

            # Persist analysis to database
            analysis_doc = {
                "sender": sender,
                "subject": subject,
                "body": body,
                "raw_headers": raw_headers,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "verdict": verdict,
                "indicators": [ind.model_dump() for ind in indicators],
                "urls_found": urls_found,
                "url_analysis": [u.model_dump() for u in url_details],
                "attachments_found": attachments_found,
                "attachment_analysis": [a.model_dump() for a in attachment_details],
                "header_analysis": header_detail.model_dump() if header_detail else None,
                "score_breakdown": breakdown.model_dump(),
                "analyzed_at": datetime.utcnow()
            }
            analysis_id = await db_manager.save_analysis(analysis_doc)
            analysis_id_str = analysis_id or f"LOCAL-{msg_id}"

            item_result = {
                "message_id": msg_id,
                "analysis_id": analysis_id_str,
                "sender": sender,
                "subject": subject,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "verdict": verdict,
                "autonomous_action_taken": False
            }

            # 4. If Threat Detected (score >= 60) -> Autonomous Pipeline (M13 -> M14 -> M15)
            if risk_score >= 60:
                new_threats_found += 1
                self.threats_detected += 1

                if self.auto_remediate:
                    # Prepare threat data for remediation engine
                    threat_data = {
                        "analysis_id": analysis_id_str,
                        "sender": sender,
                        "subject": subject,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "indicators": [ind.model_dump() for ind in indicators],
                        "url_analysis": [u.model_dump() for u in url_details],
                        "attachment_analysis": [a.model_dump() for a in attachment_details]
                    }

                    # M13: Autonomous Decision & Remediation
                    actions = remediation_engine.decide_remediation_plan(threat_data)
                    remediation_res = remediation_engine.execute_remediation(threat_data, actions, dry_run=False)
                    await db_manager.save_remediation(remediation_res.model_dump(mode="json"))
                    self.remediations_triggered += len(remediation_res.executed_actions)
                    remediations_in_cycle += len(remediation_res.executed_actions)

                    # M14: Verification & Risk Reassessment
                    reassessment_rep = verification_service.verify_and_reassess(remediation_res)

                    # M15: Autonomous Notifications (User + Admin)
                    dispatch = notification_service.dispatch_incident_notifications(
                        remediation_result=remediation_res,
                        reassessment_report=reassessment_rep,
                        target_user_email=sender
                    )
                    self.notifications_dispatched += 2

                    item_result["autonomous_action_taken"] = True
                    item_result["remediation_id"] = remediation_res.remediation_id
                    item_result["actions_count"] = len(remediation_res.executed_actions)
                    item_result["residual_risk_score"] = reassessment_rep.residual_risk_score
                    item_result["containment_status"] = reassessment_rep.containment_status

                    self._log_event(
                        "threat_neutralized",
                        f"Threat neutralized in message '{subject}' (Score: {risk_score} -> {reassessment_rep.residual_risk_score})",
                        {
                            "message_id": msg_id,
                            "actions_executed": len(remediation_res.executed_actions),
                            "containment": reassessment_rep.containment_status
                        }
                    )
                else:
                    self._log_event(
                        "threat_detected",
                        f"Threat detected in message '{subject}' (Score: {risk_score}), auto-remediation disabled.",
                        {"message_id": msg_id, "risk_score": risk_score}
                    )
            else:
                self._log_event(
                    "safe_email",
                    f"Email '{subject}' inspected and verified safe (Score: {risk_score})",
                    {"message_id": msg_id, "risk_score": risk_score}
                )

            cycle_details.append(item_result)

        completed_at = datetime.utcnow()
        self.total_cycles_completed += 1

        self._log_event(
            "cycle_complete",
            f"Cycle {cycle_id} finished: evaluated {len(cycle_details)} emails, neutralized {new_threats_found} threats.",
            {"cycle_id": cycle_id, "evaluated": len(cycle_details), "threats": new_threats_found}
        )

        return MonitoringCycleResult(
            cycle_id=cycle_id,
            started_at=started_at,
            completed_at=completed_at,
            emails_evaluated=len(cycle_details),
            new_threats_found=new_threats_found,
            remediations_executed=remediations_in_cycle,
            details=cycle_details
        )

    async def _continuous_loop(self):
        """Asynchronous background loop executed periodically."""
        logger.info(f"[MONITORING] Continuous background loop started (interval={self.poll_interval_seconds}s)")
        try:
            while self.is_running:
                await self.run_single_cycle()
                await asyncio.sleep(self.poll_interval_seconds)
        except asyncio.CancelledError:
            logger.info("[MONITORING] Background monitoring task was cancelled.")
        except Exception as e:
            logger.error(f"[MONITORING] Unexpected error in monitoring loop: {e}", exc_info=True)
            self._log_event("error", f"Monitoring worker error: {str(e)}")
        finally:
            self.is_running = False

    def start_monitoring(
        self,
        poll_interval_seconds: int = 15,
        auto_remediate: bool = True,
        provider: str = "simulated"
    ) -> bool:
        """Starts the background continuous monitoring loop."""
        if self.is_running:
            logger.warning("[MONITORING] Monitoring is already running.")
            return False

        self.poll_interval_seconds = poll_interval_seconds
        self.auto_remediate = auto_remediate
        self.active_provider = provider
        self.is_running = True

        self._background_task = asyncio.create_task(self._continuous_loop())
        self._log_event(
            "worker_started",
            f"Continuous monitoring started (interval={poll_interval_seconds}s, provider={provider})",
            {"interval": poll_interval_seconds, "auto_remediate": auto_remediate}
        )
        return True

    def stop_monitoring(self) -> bool:
        """Gracefully stops the continuous monitoring background worker."""
        was_running = self.is_running
        self.is_running = False
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()
        self._background_task = None

        self._log_event("worker_stopped", "Continuous monitoring background worker stopped.")
        return was_running


# ═══════════════════════════════════════════════════════════════════
# Global Continuous Monitoring Service Instance
# ═══════════════════════════════════════════════════════════════════
monitoring_service = ContinuousMonitoringService()