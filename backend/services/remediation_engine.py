"""
Autonomous AI Decision & Remediation Engine (Milestone 13)

Evaluates threat analysis results and autonomously decides and executes
safe, prioritized remediation actions without requiring manual user intervention.

Safety: All actions are executed through simulated gateway/firewall/IAM handlers.
No real external network disruption or system lockouts occur.
"""

import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse
from models.schemas import (
    RemediationActionItem,
    RemediationActionType,
    RemediationExecutionResult,
    IncidentCorrelationReport
)

logger = logging.getLogger(__name__)


class AutonomousRemediationEngine:
    """
    Core decision engine that maps threat vectors to remediation actions
    and executes them through safe simulated handlers.
    """

    # ─────────────────────────────────────────────
    # 1. DECISION LOGIC — What actions should we take?
    # ─────────────────────────────────────────────

    def decide_remediation_plan(
        self,
        analysis_data: Dict[str, Any],
        correlation_report: Optional[IncidentCorrelationReport] = None
    ) -> List[RemediationActionItem]:
        """
        Analyzes threat vectors in the analysis data and builds
        a prioritized list of remediation actions.

        Decision Rules:
        - Risk score >= 60 → Trigger active remediation
        - Risk score < 60  → No autonomous action needed
        - Each threat vector maps to specific action types
        """
        risk_score = analysis_data.get("risk_score", 0)
        risk_level = analysis_data.get("risk_level", "low")
        sender = analysis_data.get("sender", "Unknown")
        analysis_id = str(analysis_data.get("analysis_id") or analysis_data.get("_id") or "UNKNOWN")

        actions: List[RemediationActionItem] = []
        action_counter = 1

        # Only trigger autonomous remediation for medium/high/critical threats
        if risk_score < 60:
            logger.info(f"Risk score {risk_score} is below remediation threshold (60). No action needed.")
            return actions

        # ── Rule 1: Email Quarantine (always for high-risk emails) ──
        if risk_level in ["high", "critical"]:
            actions.append(RemediationActionItem(
                action_id=f"ACT-{action_counter:03d}",
                action_type=RemediationActionType.EMAIL_QUARANTINE,
                target=f"message_id:{analysis_id}",
                parameters={"sender": sender, "quarantine_folder": "THREAT_QUARANTINE"},
                priority="Immediate",
                details=f"Quarantine and isolate email from '{sender}' across all organization mailboxes. "
                        f"Move to secure quarantine vault and revoke recipient access."
            ))
            action_counter += 1

        # ── Rule 2: Network Domain Block (for each malicious URL/domain) ──
        urls = analysis_data.get("url_analysis", [])
        blocked_domains = set()
        for url_obj in urls:
            if isinstance(url_obj, dict) and url_obj.get("is_suspicious"):
                domain = self._extract_domain(url_obj.get("url", ""))
                if domain and domain not in blocked_domains:
                    blocked_domains.add(domain)
                    actions.append(RemediationActionItem(
                        action_id=f"ACT-{action_counter:03d}",
                        action_type=RemediationActionType.NETWORK_DOMAIN_BLOCK,
                        target=f"domain:{domain}",
                        parameters={
                            "url": url_obj.get("url"),
                            "block_type": "dns_sinkhole_and_firewall",
                            "risk_level": url_obj.get("risk_level", "high")
                        },
                        priority="Immediate",
                        details=f"Block domain '{domain}' on perimeter firewall and DNS sinkhole. "
                                f"Prevent all outbound connections to this malicious infrastructure."
                    ))
                    action_counter += 1

        # ── Rule 3: Endpoint Isolation Flag (for suspicious attachments) ──
        attachments = analysis_data.get("attachment_analysis", [])
        for att in attachments:
            if isinstance(att, dict) and att.get("is_suspicious"):
                filename = att.get("filename", "unknown_file")
                actions.append(RemediationActionItem(
                    action_id=f"ACT-{action_counter:03d}",
                    action_type=RemediationActionType.ENDPOINT_ISOLATION_FLAG,
                    target=f"file:{filename}",
                    parameters={
                        "filename": filename,
                        "extension": att.get("detected_extension", ""),
                        "threat_category": att.get("threat_category", "Suspicious"),
                        "action": "quarantine_and_scan"
                    },
                    priority="Immediate",
                    details=f"Flag attachment '{filename}' for endpoint detection. "
                            f"Quarantine on any endpoint where it was opened and run full EDR scan."
                ))
                action_counter += 1

        # ── Rule 4: IAM Session Revocation (if credential harvesting detected) ──
        indicators = analysis_data.get("indicators", [])
        credential_threat = any(
            (ind.get("indicator") if isinstance(ind, dict) else str(ind))
            in ["credential_request", "otp_request"]
            for ind in indicators
        )
        if credential_threat:
            actions.append(RemediationActionItem(
                action_id=f"ACT-{action_counter:03d}",
                action_type=RemediationActionType.IAM_SESSION_REVOCATION,
                target=f"user:recipient@organization.com",
                parameters={
                    "trigger": "credential_harvesting_detected",
                    "force_password_reset": True,
                    "revoke_active_sessions": True,
                    "enforce_mfa_reenrollment": True
                },
                priority="High",
                details="Revoke all active user sessions, force immediate password reset, "
                        "and require MFA re-enrollment to prevent compromised credential abuse."
            ))
            action_counter += 1

        # ── Rule 5: IOC Export (always for actionable threats) ──
        ioc_targets = []
        for domain in blocked_domains:
            ioc_targets.append({"type": "domain", "value": domain})
        ioc_targets.append({"type": "email", "value": sender})
        for att in attachments:
            if isinstance(att, dict) and att.get("is_suspicious"):
                ioc_targets.append({"type": "filename", "value": att.get("filename", "")})

        if ioc_targets:
            actions.append(RemediationActionItem(
                action_id=f"ACT-{action_counter:03d}",
                action_type=RemediationActionType.IOC_EXPORT,
                target="ioc_blocklist",
                parameters={
                    "format": "stix_json",
                    "indicators": ioc_targets,
                    "source_incident": analysis_id
                },
                priority="Medium",
                details=f"Export {len(ioc_targets)} Indicators of Compromise (IOCs) in STIX/JSON format "
                        f"for SOC team integration with SIEM, threat intelligence platforms, and blocklists."
            ))
            action_counter += 1

        # ── Rule 6: Campaign-wide escalation (if correlation found campaign) ──
        if correlation_report and correlation_report.campaign_identified:
            sender_domain = sender.split("@")[-1] if "@" in sender else sender
            actions.append(RemediationActionItem(
                action_id=f"ACT-{action_counter:03d}",
                action_type=RemediationActionType.NETWORK_DOMAIN_BLOCK,
                target=f"campaign_domain:{sender_domain}",
                parameters={
                    "campaign_name": correlation_report.campaign_name,
                    "related_incidents": correlation_report.correlated_incident_count,
                    "block_type": "campaign_wide_sinkhole"
                },
                priority="Immediate",
                details=f"CAMPAIGN ESCALATION: Block sender domain '@{sender_domain}' organization-wide. "
                        f"This sender is linked to '{correlation_report.campaign_name}' "
                        f"involving {correlation_report.correlated_incident_count} related incidents."
            ))

        logger.info(f"Remediation plan generated: {len(actions)} actions for analysis {analysis_id}")
        return actions

    # ─────────────────────────────────────────────
    # 2. EXECUTION LOGIC — Run the actions
    # ─────────────────────────────────────────────

    def execute_remediation(
        self,
        analysis_data: Dict[str, Any],
        actions: List[RemediationActionItem],
        dry_run: bool = False,
        correlation_report: Optional[IncidentCorrelationReport] = None
    ) -> RemediationExecutionResult:
        """
        Executes each remediation action through safe simulated handlers.
        In dry_run mode, actions are marked as 'simulated' without execution.
        """
        remediation_id = f"REM-{uuid.uuid4().hex[:8].upper()}"
        analysis_id = str(analysis_data.get("analysis_id") or analysis_data.get("_id") or "LIVE")
        risk_score = analysis_data.get("risk_score", 0)
        risk_level = analysis_data.get("risk_level", "low")

        successful = 0
        failed = 0

        for action in actions:
            try:
                if dry_run:
                    action.status = "simulated"
                    action.details = f"[DRY RUN] {action.details}"
                    successful += 1
                else:
                    # Dispatch to specific handler based on action type
                    result = self._dispatch_action(action)
                    if result:
                        action.status = "executed"
                        successful += 1
                    else:
                        action.status = "failed"
                        failed += 1
                action.timestamp = datetime.utcnow()
            except Exception as e:
                logger.error(f"Action {action.action_id} failed: {e}")
                action.status = "failed"
                action.details = f"{action.details} | ERROR: {str(e)}"
                failed += 1

        # Determine overall status
        if len(actions) == 0:
            status = "no_action_needed"
            summary = f"Risk score {risk_score}/100 is below autonomous remediation threshold. No actions required."
        elif dry_run:
            status = "simulated"
            summary = (
                f"DRY RUN completed. {len(actions)} remediation actions were simulated for "
                f"threat level {risk_level.upper()} (score: {risk_score}/100). "
                f"No changes were applied. Review actions and re-run with dry_run=false to execute."
            )
        elif failed == 0:
            status = "completed"
            summary = (
                f"Autonomous remediation COMPLETED. {successful}/{len(actions)} actions executed successfully "
                f"for {risk_level.upper()} threat (score: {risk_score}/100). "
                f"All malicious artifacts have been contained and neutralized."
            )
        else:
            status = "partial_failure"
            summary = (
                f"Remediation partially completed. {successful} succeeded, {failed} failed "
                f"out of {len(actions)} total actions. Manual review recommended for failed actions."
            )

        return RemediationExecutionResult(
            remediation_id=remediation_id,
            analysis_id=analysis_id,
            threat_level=risk_level.upper(),
            risk_score=risk_score,
            is_dry_run=dry_run,
            actions_attempted=len(actions),
            actions_successful=successful,
            actions_failed=failed,
            executed_actions=actions,
            rollback_available=not dry_run and successful > 0,
            status=status,
            summary=summary
        )

    # ─────────────────────────────────────────────
    # 3. SIMULATED ACTION HANDLERS
    # ─────────────────────────────────────────────

    def _dispatch_action(self, action: RemediationActionItem) -> bool:
        """Routes each action to its specific safe handler. Returns True on success."""
        handlers = {
            RemediationActionType.EMAIL_QUARANTINE: self._handle_email_quarantine,
            RemediationActionType.NETWORK_DOMAIN_BLOCK: self._handle_domain_block,
            RemediationActionType.NETWORK_IP_BLOCK: self._handle_ip_block,
            RemediationActionType.IAM_SESSION_REVOCATION: self._handle_iam_revocation,
            RemediationActionType.ENDPOINT_ISOLATION_FLAG: self._handle_endpoint_isolation,
            RemediationActionType.IOC_EXPORT: self._handle_ioc_export,
        }
        handler = handlers.get(action.action_type)
        if handler:
            return handler(action)
        logger.warning(f"No handler found for action type: {action.action_type}")
        return False

    def _handle_email_quarantine(self, action: RemediationActionItem) -> bool:
        """Simulates email quarantine via organization mail gateway."""
        logger.info(f"[REMEDIATION] Email quarantine executed: {action.target}")
        action.parameters["gateway_response"] = "Message quarantined successfully"
        action.parameters["quarantine_id"] = f"QRN-{uuid.uuid4().hex[:6].upper()}"
        return True

    def _handle_domain_block(self, action: RemediationActionItem) -> bool:
        """Simulates DNS sinkhole and firewall rule creation for malicious domain."""
        logger.info(f"[REMEDIATION] Domain blocked: {action.target}")
        action.parameters["firewall_rule_id"] = f"FW-{uuid.uuid4().hex[:6].upper()}"
        action.parameters["dns_sinkhole_active"] = True
        return True

    def _handle_ip_block(self, action: RemediationActionItem) -> bool:
        """Simulates IP address block on perimeter firewall."""
        logger.info(f"[REMEDIATION] IP blocked: {action.target}")
        action.parameters["firewall_rule_id"] = f"FW-IP-{uuid.uuid4().hex[:6].upper()}"
        return True

    def _handle_iam_revocation(self, action: RemediationActionItem) -> bool:
        """Simulates IAM session revocation and password reset enforcement."""
        logger.info(f"[REMEDIATION] IAM session revoked: {action.target}")
        action.parameters["sessions_terminated"] = 3
        action.parameters["password_reset_token"] = f"RST-{uuid.uuid4().hex[:8].upper()}"
        action.parameters["mfa_status"] = "re-enrollment_required"
        return True

    def _handle_endpoint_isolation(self, action: RemediationActionItem) -> bool:
        """Simulates EDR endpoint isolation flag for suspicious file."""
        logger.info(f"[REMEDIATION] Endpoint isolation flagged: {action.target}")
        action.parameters["edr_alert_id"] = f"EDR-{uuid.uuid4().hex[:6].upper()}"
        action.parameters["scan_status"] = "full_scan_initiated"
        return True

    def _handle_ioc_export(self, action: RemediationActionItem) -> bool:
        """Simulates IOC export in STIX/JSON format for SIEM integration."""
        logger.info(f"[REMEDIATION] IOC blocklist exported: {action.target}")
        indicators = action.parameters.get("indicators", [])
        action.parameters["exported_count"] = len(indicators)
        action.parameters["export_format"] = "STIX 2.1 JSON"
        action.parameters["feed_id"] = f"IOC-{uuid.uuid4().hex[:6].upper()}"
        return True

    # ─────────────────────────────────────────────
    # UTILITY
    # ─────────────────────────────────────────────

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extracts domain from a URL string."""
        if not url:
            return None
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/")[0]
            return host.split(":")[0].strip().lower() or None
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════
# Global Engine Instance
# ═══════════════════════════════════════════════════════════════════
remediation_engine = AutonomousRemediationEngine()