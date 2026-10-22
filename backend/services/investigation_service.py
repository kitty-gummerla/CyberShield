"""
Threat Investigation Service

Transforms raw detection findings into an enterprise-grade
SOC Forensic Investigation Dossier and automated Incident Remediation Playbook.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from models.schemas import (
    ThreatInvestigationDossier,
    RemediationStep,
    ForensicArtifactSummary,
    IncidentCorrelationReport
)

logger = logging.getLogger(__name__)


class ThreatInvestigationService:
    """
    Synthesizes multi-vector analysis records into deep forensic investigation dossiers.
    """

    def generate_dossier(
        self,
        analysis_data: Dict[str, Any],
        correlated_threats: Optional[IncidentCorrelationReport] = None
    ) -> ThreatInvestigationDossier:
        """
        Builds a comprehensive SOC investigation dossier from an analysis record.
        """
        analysis_id = str(analysis_data.get("analysis_id") or analysis_data.get("_id") or "LIVE_INVESTIGATION")
        analyzed_at = analysis_data.get("analyzed_at") or datetime.utcnow()
        if isinstance(analyzed_at, str):
            try:
                analyzed_at = datetime.fromisoformat(analyzed_at.replace("Z", "+00:00"))
            except Exception:
                analyzed_at = datetime.utcnow()

        sender = analysis_data.get("sender", "Unknown")
        subject = analysis_data.get("subject", "No Subject")
        risk_score = analysis_data.get("risk_score", 0)
        risk_level = analysis_data.get("risk_level", "low")
        indicators = analysis_data.get("indicators", [])
        urls = analysis_data.get("url_analysis", [])
        attachments = analysis_data.get("attachment_analysis", [])
        header_analysis = analysis_data.get("header_analysis") or {}
        breakdown = analysis_data.get("score_breakdown") or {}

        # ── 1. Attack Chain Breakdown ──
        attack_chain = {
            "Content & Social Engineering": breakdown.get("content_score", 0),
            "Sender & Domain Impersonation": breakdown.get("sender_score", 0),
            "Disguised & High-Risk URLs": breakdown.get("url_score", 0),
            "Malicious File Attachments": breakdown.get("attachment_score", 0),
            "Technical Header Forgery": breakdown.get("header_score", 0),
        }

        # ── 2. Evidence Matrix ──
        evidence_matrix = []
        for ind in indicators:
            evidence_matrix.append({
                "threat_name": ind.get("indicator", "Unknown"),
                "severity": ind.get("severity", "medium").upper(),
                "description": ind.get("description", ""),
                "captured_evidence": ind.get("evidence", []),
                "points_attributed": ind.get("score_contribution", 0)
            })

        # ── 3. Forensic Artifacts Mapping ──
        sender_identity = {
            "declared_sender": sender,
            "is_free_provider": any(ind.get("indicator") == "free_email_impersonation" for ind in indicators),
            "is_brand_impersonation": any(ind.get("indicator") == "brand_impersonation" for ind in indicators)
        }

        extracted_urls = []
        for u in urls:
            extracted_urls.append({
                "url": u.get("url"),
                "is_suspicious": u.get("is_suspicious"),
                "threat_reasons": u.get("reasons", []),
                "risk_tier": u.get("risk_level", "low")
            })

        attached_files = []
        for a in attachments:
            attached_files.append({
                "filename": a.get("filename"),
                "detected_extension": a.get("detected_extension"),
                "category": a.get("threat_category", "Standard"),
                "risk_tier": a.get("risk_level", "low"),
                "threat_reasons": a.get("reasons", [])
            })

        auth_status = {
            "spf": header_analysis.get("spf_status", "not_evaluated"),
            "dkim": header_analysis.get("dkim_status", "not_evaluated"),
            "dmarc": header_analysis.get("dmarc_status", "not_evaluated"),
            "sender_mismatch": header_analysis.get("has_sender_mismatch", False),
            "reply_to_mismatch": header_analysis.get("has_reply_to_mismatch", False)
        }

        forensic_artifacts = ForensicArtifactSummary(
            sender_identity=sender_identity,
            extracted_urls=extracted_urls,
            attached_files=attached_files,
            authentication_status=auth_status
        )

        # ── 4. Executive Technical Summary ──
        exec_summary = self._synthesize_executive_summary(
            sender, subject, risk_score, risk_level, indicators, urls, attachments, header_analysis
        )

        # ── 5. Incident Remediation Playbook ──
        remediation_playbook = self._generate_remediation_playbook(
            risk_level, indicators, urls, attachments, header_analysis
        )

        return ThreatInvestigationDossier(
            investigation_id=f"INV-{analysis_id[:8].upper()}",
            incident_timestamp=analyzed_at,
            subject=subject,
            sender=sender,
            overall_threat_level=risk_level.upper(),
            risk_score=risk_score,
            executive_summary=exec_summary,
            attack_chain_breakdown=attack_chain,
            evidence_matrix=evidence_matrix,
            forensic_artifacts=forensic_artifacts,
            compound_risk_amplifiers=breakdown.get("applied_compound_rules", []),
            remediation_playbook=remediation_playbook,
            correlated_threats=correlated_threats
        )

    def _synthesize_executive_summary(
        self, sender: str, subject: str, score: int, level: str,
        indicators: list, urls: list, attachments: list, headers: dict
    ) -> str:
        if level == "low":
            return (
                f"Incident Investigation for email '{subject}' from '{sender}' revealed no anomalous threat vectors. "
                f"Content analysis, link inspection, and technical header checks verify normal communication patterns. "
                f"Threat Level: LOW (Risk Score: {score}/100)."
            )

        threat_vectors = []
        if any(ind.get("indicator") in ["credential_request", "otp_request"] for ind in indicators):
            threat_vectors.append("active credential and 2FA authentication harvesting")
        if any(u.get("is_suspicious") for u in urls):
            threat_vectors.append("deceptive external links pointing to unverified infrastructure")
        if any(a.get("is_suspicious") for a in attachments):
            threat_vectors.append("suspicious attachment payloads (macro-enabled documents or double extensions)")
        if headers.get("is_suspicious"):
            threat_vectors.append("technical header spoofing with SPF/DKIM/DMARC verification failures")

        vector_str = "; ".join(threat_vectors) if threat_vectors else "social engineering urgency patterns"

        return (
            f"CRITICAL THREAT INCIDENT: The analyzed message from '{sender}' (Subject: '{subject}') "
            f"demonstrates a coordinated attack campaign evaluated at Risk Score {score}/100 ({level.upper()}). "
            f"Primary Threat Vectors: {vector_str}. "
            f"Multiple indicators co-occurred, activating compound risk multipliers and confirming malicious intent."
        )

    def _generate_remediation_playbook(
        self, level: str, indicators: list, urls: list, attachments: list, headers: dict
    ) -> List[RemediationStep]:
        playbook = []
        step = 1

        if level in ["high", "critical"]:
            playbook.append(RemediationStep(
                step_number=step,
                category="Email Gateway",
                action="Purge and quarantine this message across all organization mailboxes via Message-ID.",
                priority="Immediate"
            ))
            step += 1

            if any(u.get("is_suspicious") for u in urls):
                for u in urls:
                    if u.get("is_suspicious"):
                        playbook.append(RemediationStep(
                            step_number=step,
                            category="Network & Firewall",
                            action=f"Block destination URL/Domain ({u.get('url')[:50]}) on perimeter firewall and DNS sinkhole.",
                            priority="Immediate"
                        ))
                        step += 1

            if any(a.get("is_suspicious") for a in attachments):
                playbook.append(RemediationStep(
                    step_number=step,
                    category="Endpoint Security (EDR)",
                    action="Isolate any endpoint where attached files were opened. Run full Antivirus/EDR scan for persistence artifacts.",
                    priority="Immediate"
                ))
                step += 1

            if any(ind.get("indicator") in ["credential_request", "otp_request"] for ind in indicators):
                playbook.append(RemediationStep(
                    step_number=step,
                    category="Identity & Access (IAM)",
                    action="Revoke active sessions and force immediate password and MFA reset for recipient account.",
                    priority="High"
                ))
                step += 1

        else:
            playbook.append(RemediationStep(
                step_number=step,
                category="General Awareness",
                action="Standard message hygiene. Verify unexpected requests out-of-band.",
                priority="Recommended"
            ))

        return playbook


# ═══════════════════════════════════════════════════════════════════
# Global Instance
# ═══════════════════════════════════════════════════════════════════
investigation_service = ThreatInvestigationService()