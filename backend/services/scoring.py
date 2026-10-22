"""
Weighted Risk Scoring Engine — Centralized Cybersecurity Scoring

Integrates Content, Sender, URL, Attachment, and Header Authentication risks.
"""

import logging
from typing import List, Dict, Any, Tuple
from models.schemas import IndicatorDetail, URLAnalysisDetail, AttachmentAnalysisDetail, HeaderAnalysisDetail, ScoreBreakdown

logger = logging.getLogger(__name__)

INDICATOR_WEIGHTS: Dict[str, int] = {
    # Content Indicators
    "credential_request":       25,
    "otp_request":              25,
    "financial_request":        20,
    "threat_language":          18,
    "social_engineering":       18,
    "urgency_language":         12,
    "suspicious_call_to_action": 10,

    # Sender Indicators
    "brand_impersonation":      22,
    "free_email_impersonation": 20,
    "suspicious_domain":        18,
}

MAX_URL_SCORE_CAP = 35
MAX_ATTACHMENT_SCORE_CAP = 40
MAX_HEADER_SCORE_CAP = 40


class RiskScorer:
    """Evaluates multi-vector threats and computes a normalized 0-100 risk score."""

    def __init__(self, weights: Dict[str, int] = None):
        self.weights = weights or INDICATOR_WEIGHTS

    def calculate_score(
        self,
        indicators: List[IndicatorDetail],
        url_details: List[URLAnalysisDetail],
        attachment_details: List[AttachmentAnalysisDetail] = None,
        header_detail: HeaderAnalysisDetail = None
    ) -> Tuple[int, str, str, ScoreBreakdown]:
        attachment_details = attachment_details or []

        # 1. Content & Sender Scores
        content_score = 0
        sender_score = 0
        sender_keys = {"brand_impersonation", "free_email_impersonation", "suspicious_domain"}
        detected_names = set()

        for ind in indicators:
            weight = self.weights.get(ind.indicator, ind.score_contribution)
            ind.score_contribution = weight
            detected_names.add(ind.indicator)

            if ind.indicator in sender_keys:
                sender_score += weight
            else:
                content_score += weight

        # 2. URL Score
        suspicious_urls = [u for u in url_details if u.is_suspicious]
        url_score = 0
        if suspicious_urls:
            highest_url = max(u.score_contribution for u in suspicious_urls)
            bonus = (len(suspicious_urls) - 1) * 5
            url_score = min(highest_url + bonus, MAX_URL_SCORE_CAP)

        # 3. Attachment Score
        suspicious_attachments = [a for a in attachment_details if a.is_suspicious]
        attachment_score = 0
        if suspicious_attachments:
            highest_att = max(a.score_contribution for a in suspicious_attachments)
            att_bonus = (len(suspicious_attachments) - 1) * 8
            attachment_score = min(highest_att + att_bonus, MAX_ATTACHMENT_SCORE_CAP)

        # 4. Header Score (Milestone 9)
        header_score = header_detail.score_contribution if header_detail else 0
        header_score = min(header_score, MAX_HEADER_SCORE_CAP)

        base_score = content_score + sender_score + url_score + attachment_score + header_score

        # 5. Compound Risk Multipliers
        compound_multiplier = 1.0
        applied_rules = []

        has_auth_theft = ("credential_request" in detected_names) or ("otp_request" in detected_names)
        has_bad_link = url_score > 0
        has_bad_sender = sender_score > 0
        has_bad_attachment = attachment_score > 0
        has_bad_header = header_score > 0
        has_urgency_threat = ("urgency_language" in detected_names) or ("threat_language" in detected_names)

        # Compound Rule A: Credential theft + fraudulent origin (Link, Sender, or Header Spoof)
        if has_auth_theft and (has_bad_link or has_bad_sender or has_bad_header):
            compound_multiplier += 0.15
            applied_rules.append("Credential/OTP request combined with untrusted sender identity or failed header authentication")

        # Compound Rule B: Weaponized attachment + urgency or spoofed header
        if has_bad_attachment and (has_urgency_threat or has_bad_sender or has_bad_header):
            compound_multiplier += 0.15
            applied_rules.append("Suspicious attachment combined with urgency or spoofed sender authentication")

        # Compound Rule C: Authentication failure + Impersonation
        if has_bad_header and has_bad_sender:
            compound_multiplier += 0.10
            applied_rules.append("Technical authentication failure (SPF/DKIM/DMARC) aligns with brand impersonation")

        # Compound Rule D: Credential request + Coercive pressure
        if has_auth_theft and has_urgency_threat:
            compound_multiplier += 0.10
            applied_rules.append("Credential/OTP request combined with coercive urgency")

        calculated_score = int(round(base_score * compound_multiplier))
        final_score = max(0, min(calculated_score, 100))

        risk_level = self._score_to_level(final_score)
        verdict = self._generate_verdict(final_score, risk_level, detected_names, suspicious_urls, suspicious_attachments, header_detail)

        breakdown = ScoreBreakdown(
            content_score=content_score,
            sender_score=sender_score,
            url_score=url_score,
            attachment_score=attachment_score,
            header_score=header_score,
            base_score=base_score,
            compound_multiplier=round(compound_multiplier, 2),
            final_score=final_score,
            applied_compound_rules=applied_rules
        )

        return final_score, risk_level, verdict, breakdown

    def _score_to_level(self, score: int) -> str:
        if score <= 30:
            return "low"
        elif score <= 60:
            return "medium"
        elif score <= 80:
            return "high"
        else:
            return "critical"

    def _generate_verdict(self, score: int, risk_level: str, detected_names: set, urls: list, attachments: list, header: HeaderAnalysisDetail) -> str:
        if risk_level == "low":
            return "Likely Legitimate — Minimal or no suspicious indicators detected."
        if risk_level == "medium":
            if header and header.is_suspicious:
                return "Suspicious — Email failed technical authentication or contains header sender mismatches."
            if attachments:
                return "Suspicious — Email contains potentially high-risk or macro-enabled attachments."
            if urls:
                return "Suspicious — Email contains unverified or masked links."
            return "Suspicious — Behavioral indicators detected. Verify sender before proceeding."
        if risk_level == "high":
            if header and header.is_suspicious and ("credential_request" in detected_names or urls):
                return "High Probability of Phishing — Spoofed email headers detected alongside credential harvesting vectors."
            if attachments:
                return "High Probability of Phishing — Detected dangerous file payloads or double extensions."
            return "High Probability of Phishing — Multiple deceptive threat patterns detected."
        return "Critical Risk — Multi-vector attack detected (coercive tactics, header forgery, disguised links, or malicious payloads)."


risk_scorer = RiskScorer()