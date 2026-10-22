"""
Email Header Analysis Service — RFC 822 & Authentication Protocols

Parses and inspects email headers for:
1. SPF (Sender Policy Framework) authentication status
2. DKIM (DomainKeys Identified Mail) cryptographic signature status
3. DMARC (Domain-based Message Authentication) policy alignment
4. Sender Alignment & Mismatches (From vs Return-Path vs Reply-To)
5. Mail Transfer Agent (MTA) Received hops and origin IP tracking
"""

import re
import email
from email import policy
from email.parser import Parser
import logging
from typing import List, Dict, Any, Optional
from models.schemas import HeaderAnalysisDetail, HopDetail

logger = logging.getLogger(__name__)

# Scoring weights for header failures
HEADER_CHECK_SCORES = {
    "dmarc_fail":              25,  # DMARC policy violation (strong spoofing indicator)
    "spf_fail":                20,  # Unauthorized sending IP
    "dkim_fail":               20,  # Forged or altered cryptographic signature
    "return_path_mismatch":    18,  # Return-Path domain differs from From domain
    "reply_to_mismatch":       18,  # Reply-To domain redirects to third-party mailbox
    "spf_softfail":            10,  # SPF softfail (~all)
    "excessive_hops":           8,  # Unusually long relay chain (> 8 hops)
}


class HeaderAnalyzer:
    """
    Analyzes raw RFC 822 email headers or structured header dictionaries.
    """

    def analyze_headers(self, raw_headers: str) -> HeaderAnalysisDetail:
        """
        Parses a raw email header string and returns structured security findings.
        """
        if not raw_headers or not raw_headers.strip():
            return HeaderAnalysisDetail(is_suspicious=False, risk_level="low", reasons=[], score_contribution=0)

        reasons: List[str] = []
        score: int = 0

        # Parse headers using Python standard email parser
        try:
            msg = Parser(policy=policy.default).parsestr(raw_headers)
        except Exception as e:
            logger.warning(f"Failed to parse email header with default policy: {e}")
            msg = Parser().parsestr(raw_headers)

        # ── 1. Extract Key Origin Fields ──
        from_header = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        received_spf = msg.get("Received-SPF", "")
        auth_results = msg.get("Authentication-Results", "")
        dkim_signature = msg.get("DKIM-Signature", "")

        from_domain = self._extract_domain(from_header)
        reply_to_domain = self._extract_domain(reply_to)
        return_path_domain = self._extract_domain(return_path)

        # ── 2. Check Sender Alignment (Mismatches) ──
        has_sender_mismatch = False
        if from_domain and return_path_domain and from_domain != return_path_domain:
            has_sender_mismatch = True
            score += HEADER_CHECK_SCORES["return_path_mismatch"]
            reasons.append(
                f"Domain Mismatch: Displayed From domain is '@{from_domain}', but true Return-Path is '@{return_path_domain}'. "
                f"Attackers spoof From headers while bounce messages route to an attacker domain."
            )

        has_reply_to_mismatch = False
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            has_reply_to_mismatch = True
            score += HEADER_CHECK_SCORES["reply_to_mismatch"]
            reasons.append(
                f"Reply-To Redirection: Displayed From is '@{from_domain}', but Reply-To points to '@{reply_to_domain}'. "
                f"Replies will be secretly redirected to a different mailbox."
            )

        # ── 3. Parse SPF Authentication Status ──
        spf_status = self._parse_spf(received_spf, auth_results)
        if spf_status == "fail":
            score += HEADER_CHECK_SCORES["spf_fail"]
            reasons.append(
                "SPF (Sender Policy Framework) Check: FAIL. "
                "The sending mail server's IP address is NOT authorized in the sender domain's DNS SPF record."
            )
        elif spf_status == "softfail":
            score += HEADER_CHECK_SCORES["spf_softfail"]
            reasons.append(
                "SPF Check: SOFTFAIL. The sending server is likely unauthorized by the sender domain."
            )

        # ── 4. Parse DKIM Authentication Status ──
        dkim_status = self._parse_dkim(auth_results, dkim_signature)
        if dkim_status == "fail":
            score += HEADER_CHECK_SCORES["dkim_fail"]
            reasons.append(
                "DKIM (DomainKeys Identified Mail) Check: FAIL. "
                "The cryptographic digital signature is invalid or forged — email content may have been tampered with."
            )

        # ── 5. Parse DMARC Authentication Status ──
        dmarc_status = self._parse_dmarc(auth_results)
        if dmarc_status == "fail":
            score += HEADER_CHECK_SCORES["dmarc_fail"]
            reasons.append(
                "DMARC Policy Check: FAIL. "
                "The message failed sender domain alignment and validation policies."
            )

        # ── 6. Parse Received Hops ──
        received_headers = msg.get_all("Received") or []
        hops: List[HopDetail] = []
        hop_num = 1

        for r_header in reversed(received_headers):  # Chronological order
            hop_info = self._parse_received_hop(r_header, hop_num)
            hops.append(hop_info)
            hop_num += 1

        if len(hops) > 8:
            score += HEADER_CHECK_SCORES["excessive_hops"]
            reasons.append(f"Unusually high number of mail relay hops ({len(hops)} hops), indicating potential relay obfuscation.")

        # ── Final Risk Score & Normalization ──
        final_score = min(score, 40)  # Max 40 points contribution to overall email score
        is_suspicious = final_score > 0
        risk_level = self._score_to_risk(final_score)

        return HeaderAnalysisDetail(
            from_header=from_header or None,
            reply_to=reply_to or None,
            return_path=return_path or None,
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            has_sender_mismatch=has_sender_mismatch,
            has_reply_to_mismatch=has_reply_to_mismatch,
            hops_count=len(hops),
            hops=hops,
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            reasons=reasons,
            score_contribution=final_score
        )

    def _extract_domain(self, email_str: str) -> Optional[str]:
        if not email_str:
            return None
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_str)
        return match.group(1).lower() if match else None

    def _parse_spf(self, received_spf: str, auth_results: str) -> str:
        combined = f"{received_spf} {auth_results}".lower()
        if re.search(r'spf=(?:fail|hardfail)|received-spf:\s*fail', combined):
            return "fail"
        if re.search(r'spf=softfail|received-spf:\s*softfail', combined):
            return "softfail"
        if re.search(r'spf=pass|received-spf:\s*pass', combined):
            return "pass"
        return "neutral"

    def _parse_dkim(self, auth_results: str, dkim_signature: str) -> str:
        combined = auth_results.lower()
        if re.search(r'dkim=(?:fail|bad|temperror|permerror)', combined):
            return "fail"
        if re.search(r'dkim=pass', combined):
            return "pass"
        if not dkim_signature and not auth_results:
            return "none"
        return "neutral"

    def _parse_dmarc(self, auth_results: str) -> str:
        combined = auth_results.lower()
        if re.search(r'dmarc=(?:fail|reject|quarantine)', combined):
            return "fail"
        if re.search(r'dmarc=pass', combined):
            return "pass"
        return "neutral"

    def _parse_received_hop(self, header_val: str, hop_num: int) -> HopDetail:
        # Extract "from <server>", "by <server>", IP address
        from_match = re.search(r'from\s+([a-zA-Z0-9.-]+)', header_val, re.IGNORECASE)
        by_match = re.search(r'by\s+([a-zA-Z0-9.-]+)', header_val, re.IGNORECASE)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header_val)

        return HopDetail(
            hop_number=hop_num,
            from_server=from_match.group(1) if from_match else None,
            by_server=by_match.group(1) if by_match else None,
            ip_address=ip_match.group(1) if ip_match else None,
            timestamp=None
        )

    def _score_to_risk(self, score: int) -> str:
        if score == 0:
            return "low"
        elif score <= 15:
            return "medium"
        elif score <= 25:
            return "high"
        else:
            return "critical"


header_analyzer = HeaderAnalyzer()