"""
Phishing Detection Engine — Core Cybersecurity Component

This module is the brain of the detection system.
It analyzes email content and sender information to identify phishing indicators.

Key Design Principles:
  - Multi-signal detection: No single word alone triggers a phishing verdict
  - Evidence-based: Every indicator includes the exact text that triggered it
  - Transparent: Each indicator explains what was found and why it's suspicious
  - Scored: Each indicator carries a base score (formalized in Milestone 5)

Detection Categories:
  A. Content Indicators — What the email says
     (urgency, threats, credential requests, OTP, financial, social engineering)
  B. Sender Indicators — Who sent it
     (free email impersonation, suspicious domain, brand impersonation)

URL Analysis → Milestone 4 (services/url_analyzer.py)
Risk Scoring  → Milestone 5 (services/scoring.py)
"""

import re
import logging
from typing import List
from models.schemas import IndicatorDetail

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# CONTENT INDICATOR PATTERNS
# ═══════════════════════════════════════════════════════════════════
# Each entry defines:
#   patterns     → list of regex patterns to search for
#   description  → plain-English explanation (shown to user)
#   severity     → low / medium / high / critical
#   base_score   → preliminary score contribution (refined in M5)
#
# WHY REGEX PATTERNS?
# Instead of checking if "urgent" appears in the text, we use regex
# to match entire phrase structures. This reduces false positives significantly.
# Example: r"\bwithin \d+\s*hours?\b" matches "within 24 hours", "within 2 hours"
#          but NOT just the word "hours" appearing somewhere unrelated.
# ═══════════════════════════════════════════════════════════════════

CONTENT_INDICATORS: dict = {

    "urgency_language": {
        "patterns": [
            r"\burgent(ly)?\b",
            r"\bimmediately\b",
            r"\bact\s+now\b",
            r"\bright\s+now\b",
            r"\blast\s+chance\b",
            r"\bfinal\s+(notice|warning|alert|reminder)\b",
            r"\bdeadline\b",
            r"\bwithin\s+\d+\s*(hours?|minutes?|days?)\b",
            r"\btime[\s\-]?sensitive\b",
            r"\bexpire[sd]?\s+(today|soon|immediately|now)\b",
            r"\bdo\s+not\s+(ignore|delay|wait)\b",
            r"\baction\s+required\b",
            r"\bresponse\s+required\b",
        ],
        "description": (
            "Uses urgent or time-pressuring language to make the recipient act "
            "quickly without thinking carefully — a classic phishing tactic."
        ),
        "severity": "medium",
        "base_score": 12,
    },

    "threat_language": {
        "patterns": [
            r"\b(your\s+)?(account|access|service|card)\s+.{0,30}?"
            r"(suspend\w*|terminat\w*|block\w*|clos\w*|disabl\w*|restrict\w*)\b",
            r"\b(suspend\w*|terminat\w*|block\w*|clos\w*|disabl\w*)\s+.{0,30}?"
            r"(account|access|service|card)\b",
            r"\blegal\s+action\b",
            r"\bcriminal\s+(charge|prosecution|complaint|case)\b",
            r"\bpenalt(y|ies|ized)\b",
            r"\breport\w*\s+to\s+(authorities|police|law\s+enforcement)\b",
            r"\bwarrant\b",
            r"\bcourtorder\b",
        ],
        "description": (
            "Uses threats or fear-based language (account suspension, legal action) "
            "to intimidate the recipient into complying without questioning."
        ),
        "severity": "high",
        "base_score": 18,
    },

    "credential_request": {
        "patterns": [
            r"\b(enter|provide|confirm|verify|submit|update|re-?enter)\s+.{0,40}?"
            r"(password|passcode|pin|credentials?|login|username|user\s*id)\b",
            r"\b(password|credentials?|login\s+details?)\s+.{0,40}?"
            r"(enter|provide|confirm|verify|submit|update)\b",
            r"\b(sign[\s\-]?in|log[\s\-]?in)\s+.{0,30}?(to\s+verify|to\s+confirm|below|here|link)\b",
            r"\benter\s+your\s+(account|banking|email|portal|login)\s+"
            r"(details?|information|credentials?|info)\b",
            r"\bverify\s+(your\s+)?(account|identity|email|information|details?)\b",
            r"\b(update|confirm)\s+(your\s+)?(account|login|security)\s+(info|information|details?)\b",
        ],
        "description": (
            "Requests login credentials, passwords, or account verification. "
            "Legitimate organizations NEVER ask for passwords via email — this is a critical red flag."
        ),
        "severity": "critical",
        "base_score": 25,
    },

    "otp_request": {
        "patterns": [
            r"\b(enter|provide|share|send|give|submit)\s+.{0,40}?"
            r"(otp|one[\s\-]?time[\s\-]?(pass\w*|code)|verification\s+code|"
            r"auth\w*\s+code|2fa\s+code|security\s+code|sms\s+code)\b",
            r"\b(otp|one[\s\-]?time[\s\-]?pass\w*|2fa)\s+.{0,40}?"
            r"(enter|provide|share|send|give|submit)\b",
            r"\bdo\s+not\s+share\s+(your\s+)?(otp|code|pin|password)\b",
            r"\b\d{4,8}[\s\-]?digit\s+(otp|code|pin|pass)\b",
            r"\btemporary\s+(code|password|pin|passcode)\b",
            r"\bone[\s\-]?time\s+(code|pin|password|passcode)\b",
        ],
        "description": (
            "Requests OTP or 2FA authentication codes. "
            "No legitimate service will ever ask for OTP codes through email — this is a severe red flag."
        ),
        "severity": "critical",
        "base_score": 25,
    },

    "financial_request": {
        "patterns": [
            r"\bwire\s+transfer\b",
            r"\bgift\s+cards?\b",
            r"\b(send|transfer|pay)\s+.{0,30}?(money|funds?|payment|amount|cash)\b",
            r"\bpayment\s+(required|needed|pending|due|overdue|failed)\b",
            r"\binvoice\s+.{0,30}?(attached|enclosed|due|overdue)\b",
            r"\b(outstanding|unpaid|overdue)\s+.{0,30}?(balance|amount|payment|invoice)\b",
            r"\bpay\s+(now|immediately|today|within)\b",
            r"\bcredit\s+card\s+.{0,30}?(number|details?|information)\b",
            r"\bbank\s+(account|details?|information)\s+.{0,30}?"
            r"(provide|send|share|confirm)\b",
            r"\brefund\s+.{0,30}?(claim|process|issue)\b",
            r"\btransaction\s+(failed|declined|blocked)\b",
        ],
        "description": (
            "Requests financial transactions, payment details, or banking information — "
            "commonly used in financial fraud and phishing attacks."
        ),
        "severity": "high",
        "base_score": 20,
    },

    "social_engineering": {
        "patterns": [
            r"\b(congratulations?|congrats?)\s+.{0,50}?"
            r"(won|selected|chosen|winner|prize|award|reward)\b",
            r"\byou\s+(have\s+)?(won|been\s+selected|been\s+chosen)\b",
            r"\b(lottery|sweepstakes?|lucky\s+winner|jackpot)\b",
            r"\b(ceo|director|manager|president|chairman)\s+.{0,40}?"
            r"(request\w*|asking|needs?|wants?|requires?)\b",
            r"\bkeep\s+(this\s+)?(confidential|secret|private|between\s+us)\b",
            r"\bdo\s+not\s+(tell|inform|mention|share)\s+.{0,20}?"
            r"(anyone|colleagues?|others?|anyone\s+else)\b",
            r"\bthis\s+is\s+not\s+(a\s+)?(scam|spam|fraud|phishing)\b",
            r"\b(inheritance|beneficiary|next\s+of\s+kin|unclaimed\s+funds?)\b",
            r"\b(million|billion)\s+.{0,15}?(dollar|usd|gbp|eur|pound)\b",
        ],
        "description": (
            "Uses social engineering tactics — fake authority figures, false lottery wins, "
            "or secrecy requests to psychologically manipulate the recipient."
        ),
        "severity": "high",
        "base_score": 18,
    },

    "suspicious_call_to_action": {
        "patterns": [
            r"\bclick\s+(here|the\s+link|below|this\s+link)\b",
            r"\bclick\s+.{0,20}?\s+to\s+(verify|confirm|update|restore|unlock|activate|claim)\b",
            r"\b(download|open)\s+(the\s+)?(attachment|file|document)\b",
            r"\bfill\s+(out|in)\s+(the\s+)?(form|details?|information|fields?)\b",
            r"\bvisit\s+(this\s+)?(link|page|website|url|portal)\b",
            r"\bcall\s+(this|the|our)\s+(number|helpline|hotline|support\s+line)\b",
        ],
        "description": (
            "Contains suspicious calls to action that may direct the user "
            "to a phishing page, malicious download, or fraudulent contact."
        ),
        "severity": "medium",
        "base_score": 10,
    },
}


# ═══════════════════════════════════════════════════════════════════
# SENDER INDICATOR CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

SENDER_INDICATORS: dict = {

    "free_email_impersonation": {
        # Domains that are free public email providers
        "free_domains": [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "icloud.com", "mail.com", "protonmail.com",
            "ymail.com", "live.com", "msn.com", "rediffmail.com",
            "zoho.com", "inbox.com", "yandex.com",
        ],
        # Keywords in the username that suggest the sender is pretending to be an org
        "org_keywords": [
            "bank", "finance", "secure", "security", "alert", "support",
            "service", "official", "team", "noreply", "no-reply", "admin",
            "account", "paypal", "amazon", "microsoft", "apple", "google",
            "netflix", "irs", "gov", "tax", "helpdesk", "billing",
        ],
        "description": (
            "Sender is using a free public email provider (e.g., Gmail, Yahoo) "
            "while claiming to represent a company or institution — "
            "a major red flag since organizations use their own domain."
        ),
        "severity": "high",
        "base_score": 20,
    },

    "suspicious_domain": {
        # Patterns that appear in phishing sender domains
        "patterns": [
            # Suspicious keywords at start of domain (before @)
            r"(secure|security|alert|verify|account|update|login|bank|support|service)[\-\.]",
            # Suspicious keywords at end before TLD
            r"[\-\.](secure|security|alert|verify|account|update|login|bank|support)",
            # Many consecutive numbers (e.g., bank123456.com)
            r"\d{4,}",
            # High-risk / commonly abused TLDs
            r"\.(tk|ml|ga|cf|gq|xyz|top|click|link|online|site|web|info|biz|pw|cc)$",
            # Hyphenated brands (paypal-secure.com, amazon-update.net)
            r"[a-z]+-[a-z]+-[a-z]+\.",
        ],
        "description": (
            "Sender domain contains patterns commonly associated with phishing "
            "(suspicious keywords, excessive numbers, or high-risk top-level domains)."
        ),
        "severity": "high",
        "base_score": 18,
    },

    "brand_impersonation": {
        # Known brands that phishers commonly impersonate
        "brands": [
            "paypal", "amazon", "google", "microsoft", "apple", "netflix",
            "facebook", "instagram", "twitter", "linkedin", "whatsapp", "telegram",
            "dropbox", "adobe", "zoom", "slack", "spotify",
            "chase", "citibank", "wellsfargo", "barclays", "hsbc",
            "sbi", "hdfc", "icici", "axisbank", "kotak",
            "fedex", "ups", "dhl", "usps", "indiapost",
            "irs", "fbi", "interpol", "incometax",
            "ebay", "walmart", "flipkart",
        ],
        # Official domains for these brands (simplified check)
        "official_tlds": [".com", ".org", ".net", ".gov", ".edu"],
        "description": (
            "Sender domain appears to impersonate a well-known brand or organization "
            "by including the brand name in a modified or extended domain."
        ),
        "severity": "high",
        "base_score": 20,
    },
}


# ═══════════════════════════════════════════════════════════════════
# PHISHING DETECTOR CLASS
# ═══════════════════════════════════════════════════════════════════

class PhishingDetector:
    """
    Core phishing detection engine.

    Analyzes email sender, subject, and body for phishing indicators.
    Returns a list of IndicatorDetail objects — one per detected indicator.

    Usage:
        detector = PhishingDetector()
        indicators = detector.analyze(sender, subject, body)
    """

    def analyze(
        self,
        sender: str,
        subject: str,
        body: str
    ) -> List[IndicatorDetail]:
        """
        Main entry point. Runs all detection checks.

        Args:
            sender:  The sender email address
            subject: The email subject line
            body:    The full email body text

        Returns:
            List of IndicatorDetail objects (one per detected indicator)
        """
        logger.info(f"Starting phishing analysis for sender: {sender}")

        # Combine subject + body into a single text block for content analysis.
        # We analyze both together because phishers often split indicators
        # across subject and body (e.g., urgency in subject, credential request in body).
        full_content = f"{subject}\n{body}"

        indicators: List[IndicatorDetail] = []

        # ── Step 1: Content Analysis ──
        content_indicators = self._analyze_content(full_content)
        indicators.extend(content_indicators)
        logger.info(f"Content analysis found {len(content_indicators)} indicators")

        # ── Step 2: Sender Analysis ──
        sender_indicators = self._analyze_sender(sender, full_content)
        indicators.extend(sender_indicators)
        logger.info(f"Sender analysis found {len(sender_indicators)} indicators")

        logger.info(f"Total indicators detected: {len(indicators)}")
        return indicators

    # ───────────────────────────────────────
    # CONTENT ANALYSIS
    # ───────────────────────────────────────

    def _analyze_content(self, text: str) -> List[IndicatorDetail]:
        """
        Scans email content (subject + body) for phishing language patterns.
        Uses regex patterns from CONTENT_INDICATORS registry.
        """
        indicators = []
        text_lower = text.lower()

        for indicator_name, config in CONTENT_INDICATORS.items():
            evidence = self._extract_evidence(text_lower, config["patterns"])

            # Only create an indicator if we actually found evidence
            if evidence:
                indicators.append(IndicatorDetail(
                    indicator=indicator_name,
                    description=config["description"],
                    severity=config["severity"],
                    evidence=evidence[:5],  # Cap at 5 evidence items for readability
                    score_contribution=config["base_score"],
                ))

        return indicators

    # ───────────────────────────────────────
    # SENDER ANALYSIS
    # ───────────────────────────────────────

    def _analyze_sender(
        self,
        sender: str,
        content: str
    ) -> List[IndicatorDetail]:
        """
        Analyzes the sender's email address for phishing indicators.
        Checks for free email impersonation, suspicious domains, and brand impersonation.
        """
        indicators = []
        sender_lower = sender.lower().strip()

        domain = self._extract_domain(sender_lower)
        username = self._extract_username(sender_lower)

        if not domain:
            logger.warning(f"Could not extract domain from sender: {sender}")
            return indicators

        logger.info(f"Analyzing sender — username: {username}, domain: {domain}")

        # ── Check 1: Free Email Impersonation ──
        # A phisher may use security-alert@gmail.com to impersonate a bank.
        # We detect this by checking: is the domain a free provider AND
        # does the username or email content contain organizational keywords?
        fei_config = SENDER_INDICATORS["free_email_impersonation"]
        if domain in fei_config["free_domains"]:
            org_keywords_found = [
                kw for kw in fei_config["org_keywords"]
                if kw in username
            ]
            if org_keywords_found:
                indicators.append(IndicatorDetail(
                    indicator="free_email_impersonation",
                    description=fei_config["description"],
                    severity=fei_config["severity"],
                    evidence=[
                        f"Free email provider used: {domain}",
                        f"Username suggests organization: '{username}'",
                        f"Suspicious keywords in username: {', '.join(org_keywords_found[:3])}",
                    ],
                    score_contribution=fei_config["base_score"],
                ))

        # ── Check 2: Suspicious Domain Patterns ──
        # Phishing domains often contain security keywords, numbers, or
        # suspicious TLDs (e.g., fakebank-secure.xyz, amazon-update123.tk)
        sd_config = SENDER_INDICATORS["suspicious_domain"]
        suspicious_patterns_found = []
        for pattern in sd_config["patterns"]:
            if re.search(pattern, domain, re.IGNORECASE):
                suspicious_patterns_found.append(pattern)

        if suspicious_patterns_found:
            indicators.append(IndicatorDetail(
                indicator="suspicious_domain",
                description=sd_config["description"],
                severity=sd_config["severity"],
                evidence=[
                    f"Suspicious sender domain: {domain}",
                    f"Matched {len(suspicious_patterns_found)} suspicious domain pattern(s)",
                ],
                score_contribution=sd_config["base_score"],
            ))

        # ── Check 3: Brand Impersonation ──
        # Phishers register domains like paypal-secure.com or amazon.support-login.net
        # We check if a known brand name appears in the domain, but it's NOT the
        # official domain of that brand.
        bi_config = SENDER_INDICATORS["brand_impersonation"]
        impersonated_brands = []
        for brand in bi_config["brands"]:
            if brand in domain and not self._is_official_brand_domain(brand, domain):
                impersonated_brands.append(brand)

        if impersonated_brands:
            indicators.append(IndicatorDetail(
                indicator="brand_impersonation",
                description=bi_config["description"],
                severity=bi_config["severity"],
                evidence=[
                    f"Sender domain '{domain}' appears to impersonate: "
                    f"{', '.join(impersonated_brands)}",
                    "Official brand emails come from their own verified domain, "
                    "not modified versions like 'brand-secure.com' or 'brand.support-login.com'",
                ],
                score_contribution=bi_config["base_score"],
            ))

        return indicators

    # ───────────────────────────────────────
    # HELPER METHODS
    # ───────────────────────────────────────

    def _extract_evidence(
        self,
        text: str,
        patterns: List[str]
    ) -> List[str]:
        """
        Runs all regex patterns on the text.
        Returns a deduplicated list of matched strings as evidence.
        """
        evidence = []
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # re.findall returns tuples when pattern has groups
                    if isinstance(match, tuple):
                        match_text = " ".join(part for part in match if part).strip()
                    else:
                        match_text = match.strip()

                    # Only add non-empty, non-duplicate evidence
                    if match_text and match_text not in evidence:
                        evidence.append(match_text)
            except re.error as e:
                logger.error(f"Regex error in pattern '{pattern}': {e}")
                continue

        return evidence

    def _extract_domain(self, sender: str) -> str:
        """Extract the domain part from an email address."""
        try:
            if "@" in sender:
                # Handle formats like: user@domain.com or <user@domain.com>
                domain = sender.split("@")[-1]
                # Remove any trailing angle bracket
                domain = domain.replace(">", "").strip()
                return domain
        except Exception as e:
            logger.error(f"Failed to extract domain from '{sender}': {e}")
        return ""

    def _extract_username(self, sender: str) -> str:
        """Extract the username part from an email address."""
        try:
            if "@" in sender:
                username = sender.split("@")[0]
                # Remove angle bracket if present: <username
                username = username.replace("<", "").strip()
                return username
        except Exception as e:
            logger.error(f"Failed to extract username from '{sender}': {e}")
        return sender

    def _is_official_brand_domain(self, brand: str, domain: str) -> bool:
        """
        Checks if a domain is the official domain for a brand.
        Simple approach: official domain = brand.com / brand.org / brand.net etc.
        If the domain contains extra text before or after the brand name,
        it's likely impersonation.
        """
        official_patterns = [
            f"{brand}.com",
            f"{brand}.org",
            f"{brand}.net",
            f"{brand}.co",
            f"{brand}.io",
            f"{brand}.gov",
            f"{brand}.edu",
            f"{brand}.in",
        ]
        return domain in official_patterns


# ═══════════════════════════════════════════════════════════════════
# Module-level detector instance
# Import this in routes/analysis.py
# ═══════════════════════════════════════════════════════════════════
detector = PhishingDetector()