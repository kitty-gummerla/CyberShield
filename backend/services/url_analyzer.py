"""
URL Analysis Service — Static URL Analysis

Analyzes URL strings found in email bodies or submitted via standalone scanner.

⚠️ SAFETY RULE:
    Performs STATIC analysis ONLY using urllib.parse.
    NEVER makes network requests, visits, or resolves URLs.
"""

import re
import logging
from urllib.parse import urlparse
from typing import List, Tuple, Optional
from models.schemas import URLAnalysisDetail

logger = logging.getLogger(__name__)

# Regex to extract URLs from text
URL_EXTRACTION_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"{}|\\^`\[\](),;]{4,}',
    re.IGNORECASE
)

# IPv4 pattern
IPV4_PATTERN = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.link", "tiny.cc", "is.gd", "buff.ly", "adf.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "v.gd",
    "bit.do", "lnkd.in", "db.tt", "qr.ae", "po.st",
    "snip.ly", "bl.ink", "clk.sh",
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".link",
    ".online", ".site", ".web", ".fun",
    ".info", ".biz", ".pw", ".cc",
    ".icu", ".rest", ".life",
}

# Suspicious keywords in domain
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "security", "login", "signin", "verify",
    "verification", "account", "update", "confirm",
    "banking", "alert", "support", "helpdesk",
    "wallet", "auth", "authenticate",
]

# Sensitive paths often targeted by phishers
SUSPICIOUS_PATHS = [
    "/login", "/signin", "/verify", "/verification", "/auth",
    "/update-password", "/reset-password", "/account", "/banking",
    "/secure", "/wp-login", "/admin"
]

# Official brand domains
BRAND_OFFICIAL_DOMAINS = {
    "paypal":       ["paypal.com"],
    "amazon":       ["amazon.com", "amazon.in", "amazon.co.uk"],
    "google":       ["google.com", "google.co.in", "googleapis.com", "accounts.google.com"],
    "microsoft":    ["microsoft.com", "live.com", "outlook.com", "microsoftonline.com"],
    "apple":        ["apple.com", "icloud.com"],
    "netflix":      ["netflix.com"],
    "facebook":     ["facebook.com", "fb.com"],
    "instagram":    ["instagram.com"],
    "twitter":      ["twitter.com", "x.com"],
    "linkedin":     ["linkedin.com"],
    "chase":        ["chase.com"],
    "citibank":     ["citibank.com", "citi.com"],
    "wellsfargo":   ["wellsfargo.com"],
    "barclays":     ["barclays.co.uk", "barclays.com"],
    "hsbc":         ["hsbc.com", "hsbc.co.in"],
    "sbi":          ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc":         ["hdfcbank.com"],
    "icici":        ["icicibank.com"],
    "fedex":        ["fedex.com"],
    "ups":          ["ups.com"],
    "dhl":          ["dhl.com"],
    "ebay":         ["ebay.com"],
    "walmart":      ["walmart.com"],
    "dropbox":      ["dropbox.com"],
    "adobe":        ["adobe.com"],
    "zoom":         ["zoom.us"],
    "spotify":      ["spotify.com"],
}

# Weights for URL checks
URL_CHECK_SCORES = {
    "no_https":              8,
    "ip_based_url":         22,
    "url_shortener":        15,
    "suspicious_tld":       15,
    "excessive_subdomains": 12,
    "brand_impersonation":  22,
    "suspicious_keywords":  12,
    "hyphenated_domain":     8,
    "suspicious_path":      10,
    "very_long_url":         5,
    "suspicious_params":     8,
}


class URLAnalyzer:
    """Static URL analysis engine."""

    def analyze_all(self, text: str) -> Tuple[List[str], List[URLAnalysisDetail]]:
        urls_found = self.extract_urls(text)
        if not urls_found:
            return [], []

        url_details = [self.analyze_single_url(u) for u in urls_found]
        return urls_found, url_details

    def extract_urls(self, text: str) -> List[str]:
        raw_matches = URL_EXTRACTION_PATTERN.findall(text)
        cleaned = []
        for url in raw_matches:
            url = url.rstrip(".,;:!?)\"'")
            if url not in cleaned:
                cleaned.append(url)
        return cleaned

    def analyze_single_url(self, url: str) -> URLAnalysisDetail:
        reasons: List[str] = []
        total_score: int = 0

        parsed = self._safe_parse(url)
        if not parsed:
            return URLAnalysisDetail(
                url=url,
                is_suspicious=False,
                reasons=["Could not parse URL structure"],
                risk_level="low",
                score_contribution=0
            )

        domain = parsed.get("domain", "")
        full_netloc = parsed.get("netloc", "")
        scheme = parsed.get("scheme", "")
        path = parsed.get("path", "")
        query = parsed.get("query", "")
        subdomain_count = parsed.get("subdomain_count", 0)

        # 1. HTTP vs HTTPS
        if scheme == "http":
            reasons.append("Uses unencrypted HTTP instead of HTTPS.")
            total_score += URL_CHECK_SCORES["no_https"]

        # 2. IP Address Host
        if self._is_ip_based(full_netloc):
            reasons.append(f"URL uses a raw IP address ({full_netloc}) instead of a registered domain name.")
            total_score += URL_CHECK_SCORES["ip_based_url"]

        # 3. URL Shortener
        elif self._is_url_shortener(domain):
            reasons.append(f"URL uses a shortening service ({domain}) which conceals the destination.")
            total_score += URL_CHECK_SCORES["url_shortener"]

        else:
            # 4. High-risk TLD
            tld = self._extract_tld(domain)
            if tld and f".{tld}" in SUSPICIOUS_TLDS:
                reasons.append(f"URL uses a high-risk or commonly abused top-level domain (.{tld}).")
                total_score += URL_CHECK_SCORES["suspicious_tld"]

            # 5. Excessive Subdomains
            if subdomain_count > 2:
                reasons.append(f"URL has {subdomain_count} subdomain levels — commonly used to disguise true hostnames.")
                total_score += URL_CHECK_SCORES["excessive_subdomains"]

            # 6. Brand Impersonation
            brand_result = self._check_brand_impersonation(domain, full_netloc)
            if brand_result:
                reasons.append(brand_result)
                total_score += URL_CHECK_SCORES["brand_impersonation"]

            # 7. Suspicious Keywords in Domain
            kw_found = self._check_suspicious_keywords(domain)
            if kw_found:
                reasons.append(f"Domain contains trust-inducing keywords: {', '.join(kw_found)}.")
                total_score += URL_CHECK_SCORES["suspicious_keywords"]

            # 8. Hyphenated Domain
            if domain.count("-") >= 2:
                reasons.append(f"Domain contains multiple hyphens ({domain}), typical of spoofed domains.")
                total_score += URL_CHECK_SCORES["hyphenated_domain"]

        # 9. Suspicious Authentication / Login Paths on Non-Official Domains
        if any(sp in path.lower() for sp in SUSPICIOUS_PATHS):
            reasons.append(f"URL path ({path}) leads directly to a login/verification form.")
            total_score += URL_CHECK_SCORES["suspicious_path"]

        # 10. Long URL
        if len(url) > 100:
            reasons.append(f"URL is unusually long ({len(url)} characters).")
            total_score += URL_CHECK_SCORES["very_long_url"]

        # 11. Suspicious Parameters
        if query and ("redirect" in query.lower() or "url=" in query.lower()):
            reasons.append("URL contains redirect parameters which may indicate open-redirect abuse.")
            total_score += URL_CHECK_SCORES["suspicious_params"]

        risk_level = self._score_to_risk_level(total_score)
        is_suspicious = total_score > 0

        return URLAnalysisDetail(
            url=url,
            is_suspicious=is_suspicious,
            reasons=reasons,
            risk_level=risk_level,
            score_contribution=min(total_score, 35)
        )

    def _safe_parse(self, url: str) -> Optional[dict]:
        try:
            if url.startswith("www."):
                url = "http://" + url
            parsed = urlparse(url)
            netloc = parsed.netloc.lower().split(":")[0]
            parts = netloc.split(".")
            subdomain_count = max(0, len(parts) - 2)
            domain = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else netloc
            return {
                "scheme": parsed.scheme.lower(),
                "netloc": netloc,
                "domain": domain,
                "path": parsed.path,
                "query": parsed.query,
                "subdomain_count": subdomain_count,
            }
        except Exception:
            return None

    def _is_ip_based(self, netloc: str) -> bool:
        return bool(IPV4_PATTERN.match(netloc))

    def _is_url_shortener(self, domain: str) -> bool:
        return domain.lower() in URL_SHORTENERS

    def _extract_tld(self, domain: str) -> Optional[str]:
        parts = domain.rsplit(".", 1)
        return parts[1] if len(parts) == 2 else None

    def _check_brand_impersonation(self, domain: str, full_netloc: str) -> Optional[str]:
        netloc_lower = full_netloc.lower()
        for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
            if brand in netloc_lower:
                is_official = any(
                    netloc_lower == od or netloc_lower.endswith(f".{od}")
                    for od in official_domains
                )
                if not is_official:
                    return f"URL imitates brand '{brand.upper()}' on unofficial domain ({domain})."
        return None

    def _check_suspicious_keywords(self, domain: str) -> List[str]:
        return [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in domain.lower()]

    def _score_to_risk_level(self, score: int) -> str:
        if score == 0:
            return "low"
        elif score <= 15:
            return "medium"
        elif score <= 30:
            return "high"
        else:
            return "critical"


url_analyzer = URLAnalyzer()