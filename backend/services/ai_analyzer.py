"""
AI Explanation Service — Cybersecurity Awareness Assistant

Translates structured detection findings (indicators, evidence, URLs, risk score)
into plain-English educational explanations and security recommendations.

Features:
- Connects to Google Gemini API or OpenAI-compatible APIs (Groq, OpenRouter).
- Safe, deterministic offline template fallback if no API key is provided.
- Strictly grounded in the detection engine's findings (no hallucinated verdicts).
"""

import os
import logging
import httpx
from typing import List, Optional
from models.schemas import IndicatorDetail, URLAnalysisDetail

logger = logging.getLogger(__name__)


class AIExplanationService:
    """
    Handles generation of natural-language explanations and tailored advice
    grounded in structured phishing detection output.
    """

    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "gemini").lower()
        self.api_key = os.getenv("AI_API_KEY", "").strip()
        self.model_name = os.getenv("AI_MODEL_NAME", "gemini-1.5-flash")

    async def generate_explanation(
        self,
        sender: str,
        subject: str,
        risk_score: int,
        risk_level: str,
        verdict: str,
        indicators: List[IndicatorDetail],
        url_details: List[URLAnalysisDetail]
    ) -> str:
        """
        Main entry point for generating AI explanations.
        Attempts LLM API call first; gracefully falls back to template synthesis on failure.
        """
        # If no key configured or set to fallback, use heuristic generator immediately
        if not self.api_key or self.provider == "fallback" or self.api_key == "your_api_key_here":
            logger.info("No AI API key found. Using built-in cybersecurity explanation generator.")
            return self._generate_fallback_explanation(
                sender, subject, risk_score, risk_level, verdict, indicators, url_details
            )

        try:
            if self.provider == "gemini":
                return await self._call_gemini_api(
                    sender, subject, risk_score, risk_level, verdict, indicators, url_details
                )
            elif self.provider in ["openai", "groq", "openrouter"]:
                return await self._call_openai_compatible_api(
                    sender, subject, risk_score, risk_level, verdict, indicators, url_details
                )
            else:
                return self._generate_fallback_explanation(
                    sender, subject, risk_score, risk_level, verdict, indicators, url_details
                )
        except Exception as e:
            logger.warning(f"AI API call failed ({str(e)}). Switching to fallback generator.")
            return self._generate_fallback_explanation(
                sender, subject, risk_score, risk_level, verdict, indicators, url_details
            )

    def _build_prompt(
        self,
        sender: str,
        subject: str,
        risk_score: int,
        risk_level: str,
        verdict: str,
        indicators: List[IndicatorDetail],
        url_details: List[URLAnalysisDetail]
    ) -> str:
        """Constructs a strict, grounded prompt for the LLM."""
        ind_summary = "\n".join(
            f"- [{ind.severity.upper()}] {ind.indicator}: {ind.description} (Evidence: {', '.join(ind.evidence)})"
            for ind in indicators
        ) or "None detected."

        url_summary = "\n".join(
            f"- URL: {u.url} (Suspicious: {u.is_suspicious}, Reasons: {', '.join(u.reasons)})"
            for u in url_details
        ) or "No URLs present."

        prompt = f"""You are a friendly cybersecurity expert assistant.
Explain to a college student or everyday user why the following email received its specific security assessment.

EMAIL METADATA:
- Sender: {sender}
- Subject: {subject}

SECURITY ENGINE RESULTS:
- Risk Score: {risk_score}/100
- Risk Tier: {risk_level.upper()}
- Security Verdict: {verdict}

DETECTED INDICATORS:
{ind_summary}

DETECTED URLS:
{url_summary}

INSTRUCTIONS:
1. Explain in 2-3 short, clear paragraphs why this email is safe, suspicious, or dangerous.
2. Highlight the specific red flags found (e.g. coercive urgency, password requests, fake domains).
3. Do NOT contradict the Security Verdict or Risk Score.
4. Keep the tone educational, professional, and easy to understand for beginners.
"""
        return prompt

    async def _call_gemini_api(
        self,
        sender: str,
        subject: str,
        risk_score: int,
        risk_level: str,
        verdict: str,
        indicators: List[IndicatorDetail],
        url_details: List[URLAnalysisDetail]
    ) -> str:
        """Calls Google Gemini REST API using httpx."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        prompt = self._build_prompt(sender, subject, risk_score, risk_level, verdict, indicators, url_details)

        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.3,  # Low temperature for factual, consistent answers
                "maxOutputTokens": 400
            }
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return text.strip()
            else:
                raise RuntimeError(f"Gemini API returned status {response.status_code}: {response.text}")

    async def _call_openai_compatible_api(
        self,
        sender: str,
        subject: str,
        risk_score: int,
        risk_level: str,
        verdict: str,
        indicators: List[IndicatorDetail],
        url_details: List[URLAnalysisDetail]
    ) -> str:
        """Calls OpenAI / Groq / OpenRouter compatible chat completions."""
        base_urls = {
            "groq": "https://api.groq.com/openai/v1/chat/completions",
            "openai": "https://api.openai.com/v1/chat/completions",
            "openrouter": "https://openrouter.ai/api/v1/chat/completions"
        }
        url = base_urls.get(self.provider, base_urls["openai"])
        prompt = self._build_prompt(sender, subject, risk_score, risk_level, verdict, indicators, url_details)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert explaining phishing detection results."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 400
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
            else:
                raise RuntimeError(f"{self.provider} API returned status {response.status_code}: {response.text}")

    def _generate_fallback_explanation(
        self,
        sender: str,
        subject: str,
        risk_score: int,
        risk_level: str,
        verdict: str,
        indicators: List[IndicatorDetail],
        url_details: List[URLAnalysisDetail]
    ) -> str:
        """
        Deterministic, offline cybersecurity synthesis engine.
        Generates clean, human-readable explanations without needing external API calls.
        """
        if risk_level == "low":
            return (
                f"This email from '{sender}' appears legitimate (Risk Score: {risk_score}/100). "
                f"Our multi-signal detection engine analyzed the sender identity, message content, and structural "
                f"patterns and found no malicious coercion, credential harvesting, or deceptive links. "
                f"Standard security caution is still advised for any unexpected correspondence."
            )

        reasons = []
        for ind in indicators:
            if ind.indicator == "credential_request":
                reasons.append("it solicits confidential account login credentials or passwords")
            elif ind.indicator == "otp_request":
                reasons.append("it attempts to harvest one-time authentication (OTP/2FA) codes")
            elif ind.indicator == "threat_language":
                reasons.append("it employs intimidating language threatening account termination or legal consequences")
            elif ind.indicator == "urgency_language":
                reasons.append("it creates artificial time pressure to prompt hasty action without verification")
            elif ind.indicator == "free_email_impersonation":
                reasons.append(f"the sender is using a free webmail service ('{sender}') while posing as an official organization")
            elif ind.indicator == "brand_impersonation":
                reasons.append(f"the sender domain appears to imitate a known brand")
            elif ind.indicator == "financial_request":
                reasons.append("it requests urgent financial transactions or banking information updates")

        suspicious_urls = [u for u in url_details if u.is_suspicious]
        if suspicious_urls:
            reasons.append(f"it contains {len(suspicious_urls)} suspicious or masked destination link(s)")

        reasons_text = "; ".join(reasons) if reasons else "anomalous communication patterns were detected"

        explanation = (
            f"This email has been flagged as **{risk_level.upper()} RISK** with a score of **{risk_score}/100** ({verdict}).\n\n"
            f"**Why this was flagged:** Our security analysis detected that {reasons_text}.\n\n"
            f"**Cybersecurity Insight:** Attackers combine social engineering (urgency and fear) with deceptive delivery mechanisms to trick users into divulging sensitive data. Treat this communication with extreme caution."
        )
        return explanation


# ═══════════════════════════════════════════════════════════════════
# Module-level instance
# ═══════════════════════════════════════════════════════════════════
ai_service = AIExplanationService()