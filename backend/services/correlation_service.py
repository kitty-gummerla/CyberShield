"""
Threat Correlation Engine Service (Milestone 12)

Analyzes historical analysis records and identifies relational links, attack patterns,
shared infrastructure, and coordinated phishing/cyber campaigns.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse
from datetime import datetime
from models.schemas import (
    CorrelatedIncidentSummary,
    IncidentCorrelationReport,
    CampaignCluster,
    CampaignDetectionResponse
)

logger = logging.getLogger(__name__)

# Providers that should not trigger domain-level correlation by themselves
COMMON_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "icloud.com", "protonmail.com", "aol.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com"
}

# Lure keywords for subject theme matching
LURE_KEYWORDS = {
    "urgent", "urgency", "immediate", "suspended", "suspension",
    "verify", "verification", "invoice", "payroll", "salary",
    "action required", "warning", "security alert", "password",
    "reset", "expiration", "billing", "payment", "bank",
    "wire transfer", "unauthorized", "login", "account"
}


class ThreatCorrelationService:
    """
    Evaluates multi-incident relationships using static artifact matching,
    TTP similarity, infrastructure overlap, and temporal proximity.
    """

    def correlate_incident(
        self,
        target_record: Dict[str, Any],
        candidate_records: List[Dict[str, Any]]
    ) -> IncidentCorrelationReport:
        """
        Correlates a target incident against a list of candidate historical records.
        Returns a structured correlation report with confidence tiers.
        """
        target_id = str(target_record.get("analysis_id") or target_record.get("_id") or "LIVE_TARGET")
        correlated_summaries: List[CorrelatedIncidentSummary] = []

        total_searched = 0
        for candidate in candidate_records:
            cand_id = str(candidate.get("analysis_id") or candidate.get("_id") or "")
            if not cand_id or cand_id == target_id:
                continue

            total_searched += 1
            summary = self._compare_incidents(target_record, candidate)
            if summary:
                correlated_summaries.append(summary)

        # Sort highest correlation score first
        correlated_summaries.sort(key=lambda s: s.correlation_score, reverse=True)

        # Determine highest confidence
        highest_conf = "None"
        if any(s.confidence_tier == "High" for s in correlated_summaries):
            highest_conf = "High"
        elif any(s.confidence_tier == "Medium" for s in correlated_summaries):
            highest_conf = "Medium"
        elif correlated_summaries:
            highest_conf = "Low"

        # Campaign identification heuristics
        campaign_identified = False
        campaign_name = None
        campaign_summary = None
        suggested_action = "No immediate multi-incident campaign detected. Maintain standard monitoring."

        high_or_med_count = sum(1 for s in correlated_summaries if s.confidence_tier in ["High", "Medium"])
        if high_or_med_count >= 1 or len(correlated_summaries) >= 2:
            campaign_identified = True
            primary_domain = self._get_primary_shared_domain(target_record, correlated_summaries)
            campaign_name = f"Coordinated Campaign: {primary_domain or 'Multi-Vector Phishing Activity'}"
            campaign_summary = (
                f"Identified {len(correlated_summaries)} potentially related security incidents sharing common "
                f"threat infrastructure, attack patterns, or lure artifacts with this incident."
            )
            suggested_action = (
                "Initiate campaign-wide containment: Block shared sender domains, sinkhole related URLs, "
                "and quarantine messages with matching indicators across all corporate mailboxes."
            )

        return IncidentCorrelationReport(
            primary_analysis_id=target_id,
            total_records_searched=total_searched,
            correlated_incident_count=len(correlated_summaries),
            highest_confidence=highest_conf,
            correlated_incidents=correlated_summaries,
            campaign_identified=campaign_identified,
            campaign_name=campaign_name,
            campaign_summary=campaign_summary,
            suggested_action=suggested_action
        )

    def cluster_campaigns(self, all_records: List[Dict[str, Any]]) -> CampaignDetectionResponse:
        """
        Clusters all historical incident records into campaign groups using
        connected component graph analysis based on correlation thresholds.
        """
        total_incidents = len(all_records)
        if total_incidents < 2:
            return CampaignDetectionResponse(
                total_incidents_analyzed=total_incidents,
                total_campaigns_detected=0,
                campaigns=[],
                isolated_incidents_count=total_incidents
            )

        # Build adjacency list where edge exists if correlation_score >= 45 (Medium/High)
        adj: Dict[int, Set[int]] = {i: set() for i in range(total_incidents)}
        pair_data: Dict[Tuple[int, int], CorrelatedIncidentSummary] = {}

        for i in range(total_incidents):
            for j in range(i + 1, total_incidents):
                summary = self._compare_incidents(all_records[i], all_records[j])
                if summary and summary.correlation_score >= 45:
                    adj[i].add(j)
                    adj[j].add(i)
                    pair_data[(i, j)] = summary
                    pair_data[(j, i)] = summary

        # Find connected components (clusters)
        visited = set()
        clusters: List[List[int]] = []

        for i in range(total_incidents):
            if i not in visited:
                component = []
                queue = [i]
                visited.add(i)
                while queue:
                    curr = queue.pop(0)
                    component.append(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                if len(component) >= 2:
                    clusters.append(component)

        # Build CampaignCluster objects
        campaign_clusters: List[CampaignCluster] = []
        clustered_node_count = 0

        for idx, comp in enumerate(clusters, start=1):
            clustered_node_count += len(comp)
            comp_records = [all_records[k] for k in comp]

            # Aggregate metadata
            incident_ids = [str(r.get("analysis_id") or r.get("_id")) for r in comp_records]
            senders = list(set(r.get("sender") for r in comp_records if r.get("sender")))
            domains = list(set(d for r in comp_records for d in self._extract_all_domains(r)))
            
            all_indicators = []
            for r in comp_records:
                for ind in r.get("indicators", []):
                    name = ind.get("indicator") if isinstance(ind, dict) else str(ind)
                    if name:
                        all_indicators.append(name)
            common_indicators = list(set(all_indicators))

            risk_scores = [r.get("risk_score", 0) for r in comp_records]
            avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0

            # Timestamps
            timestamps = []
            for r in comp_records:
                ts = r.get("analyzed_at")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        ts = None
                if isinstance(ts, datetime):
                    timestamps.append(ts)

            earliest = min(timestamps) if timestamps else None
            latest = max(timestamps) if timestamps else None

            # Determine dominant threat characteristic for campaign name
            domain_label = domains[0] if domains else (senders[0].split("@")[-1] if senders else "Unknown")
            campaign_name = f"Campaign-{idx:03d} [{domain_label}]"

            # Confidence determination
            has_high = any(
                pair_data.get((a, b), None) and pair_data[(a, b)].confidence_tier == "High"
                for a in comp for b in comp if a != b
            )
            confidence_level = "High" if has_high else "Medium"

            summary_text = (
                f"Cluster of {len(comp_records)} related security events targeting organization assets. "
                f"Demonstrates consistent use of shared infrastructure ({', '.join(domains[:3]) if domains else 'Various'}), "
                f"common TTPs ({', '.join(common_indicators[:3]) if common_indicators else 'Phishing'}), and an average threat score of {avg_risk}/100."
            )

            campaign_clusters.append(CampaignCluster(
                campaign_id=f"CAMP-{idx:03d}",
                campaign_name=campaign_name,
                confidence_level=confidence_level,
                earliest_seen=earliest,
                latest_seen=latest,
                incident_count=len(comp_records),
                incident_ids=incident_ids,
                common_senders=senders[:5],
                common_domains=domains[:5],
                common_threat_indicators=common_indicators[:5],
                common_attack_types=["Credential Harvesting", "Brand Spoofing", "Malicious Payload Delivery"] if avg_risk >= 50 else ["Reconnaissance / Low-Risk Spam"],
                average_risk_score=avg_risk,
                summary=summary_text
            ))

        isolated_count = total_incidents - clustered_node_count

        return CampaignDetectionResponse(
            total_incidents_analyzed=total_incidents,
            total_campaigns_detected=len(campaign_clusters),
            campaigns=campaign_clusters,
            isolated_incidents_count=max(0, isolated_count)
        )

    # ─────────────────────────────────────────────
    # INTERNAL COMPARISON LOGIC
    # ─────────────────────────────────────────────

    def _compare_incidents(
        self,
        rec_a: Dict[str, Any],
        rec_b: Dict[str, Any]
    ) -> Optional[CorrelatedIncidentSummary]:
        """
        Calculates correlation score between two analysis records using multi-vector rules.
        """
        score = 0
        matched_fields: List[str] = []
        reasons: List[str] = []
        shared_indicators: List[str] = []
        shared_domains: List[str] = []
        shared_attachments: List[str] = []

        sender_a = (rec_a.get("sender") or "").strip().lower()
        sender_b = (rec_b.get("sender") or "").strip().lower()
        dom_a = self._extract_domain_from_email(sender_a)
        dom_b = self._extract_domain_from_email(sender_b)

        # 1. Sender Match
        if sender_a and sender_b and sender_a == sender_b:
            score += 40
            matched_fields.append("shared_sender")
            reasons.append(f"Identical sender address: '{sender_a}'")

        # 2. Sender Domain Match (Non-free providers)
        elif dom_a and dom_b and dom_a == dom_b:
            if dom_a not in COMMON_FREE_EMAIL_DOMAINS:
                score += 35
                matched_fields.append("shared_sender_domain")
                shared_domains.append(dom_a)
                reasons.append(f"Identical custom sender domain: '@{dom_a}'")
            else:
                # Free domain: small weight for generic free provider overlap
                score += 5

        # 3. URL / Domain Overlap
        urls_a = set(self._extract_all_urls(rec_a))
        urls_b = set(self._extract_all_urls(rec_b))
        common_urls = urls_a.intersection(urls_b)
        if common_urls:
            score += 40
            matched_fields.append("shared_destination_url")
            for u in list(common_urls)[:2]:
                reasons.append(f"Identical URL destination: '{u[:50]}'")

        all_doms_a = set(self._extract_all_domains(rec_a))
        all_doms_b = set(self._extract_all_domains(rec_b))
        common_domains = all_doms_a.intersection(all_doms_b)
        if common_domains:
            # Filter out generic domains
            specific_domains = [d for d in common_domains if d not in COMMON_FREE_EMAIL_DOMAINS]
            if specific_domains:
                if "shared_sender_domain" not in matched_fields:
                    score += 30
                    matched_fields.append("shared_infrastructure_domain")
                for d in specific_domains:
                    if d not in shared_domains:
                        shared_domains.append(d)
                        reasons.append(f"Shared threat domain: '{d}'")

        # 4. Attachment Overlap
        att_a = rec_a.get("attachment_analysis", [])
        att_b = rec_b.get("attachment_analysis", [])
        att_filenames_a = {a.get("filename", "").lower() for a in att_a if a.get("filename")}
        att_filenames_b = {b.get("filename", "").lower() for b in att_b if b.get("filename")}
        common_att_files = att_filenames_a.intersection(att_filenames_b)

        if common_att_files:
            score += 30
            matched_fields.append("shared_attachment_filename")
            for fn in common_att_files:
                shared_attachments.append(fn)
                reasons.append(f"Identical attachment filename: '{fn}'")
        else:
            # Check for same suspicious extension or threat category
            ext_a = {a.get("detected_extension", "").lower() for a in att_a if a.get("is_suspicious")}
            ext_b = {b.get("detected_extension", "").lower() for b in att_b if b.get("is_suspicious")}
            common_ext = ext_a.intersection(ext_b)
            if common_ext:
                score += 15
                matched_fields.append("shared_attachment_payload_type")
                for ext in common_ext:
                    shared_attachments.append(f"*.{ext}")
                    reasons.append(f"Matching suspicious payload type: '{ext}'")

        # 5. Shared Threat Indicators (TTPs)
        inds_a = {
            ind.get("indicator") if isinstance(ind, dict) else str(ind)
            for ind in rec_a.get("indicators", [])
        }
        inds_b = {
            ind.get("indicator") if isinstance(ind, dict) else str(ind)
            for ind in rec_b.get("indicators", [])
        }
        common_inds = inds_a.intersection(inds_b)
        if len(common_inds) >= 2:
            score += 20
            matched_fields.append("shared_ttp_pattern")
            shared_indicators.extend(list(common_inds))
            reasons.append(f"Shared attack signatures: {', '.join(list(common_inds)[:3])}")
        elif len(common_inds) == 1:
            high_value_ttps = {"credential_request", "brand_impersonation", "otp_request"}
            if common_inds.intersection(high_value_ttps):
                score += 10
                matched_fields.append("shared_ttp_pattern")
                shared_indicators.extend(list(common_inds))
                reasons.append(f"Shared attack signature: {list(common_inds)[0]}")

        # 6. Subject / Lure Similarity
        sub_a = (rec_a.get("subject") or "").lower()
        sub_b = (rec_b.get("subject") or "").lower()
        if sub_a and sub_b:
            words_a = set(re.findall(r"\b[a-zA-Z]{3,}\b", sub_a))
            words_b = set(re.findall(r"\b[a-zA-Z]{3,}\b", sub_b))
            common_words = words_a.intersection(words_b)
            common_lures = common_words.intersection(LURE_KEYWORDS)
            if len(common_lures) >= 2 or (len(words_a) > 0 and len(common_words) / len(words_a) > 0.6):
                score += 15
                matched_fields.append("similar_phishing_lure")
                reasons.append(f"Similar lure theme in subject line ({', '.join(list(common_lures or common_words)[:2])})")

        # 7. Hop / Relay IP Overlap (from header analysis)
        hops_a = self._extract_hop_ips(rec_a)
        hops_b = self._extract_hop_ips(rec_b)
        common_ips = hops_a.intersection(hops_b)
        if common_ips:
            score += 35
            matched_fields.append("shared_infrastructure_ip")
            for ip in common_ips:
                reasons.append(f"Matching originating or relay IP: '{ip}'")

        # 8. Temporal Proximity
        ts_a = self._parse_timestamp(rec_a.get("analyzed_at"))
        ts_b = self._parse_timestamp(rec_b.get("analyzed_at"))
        if ts_a and ts_b:
            diff_hours = abs((ts_a - ts_b).total_seconds()) / 3600.0
            if diff_hours <= 24:
                score += 10
                matched_fields.append("temporal_proximity_24h")
                reasons.append("Observed within a 24-hour operational window")
            elif diff_hours <= 168:  # 7 days
                score += 5
                matched_fields.append("temporal_proximity_7d")
                reasons.append("Observed within a 7-day operational window")

        # Cap score at 100
        final_score = min(100, score)

        # Discard low-scoring coincidences (< 25)
        if final_score < 25:
            return None

        # Determine confidence tier
        if final_score >= 75:
            confidence_tier = "High"
        elif final_score >= 45:
            confidence_tier = "Medium"
        else:
            confidence_tier = "Low"

        candidate_id = str(rec_b.get("analysis_id") or rec_b.get("_id") or "UNKNOWN")
        reasoning_text = "; ".join(reasons) if reasons else "General threat metric alignment."

        return CorrelatedIncidentSummary(
            analysis_id=candidate_id,
            incident_timestamp=ts_b,
            sender=rec_b.get("sender", "Unknown"),
            subject=rec_b.get("subject", "No Subject"),
            risk_score=rec_b.get("risk_score", 0),
            risk_level=rec_b.get("risk_level", "low"),
            verdict=rec_b.get("verdict", "Suspicious"),
            correlation_score=final_score,
            confidence_tier=confidence_tier,
            matched_fields=matched_fields,
            shared_indicators=shared_indicators,
            shared_domains=shared_domains,
            shared_attachments=shared_attachments,
            reasoning=reasoning_text
        )

    # ─────────────────────────────────────────────
    # EXTRACTION UTILITIES
    # ─────────────────────────────────────────────

    def _extract_domain_from_email(self, email: str) -> Optional[str]:
        if not email or "@" not in email:
            return None
        return email.split("@")[-1].strip().lower()

    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        if not url:
            return None
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/")[0]
            host = host.split(":")[0].strip().lower()
            return host if host else None
        except Exception:
            return None

    def _extract_all_urls(self, record: Dict[str, Any]) -> List[str]:
        urls = []
        for u in record.get("urls_found", []):
            if isinstance(u, str):
                urls.append(u)
        for u_obj in record.get("url_analysis", []):
            if isinstance(u_obj, dict) and u_obj.get("url"):
                urls.append(u_obj["url"])
        return urls

    def _extract_all_domains(self, record: Dict[str, Any]) -> List[str]:
        domains = set()
        sender_dom = self._extract_domain_from_email(record.get("sender", ""))
        if sender_dom:
            domains.add(sender_dom)

        for u in self._extract_all_urls(record):
            dom = self._extract_domain_from_url(u)
            if dom:
                domains.add(dom)

        header_analysis = record.get("header_analysis") or {}
        if isinstance(header_analysis, dict):
            ret_path = header_analysis.get("return_path")
            if ret_path:
                d = self._extract_domain_from_email(ret_path)
                if d:
                    domains.add(d)

        return list(domains)

    def _extract_hop_ips(self, record: Dict[str, Any]) -> Set[str]:
        ips = set()
        header_analysis = record.get("header_analysis") or {}
        if isinstance(header_analysis, dict):
            hops = header_analysis.get("hops", [])
            for hop in hops:
                if isinstance(hop, dict) and hop.get("ip_address"):
                    ip = hop["ip_address"].strip()
                    if ip and not ip.startswith(("127.", "10.", "192.168.")):
                        ips.add(ip)
        return ips

    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                return None
        return None

    def _get_primary_shared_domain(
        self,
        target_record: Dict[str, Any],
        correlated_summaries: List[CorrelatedIncidentSummary]
    ) -> Optional[str]:
        for s in correlated_summaries:
            if s.shared_domains:
                return s.shared_domains[0]
        sender_dom = self._extract_domain_from_email(target_record.get("sender", ""))
        if sender_dom and sender_dom not in COMMON_FREE_EMAIL_DOMAINS:
            return sender_dom
        return None


# ═══════════════════════════════════════════════════════════════════
# Global Correlation Service Instance
# ═══════════════════════════════════════════════════════════════════
correlation_service = ThreatCorrelationService()
