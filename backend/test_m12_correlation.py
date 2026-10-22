"""
M12 Threat Correlation Engine Verification Script
"""

import sys
import os
from datetime import datetime, timedelta

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.correlation_service import correlation_service
from services.investigation_service import investigation_service
from models.schemas import EmailAnalysisRequest, AttachmentMetadata
from fastapi.testclient import TestClient
from main import app

def run_tests():
    print("=" * 60)
    print("RUNNING M12 THREAT CORRELATION ENGINE UNIT & INTEGRATION TESTS")
    print("=" * 60)

    # ─────────────────────────────────────────────
    # TEST 1: Incident Correlation with Shared Domain & TTPs
    # ─────────────────────────────────────────────
    now = datetime.utcnow()
    incident_a = {
        "analysis_id": "INC-001",
        "analyzed_at": now,
        "sender": "admin@malicious-payroll.xyz",
        "subject": "URGENT: Review Your Pending Payroll Invoice",
        "risk_score": 88,
        "risk_level": "high",
        "verdict": "Likely Phishing",
        "indicators": [
            {"indicator": "credential_request", "severity": "high", "score_contribution": 30},
            {"indicator": "urgency_keywords", "severity": "medium", "score_contribution": 15},
            {"indicator": "brand_impersonation", "severity": "high", "score_contribution": 25}
        ],
        "urls_found": ["http://login.malicious-payroll.xyz/verify"],
        "url_analysis": [
            {"url": "http://login.malicious-payroll.xyz/verify", "is_suspicious": True, "risk_level": "high", "reasons": ["Uncommon TLD"]}
        ],
        "attachment_analysis": [
            {"filename": "payroll_update.docm", "detected_extension": "docm", "is_suspicious": True, "threat_category": "Macro Document"}
        ]
    }

    # Incident B: same domain, same attachment type, same credential request
    incident_b = {
        "analysis_id": "INC-002",
        "analyzed_at": now - timedelta(hours=2),
        "sender": "hr@malicious-payroll.xyz",
        "subject": "URGENT: Salary Invoice Verification",
        "risk_score": 92,
        "risk_level": "high",
        "verdict": "Likely Phishing",
        "indicators": [
            {"indicator": "credential_request", "severity": "high", "score_contribution": 30},
            {"indicator": "urgency_keywords", "severity": "medium", "score_contribution": 15}
        ],
        "urls_found": ["http://auth.malicious-payroll.xyz/login"],
        "url_analysis": [
            {"url": "http://auth.malicious-payroll.xyz/login", "is_suspicious": True, "risk_level": "high", "reasons": ["Uncommon TLD"]}
        ],
        "attachment_analysis": [
            {"filename": "salary_sheet.docm", "detected_extension": "docm", "is_suspicious": True, "threat_category": "Macro Document"}
        ]
    }

    # Incident C: completely unrelated benign email
    incident_c = {
        "analysis_id": "INC-003",
        "analyzed_at": now - timedelta(days=10),
        "sender": "newsletter@legitimate-news.org",
        "subject": "Weekly Tech Digest",
        "risk_score": 10,
        "risk_level": "low",
        "verdict": "Legitimate",
        "indicators": [],
        "urls_found": ["https://legitimate-news.org/articles"],
        "url_analysis": [
            {"url": "https://legitimate-news.org/articles", "is_suspicious": False, "risk_level": "low", "reasons": []}
        ],
        "attachment_analysis": []
    }

    print("\n--- Test 1.1: Correlate INC-001 against history [INC-002, INC-003] ---")
    report = correlation_service.correlate_incident(incident_a, [incident_a, incident_b, incident_c])
    print(f"Total Searched: {report.total_records_searched}")
    print(f"Correlated Incidents Count: {report.correlated_incident_count}")
    print(f"Highest Confidence: {report.highest_confidence}")
    print(f"Campaign Identified: {report.campaign_identified}")
    print(f"Campaign Name: {report.campaign_name}")

    assert report.correlated_incident_count == 1, "Expected exactly 1 correlated incident (INC-002)"
    correlated_inc = report.correlated_incidents[0]
    assert correlated_inc.analysis_id == "INC-002", "Expected INC-002 to correlate"
    assert correlated_inc.confidence_tier in ["High", "Medium"], f"Expected High or Medium confidence, got {correlated_inc.confidence_tier}"
    assert "shared_sender_domain" in correlated_inc.matched_fields, "Expected shared_sender_domain matched"
    assert "malicious-payroll.xyz" in correlated_inc.shared_domains, "Expected malicious-payroll.xyz in shared_domains"
    print("[PASS] Test 1.1: Successful multi-vector correlation and noise rejection.")

    # ─────────────────────────────────────────────
    # TEST 2: Campaign Clustering
    # ─────────────────────────────────────────────
    print("\n--- Test 1.2: Campaign Clustering across multiple records ---")
    incident_d = {
        "analysis_id": "INC-004",
        "analyzed_at": now - timedelta(hours=5),
        "sender": "support@malicious-payroll.xyz",
        "subject": "URGENT Account Action Required",
        "risk_score": 85,
        "risk_level": "high",
        "verdict": "Likely Phishing",
        "indicators": [
            {"indicator": "credential_request", "severity": "high", "score_contribution": 30}
        ],
        "urls_found": ["http://login.malicious-payroll.xyz/verify"],
        "url_analysis": [
            {"url": "http://login.malicious-payroll.xyz/verify", "is_suspicious": True, "risk_level": "high", "reasons": ["Uncommon TLD"]}
        ],
        "attachment_analysis": []
    }

    all_history = [incident_a, incident_b, incident_c, incident_d]
    campaign_res = correlation_service.cluster_campaigns(all_history)
    print(f"Total Incidents Analyzed: {campaign_res.total_incidents_analyzed}")
    print(f"Campaigns Detected: {campaign_res.total_campaigns_detected}")
    print(f"Isolated Incidents: {campaign_res.isolated_incidents_count}")
    for camp in campaign_res.campaigns:
        print(f"  -> Campaign: {camp.campaign_id} | Name: {camp.campaign_name} | Incidents: {camp.incident_count} | Confidence: {camp.confidence_level}")

    assert campaign_res.total_campaigns_detected >= 1, "Expected at least 1 campaign detected"
    camp = campaign_res.campaigns[0]
    assert camp.incident_count == 3, f"Expected 3 incidents in campaign, got {camp.incident_count}"
    assert campaign_res.isolated_incidents_count == 1, "Expected 1 isolated benign incident"
    print("[PASS] Test 1.2: Connected-component campaign clustering works accurately.")

    # ─────────────────────────────────────────────
    # TEST 3: Investigation Dossier Integration
    # ─────────────────────────────────────────────
    print("\n--- Test 1.3: Investigation Dossier includes Correlated Threats ---")
    dossier = investigation_service.generate_dossier(incident_a, correlated_threats=report)
    assert dossier.correlated_threats is not None, "Expected correlated_threats to be present in dossier"
    assert dossier.correlated_threats.correlated_incident_count == 1
    print(f"Dossier ID: {dossier.investigation_id}")
    print(f"Correlated Threats in Dossier: {dossier.correlated_threats.campaign_name}")
    print("[PASS] Test 1.3: Dossier schema and integration verified.")

    # ─────────────────────────────────────────────
    # TEST 4: FastAPI HTTP Endpoint Tests (TestClient)
    # ─────────────────────────────────────────────
    print("\n--- Test 1.4: FastAPI Routes (/api/correlation/...) ---")
    client = TestClient(app)

    # 4.1 Test /api/correlation/campaigns
    resp = client.get("/api/correlation/campaigns")
    print(f"GET /api/correlation/campaigns status: {resp.status_code}")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    camp_json = resp.json()
    assert "total_campaigns_detected" in camp_json
    print(f"Campaigns in DB: {camp_json['total_campaigns_detected']}")

    # 4.2 Test POST /api/correlation/analyze (Live correlation)
    live_req = {
        "sender": "billing-support@secure-update-portal.xyz",
        "subject": "URGENT: Immediate Account Verification Required",
        "body": "Please click http://secure-update-portal.xyz/login to enter your password and OTP immediately.",
        "attachments": [
            {"filename": "document.docm"}
        ]
    }
    live_resp = client.post("/api/correlation/analyze", json=live_req)
    print(f"POST /api/correlation/analyze status: {live_resp.status_code}")
    assert live_resp.status_code == 200, f"Expected 200, got {live_resp.status_code}"
    live_json = live_resp.json()
    assert "primary_analysis_id" in live_json
    assert "correlated_incidents" in live_json
    print(f"Live Correlation Result: Searched {live_json['total_records_searched']}, Found {live_json['correlated_incident_count']}")

    # 4.3 Test POST /api/investigation/live
    inv_resp = client.post("/api/investigation/live", json=live_req)
    print(f"POST /api/investigation/live status: {inv_resp.status_code}")
    assert inv_resp.status_code == 200, f"Expected 200, got {inv_resp.status_code}"
    inv_json = inv_resp.json()
    assert "investigation_id" in inv_json
    assert "correlated_threats" in inv_json
    print(f"Live Dossier ID: {inv_json['investigation_id']}")

    print("\n" + "=" * 60)
    print("ALL M12 CORRELATION ENGINE TESTS PASSED SUCCESSFULLY! [SUCCESS]")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
