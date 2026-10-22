"""
M13 Autonomous Remediation Engine Verification Script
"""

import sys
import os
from datetime import datetime

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.remediation_engine import remediation_engine
from models.schemas import (
    RemediationActionType,
    RemediationExecutionRequest,
    IncidentCorrelationReport
)
from fastapi.testclient import TestClient
from main import app


def run_tests():
    print("=" * 60)
    print("RUNNING M13 AUTONOMOUS REMEDIATION ENGINE VERIFICATION TESTS")
    print("=" * 60)

    # ─────────────────────────────────────────────
    # TEST 1: Decision Logic — High-Threat Incident
    # ─────────────────────────────────────────────
    print("\n--- Test 1.1: Decision Plan for High-Risk Incident (Score >= 60) ---")
    high_risk_data = {
        "analysis_id": "TEST-INC-HIGH",
        "sender": "attacker@malicious-payroll.xyz",
        "subject": "URGENT: Verify your account immediately",
        "risk_score": 88,
        "risk_level": "high",
        "indicators": [
            {"indicator": "credential_request", "severity": "high"},
            {"indicator": "urgency_keywords", "severity": "medium"}
        ],
        "url_analysis": [
            {"url": "http://login.malicious-payroll.xyz/verify", "is_suspicious": True, "risk_level": "high"}
        ],
        "attachment_analysis": [
            {"filename": "invoice_macro.docm", "detected_extension": "docm", "is_suspicious": True, "threat_category": "Macro Document"}
        ]
    }

    actions = remediation_engine.decide_remediation_plan(high_risk_data)
    print(f"Total Remediation Actions Generated: {len(actions)}")
    action_types = [a.action_type for a in actions]
    for a in actions:
        print(f"  -> [{a.priority}] {a.action_type}: {a.target}")

    # Verify expected action types were generated
    assert RemediationActionType.EMAIL_QUARANTINE in action_types, "Expected Email Quarantine"
    assert RemediationActionType.NETWORK_DOMAIN_BLOCK in action_types, "Expected Network Domain Block"
    assert RemediationActionType.ENDPOINT_ISOLATION_FLAG in action_types, "Expected Endpoint Isolation Flag"
    assert RemediationActionType.IAM_SESSION_REVOCATION in action_types, "Expected IAM Session Revocation"
    assert RemediationActionType.IOC_EXPORT in action_types, "Expected IOC Export"
    print("[PASS] Test 1.1: All appropriate remediation actions generated for multi-vector threat.")

    # ─────────────────────────────────────────────
    # TEST 2: Threshold Safety — Low-Risk Incident
    # ─────────────────────────────────────────────
    print("\n--- Test 1.2: Threshold Safety for Low-Risk Incident (Score < 60) ---")
    low_risk_data = {
        "analysis_id": "TEST-INC-LOW",
        "sender": "newsletter@safe-company.com",
        "subject": "Weekly Newsletter",
        "risk_score": 15,
        "risk_level": "low",
        "indicators": [],
        "url_analysis": [],
        "attachment_analysis": []
    }

    low_actions = remediation_engine.decide_remediation_plan(low_risk_data)
    print(f"Actions for Low-Risk Email: {len(low_actions)}")
    assert len(low_actions) == 0, "Expected 0 actions for low-risk threat below threshold"
    print("[PASS] Test 1.2: Autonomous engine safely ignored low-risk benign email.")

    # ─────────────────────────────────────────────
    # TEST 3: Execution Modes — Dry-Run vs Live
    # ─────────────────────────────────────────────
    print("\n--- Test 1.3: Dry-Run Mode vs Live Execution Mode ---")
    # Dry Run
    dry_result = remediation_engine.execute_remediation(high_risk_data, actions, dry_run=True)
    assert dry_result.is_dry_run is True
    assert dry_result.status == "simulated"
    assert all(a.status == "simulated" for a in dry_result.executed_actions)
    print(f"Dry-Run Status: {dry_result.status} | Actions Simulated: {dry_result.actions_successful}")

    # Live Execution (Safe Handlers)
    live_result = remediation_engine.execute_remediation(high_risk_data, actions, dry_run=False)
    assert live_result.is_dry_run is False
    assert live_result.status == "completed"
    assert all(a.status == "executed" for a in live_result.executed_actions)
    print(f"Live Execution Status: {live_result.status} | Actions Executed: {live_result.actions_successful}")
    print("[PASS] Test 1.3: Dry-run and Live execution modes function as expected.")

    # ─────────────────────────────────────────────
    # TEST 4: FastAPI Endpoints Verification
    # ─────────────────────────────────────────────
    print("\n--- Test 1.4: FastAPI Remediation Endpoints ---")
    client = TestClient(app)

    # 4.1 POST /api/remediation/dry-run
    req_payload = {
        "sender": "support@phish-domain.xyz",
        "subject": "URGENT Password Expiration Warning",
        "body": "Your credentials will expire. Click http://phish-domain.xyz/reset to enter your current password.",
        "attachments": [
            {"filename": "security_form.docm"}
        ],
        "dry_run": True
    }
    resp_dry = client.post("/api/remediation/dry-run", json=req_payload)
    print(f"POST /api/remediation/dry-run status: {resp_dry.status_code}")
    assert resp_dry.status_code == 200
    dry_data = resp_dry.json()
    assert dry_data["is_dry_run"] is True
    assert dry_data["actions_attempted"] > 0
    print(f"  -> Dry-Run Result: {dry_data['summary'][:80]}...")

    # 4.2 POST /api/remediation/execute-live
       # 4.2 POST /api/remediation/execute-live
    req_payload_live = dict(req_payload)
    req_payload_live["dry_run"] = False
    resp_live = client.post("/api/remediation/execute-live", json=req_payload_live)
    print(f"POST /api/remediation/execute-live status: {resp_live.status_code}")
    assert resp_live.status_code == 200
    live_data = resp_live.json()
    assert live_data["status"] == "completed"
    print(f"  -> Live Result: {live_data['summary'][:80]}...")

    # 4.3 GET /api/remediation/audit-log
    resp_log = client.get("/api/remediation/audit-log")
    print(f"GET /api/remediation/audit-log status: {resp_log.status_code}")
    assert resp_log.status_code == 200
    log_data = resp_log.json()
    assert "total_records" in log_data
    print(f"  -> Total Audit Log Entries: {log_data['total_records']}")

    print("\n" + "=" * 60)
    print("ALL M13 AUTONOMOUS REMEDIATION TESTS PASSED! [SUCCESS]")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()