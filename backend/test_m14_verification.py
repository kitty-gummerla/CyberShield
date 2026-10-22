"""
M14 Remediation Verification & Risk Reassessment Verification Script
"""

import sys
import os
from datetime import datetime

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.remediation_engine import remediation_engine
from services.verification_service import verification_service
from models.schemas import RemediationExecutionRequest
from fastapi.testclient import TestClient
from main import app


def run_tests():
    print("=" * 60)
    print("RUNNING M14 VERIFICATION & RISK REASSESSMENT TESTS")
    print("=" * 60)

    # ─────────────────────────────────────────────
    # TEST 1: Service Verification & Risk Recalculation
    # ─────────────────────────────────────────────
    print("\n--- Test 1.1: Verification of High-Risk Threat Remediation ---")
    high_threat_data = {
        "analysis_id": "TEST-INC-M14",
        "sender": "attacker@malicious-payroll.xyz",
        "subject": "URGENT Invoice Verification Required",
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

    # Generate and execute remediation (M13)
    actions = remediation_engine.decide_remediation_plan(high_threat_data)
    remediation_res = remediation_engine.execute_remediation(high_threat_data, actions, dry_run=False)
    print(f"Executed Remediation: {remediation_res.actions_successful} actions completed.")

    # Now verify and reassess risk (M14)
    report = verification_service.verify_and_reassess(remediation_res)
    print(f"Verification Report ID: {report.verification_id}")
    print(f"Containment Status:     {report.containment_status}")
    print(f"Initial Risk Score:     {report.initial_risk_score} ({report.initial_threat_level})")
    print(f"Residual Risk Score:    {report.residual_risk_score} ({report.residual_threat_level})")
    print(f"Risk Reduction:         {report.risk_reduction_percentage}%")
    print(f"Controls Verified:      {report.actions_verified}/{report.total_actions_checked}")

    assert report.containment_status == "FULLY_CONTAINED"
    assert report.residual_risk_score < report.initial_risk_score
    assert report.risk_reduction_percentage > 50.0
    assert report.actions_verified == len(actions)
    print("[PASS] Test 1.1: Verification successfully reduced risk and confirmed FULLY_CONTAINED status.")

    # ─────────────────────────────────────────────
    # TEST 2: Low-Risk Threat Verification
    # ─────────────────────────────────────────────
    print("\n--- Test 1.2: Verification of Low-Risk Benign Email ---")
    low_threat_data = {
        "analysis_id": "TEST-INC-LOW",
        "sender": "newsletter@safe.org",
        "subject": "Weekly Tech Digest",
        "risk_score": 10,
        "risk_level": "low"
    }
    low_actions = remediation_engine.decide_remediation_plan(low_threat_data)
    low_remediation_res = remediation_engine.execute_remediation(low_threat_data, low_actions, dry_run=False)
    low_report = verification_service.verify_and_reassess(low_remediation_res)

    print(f"Low Threat Containment Status: {low_report.containment_status}")
    print(f"Initial Score: {low_report.initial_risk_score} -> Residual Score: {low_report.residual_risk_score}")
    assert low_report.total_actions_checked == 0
    assert low_report.containment_status == "FULLY_CONTAINED"
    print("[PASS] Test 1.2: Low-risk email verified with normal posture.")

    # ─────────────────────────────────────────────
    # TEST 3: FastAPI Endpoints Verification (/api/verification/...)
    # ─────────────────────────────────────────────
    print("\n--- Test 1.3: Verification API Endpoint (/api/verification/verify-live) ---")
    client = TestClient(app)

    # 3.1 Send remediation result directly to /api/verification/verify-live
    response = client.post("/api/verification/verify-live", json=remediation_res.model_dump(mode="json"))
    print(f"POST /api/verification/verify-live status: {response.status_code}")
    assert response.status_code == 200

    api_report = response.json()
    assert "verification_id" in api_report
    assert api_report["containment_status"] == "FULLY_CONTAINED"
    assert "risk_reduction_percentage" in api_report
    print(f"  -> API Residual Risk Score: {api_report['residual_risk_score']}/100")
    print(f"  -> Risk Reduction:          {api_report['risk_reduction_percentage']}%")
    print(f"  -> Recommended Next Steps:  {len(api_report['next_recommended_steps'])} steps")
    print("[PASS] Test 1.3: Verification API endpoint returned 200 OK and valid report schema.")

    print("\n" + "=" * 60)
    print("ALL M14 VERIFICATION & REASSESSMENT TESTS PASSED! [SUCCESS]")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()