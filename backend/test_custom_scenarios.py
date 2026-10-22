"""
Interactive Custom Scenario Tester for M13
Demonstrates: Detection -> Investigation -> Decision -> Autonomous Remediation
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_scenario(title: str, email_data: dict):
    print("\n" + "=" * 70)
    print(f"SCENARIO: {title}")
    print("=" * 70)
    print(f"From:    {email_data['sender']}")
    print(f"Subject: {email_data['subject']}")
    print(f"Body:    {email_data['body'][:75]}...")
    if email_data.get("attachments"):
        print(f"Attach:  {[a['filename'] for a in email_data['attachments']]}")
    print("-" * 70)

    # Call the Live Remediation endpoint
    response = client.post("/api/remediation/execute-live", json=email_data)
    result = response.json()

    # 1. Detection Verdict
    print(f"1. DETECTION RESULT:")
    print(f"   - Risk Score:  {result['risk_score']}/100")
    print(f"   - Threat Tier: {result['threat_level']}")

    # 2. Autonomous Decision & Correction
    print(f"\n2. AUTONOMOUS CORRECTION (Status: {result['status'].upper()}):")
    if result["actions_attempted"] == 0:
        print("   -> NO THREAT DETECTED. No remediation needed. Email allowed.")
    else:
        print(f"   -> {result['actions_successful']} Autonomous Actions Taken:")
        for action in result["executed_actions"]:
            status_icon = "[EXECUTED]" if action["status"] == "executed" else "[SIMULATED]"
            print(f"      * {status_icon} ({action['priority']}) {action['action_type']}")
            print(f"        Target:  {action['target']}")
            print(f"        Action:  {action['details']}")
            # Show simulated system IDs (Firewall rules, quarantine IDs, etc.)
            params = action.get("parameters", {})
            relevant_ids = {k: v for k, v in params.items() if "id" in k or "token" in k}
            if relevant_ids:
                print(f"        Evidence: {relevant_ids}")
            print()

    print(f"Summary: {result['summary']}")


if __name__ == "__main__":
    print("\n" + "#" * 70)
    print("# AUTONOMOUS DETECTION & CORRECTION DEMONSTRATION")
    print("#" * 70)

    # -------------------------------------------------------------
    # SCENARIO A: Normal Benign Email
    # -------------------------------------------------------------
    test_scenario(
        title="A) Clean Business Email (Should NOT remediate)",
        email_data={
            "sender": "sarah.manager@legitimate-company.com",
            "subject": "Project Status Meeting Notes",
            "body": "Hi team, please review the minutes from our Monday sync attached. Have a great week.",
            "attachments": [],
            "dry_run": False
        }
    )

    # -------------------------------------------------------------
    # SCENARIO B: Credential Harvesting Phishing Attack
    # -------------------------------------------------------------
    test_scenario(
        title="B) Microsoft 365 Credential Phish (Detect & Neutralize Link + User Reset)",
        email_data={
            "sender": "security-alert@microsoft-verify-auth.xyz",
            "subject": "CRITICAL: Office 365 Password Expiration in 24 Hours",
            "body": "Your account access will be terminated today. Click http://microsoft-verify-auth.xyz/login to enter your password and OTP immediately to avoid disruption.",
            "attachments": [],
            "dry_run": False
        }
    )

    # -------------------------------------------------------------
    # SCENARIO C: Ransomware / Macro Malware Dropper
    # -------------------------------------------------------------
    test_scenario(
        title="C) Malicious Invoice Dropper (Detect & Isolate File + Quarantine)",
        email_data={
            "sender": "billing@fake-vendor-invoices.com",
            "subject": "Overdue Payment Notice: INV-99824",
            "body": "Please find attached your outstanding invoice. Enable macros to view the digitally signed document.",
            "attachments": [
                {"filename": "overdue_invoice_march.docm"}
            ],
            "dry_run": False
        }
    )