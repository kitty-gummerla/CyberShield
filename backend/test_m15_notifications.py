"""
M15 Autonomous User & Admin Notification Verification Script
"""

import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.remediation_engine import remediation_engine
from services.verification_service import verification_service
from services.notification_service import notification_service
from fastapi.testclient import TestClient
from main import app


def run_tests():
    print("=" * 60)
    print("RUNNING M15 NOTIFICATION & INCIDENT REPORTING TESTS")
    print("=" * 60)

    # 1. Simulate Threat Remediation + Verification Pipeline (M13 + M14)
    print("\n--- Test 1.1: Generate Incident & Dispatch Notifications ---")
    threat_data = {
        "analysis_id": "TEST-INC-M15",
        "sender": "attacker@malicious-payroll.xyz",
        "subject": "URGENT Payment Request",
        "risk_score": 85,
        "risk_level": "high",
        "indicators": [
            {"indicator": "credential_request", "severity": "high"}
        ],
        "url_analysis": [
            {"url": "http://login.malicious-payroll.xyz/verify", "is_suspicious": True, "risk_level": "high"}
        ],
        "attachment_analysis": []
    }

    actions = remediation_engine.decide_remediation_plan(threat_data)
    remediation_res = remediation_engine.execute_remediation(threat_data, actions, dry_run=False)
    reassessment_rep = verification_service.verify_and_reassess(remediation_res)

    # 2. Dispatch Notifications (M15)
    dispatch = notification_service.dispatch_incident_notifications(
        remediation_result=remediation_res,
        reassessment_report=reassessment_rep,
        target_user_email="employee.victim@organization.com"
    )

    print(f"Dispatch ID:           {dispatch.dispatch_id}")
    print(f"Delivered Channels:    {dispatch.channels_delivered}")
    print(f"User Notif Subject:    {dispatch.user_notification.subject}")
    print(f"Admin Notif Subject:   {dispatch.admin_notification.subject}")

    assert dispatch.user_notification is not None
    assert dispatch.admin_notification is not None
    assert "not need to take any action" in dispatch.user_notification.message.lower()
    assert "INCIDENT RESOLUTION REPORT" in dispatch.admin_notification.message
    print("[PASS] Test 1.1: Tailored notifications generated for both user and admin.")

    # 3. Test In-App Notification Querying & Filtering
    print("\n--- Test 1.2: In-App Notification Inbox & Filtering ---")
    user_notifs = notification_service.get_all_notifications(recipient_type="user")
    admin_notifs = notification_service.get_all_notifications(recipient_type="admin")
    print(f"User Notifications in Inbox:  {len(user_notifs)}")
    print(f"Admin Notifications in Inbox: {len(admin_notifs)}")

    assert len(user_notifs) >= 1
    assert len(admin_notifs) >= 1
    print("[PASS] Test 1.2: In-app notification queue correctly filters by recipient role.")

    # 4. Test FastAPI HTTP Endpoints
    print("\n--- Test 1.3: FastAPI Notification Endpoints ---")
    client = TestClient(app)

    # 4.1 GET /api/notifications
    resp_get = client.get("/api/notifications")
    print(f"GET /api/notifications status: {resp_get.status_code}")
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["total_notifications"] >= 2
    assert "unread_count" in data

    # 4.2 PATCH /api/notifications/{id}/read
    first_notif_id = data["notifications"][0]["notification_id"]
    resp_patch = client.patch(f"/api/notifications/{first_notif_id}/read")
    print(f"PATCH /api/notifications/{first_notif_id}/read status: {resp_patch.status_code}")
    assert resp_patch.status_code == 200

    # 4.3 POST /api/notifications/dispatch-live
    payload = {
        "remediation_result": remediation_res.model_dump(mode="json"),
        "reassessment_report": reassessment_rep.model_dump(mode="json"),
        "target_user_email": "custom.user@organization.com"
    }
    resp_live = client.post("/api/notifications/dispatch-live", json=payload)
    print(f"POST /api/notifications/dispatch-live status: {resp_live.status_code}")
    assert resp_live.status_code == 200
    live_dispatch = resp_live.json()
    assert live_dispatch["user_notification"]["recipient"] == "custom.user@organization.com"

    print("\n" + "=" * 60)
    print("ALL M15 NOTIFICATION & INCIDENT REPORTING TESTS PASSED! [SUCCESS]")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()