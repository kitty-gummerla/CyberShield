"""
M16 Continuous Monitoring Engine Verification Script
"""

import sys
import os
import asyncio

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.monitoring_service import monitoring_service
from fastapi.testclient import TestClient
from main import app


def run_tests():
    print("=" * 60)
    print("RUNNING M16 CONTINUOUS MONITORING TESTS")
    print("=" * 60)

    # Reset cache to ensure clean test state
    monitoring_service.reset_processed_cache()

    # ────────────────────────────────────────────────────────
    # 1. Test Single Evaluation Cycle (Autonomous Chaining)
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.1: Single Evaluation Cycle & Autonomous Pipeline ---")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cycle_result = loop.run_until_complete(monitoring_service.run_single_cycle())

    print(f"Cycle ID:                {cycle_result.cycle_id}")
    print(f"Emails Evaluated:        {cycle_result.emails_evaluated}")
    print(f"Threats Found:           {cycle_result.new_threats_found}")
    print(f"Remediations Executed:   {cycle_result.remediations_executed}")

    assert cycle_result.emails_evaluated == 4, f"Expected 4 emails evaluated, got {cycle_result.emails_evaluated}"
    assert cycle_result.new_threats_found == 2, f"Expected 2 high-risk threats (score >= 60), got {cycle_result.new_threats_found}"
    assert cycle_result.remediations_executed > 0, "Expected autonomous remediations to execute"
    print("[PASS] Test 1.1: Single cycle ingested all emails and autonomously neutralized threats.")

    # ────────────────────────────────────────────────────────
    # 2. Test Deduplication (Second Cycle Should Skip Processed)
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.2: Deduplication Protection ---")
    second_cycle = loop.run_until_complete(monitoring_service.run_single_cycle())
    print(f"Second Cycle Emails:     {second_cycle.emails_evaluated}")
    print(f"Second Cycle Threats:    {second_cycle.new_threats_found}")

    assert second_cycle.emails_evaluated == 0, "Deduplication failed: already-processed emails were re-evaluated!"
    print("[PASS] Test 1.2: Deduplication correctly prevented redundant scans.")

    # ────────────────────────────────────────────────────────
    # 3. Test Monitoring Engine Status & Metrics
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.3: Monitoring Engine Metrics & Telemetry ---")
    status = monitoring_service.get_status()
    print(f"Total Cycles Completed:  {status.total_cycles_completed}")
    print(f"Total Emails Scanned:    {status.total_emails_scanned}")
    print(f"Threats Neutralized:     {status.threats_detected}")
    print(f"Remediations Triggered:  {status.remediations_triggered}")
    print(f"Notifications Sent:      {status.notifications_dispatched}")
    print(f"Recent Events in Log:    {len(status.recent_events)}")

    assert status.total_cycles_completed >= 2
    assert status.total_emails_scanned == 4
    assert status.threats_detected == 2
    assert status.notifications_dispatched >= 4
    assert len(status.recent_events) > 0
    print("[PASS] Test 1.3: Monitoring status counters and telemetry accurately tracked.")

    # ────────────────────────────────────────────────────────
    # 4. Test FastAPI HTTP Endpoints
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.4: FastAPI Continuous Monitoring Endpoints ---")
    client = TestClient(app)

    # 4.1 GET /api/monitoring/status
    resp_status = client.get("/api/monitoring/status")
    print(f"GET /api/monitoring/status: {resp_status.status_code}")
    assert resp_status.status_code == 200
    assert resp_status.json()["total_emails_scanned"] == 4

    # 4.2 GET /api/monitoring/events
    resp_events = client.get("/api/monitoring/events?limit=5")
    print(f"GET /api/monitoring/events: {resp_events.status_code}")
    assert resp_events.status_code == 200
    events = resp_events.json()
    assert len(events) > 0
    print(f"Latest Event: [{events[0]['event_type']}] {events[0]['message']}")

    # 4.3 POST /api/monitoring/reset
    resp_reset = client.post("/api/monitoring/reset")
    print(f"POST /api/monitoring/reset: {resp_reset.status_code}")
    assert resp_reset.status_code == 200

    # 4.4 POST /api/monitoring/poll-now
    resp_poll = client.post("/api/monitoring/poll-now")
    print(f"POST /api/monitoring/poll-now: {resp_poll.status_code}")
    assert resp_poll.status_code == 200
    poll_data = resp_poll.json()
    assert poll_data["emails_evaluated"] == 4  # Because we reset cache
    print(f"Poll-now Evaluated: {poll_data['emails_evaluated']} emails")

    # 4.5 POST /api/monitoring/start and /stop
    resp_start = client.post("/api/monitoring/start", json={"poll_interval_seconds": 10, "auto_remediate": True})
    print(f"POST /api/monitoring/start: {resp_start.status_code}")
    assert resp_start.status_code == 200
    assert resp_start.json()["status"] == "started"

    resp_stop = client.post("/api/monitoring/stop")
    print(f"POST /api/monitoring/stop: {resp_stop.status_code}")
    assert resp_stop.status_code == 200
    assert resp_stop.json()["status"] == "stopped"

    print("[PASS] Test 1.4: All FastAPI monitoring endpoints responded successfully.")

    print("\n" + "=" * 60)
    print("ALL M16 CONTINUOUS MONITORING TESTS PASSED SUCCESSFULLY! [SUCCESS]")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()