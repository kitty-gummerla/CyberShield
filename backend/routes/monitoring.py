"""
Continuous Monitoring API Routes (Milestone 16)

Provides endpoints to:
1. GET  /api/monitoring/status    -> Retrieve live monitoring state, counters, and metrics.
2. POST /api/monitoring/start     -> Launch the continuous background polling task.
3. POST /api/monitoring/stop      -> Stop the continuous background task.
4. POST /api/monitoring/poll-now  -> Manually trigger an immediate single evaluation cycle.
5. GET  /api/monitoring/events    -> Retrieve recent telemetry events.
6. POST /api/monitoring/reset     -> Clear the processed email deduplication cache.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
import logging

from models.schemas import (
    MonitoringStatus,
    MonitoringCycleResult,
    MonitoringStartRequest,
    MonitoringEvent
)
from services.monitoring_service import monitoring_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/monitoring", tags=["Continuous Monitoring & Watchdog"])


# ─────────────────────────────────────────────
# 1. GET MONITORING STATUS
# ─────────────────────────────────────────────
@router.get(
    "/status",
    response_model=MonitoringStatus,
    summary="Get continuous monitoring status and metrics",
    description="Returns whether the engine is active, total cycles, emails scanned, threats neutralized, and recent events."
)
async def get_monitoring_status():
    return monitoring_service.get_status()


# ─────────────────────────────────────────────
# 2. START CONTINUOUS MONITORING
# ─────────────────────────────────────────────
@router.post(
    "/start",
    summary="Start continuous background monitoring",
    description="Starts the asynchronous watchdog loop to periodically check inboxes and autonomously remediate threats."
)
async def start_monitoring(request: MonitoringStartRequest):
    started = monitoring_service.start_monitoring(
        poll_interval_seconds=request.poll_interval_seconds,
        auto_remediate=request.auto_remediate,
        provider=request.provider
    )
    if not started:
        return {
            "status": "already_running",
            "message": "Continuous monitoring is already active.",
            "current_status": monitoring_service.get_status()
        }
    return {
        "status": "started",
        "message": f"Continuous monitoring started with {request.poll_interval_seconds}s polling interval.",
        "current_status": monitoring_service.get_status()
    }


# ─────────────────────────────────────────────
# 3. STOP CONTINUOUS MONITORING
# ─────────────────────────────────────────────
@router.post(
    "/stop",
    summary="Stop continuous background monitoring",
    description="Gracefully cancels the background polling worker."
)
async def stop_monitoring():
    monitoring_service.stop_monitoring()
    return {
        "status": "stopped",
        "message": "Continuous monitoring stopped successfully."
    }


# ─────────────────────────────────────────────
# 4. POLL NOW (SINGLE IMMEDIATE CYCLE)
# ─────────────────────────────────────────────
@router.post(
    "/poll-now",
    response_model=MonitoringCycleResult,
    summary="Trigger immediate single evaluation cycle",
    description="Runs a single-pass inspection immediately without waiting for the background timer."
)
async def poll_now():
    try:
        result = await monitoring_service.run_single_cycle()
        return result
    except Exception as e:
        logger.error(f"Manual poll cycle failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Poll cycle failed: {str(e)}")


# ─────────────────────────────────────────────
# 5. GET RECENT TELEMETRY EVENTS
# ─────────────────────────────────────────────
@router.get(
    "/events",
    response_model=List[MonitoringEvent],
    summary="Get recent monitoring telemetry events",
    description="Returns the live stream of detection, remediation, and verification events."
)
async def get_events(limit: int = Query(default=20, ge=1, le=50)):
    return monitoring_service.get_events(limit=limit)


# ─────────────────────────────────────────────
# 6. RESET PROCESSED CACHE
# ─────────────────────────────────────────────
@router.post(
    "/reset",
    summary="Reset processed email cache",
    description="Clears deduplication memory so existing inbox items can be re-evaluated on the next cycle."
)
async def reset_cache():
    monitoring_service.reset_processed_cache()
    return {"status": "ok", "message": "Deduplication cache cleared. Ready for re-evaluation."}