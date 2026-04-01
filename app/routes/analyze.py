"""
IP analysis endpoint: threat intel, enrichment, decision, simulated actions.
"""

import logging

from fastapi import APIRouter, HTTPException

from app.models.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.pipeline import analyze_ip

router = APIRouter(tags=["soar"])
log = logging.getLogger("sentinel_soar")


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze an IP against AbuseIPDB, enrich, apply policy, and return a decision.

    Invalid IPs are rejected with **422** (validation). Unexpected server errors return **500**.
    External API failures still return **200** with fail-open scores (0) and audit `intel_degraded`.
    """
    try:
        return await analyze_ip(body.ip)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — last-resort handler; details not exposed to client
        log.info(
            "analyze_internal_error",
            extra={
                "structured": {
                    "event": "analyze_internal_error",
                    "error_type": type(exc).__name__,
                }
            },
        )
        raise HTTPException(status_code=500, detail="Internal error during analysis") from exc
