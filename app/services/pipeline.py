"""
Pipeline: AbuseIPDB → enrichment → decision → actions → structured audit log.
"""

from app.models.schemas import AnalyzeResponse
from app.services import abuseipdb, actions, decision_engine, enrichment
from app.utils.logger import get_logger, log_analyze_audit

logger = get_logger()


async def analyze_ip(ip: str) -> AnalyzeResponse:
    """
    Run full SOAR flow for one IP.

    Preserves fail-open behavior: if AbuseIPDB fails or times out, threat_score is 0
    and status becomes safe / action allowed; degradation is recorded in audit logs.
    """
    raw_intel = await abuseipdb.fetch_abuseipdb(ip)
    err = raw_intel.get("raw_error")
    intel_degraded = bool(err)
    if err:
        logger.info(
            "intel_degraded",
            extra={
                "structured": {
                    "event": "intel_degraded",
                    "ip": ip,
                    "intel_detail": err,
                }
            },
        )

    enriched = enrichment.enrich(ip, raw_intel)
    decided = decision_engine.decide(enriched)
    final = actions.execute(decided)

    log_analyze_audit(
        ip=final["ip"],
        country=final.get("country") or "",
        isp=final.get("isp") or "",
        threat_score=final["threat_score"],
        status=final["status"],
        action=final["action"],
        intel_degraded=intel_degraded,
        intel_detail=err if err else None,
    )

    return AnalyzeResponse(
        ip=final["ip"],
        country=final.get("country") or "",
        isp=final.get("isp") or "",
        threat_score=final["threat_score"],
        status=final["status"],
        action=final["action"],
    )
