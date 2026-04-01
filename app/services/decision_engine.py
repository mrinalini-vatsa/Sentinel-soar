"""
Rule-based decision: map AbuseIPDB-style threat score to status.

- score > 70  → malicious
- 40 ≤ score ≤ 70 → suspicious
- else → safe
"""

from typing import Any, Dict, Literal

THRESHOLD_HIGH = 70
THRESHOLD_LOW = 40


def decide(enriched: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply SentinelSOAR policy to the enriched record.

    Adds `status`: malicious | suspicious | safe
    """
    score = int(enriched.get("threat_score") or 0)
    if score > THRESHOLD_HIGH:
        status: Literal["malicious", "suspicious", "safe"] = "malicious"
    elif score >= THRESHOLD_LOW:
        status = "suspicious"
    else:
        status = "safe"

    return {**enriched, "status": status}
