"""
Alert enrichment: merge raw IP with threat-intel fields into one structured record.

This layer stays independent of HTTP so it can be reused from CLI, Streamlit, or workers.
"""

from typing import Any, Dict


def enrich(ip: str, intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine client IP with AbuseIPDB-derived attributes.

    Args:
        ip: Address under analysis
        intel: Output of abuseipdb.fetch_abuseipdb

    Returns:
        Flat dict suitable for decision_engine + actions + API response assembly.
    """
    return {
        "ip": ip.strip(),
        "country": intel.get("country") or "",
        "isp": intel.get("isp") or "Unknown",
        "threat_score": int(intel.get("threat_score") or 0),
        "malicious_count": int(intel.get("malicious_count") or 0),
    }
