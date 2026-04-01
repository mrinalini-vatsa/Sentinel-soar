"""
AbuseIPDB integration: IP reputation, geo, and report counts using `requests` with timeouts.

On timeout, connection errors, or HTTP errors, returns a fail-open payload with `raw_error` set.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

import requests

from app.core.config import get_settings


def fetch_abuseipdb_sync(ip: str) -> Dict[str, Any]:
    """
    Synchronous AbuseIPDB check (run via asyncio.to_thread from async routes).

    Returns keys: threat_score, country, isp, malicious_count, raw_error (optional).
    """
    settings = get_settings()
    key = (settings.abuseipdb_api_key or "").strip()
    base = settings.abuseipdb_base_url.rstrip("/")
    url = f"{base}/check"
    timeout = settings.abuseipdb_timeout_seconds

    if not key:
        return _failure_payload(
            ip,
            "ABUSEIPDB_API_KEY is not set; add it to .env",
        )

    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.Timeout:
        return _failure_payload(ip, f"AbuseIPDB request timed out after {timeout}s")
    except requests.RequestException as exc:
        return _failure_payload(ip, f"Network error: {exc}")

    if resp.status_code == 401:
        return _failure_payload(ip, "AbuseIPDB returned 401 (invalid API key)")
    if resp.status_code == 429:
        return _failure_payload(ip, "AbuseIPDB rate limited (429)")
    if resp.status_code != 200:
        return _failure_payload(
            ip,
            f"AbuseIPDB HTTP {resp.status_code}: {resp.text[:200]}",
        )

    try:
        body = resp.json()
    except ValueError:
        return _failure_payload(ip, "Invalid JSON from AbuseIPDB")

    data = body.get("data") or {}
    score = int(data.get("abuseConfidenceScore") or 0)
    score = max(0, min(100, score))

    return {
        "threat_score": score,
        "country": str(data.get("countryCode") or "").upper()[:2] or "",
        "isp": str(data.get("isp") or "").strip() or "Unknown",
        "malicious_count": int(data.get("totalReports") or 0),
        "raw_error": None,
    }


async def fetch_abuseipdb(ip: str) -> Dict[str, Any]:
    """Async wrapper so FastAPI handlers stay non-blocking."""
    return await asyncio.to_thread(fetch_abuseipdb_sync, ip)


def _failure_payload(ip: str, message: str) -> Dict[str, Any]:
    """Fail-open defaults when intel is unavailable."""
    return {
        "threat_score": 0,
        "country": "",
        "isp": "",
        "malicious_count": 0,
        "raw_error": message,
    }
