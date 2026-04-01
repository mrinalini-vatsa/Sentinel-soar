"""
Structured JSON logging: one JSON object per line (stdout + file).

Each /analyze completion emits an audit record with:
timestamp, ip, country, isp, threat_score, status, action.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from app.core.config import get_settings

_LOGGER_NAME = "sentinel_soar"


class _JsonLineFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        extra = getattr(record, "structured", None)
        if isinstance(extra, Mapping):
            payload.update(dict(extra))
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """
    Configure JSON line logging to stdout and `log_file` (from settings by default).
    """
    settings = get_settings()
    path = log_file or settings.log_file
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log = logging.getLogger(_LOGGER_NAME)
    log.setLevel(logging.INFO)
    if log.handlers:
        return log

    fmt = _JsonLineFormatter()
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(ch)
    log.propagate = False
    return log


def log_analyze_audit(
    *,
    ip: str,
    country: str,
    isp: str,
    threat_score: int,
    status: str,
    action: str,
    intel_degraded: bool = False,
    intel_detail: Optional[str] = None,
) -> None:
    """One structured JSON line per analyze request."""
    log = logging.getLogger(_LOGGER_NAME)
    record: dict[str, Any] = {
        "event": "analyze_request",
        "ip": ip,
        "country": country,
        "isp": isp,
        "threat_score": threat_score,
        "status": status,
        "action": action,
    }
    if intel_degraded:
        record["intel_degraded"] = True
    if intel_detail:
        record["intel_detail"] = intel_detail
    log.info("analyze_request", extra={"structured": record})


def get_logger() -> logging.Logger:
    """Same application logger (structured JSON)."""
    return logging.getLogger(_LOGGER_NAME)
