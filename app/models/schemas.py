"""
Pydantic models for API request/response validation.
"""

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    """POST /analyze body."""

    ip: str = Field(..., min_length=3, max_length=45, description="IPv4 or IPv6 address")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        s = (v or "").strip()
        try:
            ipaddress.ip_address(s)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {v!r}") from exc
        return s


class AnalyzeResponse(BaseModel):
    """SOAR analysis result."""

    ip: str
    country: str = Field(default="", description="ISO country code or empty if unknown")
    isp: str = Field(default="", description="ISP / organization name")
    threat_score: int = Field(..., ge=0, le=100, description="0–100 abuse confidence style score")
    status: Literal["malicious", "suspicious", "safe"] = Field(
        ...,
        description="malicious (>70), suspicious (40–70), or safe (<40)",
    )
    action: Literal["blocked", "monitored", "allowed"] = Field(
        ...,
        description="blocked, monitored, or allowed (simulated)",
    )
