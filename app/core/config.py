"""
Application settings from environment variables and optional `.env`.

Supports `ABUSEIPDB_API_KEY` (preferred) and legacy `API_KEY` for the same value.
"""

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SentinelSOAR service configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    abuseipdb_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "API_KEY"),
        description="AbuseIPDB API key",
    )
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    abuseipdb_timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)

    log_file: str = "logs.jsonl"


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
