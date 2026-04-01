"""
Action module: simulate SOAR outcomes (no real firewall changes).

Maps status → API action: malicious → blocked, suspicious → monitored, safe → allowed.
Audit fields are logged once in the pipeline (`log_analyze_audit`).
"""

from typing import Any, Dict, Literal

ActionLiteral = Literal["blocked", "monitored", "allowed"]


def execute(decided: Dict[str, Any]) -> Dict[str, Any]:
    """Attach `action` for the API response."""
    status = decided.get("status", "safe")

    if status == "malicious":
        action: ActionLiteral = "blocked"
    elif status == "suspicious":
        action = "monitored"
    else:
        action = "allowed"

    return {**decided, "action": action}
