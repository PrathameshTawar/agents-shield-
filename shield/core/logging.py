"""Structured audit logging for AgentShield security decisions."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("agentshield.audit")
logger.setLevel(logging.INFO)

# Formatter producing strict JSON lines
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def audit_log(
    event_type: str,
    decision: str,
    risk_level: Optional[str] = None,
    user_id: Optional[str] = None,
    user_role: Optional[str] = None,
    tenant_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    rules_triggered: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Records an immutable structured audit log entry for every security perimeter decision."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id or str(uuid4()),
        "event_type": event_type,
        "decision": decision,
        "risk_level": risk_level,
        "client": {
            "user_id": user_id or "anonymous",
            "user_role": user_role or "unknown",
            "tenant_id": tenant_id or "unknown",
        },
        "tool_name": tool_name,
        "rules_triggered": rules_triggered or [],
        "metadata": metadata or {},
    }
    logger.info(json.dumps(log_entry))
    return log_entry
