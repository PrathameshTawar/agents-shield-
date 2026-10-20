"""Domain models, security risk levels, and decision structures for AgentShield."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


class SecurityRiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionDecision(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class InputEvaluation(BaseModel):
    """Result of evaluating incoming user requests or untrusted retrieved documents."""

    sanitized_text: str
    decision: ActionDecision
    risk_level: SecurityRiskLevel
    injection_detected: bool = False
    pii_detected: bool = False
    detected_entities: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    """Proposed tool action submitted for authorization before execution."""

    user_id: str = "anonymous"
    user_role: str = "read_only"
    tenant_id: str = "default_tenant"
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolAuthDecision(BaseModel):
    """Authoritative decision on whether an agent tool call is permitted to execute."""

    allowed: bool
    decision: ActionDecision
    requires_human_approval: bool = False
    reason: str
    tool_name: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OutputValidationResult(BaseModel):
    """Result of inspecting model-generated responses before returning to users."""

    sanitized_output: str
    passed: bool
    decision: ActionDecision
    leaks_detected: List[str] = Field(default_factory=list)
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
