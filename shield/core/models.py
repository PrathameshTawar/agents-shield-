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


class UserIdentity(BaseModel):
    """Server-verified identity of the caller."""

    user_id: str = "anonymous"
    user_role: str = "read_only"
    tenant_id: str = "default_tenant"
    is_authenticated: bool = False


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
    approval_token: Optional[str] = Field(default=None, description="One-time signed human approval token")


class ToolAuthDecision(BaseModel):
    """Authoritative decision on whether an agent tool call is permitted to execute."""

    allowed: bool
    decision: ActionDecision
    requires_human_approval: bool = False
    approval_id: Optional[str] = Field(default=None, description="Pending approval ID if human review is required")
    reason: str
    tool_name: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PendingApproval(BaseModel):
    """Record of an action queued for human reviewer authorization."""

    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    tool_name: str
    user_id: str
    user_role: str
    tenant_id: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"  # pending, approved, rejected, used, expired
    approval_token: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(...)


class OutputValidationResult(BaseModel):
    """Result of inspecting model-generated responses before returning to users."""

    sanitized_output: str
    passed: bool
    decision: ActionDecision
    leaks_detected: List[str] = Field(default_factory=list)
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
