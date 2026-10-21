"""Pydantic request and response schemas for AgentShield REST security gateway."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from shield.evaluator.red_team import SecurityScorecard


class EvaluateInputRequest(BaseModel):
    """Payload to evaluate an incoming user prompt or retrieved document."""

    text: str = Field(..., max_length=50_000, description="Prompt or untrusted text to evaluate")
    is_retrieved_document: bool = Field(default=False, description="True if text is from an external document/tool")
    redact_pii: bool = Field(default=True, description="Whether to mask detected sensitive personal info")
    source_label: Optional[str] = Field(default="user_prompt", description="Origin identifier for auditing")


class EvaluateInputResponse(BaseModel):
    allowed: bool
    decision: str
    risk_level: str
    sanitized_text: str
    injection_detected: bool
    pii_detected: bool
    detected_entities: List[str]
    reasons: List[str]


class AuthorizeToolRequest(BaseModel):
    """Payload to authorize an agent's proposed tool invocation before execution."""

    user_id: Optional[str] = Field(default=None, description="Optional caller user ID")
    user_role: Optional[str] = Field(default=None, description="Caller role; overridden by verified API key when provided")
    tenant_id: Optional[str] = Field(default=None, description="Caller tenant; overridden by verified API key when provided")
    tool_name: str = Field(...)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    approval_token: Optional[str] = Field(default=None, description="Single-use human review approval token")


class AuthorizeToolResponse(BaseModel):
    allowed: bool
    decision: str
    requires_human_approval: bool
    approval_id: Optional[str] = None
    tool_name: str
    reason: str


class ApproveToolRequest(BaseModel):
    """Request payload to grant human approval for a pending risky tool call."""

    reason: Optional[str] = Field(default="Approved by authorized reviewer")


class ApproveToolResponse(BaseModel):
    success: bool
    approval_id: str
    approval_token: Optional[str] = None
    status: str
    message: str


class RejectToolRequest(BaseModel):
    """Request payload to reject a pending risky tool call."""

    reason: Optional[str] = Field(default="Rejected by reviewer")


class RejectToolResponse(BaseModel):
    success: bool
    approval_id: str
    status: str
    message: str


class ValidateOutputRequest(BaseModel):
    """Payload to inspect model responses before displaying them to users."""

    output_text: str = Field(..., max_length=50_000, description="Generated text to validate")
    canary_secrets: Optional[List[str]] = Field(default=None, description="Protected internal canary tokens")
    expected_schema: Optional[Dict[str, Any]] = Field(default=None, description="Optional expected JSON schema structure")


class ValidateOutputResponse(BaseModel):
    passed: bool
    decision: str
    sanitized_output: str
    leaks_detected: List[str]
    reason: str


class RunEvaluationResponse(BaseModel):
    scorecard: SecurityScorecard
    markdown_report: str
