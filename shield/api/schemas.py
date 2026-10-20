"""Pydantic request and response schemas for AgentShield REST security gateway."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from shield.evaluator.red_team import SecurityScorecard


class EvaluateInputRequest(BaseModel):
    """Payload to evaluate an incoming user prompt or retrieved document."""

    text: str = Field(..., description="Prompt or untrusted text to evaluate")
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

    user_id: str = Field(default="anonymous")
    user_role: str = Field(default="read_only")
    tenant_id: str = Field(default="default_tenant")
    tool_name: str = Field(...)
    arguments: Dict[str, Any] = Field(default_factory=dict)


class AuthorizeToolResponse(BaseModel):
    allowed: bool
    decision: str
    requires_human_approval: bool
    tool_name: str
    reason: str


class ValidateOutputRequest(BaseModel):
    """Payload to inspect model responses before displaying them to users."""

    output_text: str = Field(..., description="Generated text to validate")
    canary_secrets: Optional[List[str]] = Field(default=None, description="Protected internal canary tokens")


class ValidateOutputResponse(BaseModel):
    passed: bool
    decision: str
    sanitized_output: str
    leaks_detected: List[str]
    reason: str


class RunEvaluationResponse(BaseModel):
    scorecard: SecurityScorecard
    markdown_report: str
