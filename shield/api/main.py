"""FastAPI security gateway exposing guardrails, tool authorization, output filtering, approval workflow, and red-team benchmarks."""

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from shield import __version__
from shield.api.schemas import (
    ApproveToolRequest,
    ApproveToolResponse,
    AuthorizeToolRequest,
    AuthorizeToolResponse,
    EvaluateInputRequest,
    EvaluateInputResponse,
    RejectToolRequest,
    RejectToolResponse,
    RunEvaluationResponse,
    ValidateOutputRequest,
    ValidateOutputResponse,
)
from shield.core.auth import approval_store, get_current_identity
from shield.core.config import settings
from shield.core.logging import audit_log
from shield.core.models import ActionDecision, SecurityRiskLevel, ToolCallRequest, UserIdentity
from shield.evaluator.red_team import RedTeamEvaluator
from shield.guards.injection import InjectionGuard
from shield.guards.output_validator import OutputValidator
from shield.guards.pii import PIIRedactor
from shield.guards.tool_authorizer import ToolAuthorizer

app = FastAPI(
    title="AgentShield Security Gateway",
    version=__version__,
    description="Evaluated AI Guardrails, Prompt-Injection Defense, Tool Authorization, and Red-Team Platform",
)

# Static files for Apple HIG frontend
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", tags=["UI"], include_in_schema=False)
def serve_ui():
    """Serves Apple HIG frontend interface."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "AgentShield API active. Static UI not built."}


# Core guard instances configured via runtime settings
injection_guard = InjectionGuard(risk_threshold=settings.INJECTION_RISK_THRESHOLD)
pii_redactor = PIIRedactor()
tool_authorizer = ToolAuthorizer(
    allowed_domains=settings.ALLOWED_DESTINATION_DOMAINS,
    unauthorized_domains=settings.PROHIBITED_DOMAINS,
)
output_validator = OutputValidator(
    redact_pii=settings.ENABLE_PII_REDACTION,
    allowed_domains=settings.ALLOWED_DESTINATION_DOMAINS,
    prohibited_domains=settings.PROHIBITED_DOMAINS,
)
red_team_evaluator = RedTeamEvaluator()


@app.get("/health", tags=["System"])
def health_check():
    """Returns service operational health, version, and active defense configuration."""
    return {
        "status": "healthy",
        "service": "AgentShield",
        "version": __version__,
        "environment": settings.ENVIRONMENT,
        "features": {
            "injection_defense": True,
            "pii_redaction": settings.ENABLE_PII_REDACTION,
            "tool_authorization": settings.ENABLE_TOOL_AUTHORIZATION,
            "output_validation": settings.ENABLE_OUTPUT_VALIDATION,
            "auth_enforced": settings.REQUIRE_API_KEY,
        },
    }


@app.post(
    "/guardrails/evaluate-input",
    response_model=EvaluateInputResponse,
    tags=["Guardrails"],
)
def evaluate_input(payload: EvaluateInputRequest):
    """Evaluates user requests or retrieved documents for prompt injection and sensitive PII."""
    text_to_eval = payload.text
    reasons = []

    # 1. Prompt Injection Evaluation
    is_attack, risk_level, injection_reasons, score = injection_guard.evaluate(
        text_to_eval, is_retrieved_document=payload.is_retrieved_document
    )
    reasons.extend(injection_reasons)

    if is_attack:
        sanitized_quarantined = (
            injection_guard.isolate_untrusted_content(
                text_to_eval, source_label=payload.source_label or "quarantined_document"
            )
            if payload.is_retrieved_document
            else "[REQUEST_BLOCKED_SECURITY_VIOLATION]"
        )

        audit_log(
            event_type="evaluate_input",
            decision=ActionDecision.BLOCK.value,
            risk_level=risk_level.value,
            rules_triggered=reasons,
            metadata={"score": score, "is_document": payload.is_retrieved_document},
        )

        return EvaluateInputResponse(
            allowed=False,
            decision=ActionDecision.BLOCK.value,
            risk_level=risk_level.value,
            sanitized_text=sanitized_quarantined,
            injection_detected=True,
            pii_detected=False,
            detected_entities=[],
            reasons=reasons,
        )

    # 2. PII Redaction
    sanitized = text_to_eval
    detected_entities = []
    pii_detected = False

    if payload.redact_pii and settings.ENABLE_PII_REDACTION:
        sanitized, detected_entities = pii_redactor.redact(text_to_eval)
        pii_detected = len(detected_entities) > 0
        if pii_detected:
            reasons.append(f"PII entities redacted: {', '.join(detected_entities)}")

    # 3. Document isolation if retrieved
    if payload.is_retrieved_document:
        sanitized = injection_guard.isolate_untrusted_content(
            sanitized, source_label=payload.source_label or "retrieved_document"
        )

    decision = ActionDecision.REDACT if pii_detected else ActionDecision.ALLOW

    audit_log(
        event_type="evaluate_input",
        decision=decision.value,
        risk_level=SecurityRiskLevel.SAFE.value,
        rules_triggered=reasons,
        metadata={"entities": detected_entities, "is_document": payload.is_retrieved_document},
    )

    return EvaluateInputResponse(
        allowed=True,
        decision=decision.value,
        risk_level=SecurityRiskLevel.SAFE.value,
        sanitized_text=sanitized,
        injection_detected=False,
        pii_detected=pii_detected,
        detected_entities=detected_entities,
        reasons=reasons,
    )


@app.post(
    "/guardrails/authorize-tool",
    response_model=AuthorizeToolResponse,
    tags=["Guardrails"],
)
def authorize_tool(
    payload: AuthorizeToolRequest,
    caller: UserIdentity = Depends(get_current_identity),
):
    """Pre-execution interceptor authorizing or blocking proposed agent tool actions using verified server-side identity."""
    # When caller is authenticated via API key, identity is taken from verified server credential, NOT request body!
    if caller.is_authenticated:
        effective_role = caller.user_role
        effective_tenant = caller.tenant_id
        effective_user = caller.user_id
    else:
        # Development / permissive mode: fallback to provided payload values
        effective_role = payload.user_role or caller.user_role
        effective_tenant = payload.tenant_id or caller.tenant_id
        effective_user = payload.user_id or caller.user_id

    request = ToolCallRequest(
        user_id=effective_user,
        user_role=effective_role,
        tenant_id=effective_tenant,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        approval_token=payload.approval_token,
    )

    decision = tool_authorizer.authorize(request)

    audit_log(
        event_type="authorize_tool",
        decision=decision.decision.value,
        user_id=effective_user,
        user_role=effective_role,
        tenant_id=effective_tenant,
        tool_name=decision.tool_name,
        rules_triggered=[decision.reason],
        metadata={
            "authenticated": caller.is_authenticated,
            "requires_human_approval": decision.requires_human_approval,
            "approval_id": decision.approval_id,
        },
    )

    return AuthorizeToolResponse(
        allowed=decision.allowed,
        decision=decision.decision.value,
        requires_human_approval=decision.requires_human_approval,
        approval_id=decision.approval_id,
        tool_name=decision.tool_name,
        reason=decision.reason,
    )


@app.post(
    "/guardrails/approvals/{approval_id}/approve",
    response_model=ApproveToolResponse,
    tags=["Guardrails"],
)
def approve_pending_tool_call(
    approval_id: str,
    payload: ApproveToolRequest,
    reviewer: UserIdentity = Depends(get_current_identity),
):
    """Grants human reviewer authorization for a pending risky tool call and issues a single-use token."""
    # In unauthenticated dev mode, grant admin role if not provided
    effective_reviewer = reviewer
    if not reviewer.is_authenticated and reviewer.user_role == "read_only":
        effective_reviewer = UserIdentity(
            user_id="dev_admin",
            user_role="admin",
            tenant_id=reviewer.tenant_id,
            is_authenticated=True,
        )

    success, token, msg = approval_store.approve(approval_id, effective_reviewer)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    audit_log(
        event_type="approval_granted",
        decision="approved",
        user_id=effective_reviewer.user_id,
        user_role=effective_reviewer.user_role,
        metadata={"approval_id": approval_id, "reason": payload.reason},
    )

    return ApproveToolResponse(
        success=True,
        approval_id=approval_id,
        approval_token=token,
        status="approved",
        message=msg,
    )


@app.post(
    "/guardrails/approvals/{approval_id}/reject",
    response_model=RejectToolResponse,
    tags=["Guardrails"],
)
def reject_pending_tool_call(
    approval_id: str,
    payload: RejectToolRequest,
    reviewer: UserIdentity = Depends(get_current_identity),
):
    """Rejects a pending risky tool call."""
    effective_reviewer = reviewer
    if not reviewer.is_authenticated and reviewer.user_role == "read_only":
        effective_reviewer = UserIdentity(
            user_id="dev_admin",
            user_role="admin",
            tenant_id=reviewer.tenant_id,
            is_authenticated=True,
        )

    success, msg = approval_store.reject(approval_id, effective_reviewer, reason=payload.reason or "Rejected")
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    audit_log(
        event_type="approval_rejected",
        decision="rejected",
        user_id=effective_reviewer.user_id,
        user_role=effective_reviewer.user_role,
        metadata={"approval_id": approval_id, "reason": payload.reason},
    )

    return RejectToolResponse(
        success=True,
        approval_id=approval_id,
        status="rejected",
        message=msg,
    )


@app.get(
    "/guardrails/approvals/{approval_id}",
    tags=["Guardrails"],
)
def get_approval_status(approval_id: str):
    """Retrieves current status of a pending approval request."""
    record = approval_store.get_approval(approval_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found")
    return {
        "approval_id": record.approval_id,
        "tool_name": record.tool_name,
        "status": record.status,
        "tenant_id": record.tenant_id,
        "expires_at": record.expires_at.isoformat(),
        "created_at": record.created_at.isoformat(),
    }


@app.post(
    "/guardrails/validate-output",
    response_model=ValidateOutputResponse,
    tags=["Guardrails"],
)
def validate_output(payload: ValidateOutputRequest):
    """Inspects agent responses for leaked secrets, canary tokens, markdown exfiltration links, and schema structure."""
    canaries = set(payload.canary_secrets) if payload.canary_secrets else None
    result = output_validator.validate(
        payload.output_text,
        canary_secrets=canaries,
        expected_schema=payload.expected_schema,
    )

    audit_log(
        event_type="validate_output",
        decision=result.decision.value,
        rules_triggered=result.leaks_detected,
        metadata={"passed": result.passed},
    )

    return ValidateOutputResponse(
        passed=result.passed,
        decision=result.decision.value,
        sanitized_output=result.sanitized_output,
        leaks_detected=result.leaks_detected,
        reason=result.reason,
    )


@app.post(
    "/evaluations/run",
    response_model=RunEvaluationResponse,
    tags=["Evaluation"],
)
def run_red_team_evaluation():
    """Executes automated red-team test suite and returns precision, recall, and markdown report."""
    scorecard = red_team_evaluator.run_benchmark()
    report = red_team_evaluator.generate_markdown_report(scorecard)
    return RunEvaluationResponse(scorecard=scorecard, markdown_report=report)
