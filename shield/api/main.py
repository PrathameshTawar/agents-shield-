"""FastAPI security gateway exposing guardrails, tool authorization, output filtering, and red-team benchmarks."""

from fastapi import FastAPI, status
from shield import __version__
from shield.api.schemas import (
    AuthorizeToolRequest,
    AuthorizeToolResponse,
    EvaluateInputRequest,
    EvaluateInputResponse,
    RunEvaluationResponse,
    ValidateOutputRequest,
    ValidateOutputResponse,
)
from shield.core.models import ActionDecision, SecurityRiskLevel, ToolCallRequest
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

# Core guard instances
injection_guard = InjectionGuard()
pii_redactor = PIIRedactor()
tool_authorizer = ToolAuthorizer()
output_validator = OutputValidator()
red_team_evaluator = RedTeamEvaluator()


@app.get("/health", tags=["System"])
def health_check():
    """Returns service operational health and version."""
    return {"status": "healthy", "service": "AgentShield", "version": __version__}


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
        return EvaluateInputResponse(
            allowed=False,
            decision=ActionDecision.BLOCK.value,
            risk_level=risk_level.value,
            sanitized_text="[REQUEST_BLOCKED_SECURITY_VIOLATION]",
            injection_detected=True,
            pii_detected=False,
            detected_entities=[],
            reasons=reasons,
        )

    # 2. PII Redaction
    sanitized = text_to_eval
    detected_entities = []
    pii_detected = False

    if payload.redact_pii:
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
def authorize_tool(payload: AuthorizeToolRequest):
    """Pre-execution interceptor authorizing or blocking proposed agent tool actions."""
    request = ToolCallRequest(
        user_id=payload.user_id,
        user_role=payload.user_role,
        tenant_id=payload.tenant_id,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
    )
    decision = tool_authorizer.authorize(request)
    return AuthorizeToolResponse(
        allowed=decision.allowed,
        decision=decision.decision.value,
        requires_human_approval=decision.requires_human_approval,
        tool_name=decision.tool_name,
        reason=decision.reason,
    )


@app.post(
    "/guardrails/validate-output",
    response_model=ValidateOutputResponse,
    tags=["Guardrails"],
)
def validate_output(payload: ValidateOutputRequest):
    """Inspects agent responses for leaked secrets, canary tokens, and exfiltration links."""
    canaries = set(payload.canary_secrets) if payload.canary_secrets else None
    result = output_validator.validate(payload.output_text, canary_secrets=canaries)
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
