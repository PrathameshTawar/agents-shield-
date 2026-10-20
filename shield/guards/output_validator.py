"""Output validation guard inspecting model responses for secret leaks, markdown exfiltration, and schema compliance."""

import re
from typing import List, Optional, Set
from pydantic import BaseModel, ValidationError
from shield.core.models import ActionDecision, OutputValidationResult
from shield.guards.pii import PIIRedactor


class OutputValidator:
    """Validates and sanitizes agent responses prior to delivering them to end users."""

    MARKDOWN_EXFILTRATION_PATTERN = re.compile(
        r"!\[.*?\]\((https?://[^\s\)]+[\?&](?:token|data|secret|key)=[^\s\)]+)\)",
        re.IGNORECASE,
    )

    def __init__(self, redact_pii: bool = True):
        self.redact_pii = redact_pii
        self.pii_redactor = PIIRedactor()

    def validate(
        self,
        output_text: str,
        canary_secrets: Optional[Set[str]] = None,
        expected_schema: Optional[type[BaseModel]] = None,
    ) -> OutputValidationResult:
        """Inspects output for leaked secrets, markdown image exfiltration URLs, PII, and schema structure."""
        leaks_found: List[str] = []
        cleaned_text = output_text

        # 1. Canary Secret Detection (exact secrets present in system prompt / context)
        if canary_secrets:
            for secret in canary_secrets:
                if secret and secret in cleaned_text:
                    leaks_found.append(f"Canary secret detected: '{secret[:4]}***'")
                    cleaned_text = cleaned_text.replace(secret, "[PROTECTED_SECRET_REDACTED]")

        # 2. Markdown Image / Webhook Exfiltration Detection
        exfil_match = self.MARKDOWN_EXFILTRATION_PATTERN.search(cleaned_text)
        if exfil_match:
            leaks_found.append("Markdown image data exfiltration URL detected")
            cleaned_text = self.MARKDOWN_EXFILTRATION_PATTERN.sub("[EXFILTRATION_URL_BLOCKED]", cleaned_text)

        # 3. PII & API Key Scanning and Redaction
        if self.redact_pii:
            scanned = self.pii_redactor.scan(cleaned_text)
            if scanned:
                types = list({item["entity_type"] for item in scanned})
                leaks_found.extend([f"PII/Secret detected: {t}" for t in types])
                cleaned_text, _ = self.pii_redactor.redact(cleaned_text)

        # 4. Structured Schema Validation (if applicable)
        if expected_schema:
            try:
                expected_schema.model_validate_json(output_text)
            except (ValidationError, ValueError) as err:
                return OutputValidationResult(
                    sanitized_output=cleaned_text,
                    passed=False,
                    decision=ActionDecision.BLOCK,
                    leaks_detected=leaks_found,
                    reason=f"Output failed structured schema validation: {str(err)}",
                )

        has_critical_leaks = any(
            "canary" in leak.lower() or "exfiltration" in leak.lower()
            for leak in leaks_found
        )
        decision = ActionDecision.BLOCK if has_critical_leaks else (
            ActionDecision.REDACT if leaks_found else ActionDecision.ALLOW
        )
        passed = not has_critical_leaks

        reason = (
            f"Blocked: sensitive data or exfiltration detected ({', '.join(leaks_found)})"
            if not passed
            else (
                f"Sanitized: redacted sensitive entities ({', '.join(leaks_found)})"
                if leaks_found
                else "Output passed all security and schema validations"
            )
        )

        return OutputValidationResult(
            sanitized_output=cleaned_text,
            passed=passed,
            decision=decision,
            leaks_detected=leaks_found,
            reason=reason,
        )
