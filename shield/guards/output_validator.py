"""Output validation guard inspecting model responses for secret leaks, markdown exfiltration, and schema compliance."""

import re
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse
from pydantic import BaseModel, ValidationError
from shield.core.config import settings
from shield.core.models import ActionDecision, OutputValidationResult
from shield.guards.pii import PIIRedactor

# Regex for Markdown Images: ![alt](url)
MARKDOWN_IMAGE_REGEX = re.compile(r"!\[(.*?)\]\((https?://[^\s\)]+)\)", re.IGNORECASE)

# Regex for Markdown Links: [text](url)
MARKDOWN_LINK_REGEX = re.compile(r"(?<!!)\[(.*?)\]\((https?://[^\s\)]+)\)", re.IGNORECASE)


class OutputValidator:
    """Validates and sanitizes agent responses prior to delivering them to end users."""

    def __init__(
        self,
        redact_pii: bool = True,
        allowed_domains: Optional[Set[str]] = None,
        prohibited_domains: Optional[Set[str]] = None,
        enforce_image_allowlist: bool = True,
    ):
        self.redact_pii = redact_pii
        self.pii_redactor = PIIRedactor()
        self.allowed_domains = allowed_domains or settings.ALLOWED_DESTINATION_DOMAINS
        self.prohibited_domains = prohibited_domains or settings.PROHIBITED_DOMAINS
        self.enforce_image_allowlist = enforce_image_allowlist

    def _is_domain_allowed(self, hostname: str) -> bool:
        """Returns True if the hostname matches or is a subdomain of an allowed domain."""
        clean_host = hostname.lower()
        return any(
            clean_host == allowed or clean_host.endswith("." + allowed)
            for allowed in self.allowed_domains
        )

    def _is_domain_prohibited(self, hostname: str) -> bool:
        """Returns True if the hostname matches or is a subdomain of a prohibited domain."""
        clean_host = hostname.lower()
        return any(
            clean_host == bad or clean_host.endswith("." + bad)
            for bad in self.prohibited_domains
        )

    def validate(
        self,
        output_text: str,
        canary_secrets: Optional[Set[str]] = None,
        expected_schema: Optional[Union[type[BaseModel], Dict[str, Any]]] = None,
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

        # 2. Markdown Image Exfiltration Detection
        # Markdown images trigger automatic browser/client GET requests upon render.
        # Defend by enforcing domain allowlist on all embedded images and blocking prohibited domains.
        for match in MARKDOWN_IMAGE_REGEX.finditer(output_text):
            alt_text = match.group(1)
            raw_url = match.group(2)
            try:
                parsed = urlparse(raw_url)
                host = (parsed.hostname or "").lower()
            except Exception:
                host = ""

            is_prohibited = self._is_domain_prohibited(host)
            is_unapproved = self.enforce_image_allowlist and not self._is_domain_allowed(host)
            has_sensitive_params = any(
                p in (parsed.query or "").lower()
                for p in ["token", "data", "secret", "key", "q", "payload"]
            )

            if is_prohibited or is_unapproved or has_sensitive_params:
                leaks_found.append(f"Markdown image exfiltration URL blocked: host '{host or 'unknown'}'")
                # Neutralize image by replacing URL with blocked placeholder
                full_image_tag = match.group(0)
                cleaned_text = cleaned_text.replace(
                    full_image_tag,
                    f"![{alt_text}][EXFILTRATION_URL_BLOCKED]",
                )

        # 3. Markdown Link Exfiltration & Prohibited Destination Detection
        for match in MARKDOWN_LINK_REGEX.finditer(cleaned_text):
            raw_url = match.group(2)
            try:
                parsed = urlparse(raw_url)
                host = (parsed.hostname or "").lower()
            except Exception:
                host = ""

            if self._is_domain_prohibited(host):
                leaks_found.append(f"Markdown hyperlink to prohibited host blocked: '{host}'")
                full_link_tag = match.group(0)
                link_text = match.group(1)
                cleaned_text = cleaned_text.replace(
                    full_link_tag,
                    f"[{link_text}][PROHIBITED_LINK_BLOCKED]",
                )

        # 4. PII & API Key Scanning and Redaction
        if self.redact_pii:
            scanned = self.pii_redactor.scan(cleaned_text)
            if scanned:
                types = list({item["entity_type"] for item in scanned})
                leaks_found.extend([f"PII/Secret detected: {t}" for t in types])
                cleaned_text, _ = self.pii_redactor.redact(cleaned_text)

        # 5. Structured Schema Validation (if applicable)
        if expected_schema:
            if isinstance(expected_schema, type) and issubclass(expected_schema, BaseModel):
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
            elif isinstance(expected_schema, dict):
                import json
                try:
                    parsed_json = json.loads(output_text)
                    # Basic key check
                    for req_key in expected_schema.get("required", []):
                        if req_key not in parsed_json:
                            raise ValueError(f"Missing required key '{req_key}'")
                except Exception as err:
                    return OutputValidationResult(
                        sanitized_output=cleaned_text,
                        passed=False,
                        decision=ActionDecision.BLOCK,
                        leaks_detected=leaks_found,
                        reason=f"Output failed structured schema validation: {str(err)}",
                    )

        has_critical_leaks = any(
            "canary" in leak.lower() or "exfiltration" in leak.lower() or "prohibited host" in leak.lower()
            for leak in leaks_found
        )
        decision = (
            ActionDecision.BLOCK
            if has_critical_leaks
            else (ActionDecision.REDACT if leaks_found else ActionDecision.ALLOW)
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
