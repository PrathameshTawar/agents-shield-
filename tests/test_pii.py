"""Unit tests for PIIRedactor: scanning, redaction, and tokenization."""

from shield.guards.pii import PIIRedactor


def test_redact_emails():
    redactor = PIIRedactor()
    text = "Please reach out to support@company.org or ceo@corp.com for assistance."
    redacted, types = redactor.redact(text)

    assert "[EMAIL_REDACTED]" in redacted
    assert "support@company.org" not in redacted
    assert "ceo@corp.com" not in redacted
    assert "email" in types


def test_redact_phones():
    redactor = PIIRedactor()
    text = "Call US office at (555) 234-5678 or India branch at +91 9876543210 immediately."
    redacted, types = redactor.redact(text)

    assert "[PHONE_REDACTED]" in redacted
    assert "555" not in redacted
    assert "9876543210" not in redacted
    assert "phone" in types


def test_redact_api_keys():
    redactor = PIIRedactor()
    text = "Set OPENAI_API_KEY=sk-abcdef1234567890abcdef123456 and GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"
    redacted, types = redactor.redact(text)

    assert "[API_KEY_REDACTED]" in redacted
    assert "sk-" not in redacted
    assert "ghp_" not in redacted
    assert "api_key" in types


def test_redact_credit_cards_and_ssn():
    redactor = PIIRedactor()
    text = "Customer card: 4111-2222-3333-4444, SSN: 123-45-6789."
    redacted, types = redactor.redact(text)

    assert "[CREDIT_CARD_REDACTED]" in redacted
    assert "[SSN_REDACTED]" in redacted
    assert "4111" not in redacted
    assert "123-45-6789" not in redacted


def test_scan_identifies_entities_with_indices():
    redactor = PIIRedactor()
    text = "Contact alice@test.com today."
    detected = redactor.scan(text)

    assert len(detected) == 1
    assert detected[0]["entity_type"] == "email"
    assert detected[0]["value"] == "alice@test.com"
    assert detected[0]["start"] == 8
    assert detected[0]["end"] == 22


def test_reversible_tokenization_and_restoration():
    redactor = PIIRedactor()
    text = "Send confirmation to admin@secure.net and user@test.io."
    tokenized, token_map = redactor.tokenize_reversible(text)

    assert "[EMAIL_1]" in tokenized or "[EMAIL_2]" in tokenized
    assert "admin@secure.net" not in tokenized

    restored = redactor.restore_tokens(tokenized, token_map)
    assert restored == text
