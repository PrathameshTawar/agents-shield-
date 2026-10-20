"""High-precision PII, secret, and sensitive data detection and redaction engine."""

import re
from typing import Dict, List, Optional, Tuple


class PIIRedactor:
    """Detects, redacts, and tokenizes PII and credentials using robust contextual regular expressions."""

    PATTERNS: Dict[str, Tuple[re.Pattern, str]] = {
        "api_key": (
            re.compile(
                r"(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|bearer\s+[A-Za-z0-9\-_\.]{24,})",
                re.IGNORECASE,
            ),
            "[API_KEY_REDACTED]",
        ),
        "email": (
            re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
            ),
            "[EMAIL_REDACTED]",
        ),
        "phone": (
            re.compile(
                r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b(?:\+91[\s-]?)?[6789]\d{9}\b",
            ),
            "[PHONE_REDACTED]",
        ),
        "credit_card": (
            re.compile(
                r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            ),
            "[CREDIT_CARD_REDACTED]",
        ),
        "ssn": (
            re.compile(
                r"\b\d{3}-\d{2}-\d{4}\b",
            ),
            "[SSN_REDACTED]",
        ),
        "aadhaar": (
            re.compile(
                r"\b\d{4}\s\d{4}\s\d{4}\b",
            ),
            "[AADHAAR_REDACTED]",
        ),
        "ipv4": (
            re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            ),
            "[IP_ADDRESS_REDACTED]",
        ),
    }

    def __init__(self, enabled_detectors: Optional[List[str]] = None):
        if enabled_detectors:
            self.active_patterns = {
                k: v for k, v in self.PATTERNS.items() if k in enabled_detectors
            }
        else:
            self.active_patterns = self.PATTERNS.copy()

    def scan(self, text: str) -> List[Dict[str, str]]:
        """Scans input text and returns metadata of all detected sensitive entities."""
        detected = []
        for name, (pattern, _) in self.active_patterns.items():
            for match in pattern.finditer(text):
                val = match.group(0)
                # Filter out obvious false positives like standard version numbers (e.g. 1.2.3.4)
                if name == "ipv4" and (val.startswith("0.0.0.0") or val.startswith("127.0.0.1")):
                    continue
                detected.append({
                    "entity_type": name,
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                })
        return detected

    def redact(self, text: str) -> Tuple[str, List[str]]:
        """Redacts sensitive values with standard replacement placeholders."""
        redacted = text
        detected_types: List[str] = []

        for name, (pattern, placeholder) in self.active_patterns.items():
            if pattern.search(redacted):
                detected_types.append(name)
                redacted = pattern.sub(placeholder, redacted)

        return redacted, detected_types

    def tokenize_reversible(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Reversibly replaces sensitive entities with numbered tokens (e.g. [EMAIL_1]) and returns mapping."""
        token_map: Dict[str, str] = {}
        tokenized = text

        for name, (pattern, _) in self.active_patterns.items():
            matches = list(pattern.finditer(tokenized))
            for i, match in enumerate(reversed(matches), start=1):
                raw_val = match.group(0)
                token_placeholder = f"[{name.upper()}_{len(token_map) + 1}]"
                token_map[token_placeholder] = raw_val
                tokenized = (
                    tokenized[: match.start()] + token_placeholder + tokenized[match.end() :]
                )

        return tokenized, token_map

    @staticmethod
    def restore_tokens(text: str, token_map: Dict[str, str]) -> str:
        """Restores original values from token map."""
        restored = text
        for token, original in token_map.items():
            restored = restored.replace(token, original)
        return restored
