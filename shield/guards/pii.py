"""High-precision PII, secret, and sensitive data detection, checksum validation, and tokenization engine."""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Verhoeff tables for Aadhaar checksum validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def is_luhn_valid(number: str) -> bool:
    """Validates credit card numbers using Luhn checksum algorithm."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def is_verhoeff_valid(number: str) -> bool:
    """Validates 12-digit Indian Aadhaar numbers using Verhoeff checksum algorithm."""
    clean = "".join(c for c in number if c.isdigit())
    if len(clean) != 12:
        return False
    c = 0
    for i, item in enumerate(reversed(clean)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(item)]]
    return c == 0


class PIIRedactor:
    """Detects, redacts, and tokenizes PII and credentials using robust contextual regular expressions and checksum validation."""

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
                r"(?<!\d)(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)|"
                r"(?<!\d)\+91[\s-]?[6789]\d{9}(?!\d)|"
                r"(?<!\d)[6789]\d{9}(?!\d)",
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

    # Priority order for overlap resolution
    PRIORITY = {
        "api_key": 100,
        "credit_card": 90,
        "ssn": 80,
        "aadhaar": 70,
        "email": 60,
        "phone": 50,
        "ipv4": 40,
    }

    PHONE_CONTEXT_WORDS = {
        "phone",
        "call",
        "mobile",
        "cell",
        "tel",
        "contact",
        "reach",
        "dial",
        "ph:",
        "phone:",
        "whatsapp",
        "sms",
    }

    CARD_CONTEXT_WORDS = {
        "card",
        "credit",
        "debit",
        "visa",
        "mastercard",
        "amex",
        "cvv",
        "payment",
        "cc",
        "charge",
    }

    def __init__(self, enabled_detectors: Optional[List[str]] = None):
        if enabled_detectors:
            self.active_patterns = {k: v for k, v in self.PATTERNS.items() if k in enabled_detectors}
        else:
            self.active_patterns = self.PATTERNS.copy()

    def _has_nearby_context(self, text: str, start: int, end: int, context_words: Set[str], window: int = 50) -> bool:
        """Checks if any context keyword appears within window characters around the match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        surrounding = text[ctx_start:ctx_end].lower()
        return any(word in surrounding for word in context_words)

    def _is_version_number(self, text: str, start: int, end: int) -> bool:
        """Determines if an IPv4 candidate is actually a software release/version number like 'Version 1.2.3.4'."""
        prefix = text[max(0, start - 20) : start].lower()
        # Look for version indicators preceding the digits
        if re.search(r"\b(?:version|ver|v|build|release|rev)[\s.:=-]*$", prefix):
            return True
        # Check if preceded by a letter/hyphen without word boundary (e.g. app-1.2.3.4)
        if start > 0 and text[start - 1] in "-_":
            return True
        return False

    def scan(self, text: str) -> List[Dict[str, Any]]:
        """Scans input text, validates checksums, context filters, and returns non-overlapping entities sorted left-to-right."""
        candidates = []

        for name, (pattern, _) in self.active_patterns.items():
            for match in pattern.finditer(text):
                val = match.group(0)
                start = match.start()
                end = match.end()

                # 1. IPv4 False Positive Filtering
                if name == "ipv4":
                    if self._is_version_number(text, start, end):
                        continue
                    if val.startswith("0.0.0.0") or val.startswith("127.0.0.1"):
                        continue

                # 2. Credit Card Validation (Luhn algorithm or explicit card context)
                elif name == "credit_card":
                    has_card_ctx = self._has_nearby_context(text, start, end, self.CARD_CONTEXT_WORDS)
                    is_luhn = is_luhn_valid(val)
                    # If it's a raw unseparated 16-digit number, require Luhn check
                    if "-" not in val and " " not in val:
                        if not is_luhn:
                            continue
                    else:
                        # Has formatting: accept if Luhn is valid OR has explicit card context
                        if not (is_luhn or has_card_ctx):
                            continue

                # 3. Aadhaar Validation (Verhoeff checksum or explicit context)
                elif name == "aadhaar":
                    has_aadhaar_ctx = "aadhaar" in text[max(0, start - 30) : min(len(text), end + 30)].lower()
                    if not (is_verhoeff_valid(val) or has_aadhaar_ctx):
                        continue

                # 4. Phone Number Validation (avoid false positives on order IDs / random 10-digit numbers)
                elif name == "phone":
                    clean_digits = "".join(c for c in val if c.isdigit())
                    # If it's unformatted 10 digits without '+' or '()' or '-'
                    is_unformatted = not any(c in val for c in ["+", "(", ")", "-"])
                    if is_unformatted and len(clean_digits) == 10:
                        has_phone_ctx = self._has_nearby_context(text, start, end, self.PHONE_CONTEXT_WORDS)
                        if not has_phone_ctx:
                            # Not a phone number, skip (e.g. Order ID 1234567890)
                            continue

                candidates.append(
                    {
                        "entity_type": name,
                        "value": val,
                        "start": start,
                        "end": end,
                        "priority": self.PRIORITY.get(name, 0),
                        "length": end - start,
                    }
                )

        # Overlap Resolution: sort by start asc, priority desc, length desc
        candidates.sort(key=lambda x: (x["start"], -x["priority"], -x["length"]))

        resolved: List[Dict[str, Any]] = []
        for cand in candidates:
            # Check overlap with existing accepted entities
            overlaps = False
            for accepted in resolved:
                if not (cand["end"] <= accepted["start"] or cand["start"] >= accepted["end"]):
                    overlaps = True
                    break
            if not overlaps:
                resolved.append(cand)

        # Sort left-to-right
        resolved.sort(key=lambda x: x["start"])
        return resolved

    def redact(self, text: str) -> Tuple[str, List[str]]:
        """Redacts sensitive values with standard replacement placeholders in left-to-right order."""
        entities = self.scan(text)
        if not entities:
            return text, []

        result_parts = []
        last_idx = 0
        detected_types: Set[str] = set()

        for ent in entities:
            result_parts.append(text[last_idx : ent["start"]])
            placeholder = self.active_patterns[ent["entity_type"]][1]
            result_parts.append(placeholder)
            detected_types.add(ent["entity_type"])
            last_idx = ent["end"]

        result_parts.append(text[last_idx:])
        return "".join(result_parts), sorted(list(detected_types))

    def tokenize_reversible(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Reversibly replaces sensitive entities with strictly numbered tokens (e.g. [EMAIL_1], [EMAIL_2]) in left-to-right order."""
        entities = self.scan(text)
        if not entities:
            return text, {}

        token_map: Dict[str, str] = {}
        type_counters: Dict[str, int] = {}
        result_parts = []
        last_idx = 0

        for ent in entities:
            ent_type = ent["entity_type"]
            type_counters[ent_type] = type_counters.get(ent_type, 0) + 1
            token_label = f"[{ent_type.upper()}_{type_counters[ent_type]}]"

            result_parts.append(text[last_idx : ent["start"]])
            result_parts.append(token_label)
            token_map[token_label] = ent["value"]
            last_idx = ent["end"]

        result_parts.append(text[last_idx:])
        return "".join(result_parts), token_map

    @staticmethod
    def restore_tokens(text: str, token_map: Dict[str, str]) -> str:
        """Restores original values from token map."""
        restored = text
        for token, original in token_map.items():
            restored = restored.replace(token, original)
        return restored
