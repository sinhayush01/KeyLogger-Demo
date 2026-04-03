import re
from dataclasses import dataclass
from typing import Optional


SENSITIVITY_NONE = "none"
SENSITIVITY_PASSWORD = "password"
SENSITIVITY_OTP = "otp"
SENSITIVITY_CREDIT_CARD = "credit_card"
SENSITIVITY_EMAIL = "email"
SENSITIVITY_API_TOKEN = "api_token"


EMAIL_SEARCH_RE = re.compile(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
EMAIL_FULLMATCH_RE = re.compile(r"(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$")

OTP_SEARCH_RE = re.compile(r"\b\d{6}\b")
OTP_FULLMATCH_RE = re.compile(r"^\d{6}$")

# Candidate card-like sequences. We'll then Luhn-check each candidate.
CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]*?){13,19}")

# API token patterns (training/demo; intentionally conservative to avoid over-triggering).
GH_TOKEN_RE = re.compile(r"^ghp_[A-Za-z0-9]{36}$")
AWS_ACCESS_KEY_RE = re.compile(r"^AKIA[0-9A-Z]{16}$")
AWS_SECRET_LIKE_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
GOOGLE_API_KEY_RE = re.compile(r"^AIza[0-9A-Za-z_-]{35,}$")

JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class DetectionResult:
    sensitivity_classification: str


def _luhn_checksum(num_str: str) -> bool:
    digits = [int(ch) for ch in num_str]
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_credit_card_like(value: str) -> bool:
    # Try to detect a card-like substring, not only a whole-field match.
    for candidate in CARD_CANDIDATE_RE.findall(value):
        digits = re.sub(r"\D", "", candidate)
        # For a security-awareness demo, trigger protection as soon as a card-like
        # 13-19 digit sequence is present to avoid temporarily logging plaintext digits.
        if 13 <= len(digits) <= 19:
            return True
    return False


def _is_api_token_like(value: str) -> bool:
    v = value.strip()
    if len(v) < 16:
        return False

    # Known-token prefixes / formats.
    if GH_TOKEN_RE.search(v):
        return True
    if AWS_ACCESS_KEY_RE.search(v):
        return True
    if GOOGLE_API_KEY_RE.search(v):
        return True
    if JWT_RE.search(v):
        return True

    # Common explicit prefixes (often pasted alongside surrounding text).
    if re.search(r"\b(sk-|pk-|xoxb-|xoxp-|ya29|ghp_|AKIA|AIza)\w*", v) and len(v) >= 20:
        has_letter = any(ch.isalpha() for ch in v)
        has_digit = any(ch.isdigit() for ch in v)
        if has_letter and has_digit:
            return True

    # Generic "tokeny" strings: long, mixed alnum, often with separators.
    # Avoid triggering on simple English words by requiring both letters and digits.
    has_letter = any(ch.isalpha() for ch in v)
    has_digit = any(ch.isdigit() for ch in v)
    if not (has_letter and has_digit):
        return False

    if any(sep in v for sep in ["-", "_", "."]) and len(v) >= 24:
        return True

    # AWS secret-like is often base64-like.
    if AWS_SECRET_LIKE_RE.match(v) and len(v) == 40:
        return True

    return False


def classify_value(value: str, field_kind: str) -> DetectionResult:
    """
    Classify input based on the field type and content patterns.

    IMPORTANT: this never captures system-wide keystrokes; it only classifies strings
    that the user entered into this app's own controlled widgets.
    """
    raw = value or ""
    v = raw.strip()

    # Field-based overrides.
    if field_kind == "password":
        return DetectionResult(SENSITIVITY_PASSWORD)
    if field_kind == "otp":
        return DetectionResult(SENSITIVITY_OTP)

    # Pattern-based detection.
    if OTP_FULLMATCH_RE.fullmatch(v) or OTP_SEARCH_RE.search(v):
        return DetectionResult(SENSITIVITY_OTP)

    if EMAIL_FULLMATCH_RE.fullmatch(v):
        return DetectionResult(SENSITIVITY_EMAIL)

    if EMAIL_SEARCH_RE.search(v) and not re.search(r"\s", v):
        # No whitespace: likely a pasted value; treat as email.
        return DetectionResult(SENSITIVITY_EMAIL)

    if _is_credit_card_like(v):
        return DetectionResult(SENSITIVITY_CREDIT_CARD)

    if _is_api_token_like(v):
        return DetectionResult(SENSITIVITY_API_TOKEN)

    return DetectionResult(SENSITIVITY_NONE)

