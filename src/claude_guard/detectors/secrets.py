"""Secret and sensitive-data detector (regex, entropy, checksums).

Specific rules run first and claim their spans; later rules (generic assignments, high entropy)
skip anything already claimed, so one value yields at most one finding.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

from claude_guard.config import Policy, SecretsPolicy
from claude_guard.detectors.base import build_finding, mask_secret
from claude_guard.detectors.obfuscation import decoded_candidates, strip_invisible
from claude_guard.models import Category, Finding, InspectionContext, Severity, Span

Validator = Callable[[str], bool]


@dataclass(frozen=True)
class SecretRule:
    name: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    group: str | int = 0
    validator: Validator | None = None


# --- Validators ---------------------------------------------------------------


def luhn_valid(number: str) -> bool:
    digits = [int(char) for char in number if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


_PAN_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|3[0689]|6(?:011|5|4[4-9]|22)|35)")


def pan_valid(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    return bool(_PAN_PREFIX.match(digits)) and luhn_valid(digits)


_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
_PESEL_CENTURY = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}


def pesel_valid(value: str) -> bool:
    if len(value) != 11 or not value.isdigit():
        return False
    digits = [int(char) for char in value]
    checksum = (10 - sum(w * d for w, d in zip(_PESEL_WEIGHTS, digits, strict=False)) % 10) % 10
    if checksum != digits[10]:
        return False
    year, month, day = int(value[0:2]), int(value[2:4]), int(value[4:6])
    offset = (month - 1) // 20 * 20 if month else -1
    if offset not in _PESEL_CENTURY:
        return False
    try:
        date(_PESEL_CENTURY[offset] + year, month - offset, day)
    except ValueError:
        return False
    return True


_IBAN_LENGTHS = {
    "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20,
    "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IT": 27,
    "LT": 20, "LU": 20, "LV": 21, "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24,
    "SE": 24, "SI": 19, "SK": 24, "UA": 29,
}  # fmt: skip


def iban_valid(value: str) -> bool:
    iban = value.replace(" ", "").upper()
    expected = _IBAN_LENGTHS.get(iban[:2])
    if expected is not None and len(iban) != expected:
        return False
    if not 15 <= len(iban) <= 34:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def nrb_valid(value: str) -> bool:
    """Polish domestic account number (NRB): an IBAN without the PL prefix."""
    digits = value.replace(" ", "")
    return len(digits) == 26 and iban_valid(f"PL{digits}")


def jwt_valid(value: str) -> bool:
    header = value.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        parsed = json.loads(decoded)
    except (binascii.Error, ValueError):
        return False
    return isinstance(parsed, dict) and "alg" in parsed


_PLACEHOLDER = re.compile(
    r"^(?:[$<{%]|\*{3})|example|placeholder|your[_-]?|xxx|changeme|redacted|dummy|<[^>]+>",
    re.IGNORECASE,
)
_DOTTED_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def assigned_value_valid(value: str) -> bool:
    """Reject placeholders, env lookups and code references in `password = ...` assignments."""
    if _PLACEHOLDER.search(value) or "(" in value or "[" in value:
        return False
    return not _DOTTED_IDENTIFIER.fullmatch(value)


# --- Rules --------------------------------------------------------------------

_B = r"(?<![A-Za-z0-9_-])"  # left token boundary that also treats '-' and '_' as part of tokens
_E = r"(?![A-Za-z0-9_-])"

SPECIFIC_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private_key",
        "PEM private key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
            r"[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)"
        ),
        Severity.CRITICAL,
        0.99,
    ),
    SecretRule(
        "anthropic_api_key",
        "Anthropic API key",
        re.compile(_B + r"sk-ant-[A-Za-z0-9_-]{20,}" + _E),
        Severity.CRITICAL,
        0.99,
    ),
    SecretRule(
        "openai_api_key",
        "OpenAI API key",
        re.compile(_B + r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}" + _E),
        Severity.CRITICAL,
        0.9,
    ),
    SecretRule(
        "aws_access_key_id",
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        Severity.HIGH,
        0.95,
    ),
    SecretRule(
        "aws_secret_access_key",
        "AWS secret access key",
        re.compile(
            r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?[=:]\s*[\"']?(?P<value>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        Severity.CRITICAL,
        0.9,
        group="value",
    ),
    SecretRule(
        "github_token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
        Severity.CRITICAL,
        0.98,
    ),
    SecretRule(
        "slack_token",
        "Slack token",
        re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        Severity.HIGH,
        0.95,
    ),
    SecretRule(
        "stripe_live_key",
        "Stripe live key",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b"),
        Severity.CRITICAL,
        0.98,
    ),
    SecretRule(
        "google_api_key",
        "Google API key",
        re.compile(_B + r"AIza[0-9A-Za-z_-]{35}" + _E),
        Severity.HIGH,
        0.95,
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        Severity.HIGH,
        0.9,
        validator=jwt_valid,
    ),
    SecretRule(
        "iban",
        "IBAN bank account number",
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
        Severity.HIGH,
        0.9,
        validator=iban_valid,
    ),
    SecretRule(
        "nrb",
        "Polish bank account number (NRB)",
        re.compile(r"(?<![\d-])\d{2}(?: ?\d{4}){6}(?![\d-])"),
        Severity.HIGH,
        0.75,
        validator=nrb_valid,
    ),
    SecretRule(
        "payment_card",
        "Payment card number (PAN)",
        re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"),
        Severity.HIGH,
        0.85,
        validator=pan_valid,
    ),
    SecretRule(
        "pesel",
        "Polish national ID number (PESEL)",
        re.compile(r"(?<!\d)\d{11}(?!\d)"),
        Severity.HIGH,
        0.8,
        validator=pesel_valid,
    ),
    SecretRule(
        "credential_assignment",
        "Credential assigned in code or config",
        re.compile(
            r"(?i)(?:(?<![A-Za-z0-9])|(?<=[_-]))(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token"
            r"|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?(?P<value>[^\s\"',;]{6,})"
        ),
        Severity.HIGH,
        0.65,
        group="value",
        validator=assigned_value_valid,
    ),
)

_ENTROPY_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{8,}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"[0-9a-fA-F-]+")
ENTROPY_MAX_LENGTH = 256
# Below the default threshold on purpose: random-looking strings are only a warning.
ENTROPY_RULE = SecretRule(
    "high_entropy",
    "High-entropy string (possible secret)",
    _ENTROPY_TOKEN,
    Severity.MEDIUM,
    0.4,
)


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum(count / length * math.log2(count / length) for count in counts.values())


_WORD_SEPARATORS = re.compile(r"[-_]+")
SLUG_MIN_SEPARATORS = 3
SLUG_MAX_PART = 12


def _looks_like_slug(token: str) -> bool:
    """Short words joined by `-`/`_` (e.g. `-Users-alice-Projects-app-2026`), not random data."""
    parts = [part for part in _WORD_SEPARATORS.split(token) if part]
    return len(parts) > SLUG_MIN_SEPARATORS and max(len(part) for part in parts) <= SLUG_MAX_PART


def _looks_random(token: str) -> bool:
    has_digit = any(char.isdigit() for char in token)
    has_upper = any(char.isupper() for char in token)
    has_lower = any(char.islower() for char in token)
    return (
        has_digit
        and has_upper
        and has_lower
        and not _HEX.fullmatch(token)
        and not _looks_like_slug(token)
    )


@dataclass(frozen=True)
class SecretHit:
    rule: SecretRule
    start: int
    end: int


class SecretScanner:
    """Finds secret spans in text. Shared by the detector and the audit log redaction."""

    def __init__(self, policy: SecretsPolicy) -> None:
        self._policy = policy
        self._allowlist = [re.compile(pattern) for pattern in policy.allowlist]

    def scan(self, text: str) -> list[SecretHit]:
        """Secret spans in `text`, also when split by invisible characters or base64-encoded."""
        cleaned, mapping = strip_invisible(text)
        hits = self._scan_clean(cleaned)
        if len(cleaned) == len(text):
            return hits
        # Map spans found in the cleaned text back to the original, invisible characters included.
        return [
            SecretHit(hit.rule, mapping[hit.start], mapping[hit.end - 1] + 1)
            for hit in hits
            if hit.end > hit.start
        ]

    def _scan_clean(self, text: str, decode: bool = True) -> list[SecretHit]:
        claimed: list[tuple[int, int]] = []
        hits: list[SecretHit] = []

        def overlaps(start: int, end: int) -> bool:
            return any(start < c_end and c_start < end for c_start, c_end in claimed)

        for rule in SPECIFIC_RULES:
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.group)
                value = match.group(rule.group)
                if overlaps(start, end) or self._allowlisted(value):
                    continue
                if rule.validator and not rule.validator(value):
                    continue
                claimed.append((start, end))
                hits.append(SecretHit(rule, start, end))

        if decode:
            # A base64 blob (e.g. an encoded .env file) is reported whole if it hides a secret.
            for decoded in decoded_candidates(text, encodings=("base64",)):
                if overlaps(decoded.start, decoded.end):
                    continue
                inner = self._scan_clean(decoded.text, decode=False)
                specific = [hit for hit in inner if hit.rule is not ENTROPY_RULE]
                if specific:
                    rule = specific[0].rule
                    encoded_rule = SecretRule(
                        "encoded_secret",
                        f"Base64-encoded {rule.description}",
                        rule.pattern,
                        rule.severity,
                        rule.confidence,
                    )
                    claimed.append((decoded.start, decoded.end))
                    hits.append(SecretHit(encoded_rule, decoded.start, decoded.end))

        for start, end in self._entropy_candidates(text):
            token = text[start:end]
            if not self._policy.entropy_min_length <= len(token) <= ENTROPY_MAX_LENGTH:
                continue
            if overlaps(start, end) or self._allowlisted(token) or not _looks_random(token):
                continue
            if shannon_entropy(token) < self._policy.entropy_threshold:
                continue
            claimed.append((start, end))
            hits.append(SecretHit(ENTROPY_RULE, start, end))

        return sorted(hits, key=lambda hit: hit.start)

    @staticmethod
    def _entropy_candidates(text: str) -> list[tuple[int, int]]:
        """Token spans for the entropy rule.

        A token with `/` that starts with `/` or follows `.`, `~` or `/` (as in `~/.claude/...`)
        is a path: its segments are judged one by one, so long mixed-case paths are not mistaken
        for secrets while a key inside a path still is.
        """
        spans: list[tuple[int, int]] = []
        for match in _ENTROPY_TOKEN.finditer(text):
            token = match.group()
            before = text[match.start() - 1] if match.start() else ""
            is_path = "/" in token and (token.startswith("/") or before in (".", "~", "/"))
            if not is_path:
                spans.append(match.span())
                continue
            offset = match.start()
            for segment in match.group().split("/"):
                if segment:
                    spans.append((offset, offset + len(segment)))
                offset += len(segment) + 1
        return spans

    def mask(self, text: str) -> str:
        """Replace every secret in `text` with its masked preview (for logs)."""
        for hit in reversed(self.scan(text)):
            text = text[: hit.start] + mask_secret(text[hit.start : hit.end]) + text[hit.end :]
        return text

    def _allowlisted(self, value: str) -> bool:
        return any(pattern.search(value) for pattern in self._allowlist)


class SecretsDetector:
    """Finds credentials and personal data so they can be redacted or blocked."""

    name = "secrets"

    def __init__(self, policy: Policy) -> None:
        self._policy = policy.secrets
        self._scanner = SecretScanner(policy.secrets)

    async def detect(self, ctx: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for segment in ctx.segments:
            for hit in self._scanner.scan(segment.text):
                rule = hit.rule
                finding = build_finding(
                    detector=self.name,
                    category=Category.SECRETS,
                    policy=self._policy,
                    direction=ctx.direction,
                    rule=rule.name,
                    message=f"{rule.description} detected",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    segment=segment,
                    span=Span(start=hit.start, end=hit.end),
                    excerpt=mask_secret(segment.text[hit.start : hit.end]),
                    replacement=f"[REDACTED:{rule.name}]",
                )
                if finding:
                    findings.append(finding)
        return findings
