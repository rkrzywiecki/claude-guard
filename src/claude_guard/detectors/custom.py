"""User-defined regex rules from `custom_rules` in policy.yaml.

Each rule belongs to a policy category and gets that category's action, threshold, severity
filter and per-direction overrides, exactly like a built-in rule. Findings are named
`custom:<name>`.

- `secrets` rules report every match with a span, so the match is redacted (`[REDACTED:<name>]`)
  and its excerpt masked. They inspect all segments, like the built-in secrets rules.
- Other categories report the first match per segment and skip operator content (system prompt,
  tool definitions). They are matched against the normalized readings used by the injection
  detector too (invisible characters removed, homoglyphs and leetspeak folded), so simple
  obfuscation does not defeat them.

Filters narrow where a rule applies: `directions`, `tools` (globs on the tool name; only tool
call inputs), `fields` (tool input fields), `untrusted_only` (tool results, fetched content).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase

from claude_guard.config import CustomRule, Policy
from claude_guard.detectors.base import build_finding, mask_secret, snippet
from claude_guard.detectors.obfuscation import views
from claude_guard.detectors.secrets import SecretRule
from claude_guard.models import (
    OPERATOR_ROLES,
    Category,
    Finding,
    InspectionContext,
    Span,
    TextSegment,
)


def masking_rules(policy: Policy) -> tuple[SecretRule, ...]:
    """Custom `secrets` rules as scanner rules, so their matches are masked in logs too."""
    return tuple(
        SecretRule(rule.name, rule.description, rule.compiled(), rule.severity, rule.confidence)
        for rule in policy.custom_rules
        if rule.category is Category.SECRETS
    )


@dataclass(frozen=True)
class _Compiled:
    rule: CustomRule
    pattern: re.Pattern[str]


class CustomRulesDetector:
    """Runs the policy's `custom_rules`."""

    name = "custom"

    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._rules = tuple(_Compiled(rule, rule.compiled()) for rule in policy.custom_rules)

    async def detect(self, ctx: InspectionContext) -> list[Finding]:
        findings: list[Finding | None] = []
        for compiled in self._rules:
            rule = compiled.rule
            if rule.directions and ctx.direction not in rule.directions:
                continue
            for segment in ctx.segments:
                if not _applies(rule, segment):
                    continue
                if rule.category is Category.SECRETS:
                    findings.extend(self._secret_matches(ctx, compiled, segment))
                else:
                    findings.append(self._first_match(ctx, compiled, segment))
        return [finding for finding in findings if finding]

    def _secret_matches(
        self, ctx: InspectionContext, compiled: _Compiled, segment: TextSegment
    ) -> list[Finding | None]:
        rule = compiled.rule
        return [
            build_finding(
                detector=self.name,
                category=rule.category,
                policy=self._policy.for_category(rule.category),
                direction=ctx.direction,
                rule=f"custom:{rule.name}",
                message=rule.description,
                severity=rule.severity,
                confidence=rule.confidence,
                segment=segment,
                span=Span(start=match.start(), end=match.end()),
                excerpt=mask_secret(match.group()),
                replacement=f"[REDACTED:{rule.name}]",
            )
            for match in compiled.pattern.finditer(segment.text)
            if match.end() > match.start()
        ]

    def _first_match(
        self, ctx: InspectionContext, compiled: _Compiled, segment: TextSegment
    ) -> Finding | None:
        rule = compiled.rule
        for view in views(segment.text):
            match = compiled.pattern.search(view)
            if match:
                span_valid = view == segment.text
                return build_finding(
                    detector=self.name,
                    category=rule.category,
                    policy=self._policy.for_category(rule.category),
                    direction=ctx.direction,
                    rule=f"custom:{rule.name}",
                    message=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    segment=segment,
                    span=Span(start=match.start(), end=match.end()) if span_valid else None,
                    excerpt=snippet(view, match.start(), match.end()),
                )
        return None


def _applies(rule: CustomRule, segment: TextSegment) -> bool:
    if rule.category is not Category.SECRETS and segment.role in OPERATOR_ROLES:
        return False
    if rule.untrusted_only and segment.trusted:
        return False
    if rule.tools and not (
        segment.tool_name and any(fnmatchcase(segment.tool_name, glob) for glob in rule.tools)
    ):
        return False
    return not rule.fields or segment.tool_field in rule.fields
