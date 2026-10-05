"""Prompt injection and jailbreak heuristics.

Each segment is matched in several readings (see `obfuscation.views`): NFKC-normalized with
invisible characters removed, homoglyphs folded to Latin, leetspeak undone and letter-spacing
collapsed. Base64/hex/percent-encoded runs are decoded and matched too, and sibling blocks of one
message are joined so a phrase split across blocks is still found.

Segments with an operator role (system prompt, tool definitions) are not inspected. Untrusted
segments (tool results, fetched content) get a confidence boost and are also checked for fake
conversation markers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from claude_guard.config import Policy
from claude_guard.detectors.base import build_finding, snippet
from claude_guard.detectors.obfuscation import Decoded, decoded_candidates, normalize, views
from claude_guard.models import (
    OPERATOR_ROLES,
    Category,
    Finding,
    InspectionContext,
    Severity,
    Span,
    TextSegment,
)

UNTRUSTED_BOOST = 0.1

_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]+")
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\u180e\ufeff]")
_BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Blocks of one message share a group: "messages[3]", "content" (a response), "tool_response".
_GROUP = re.compile(r"^(?:messages\[\d+\]|content|tool_response|tool_input)")
ZERO_WIDTH_MIN_COUNT = 3


@dataclass(frozen=True)
class InjectionRule:
    name: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    untrusted_only: bool = False


_OBJECT = (
    r"(?:instructions?|prompts?|rules|directives|guidelines|guardrails|constraints|programming)"
)
# Words that tie the object to the conversation ("previous instructions"), unlike "all warnings".
_ANCHOR = r"(?:previous|prior|above|earlier|preceding|former|original|initial|your|system)"
_VERB = r"(?:ignore|disregard|forget|override|bypass)"

RULES: tuple[InjectionRule, ...] = (
    InjectionRule(
        "ignore_instructions",
        "Instruction to ignore previous instructions",
        re.compile(
            rf"\b{_VERB}\s+(?:(?:all|any|the|of|these|those)\s+){{0,3}}{_ANCHOR}\s+(?:\w+\s+){{0,2}}"
            rf"{_OBJECT}\b"
            rf"|\b{_VERB}\s+(?:all|any)\s+{_OBJECT}\b"
            rf"|\b{_VERB}\s+(?:all\s+of\s+)?(?:everything\s+)?the\s+above\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.85,
    ),
    InjectionRule(
        "ignore_instructions_pl",
        "Instruction to ignore previous instructions (Polish)",
        re.compile(
            r"\b(?:zignoruj|ignoruj|pomiń|pomin|zapomnij)\s+(?:o\s+)?(?:wszystki\w*\s+)?"
            r"(?:poprzedni\w*|wcześniejsz\w*|wczesniejsz\w*|powyższ\w*|powyzsz\w*|swo[ij]\w*"
            r"|two[ij]\w*|systemow\w*)\s+(?:\w+\s+)?(?:instrukcj\w*|polece\w*|zasad\w*|regu\w*)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.85,
    ),
    InjectionRule(
        "ignore_instructions_multilingual",
        "Instruction to ignore previous instructions (non-English)",
        re.compile(
            "|".join(
                (
                    # German
                    r"\b(?:ignorier(?:e|en)?|vergiss|missachte)\s+(?:(?:alle|die|deine|sämtliche)"
                    r"\s+){0,2}(?:vorherigen|bisherigen|obigen|vorigen|früheren|ursprünglichen)\s+"
                    r"(?:Anweisungen|Instruktionen|Befehle|Regeln|Vorgaben)",
                    # Spanish
                    r"\b(?:ignora|ignore|olvida|olvide|omite)\s+(?:(?:todas|todos|las|los|tus|sus)"
                    r"\s+){0,2}(?:instrucciones|indicaciones|reglas|órdenes)\s+(?:anteriores|previas)"
                    r"|\b(?:ignora|olvida)\s+tus\s+(?:instrucciones|reglas)",
                    # French
                    r"\b(?:ignore[zs]?|oublie[zs]?)\s+(?:(?:toutes|tous|les|tes|vos)\s+){0,2}"
                    r"(?:instructions|consignes|règles|directives)\s+(?:précédentes|antérieures)"
                    r"|\b(?:ignore[zs]?|oublie[zs]?)\s+(?:tes|vos)\s+(?:instructions|consignes|règles)",
                    # Italian
                    r"\b(?:ignora|dimentica)\s+(?:(?:tutte|tutti|le|gli|tue)\s+){0,2}"
                    r"(?:istruzioni|regole|indicazioni)\s+precedenti",
                    # Portuguese
                    r"\b(?:ignore|ignora|esqueça|esqueca)\s+(?:(?:todas|todos|as|os|suas)\s+){0,2}"
                    r"(?:instruções|instrucoes|regras|orientações)\s+anteriores",
                    # Russian
                    r"(?:игнорируй|игнорируйте|проигнорируй|забудь|забудьте)\s+(?:(?:все|всё)\s+)?"
                    r"(?:предыдущие|прошлые|прежние|свои|твои|вышеуказанные)\s+"
                    r"(?:инструкции|указания|правила|команды)",
                    # Chinese
                    r"(?:忽略|无视|忘记|忽视)掉?(?:之前|以前|上面|先前|前面|所有|全部)的?(?:所有|全部)?的?"
                    r"(?:指令|指示|说明|规则|提示)",
                    # Japanese
                    r"(?:以前|前|上記|これまで)の(?:指示|命令|ルール|指令)を?(?:すべて|全て)?無視",
                    # Korean
                    r"(?:이전|앞|위)의?\s*(?:모든\s*)?(?:지시|명령|지침|규칙)(?:을|를|들을)?\s*(?:모두\s*)?무시",
                )
            ),
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.85,
    ),
    InjectionRule(
        "jailbreak_persona",
        "Jailbreak persona or unrestricted mode",
        re.compile(
            r"\b(?:do anything now|DAN mode|developer mode|god mode|jailbr(?:eak|oken)(?: mode)?"
            r"|you are now (?:\w+\s+){0,3}(?:unrestricted|unfiltered|uncensored|free from)"
            r"|(?:without|no) (?:any )?(?:restrictions|filters|limitations|guardrails|rules) "
            r"(?:at all|whatsoever|anymore))",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.8,
    ),
    InjectionRule(
        "new_instructions",
        "Attempt to inject replacement instructions",
        re.compile(
            r"\b(?:new|updated|real|actual|true|important|urgent)\s+(?:system\s+)?instructions?\s*:"
            r"|\bfrom now on,? you (?:will|must|are)\b",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        0.6,
    ),
    InjectionRule(
        "prompt_extraction",
        "Attempt to extract the system prompt",
        re.compile(
            r"\b(?:reveal|print|show|repeat|output|leak|dump|display)\s+(?:me\s+)?(?:your|the)\s+"
            r"(?:full\s+|entire\s+|original\s+)?(?:system\s+prompt|initial\s+instructions"
            r"|hidden\s+instructions|instructions\s+above)",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        0.75,
    ),
    InjectionRule(
        "special_tokens",
        "Model control tokens in content",
        re.compile(
            r"<\|(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|>|<<SYS>>|\[/?INST\]"
        ),
        Severity.HIGH,
        0.8,
    ),
    InjectionRule(
        "fake_role_tag",
        "Fake system/assistant tag in untrusted content",
        re.compile(
            r"</?(?:system|assistant|human|user|instructions?|system[-_]?(?:prompt|message|reminder))>",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.75,
        untrusted_only=True,
    ),
    InjectionRule(
        "fake_role_turn",
        "Fake conversation turn in untrusted content",
        re.compile(r"(?m)^[ \t]*(?:Human|Assistant|System)[ \t]*:[ \t]*\S"),
        Severity.HIGH,
        0.7,
        untrusted_only=True,
    ),
    InjectionRule(
        "hidden_html_comment",
        "Instructions hidden in an HTML comment",
        re.compile(
            r"<!--(?:(?!-->)[\s\S]){0,2000}?"
            r"\b(?:ignore|instruction|assistant|AI|Claude|system|execute|run|do not tell)\b"
            r"(?:(?!-->)[\s\S]){0,2000}?-->",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        0.7,
    ),
    InjectionRule(
        "hidden_html_element",
        "Text hidden with CSS",
        re.compile(
            r"<[a-z]+[^>]{0,500}?style\s*=\s*[\"'][^\"']{0,500}?(?:display\s*:\s*none|visibility\s*:\s*hidden"
            r"|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\s*[;\"'])[^\"']{0,500}[\"'][^>]{0,500}>\s*[^<\s]",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        0.65,
    ),
    InjectionRule(
        "markdown_comment",
        "Instructions hidden in a markdown comment",
        re.compile(
            r"^\[//\]:\s*#\s*\((?=[^)]*\b(?:ignore|instruction|assistant|AI|Claude|system)\b)[^)]*\)",
            re.IGNORECASE | re.MULTILINE,
        ),
        Severity.MEDIUM,
        0.6,
    ),
    InjectionRule(
        "markdown_image_exfil",
        "Markdown image with templated query (data exfiltration via rendering)",
        re.compile(
            r"!\[[^\]]*\]\(\s*https?://[^\s)]+\?[^\s)]*(?:\{|\$|%7B|\[[A-Z_]+\])[^\s)]*\)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.75,
    ),
)


def decode_tag_characters(text: str) -> str:
    """Unicode tag characters mirror ASCII (U+E0041 is a hidden 'A'); reveal what they say."""
    return "".join(chr(ord(char) - 0xE0000) for char in text if 0xE0020 <= ord(char) <= 0xE007E)


def _group_key(location: str) -> str:
    match = _GROUP.match(location)
    return match.group() if match else location


class InjectionDetector:
    """Heuristic detector for direct and indirect prompt injection."""

    name = "injection"

    def __init__(self, policy: Policy) -> None:
        self._policy = policy.prompt_injection

    async def detect(self, ctx: InspectionContext) -> list[Finding]:
        segments = [s for s in ctx.segments if s.role not in OPERATOR_ROLES]
        results: list[Finding | None] = []
        found_rules: dict[str, set[str]] = {}
        for segment in segments:
            matched = self._match_rules(ctx, segment)
            found_rules.setdefault(_group_key(segment.location), set()).update(
                finding.rule for finding in matched if finding
            )
            results.extend(matched)
            results.extend(self._encoded(ctx, segment))
            results.extend(self._invisible_characters(ctx, segment))
        results.extend(self._split_across_blocks(ctx, segments, found_rules))
        return [finding for finding in results if finding]

    def _finding(
        self,
        ctx: InspectionContext,
        segment: TextSegment,
        rule: str,
        message: str,
        severity: Severity,
        confidence: float,
        excerpt: str,
        span: Span | None = None,
    ) -> Finding | None:
        boost = 0.0 if segment.trusted else UNTRUSTED_BOOST
        return build_finding(
            detector=self.name,
            category=Category.PROMPT_INJECTION,
            policy=self._policy,
            direction=ctx.direction,
            rule=rule,
            message=message,
            severity=severity,
            confidence=confidence + boost,
            segment=segment,
            span=span,
            excerpt=excerpt,
        )

    def _match_rules(self, ctx: InspectionContext, segment: TextSegment) -> list[Finding | None]:
        readings = views(segment.text)
        results: list[Finding | None] = []
        for rule in RULES:
            if rule.untrusted_only and segment.trusted:
                continue
            for view in readings:
                match = rule.pattern.search(view)
                if match:
                    span_valid = view == segment.text
                    results.append(
                        self._finding(
                            ctx,
                            segment,
                            rule.name,
                            rule.description,
                            rule.severity,
                            rule.confidence,
                            snippet(view, match.start(), match.end()),
                            Span(start=match.start(), end=match.end()) if span_valid else None,
                        )
                    )
                    break
        return results

    def _encoded(self, ctx: InspectionContext, segment: TextSegment) -> list[Finding | None]:
        """Instructions hidden in base64, hex or percent-encoding (up to two layers deep)."""
        results: list[Finding | None] = []
        candidates = decoded_candidates(segment.text)
        for outer in list(candidates):
            candidates.extend(
                Decoded(f"{outer.encoding}+{inner.encoding}", inner.text, outer.start, outer.end)
                for inner in decoded_candidates(outer.text)
            )
        for decoded in candidates:
            text = normalize(decoded.text)
            for rule in RULES:
                if rule.untrusted_only:
                    continue
                match = rule.pattern.search(text)
                if match:
                    results.append(
                        self._finding(
                            ctx,
                            segment,
                            "encoded_instructions",
                            f"{decoded.encoding}-encoded text: {rule.description}",
                            rule.severity,
                            rule.confidence,
                            f"decoded: {snippet(text, match.start(), match.end())}",
                            Span(start=decoded.start, end=decoded.end),
                        )
                    )
                    break
        return results

    def _split_across_blocks(
        self,
        ctx: InspectionContext,
        segments: list[TextSegment],
        found_rules: dict[str, set[str]],
    ) -> list[Finding | None]:
        """Patterns cut across sibling blocks of one message ("Ignore all" | "previous ...")."""
        groups: dict[str, list[TextSegment]] = {}
        for segment in segments:
            groups.setdefault(_group_key(segment.location), []).append(segment)

        results: list[Finding | None] = []
        for key, members in groups.items():
            if len(members) < 2:
                continue
            joined = TextSegment(
                location=members[0].location,
                text=" ".join(member.text for member in members),
                role=members[0].role,
                trusted=all(member.trusted for member in members),
            )
            for finding in self._match_rules(ctx, joined):
                if finding and finding.rule not in found_rules.get(key, set()):
                    results.append(
                        finding.model_copy(
                            update={
                                "message": f"{finding.message} (split across content blocks)",
                                "span": None,
                            }
                        )
                    )
        return results

    def _invisible_characters(
        self, ctx: InspectionContext, segment: TextSegment
    ) -> list[Finding | None]:
        text = segment.text
        results: list[Finding | None] = []

        tag_runs = _TAG_CHARS.findall(text)
        if tag_runs:
            hidden = decode_tag_characters("".join(tag_runs))
            results.append(
                self._finding(
                    ctx,
                    segment,
                    "unicode_tag_characters",
                    "Hidden text encoded in Unicode tag characters",
                    Severity.HIGH,
                    0.9,
                    f"hidden text: {snippet(hidden, 0, len(hidden))}",
                )
            )

        # A leading BOM is legitimate; count the rest.
        zero_width = len(_ZERO_WIDTH.findall(text.removeprefix("\ufeff")))
        if zero_width >= ZERO_WIDTH_MIN_COUNT:
            results.append(
                self._finding(
                    ctx,
                    segment,
                    "zero_width_characters",
                    f"{zero_width} zero-width characters (possible obfuscation)",
                    Severity.MEDIUM,
                    0.6,
                    f"{zero_width} zero-width characters",
                )
            )

        bidi = len(_BIDI_CONTROLS.findall(text))
        if bidi:
            results.append(
                self._finding(
                    ctx,
                    segment,
                    "bidi_control_characters",
                    "Bidirectional control characters can hide or reorder text",
                    Severity.MEDIUM,
                    0.65,
                    f"{bidi} bidi control characters",
                )
            )
        return results
