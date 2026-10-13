"""GuardEngine: runs detectors over a payload and aggregates a Verdict.

Flow of `inspect`:
1. Extract text segments from the payload (`payload.extract`).
2. Run the heuristic detectors concurrently.
3. Run the LLM judge when enabled and `needs_judgement` says so (heuristics uncertain, or
   untrusted content in the current turn in `untrusted` mode).
4. Downgrade findings that sit in conversation history (see below).
5. Aggregate into a Verdict (strictest action wins), apply the fail mode on errors, audit.

Conversation history: a request carries the whole conversation, so content that was inspected
when it was new comes back on every later request. Findings located before the last assistant
message are therefore capped at `warn`, except secrets, which keep `redact` so the same value is
consistently masked. Without this, one old tool result would block every following request.

Requests are inspected unit by unit (message, tool definition, system prompt) through an
`InspectionCache` (`GUARD_INSPECTION_CACHE_SIZE`): units seen on an earlier request reuse their
findings, so a growing conversation only costs the new messages. The LLM judge is not cached.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

import structlog

from claude_guard.alerts import Alerter
from claude_guard.audit import AuditLog
from claude_guard.cache import InspectionCache, inspection_unit, unit_key
from claude_guard.config import Policy, Settings, get_settings, load_policy, protected_paths
from claude_guard.detectors.base import Detector
from claude_guard.detectors.commands import CommandsDetector
from claude_guard.detectors.custom import CustomRulesDetector, masking_rules
from claude_guard.detectors.exfiltration import ExfiltrationDetector
from claude_guard.detectors.injection import InjectionDetector
from claude_guard.detectors.llm_judge import LlmJudgeDetector, needs_judgement
from claude_guard.detectors.secrets import SecretScanner, SecretsDetector
from claude_guard.detectors.tools import ToolPolicyDetector
from claude_guard.models import (
    Action,
    Category,
    Direction,
    Finding,
    InspectionContext,
    TextSegment,
    ToolCall,
    Verdict,
)
from claude_guard.payload import Extraction, JsonObject, apply_redactions, extract

log = structlog.get_logger(__name__)

HISTORY_CAPPED_ACTIONS = frozenset({Action.BLOCK, Action.REDACT})


class GuardEngine:
    """Inspects payloads in any direction using one shared set of detectors."""

    def __init__(
        self,
        policy: Policy,
        settings: Settings,
        *,
        detectors: Sequence[Detector] | None = None,
        judge: Detector | None = None,
        use_llm_judge: bool = True,
        audit: AuditLog | None = None,
        alerter: Alerter | None = None,
        cache_size: int | None = None,
    ) -> None:
        self._policy = policy
        self._settings = settings
        self._detectors: tuple[Detector, ...] = tuple(
            detectors
            if detectors is not None
            else (
                SecretsDetector(policy),
                InjectionDetector(policy),
                CommandsDetector(policy, protected_paths(settings)),
                ExfiltrationDetector(policy),
                CustomRulesDetector(policy),
                ToolPolicyDetector(policy),
            )
        )
        self._judge = judge
        self._use_llm_judge = use_llm_judge and policy.llm_judge.enabled
        self._scanner = SecretScanner(policy.secrets, masking_rules(policy))
        self._alerter = alerter
        size = settings.inspection_cache_size if cache_size is None else cache_size
        self._cache = InspectionCache(size) if size > 0 else None
        self._audit = audit or AuditLog(
            settings.audit_path,
            self._scanner,
            max_bytes=settings.audit_max_bytes,
            backups=settings.audit_backups,
        )

    @classmethod
    def from_settings(
        cls,
        settings: Settings | None = None,
        *,
        use_llm_judge: bool = True,
        use_alerts: bool = True,
    ) -> GuardEngine:
        settings = settings or get_settings()
        return cls(
            load_policy(settings.policy_path),
            settings,
            use_llm_judge=use_llm_judge,
            alerter=Alerter.from_settings(settings) if use_alerts else None,
        )

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def cache(self) -> InspectionCache | None:
        """Findings of request units already inspected (None when disabled)."""
        return self._cache

    @property
    def scanner(self) -> SecretScanner:
        """Masks built-in and custom secrets in outward-facing text."""
        return self._scanner

    async def inspect(
        self,
        direction: Direction,
        payload: JsonObject,
        *,
        session_id: str | None = None,
        source: str | None = None,
    ) -> Verdict:
        started = time.perf_counter()
        try:
            verdict = await self._inspect(direction, payload, session_id)
        except Exception as exc:
            log.error(
                "guard_engine_failed", direction=direction.value, error_type=type(exc).__name__
            )
            verdict = self._apply_fail_mode(
                Verdict(direction=direction, action=Action.ALLOW), f"{type(exc).__name__}: {exc}"
            )
        duration_ms = (time.perf_counter() - started) * 1000
        record = self._audit.record(
            verdict, source=source, session_id=session_id, duration_ms=duration_ms
        )
        if self._alerter is not None:
            self._alerter.notify(record)
        return verdict

    async def flush_alerts(self) -> None:
        """Wait for alerts still being sent (bounded by GUARD_ALERT_TIMEOUT)."""
        if self._alerter is not None:
            await self._alerter.flush()

    def safe_reason(self, verdict: Verdict) -> str:
        """`verdict.reason` with secrets masked, for messages shown to clients and users.

        Reasons are mostly rule descriptions, but LLM judge explanations and error messages can
        quote the inspected content.
        """
        return self._scanner.mask(verdict.reason)

    def mask(self, text: str) -> str:
        """Mask secrets in arbitrary outward-facing text."""
        return self._scanner.mask(text)

    def redact(self, payload: JsonObject, verdict: Verdict) -> JsonObject:
        """Return a copy of `payload` with every `redact` finding's span replaced."""
        return apply_redactions(payload, (f for f in verdict.findings if f.action is Action.REDACT))

    async def _inspect(
        self, direction: Direction, payload: JsonObject, session_id: str | None
    ) -> Verdict:
        extraction = extract(direction, payload)
        tool_name = payload.get("tool_name") if direction is Direction.TOOL_INPUT else None
        tool_input = payload.get("tool_input") if direction is Direction.TOOL_INPUT else None
        cwd = payload.get("cwd") if direction is Direction.TOOL_INPUT else None
        ctx = InspectionContext(
            direction=direction,
            segments=tuple(extraction.segments),
            tool_name=tool_name if isinstance(tool_name, str) else None,
            tool_input=tool_input if isinstance(tool_input, dict) else None,
            session_id=session_id,
            notes=tuple(extraction.notes),
            cwd=cwd if isinstance(cwd, str) else None,
            tool_calls=tuple(extraction.tool_calls),
        )

        if direction is Direction.REQUEST and self._cache is not None:
            findings, errors = await self._detect_cached(ctx, self._cache)
        else:
            findings, errors = await self._detect(ctx)

        if self._use_llm_judge:
            judge_ctx = self._judge_context(ctx, extraction)
            if needs_judgement(
                self._policy, findings, untrusted_content=bool(judge_ctx.untrusted_segments)
            ):
                findings.extend(await self._judge_detector().detect(judge_ctx))

        if direction is Direction.REQUEST:
            findings = [self._cap_history(finding, extraction) for finding in findings]

        verdict = Verdict.from_findings(direction, findings, extraction.notes)
        if errors:
            verdict = self._apply_fail_mode(verdict, "; ".join(errors))
        return verdict

    async def _detect(self, ctx: InspectionContext) -> tuple[list[Finding], list[str]]:
        """Run the heuristic detectors concurrently; returns (findings, errors)."""
        results = await asyncio.gather(
            *(detector.detect(ctx) for detector in self._detectors), return_exceptions=True
        )
        findings: list[Finding] = []
        errors: list[str] = []
        for detector, result in zip(self._detectors, results, strict=True):
            if isinstance(result, BaseException):
                if not isinstance(result, Exception):
                    raise result
                log.error(
                    "detector_failed", detector=detector.name, error_type=type(result).__name__
                )
                errors.append(f"{detector.name}: {type(result).__name__}: {result}")
            else:
                findings.extend(result)
        return findings, errors

    async def _detect_cached(
        self, ctx: InspectionContext, cache: InspectionCache
    ) -> tuple[list[Finding], list[str]]:
        """`_detect` on the units not in the cache; findings come back in payload order."""
        items: list[TextSegment | ToolCall] = [*ctx.segments, *ctx.tool_calls]
        units: dict[str, list[TextSegment | ToolCall]] = {}
        for item in items:
            units.setdefault(inspection_unit(item.location), []).append(item)

        findings: list[Finding] = []
        pending: dict[str, str] = {}  # unit -> key
        for unit, members in units.items():
            key = unit_key(members)
            cached = cache.get(key)
            if cached is None:
                pending[unit] = key
            else:
                findings.extend(cached)

        errors: list[str] = []
        if pending:
            fresh, errors = await self._detect(
                ctx.model_copy(
                    update={
                        "segments": tuple(
                            s for s in ctx.segments if inspection_unit(s.location) in pending
                        ),
                        "tool_calls": tuple(
                            c for c in ctx.tool_calls if inspection_unit(c.location) in pending
                        ),
                    }
                )
            )
            findings.extend(fresh)
            if not errors:
                self._store(cache, pending, fresh)

        order = {unit: index for index, unit in enumerate(units)}
        findings.sort(key=lambda f: order.get(inspection_unit(f.location or ""), len(order)))
        return findings, errors

    @staticmethod
    def _store(cache: InspectionCache, pending: dict[str, str], findings: list[Finding]) -> None:
        by_unit: dict[str, list[Finding]] = {unit: [] for unit in pending}
        for finding in findings:
            unit = inspection_unit(finding.location) if finding.location else None
            if unit not in by_unit:
                return  # not attributable to one unit: keep nothing rather than lose it
            by_unit[unit].append(finding)
        for unit, key in pending.items():
            cache.put(key, by_unit[unit])

    def _judge_detector(self) -> Detector:
        if self._judge is None:
            self._judge = LlmJudgeDetector(self._policy, self._settings)
        return self._judge

    @staticmethod
    def _judge_context(ctx: InspectionContext, extraction: Extraction) -> InspectionContext:
        """The judge only sees the current turn: history was judged when it was new."""
        current = tuple(s for s in ctx.segments if not extraction.is_historical(s.location))
        return ctx.model_copy(update={"segments": current})

    @staticmethod
    def _cap_history(finding: Finding, extraction: Extraction) -> Finding:
        if (
            finding.category is Category.SECRETS
            or finding.action not in HISTORY_CAPPED_ACTIONS
            or not extraction.is_historical(finding.location)
        ):
            return finding
        return finding.model_copy(
            update={"action": Action.WARN, "message": f"{finding.message} (in history)"}
        )

    def _apply_fail_mode(self, verdict: Verdict, error: str) -> Verdict:
        action = Action.BLOCK if self._settings.fail_mode == "closed" else verdict.action
        return verdict.model_copy(update={"action": action, "error": error})
