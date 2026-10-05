"""GuardEngine: runs detectors over a payload and aggregates a Verdict.

Flow of `inspect`:
1. Extract text segments from the payload (`payload.extract`).
2. Run the heuristic detectors concurrently.
3. Run the LLM judge when enabled and `needs_judgement` says the heuristics were uncertain.
4. Downgrade findings that sit in conversation history (see below).
5. Aggregate into a Verdict (strictest action wins), apply the fail mode on errors, audit.

Conversation history: a request carries the whole conversation, so content that was inspected
when it was new comes back on every later request. Findings located before the last assistant
message are therefore capped at `warn`, except secrets, which keep `redact` so the same value is
consistently masked. Without this, one old tool result would block every following request.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

import structlog

from claude_guard.audit import AuditLog
from claude_guard.config import Policy, Settings, get_settings, load_policy
from claude_guard.detectors.base import Detector
from claude_guard.detectors.commands import CommandsDetector
from claude_guard.detectors.injection import InjectionDetector
from claude_guard.detectors.llm_judge import LlmJudgeDetector, needs_judgement
from claude_guard.detectors.secrets import SecretScanner, SecretsDetector
from claude_guard.models import (
    Action,
    Category,
    Direction,
    Finding,
    InspectionContext,
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
    ) -> None:
        self._policy = policy
        self._settings = settings
        self._detectors: tuple[Detector, ...] = tuple(
            detectors
            if detectors is not None
            else (SecretsDetector(policy), InjectionDetector(policy), CommandsDetector(policy))
        )
        self._judge = judge
        self._use_llm_judge = use_llm_judge and policy.llm_judge.enabled
        self._scanner = SecretScanner(policy.secrets)
        self._audit = audit or AuditLog(settings.audit_path, self._scanner)

    @classmethod
    def from_settings(
        cls, settings: Settings | None = None, *, use_llm_judge: bool = True
    ) -> GuardEngine:
        settings = settings or get_settings()
        return cls(load_policy(settings.policy_path), settings, use_llm_judge=use_llm_judge)

    @property
    def policy(self) -> Policy:
        return self._policy

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
        self._audit.record(verdict, source=source, session_id=session_id, duration_ms=duration_ms)
        return verdict

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
        ctx = InspectionContext(
            direction=direction,
            segments=tuple(extraction.segments),
            tool_name=tool_name if isinstance(tool_name, str) else None,
            tool_input=tool_input if isinstance(tool_input, dict) else None,
            session_id=session_id,
            notes=tuple(extraction.notes),
        )

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

        if self._use_llm_judge and needs_judgement(self._policy, findings):
            findings.extend(
                await self._judge_detector().detect(self._judge_context(ctx, extraction))
            )

        if direction is Direction.REQUEST:
            findings = [self._cap_history(finding, extraction) for finding in findings]

        verdict = Verdict.from_findings(direction, findings, extraction.notes)
        if errors:
            verdict = self._apply_fail_mode(verdict, "; ".join(errors))
        return verdict

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
