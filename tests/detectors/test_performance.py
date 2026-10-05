"""Guards against catastrophic regex backtracking (ReDoS) on adversarial input."""

import time

import pytest

from claude_guard.config import Policy
from claude_guard.detectors.commands import CommandsDetector
from claude_guard.detectors.injection import InjectionDetector
from claude_guard.detectors.secrets import SecretsDetector
from claude_guard.models import Direction, InspectionContext, TextSegment

SIZE = 100_000
TIME_LIMIT_SECONDS = 2.0

ADVERSARIAL = {
    "underscore_runs": "a_" * (SIZE // 2),
    "spaced_digits": "1 " * (SIZE // 2),
    "newlines": "\n" * SIZE,
    "open_tags": "<a " * (SIZE // 3),
    "open_comment": "<!--" + "x " * (SIZE // 2),
    "repeated_pipes": "cat | " * (SIZE // 6),
    "repeated_curl": "curl " * (SIZE // 5),
    "dotted": "a.b" * (SIZE // 3),
    "base64ish": "Ab3+" * (SIZE // 4),
    "assignments": "a=b $a " * (SIZE // 7),
    "ansi_c": "$'\\x41' " * (SIZE // 9),
    "nested_quotes": 'bash -c "' * (SIZE // 9),
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
async def test_detectors_are_linear_enough(name: str) -> None:
    policy = Policy()
    detectors = (SecretsDetector(policy), InjectionDetector(policy), CommandsDetector(policy))
    segment = TextSegment(
        location="x", text=ADVERSARIAL[name], trusted=False, tool_name="Bash", tool_field="command"
    )
    ctx = InspectionContext(direction=Direction.TOOL_INPUT, segments=(segment,))
    for detector in detectors:
        start = time.perf_counter()
        await detector.detect(ctx)
        elapsed = time.perf_counter() - start
        assert elapsed < TIME_LIMIT_SECONDS, f"{detector.name} took {elapsed:.2f}s on {name}"
