"""Tests for detector helpers."""

from claude_guard.config import Policy
from claude_guard.detectors.base import Detector, build_finding, mask_secret, snippet
from claude_guard.detectors.commands import CommandsDetector
from claude_guard.detectors.injection import InjectionDetector
from claude_guard.detectors.secrets import SecretsDetector
from claude_guard.models import Action, Category, Direction, Severity


def test_detectors_implement_protocol() -> None:
    policy = Policy()
    for detector in (SecretsDetector(policy), InjectionDetector(policy), CommandsDetector(policy)):
        assert isinstance(detector, Detector)


def test_mask_secret_keeps_prefix_and_suffix() -> None:
    assert mask_secret("sk-ant-api03-abcdefghijklmnopqrstuvwxyzabcd") == "sk-ant-***abcd"


def test_mask_secret_short_value_hides_suffix() -> None:
    assert mask_secret("90010112345") == "90***"
    assert mask_secret("abc") == "***"


def test_snippet_is_single_line_and_capped() -> None:
    text = "a" * 100 + "\nMATCH\n" + "b" * 500
    result = snippet(text, 101, 106)
    assert "\n" not in result
    assert "MATCH" in result
    assert len(result) <= 166


def test_build_finding_skips_allowed() -> None:
    policy = Policy().dangerous_commands.model_copy(update={"enabled": False})
    finding = build_finding(
        detector="t",
        category=Category.DANGEROUS_COMMANDS,
        policy=policy,
        direction=Direction.TOOL_INPUT,
        rule="r",
        message="m",
        severity=Severity.HIGH,
        confidence=1.0,
    )
    assert finding is None


def test_build_finding_clamps_confidence() -> None:
    finding = build_finding(
        detector="t",
        category=Category.PROMPT_INJECTION,
        policy=Policy().prompt_injection,
        direction=Direction.REQUEST,
        rule="r",
        message="m",
        severity=Severity.HIGH,
        confidence=1.3,
    )
    assert finding is not None
    assert finding.confidence == 1.0
    assert finding.action is Action.BLOCK
