"""Tests for the latency benchmark (`claude-guard bench`)."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from claude_guard import bench
from claude_guard.bench import (
    Bench,
    BenchError,
    LatencyStats,
    Scenario,
    conversation_request,
    engine_cases,
    run_bench,
)
from claude_guard.cli import app
from claude_guard.config import Settings, get_settings, load_policy
from claude_guard.engine import GuardEngine
from claude_guard.models import Action, Category, Finding, Severity


@pytest.fixture
def settings(repo_root: Path, tmp_path: Path) -> Settings:
    return Settings(policy_path=repo_root / "policy.yaml", audit_path=tmp_path / "audit.jsonl")


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Small payloads and no warm-up, so scenarios run in a few seconds."""
    monkeypatch.setattr(bench, "SIZES", {"small": 1, "medium": 2})
    monkeypatch.setattr(bench, "STREAM_SIZE", "small")
    monkeypatch.setattr(bench, "WARMUP", dict.fromkeys(bench.WARMUP, 0))


def test_latency_stats_percentiles() -> None:
    stats = LatencyStats.from_seconds([i / 1000 for i in range(1, 101)])
    assert stats.samples == 100
    assert (stats.p50_ms, stats.p95_ms, stats.p99_ms, stats.max_ms) == (50, 95, 99, 100)
    assert stats.mean_ms == 50.5


def test_latency_stats_single_sample() -> None:
    stats = LatencyStats.from_seconds([0.002])
    assert stats.p50_ms == stats.p99_ms == stats.max_ms == 2


def test_latency_stats_requires_samples() -> None:
    with pytest.raises(ValueError, match="no samples"):
        LatencyStats.from_seconds([])


def test_conversation_grows_with_turns() -> None:
    small, large = conversation_request(1), conversation_request(10, stream=True)
    assert len(small["messages"]) == 3  # type: ignore[arg-type]
    assert len(large["messages"]) == 21  # type: ignore[arg-type]
    assert large["stream"] is True
    assert len(json.dumps(large)) > 5 * len(json.dumps(small))


async def test_payloads_take_the_clean_path(settings: Settings) -> None:
    """The benchmark measures ordinary traffic: nothing is blocked or redacted."""
    engine = GuardEngine(load_policy(settings.policy_path), settings, use_llm_judge=False)
    for case, direction, payload in engine_cases():
        verdict = await engine.inspect(direction, payload)
        assert verdict.action in (Action.ALLOW, Action.WARN), (case, verdict.findings)


def test_engine_scenario(settings: Settings, quick: None) -> None:
    report = run_bench(settings, [Scenario.ENGINE], iterations=2)
    assert report.results[4].case == "tool_output (Read, largest file)"
    assert len(report.results) == 2 + 3 + 2
    assert report.results[-1].case == "request medium, next turn"
    assert all(r.added.samples == 2 and r.added.p50_ms > 0 for r in report.results)
    assert not settings.audit_path.exists()  # the real audit log is left alone


def test_proxy_scenario(settings: Settings, quick: None) -> None:
    report = run_bench(settings, [Scenario.PROXY], iterations=2)
    cases = {r.case: r for r in report.results}
    assert set(cases) == {
        "non-streaming, request small, first",
        "non-streaming, request small, next turn",
        "non-streaming, request medium, first",
        "non-streaming, request medium, next turn",
        "stream buffer, first token (request small)",
        "stream buffer, total (request small)",
        "stream audit, first token (request small)",
        "stream audit, total (request small)",
    }
    assert all(r.baseline is not None for r in report.results)
    # Buffering holds the first token until the whole stream (20 deltas x 5 ms) is inspected.
    assert cases["stream buffer, first token (request small)"].added.p50_ms > 80
    assert cases["stream audit, first token (request small)"].added.p50_ms < 80


def test_hooks_scenario(settings: Settings, quick: None) -> None:
    report = run_bench(settings, [Scenario.HOOKS], iterations=1)
    cases = [r.case for r in report.results]
    assert cases[0] == "python -c pass (interpreter floor)"
    for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
        assert f"{event}: in process" in cases
        assert f"{event}: venv script" in cases
    assert any("new process per event" in note for note in report.notes)


def test_judge_failure_is_reported(
    settings: Settings, quick: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = Finding(
        detector="llm_judge",
        category=Category.LLM_JUDGE,
        rule="judge_unavailable",
        message="LLM judge unavailable",
        severity=Severity.HIGH,
        action=Action.BLOCK,
        confidence=1.0,
    )

    async def detect(*_: object) -> list[Finding]:
        return [failure]

    monkeypatch.setattr(bench.LlmJudgeDetector, "detect", detect)
    with pytest.raises(BenchError, match="LLM judge call failed"):
        Bench(settings, iterations=1).run([Scenario.JUDGE])


def test_judge_without_credentials_is_reported(
    settings: Settings, quick: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def detect(*_: object) -> list[Finding]:
        raise TypeError("Could not resolve authentication method")

    monkeypatch.setattr(bench.LlmJudgeDetector, "detect", detect)
    with pytest.raises(BenchError, match="TypeError"):
        Bench(settings, iterations=1).run([Scenario.JUDGE])


def test_judge_scenario(settings: Settings, quick: None, monkeypatch: pytest.MonkeyPatch) -> None:
    async def detect(*_: object) -> list[Finding]:
        return []

    monkeypatch.setattr(bench.LlmJudgeDetector, "detect", detect)
    report = run_bench(settings, [Scenario.JUDGE], iterations=3)
    assert report.results[0].added.samples == 3
    assert "real API calls" in report.notes[0]


def test_idle_pauses_before_each_call(
    settings: Settings, quick: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    pauses: list[float] = []
    monkeypatch.setattr(bench.time, "sleep", pauses.append)
    run_bench(settings, [Scenario.ENGINE], iterations=2, idle=0.05)
    assert pauses == [0.05] * 2 * 7


# --- CLI ----------------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo_root: Path) -> None:
    monkeypatch.setenv("GUARD_POLICY_PATH", str(repo_root / "policy.yaml"))
    monkeypatch.setenv("GUARD_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()


def test_cli_bench_json(env: None, quick: None) -> None:
    result = CliRunner().invoke(app, ["bench", "-s", "engine", "--iterations", "1", "--json"])
    assert result.exit_code == 0, result.stderr
    data = json.loads(result.stdout)
    assert {r["scenario"] for r in data["results"]} == {"engine"}
    assert "p95_ms" in data["results"][0]["added"]


def test_cli_bench_table(env: None, quick: None) -> None:
    result = CliRunner().invoke(app, ["bench", "-s", "engine", "--iterations", "1"])
    assert result.exit_code == 0
    assert "Latency added by claude-guard" in result.stdout
    assert "running engine" in result.stderr


def test_cli_bench_unknown_scenario(env: None) -> None:
    result = CliRunner().invoke(app, ["bench", "-s", "nope"])
    assert result.exit_code == 2
    assert "error:" in result.stderr
