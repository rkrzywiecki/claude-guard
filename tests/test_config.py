"""Tests for settings and policy loading/validation."""

from pathlib import Path

import pytest

from claude_guard.config import (
    DEFAULT_JUDGE_MODEL,
    Policy,
    PolicyError,
    Settings,
    get_settings,
    load_policy,
)
from claude_guard.models import Action, Category, Direction, Severity


def write_policy(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")
    return path


# --- Settings ---------------------------------------------------------------


def test_settings_defaults() -> None:
    settings = Settings()
    assert settings.fail_mode == "closed"
    assert settings.stream_mode == "buffer"
    assert settings.port == 8787
    assert settings.hook_llm is False
    assert settings.judge_model == DEFAULT_JUDGE_MODEL


def test_settings_read_guard_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_FAIL_MODE", "open")
    monkeypatch.setenv("GUARD_STREAM_MODE", "audit")
    monkeypatch.setenv("GUARD_JUDGE_MODEL", "custom-judge")
    monkeypatch.setenv("GUARD_PORT", "9000")
    settings = Settings()
    assert settings.fail_mode == "open"
    assert settings.stream_mode == "audit"
    assert settings.judge_model == "custom-judge"
    assert settings.port == 9000


def test_settings_read_dotenv(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("GUARD_HOOK_LLM=true\n", encoding="utf-8")
    assert Settings().hook_llm is True


def test_settings_read_anthropic_key_from_dotenv(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=from-dotenv\n", encoding="utf-8")
    settings = Settings()
    assert settings.anthropic_api_key is not None
    assert settings.anthropic_api_key.get_secret_value() == "from-dotenv"
    assert "from-dotenv" not in repr(settings)


def test_settings_reject_invalid_fail_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_FAIL_MODE", "sometimes")
    with pytest.raises(ValueError, match="fail_mode"):
        Settings()


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


# --- Shipped policy ---------------------------------------------------------


def test_shipped_policy_loads(repo_root: Path) -> None:
    policy = load_policy(repo_root / "policy.yaml")
    assert policy.secrets.action is Action.REDACT
    assert policy.prompt_injection.action is Action.BLOCK
    assert policy.dangerous_commands.action is Action.BLOCK
    assert policy.data_exfiltration.action is Action.BLOCK
    assert policy.llm_judge.enabled is False


def test_shipped_policy_matches_model_defaults(repo_root: Path) -> None:
    assert load_policy(repo_root / "policy.yaml") == Policy()


# --- Loading errors ---------------------------------------------------------


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "nope.yaml")


def test_invalid_yaml(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "secrets: [unclosed\n")
    with pytest.raises(PolicyError, match="cannot parse"):
        load_policy(path)


def test_non_mapping_top_level(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "- a\n- b\n")
    with pytest.raises(PolicyError, match="mapping"):
        load_policy(path)


def test_empty_file_uses_defaults(tmp_path: Path) -> None:
    assert load_policy(write_policy(tmp_path, "")) == Policy()


def test_partial_policy_keeps_other_defaults(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "secrets:\n  action: block\n  threshold: 0.9\n")
    policy = load_policy(path)
    assert policy.secrets.action is Action.BLOCK
    assert policy.secrets.threshold == 0.9
    assert policy.prompt_injection == Policy().prompt_injection


# --- Validation -------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("version: 2\n", "version"),
        ("unknown_category: {}\n", "unknown_category"),
        ("secrets:\n  typo_field: 1\n", "typo_field"),
        ("secrets:\n  action: nuke\n", "action"),
        ("secrets:\n  threshold: 1.5\n", "threshold"),
        ("secrets:\n  threshold: -0.1\n", "threshold"),
        ("secrets:\n  min_severity: extreme\n", "min_severity"),
        ("secrets:\n  allowlist: ['[unclosed']\n", "invalid regex"),
        ("dangerous_commands:\n  allowlist: ['(']\n", "invalid regex"),
        ("prompt_injection:\n  action: redact\n", "redact"),
        ("dangerous_commands:\n  direction_actions:\n    tool_input: redact\n", "redact"),
        ("prompt_injection:\n  direction_actions:\n    sideways: warn\n", "direction_actions"),
        ("llm_judge:\n  uncertain_range: [0.8, 0.2]\n", "uncertain_range"),
        ("llm_judge:\n  mode: sometimes\n", "mode"),
        ("llm_judge:\n  max_retries: 50\n", "max_retries"),
    ],
)
def test_invalid_policy_rejected(tmp_path: Path, content: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        load_policy(write_policy(tmp_path, content))


def test_for_category_covers_all_categories() -> None:
    policy = Policy()
    for category in Category:
        assert policy.for_category(category) is getattr(policy, category.value)


# --- Action resolution ------------------------------------------------------


def test_resolve_action_above_threshold() -> None:
    policy = Policy().prompt_injection
    assert policy.resolve_action(Direction.REQUEST, 0.9, Severity.HIGH) is Action.BLOCK


def test_resolve_action_below_threshold_downgrades_to_warn() -> None:
    policy = Policy().prompt_injection
    assert policy.resolve_action(Direction.REQUEST, 0.5, Severity.HIGH) is Action.WARN


def test_resolve_action_below_min_severity_is_ignored(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "secrets:\n  min_severity: high\n")
    policy = load_policy(path).secrets
    assert policy.resolve_action(Direction.REQUEST, 1.0, Severity.MEDIUM) is Action.ALLOW
    assert policy.resolve_action(Direction.REQUEST, 1.0, Severity.CRITICAL) is Action.REDACT


def test_resolve_action_disabled_category(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "dangerous_commands:\n  enabled: false\n")
    policy = load_policy(path).dangerous_commands
    assert policy.resolve_action(Direction.TOOL_INPUT, 1.0, Severity.CRITICAL) is Action.ALLOW


def test_resolve_action_direction_override(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path, "prompt_injection:\n  direction_actions:\n    tool_output: warn\n"
    )
    policy = load_policy(path).prompt_injection
    assert policy.resolve_action(Direction.TOOL_OUTPUT, 1.0, Severity.HIGH) is Action.WARN
    assert policy.resolve_action(Direction.REQUEST, 1.0, Severity.HIGH) is Action.BLOCK
