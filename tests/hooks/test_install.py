"""Tests for merging claude-guard hooks into Claude Code settings.json."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from claude_guard.cli import app
from claude_guard.config import Settings
from claude_guard.hooks.handlers import HookEvent
from claude_guard.hooks.install import (
    InstallError,
    guard_root,
    hook_command,
    install,
    merge_hooks,
)

ROOT = Path("/opt/claude guard")
OTHER_HOOK = {"type": "command", "command": "npx prettier --write"}


def existing_settings() -> dict[str, Any]:
    return {
        "permissions": {"allow": ["Bash(uv run pytest:*)"]},
        "env": {"FOO": "1"},
        "hooks": {
            "PostToolUse": [{"matcher": "Edit|Write", "hooks": [OTHER_HOOK]}],
            "Notification": [{"hooks": [{"type": "command", "command": "say done"}]}],
        },
    }


def guard_commands(settings: dict[str, Any], event: str) -> list[str]:
    return [
        hook["command"]
        for group in settings["hooks"][event]
        for hook in group["hooks"]
        if "claude-guard hook" in hook["command"]
    ]


def test_guard_root_is_the_project() -> None:
    assert (guard_root() / "pyproject.toml").exists()
    assert (guard_root() / "policy.yaml").exists()


def test_hook_command_uses_absolute_quoted_paths() -> None:
    command = hook_command(HookEvent.PRE_TOOL_USE, Settings(), ROOT)
    assert command == (
        "GUARD_POLICY_PATH='/opt/claude guard/policy.yaml' "
        "GUARD_AUDIT_PATH='/opt/claude guard/logs/audit.jsonl' "
        "uv run --quiet --project '/opt/claude guard' claude-guard hook PreToolUse"
    )


def test_hook_command_keeps_absolute_settings(tmp_path: Path) -> None:
    settings = Settings(policy_path=tmp_path / "p.yaml", audit_path=tmp_path / "a.jsonl")
    command = hook_command(HookEvent.STOP, settings, ROOT)
    assert f"GUARD_POLICY_PATH={tmp_path}/p.yaml" in command
    assert f"GUARD_AUDIT_PATH={tmp_path}/a.jsonl" in command


def test_merge_adds_all_events_and_keeps_existing() -> None:
    merged: dict[str, Any] = merge_hooks(existing_settings(), Settings(), ROOT)

    assert merged["permissions"] == {"allow": ["Bash(uv run pytest:*)"]}
    assert merged["env"] == {"FOO": "1"}
    hooks = merged["hooks"]
    assert hooks["Notification"] == existing_settings()["hooks"]["Notification"]
    assert hooks["PostToolUse"][0] == {"matcher": "Edit|Write", "hooks": [OTHER_HOOK]}

    for event in HookEvent:
        [command] = guard_commands(merged, event.value)
        assert command.endswith(f"claude-guard hook {event.value}")

    pre = hooks["PreToolUse"][-1]
    assert pre["matcher"] == "*"
    assert pre["hooks"][0]["timeout"] == 15
    assert "matcher" not in hooks["UserPromptSubmit"][-1]
    assert hooks["Stop"][-1]["hooks"][0]["timeout"] == 30


def test_merge_is_idempotent_and_replaces_old_guard_entries() -> None:
    stale = existing_settings()
    stale["hooks"]["Stop"] = [
        {"hooks": [{"type": "command", "command": "old/path claude-guard hook Stop"}]}
    ]
    once: dict[str, Any] = merge_hooks(stale, Settings(), ROOT)
    twice: dict[str, Any] = merge_hooks(once, Settings(), ROOT)
    assert once == twice
    [command] = guard_commands(twice, "Stop")
    assert "old/path" not in command


def test_merge_keeps_other_hooks_in_shared_group() -> None:
    settings: dict[str, Any] = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        OTHER_HOOK,
                        {"type": "command", "command": "x claude-guard hook PreToolUse"},
                    ],
                }
            ]
        }
    }
    merged: dict[str, Any] = merge_hooks(settings, Settings(), ROOT)
    groups = merged["hooks"]["PreToolUse"]
    assert groups[0] == {"matcher": "*", "hooks": [OTHER_HOOK]}
    assert len(groups) == 2


@pytest.mark.parametrize(
    "settings",
    [{"hooks": []}, {"hooks": {"Stop": {"not": "a list"}}}],
)
def test_merge_rejects_malformed_hooks(settings: dict[str, Any]) -> None:
    with pytest.raises(InstallError):
        merge_hooks(settings, Settings(), ROOT)


# --- Writing files ----------------------------------------------------------------


def test_install_creates_new_file(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    assert install(path, Settings(), ROOT) is None
    written = json.loads(path.read_text(encoding="utf-8"))
    assert set(written["hooks"]) == {e.value for e in HookEvent}


def test_install_backs_up_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    original = json.dumps(existing_settings())
    path.write_text(original, encoding="utf-8")

    backup = install(path, Settings(), ROOT)

    assert backup is not None
    assert backup.name.startswith("settings.json.bak-")
    assert backup.read_text(encoding="utf-8") == original
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["permissions"] == existing_settings()["permissions"]


def test_install_refuses_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{ broken", encoding="utf-8")
    with pytest.raises(InstallError, match="not valid JSON"):
        install(path, Settings(), ROOT)
    assert path.read_text(encoding="utf-8") == "{ broken"
    assert list(tmp_path.iterdir()) == [path]  # no backup, no changes


def test_install_refuses_non_object(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(InstallError, match="JSON object"):
        install(path, Settings(), ROOT)


# --- CLI ------------------------------------------------------------------------


def test_cli_project_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(app, ["install-hooks", "--project"])
    assert result.exit_code == 0, result.output
    path = project / ".claude" / "settings.json"
    assert f"Installed claude-guard hooks in {path}" in result.output
    written = json.loads(path.read_text(encoding="utf-8"))
    command = guard_commands(written, "PreToolUse")[0]
    assert str(guard_root()) in command


def test_cli_user_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    result = CliRunner().invoke(app, ["install-hooks", "--user"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".claude" / "settings.json").exists()


def test_cli_dry_run_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["install-hooks", "--dry-run"])
    assert result.exit_code == 0
    assert "claude-guard hook Stop" in result.output
    assert not (tmp_path / ".claude").exists()


def test_cli_reports_invalid_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{", encoding="utf-8")
    result = CliRunner().invoke(app, ["install-hooks"])
    assert result.exit_code == 1
    assert "not valid JSON" in result.output
