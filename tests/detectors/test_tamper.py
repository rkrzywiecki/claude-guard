"""Tests for guard tampering and persistence through file-modifying tool calls."""

from pathlib import Path

import pytest

from claude_guard.config import DangerousCommandsPolicy, Policy, Settings, protected_paths
from claude_guard.detectors.commands import CommandsDetector
from claude_guard.models import Action, InspectionContext
from tests.detectors.helpers import findings, rules, tool_ctx


@pytest.fixture
def guard_dir(tmp_path: Path) -> Path:
    root = tmp_path / "claude-guard"
    (root / "logs" / "sessions").mkdir(parents=True)
    (root / "policy.yaml").write_text("version: 1\n", encoding="utf-8")
    (root / "logs" / "audit.jsonl").write_text("", encoding="utf-8")
    return root


@pytest.fixture
def detector(guard_dir: Path) -> CommandsDetector:
    settings = Settings(
        policy_path=guard_dir / "policy.yaml", audit_path=guard_dir / "logs" / "audit.jsonl"
    )
    return CommandsDetector(Policy(), protected_paths(settings))


def bash(command: str, cwd: Path | str | None = None) -> InspectionContext:
    ctx = tool_ctx("Bash", "command", command)
    return ctx.model_copy(update={"cwd": str(cwd) if cwd is not None else None})


def write(tool: str, path: str, cwd: Path | None = None) -> InspectionContext:
    ctx = tool_ctx(tool, "file_path", path)
    return ctx.model_copy(update={"cwd": str(cwd) if cwd is not None else None})


def test_protected_paths_cover_policy_audit_and_offsets() -> None:
    settings = Settings(
        policy_path=Path("/g/policy.yaml"), audit_path=Path("/g/logs/a.jsonl"), audit_backups=2
    )
    assert protected_paths(settings) == (
        Path("/g/policy.yaml"),
        Path("/g/logs/a.jsonl"),
        Path("/g/logs/a.jsonl.1"),
        Path("/g/logs/a.jsonl.2"),
        Path("/g/logs/sessions"),
    )


async def test_rotated_audit_log_is_protected(detector: CommandsDetector, guard_dir: Path) -> None:
    command = f"rm {guard_dir}/logs/audit.jsonl.3"
    assert await rules(detector, bash(command)) == ["guard_tamper"]


# --- Guard files: absolute paths --------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "sed -i '' 's/enabled: true/enabled: false/' {g}/policy.yaml",
        "perl -pi -e 's/block/allow/' {g}/policy.yaml",
        "echo 'version: 1' > {g}/policy.yaml",
        "cat /dev/null | tee {g}/policy.yaml",
        "cp /tmp/lax.yaml {g}/policy.yaml",
        "mv {g}/policy.yaml /tmp/old.yaml",
        "rm {g}/logs/audit.jsonl",
        "truncate -s 0 {g}/logs/audit.jsonl",
        "rm -rf {g}/logs",
        "rm {g}/logs/sessions/sess-1.offset",
        "rm {g}/logs/*.jsonl",
        "sudo bash -c 'echo > {g}/logs/audit.jsonl'",
    ],
)
async def test_shell_tampering_with_guard_files(
    detector: CommandsDetector, guard_dir: Path, command: str
) -> None:
    found = await findings(detector, bash(command.format(g=guard_dir)))
    [finding] = [f for f in found if f.rule != "recursive_delete"]
    assert finding.rule == "guard_tamper"
    assert finding.action is Action.BLOCK


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
async def test_file_tool_tampering_with_policy(
    detector: CommandsDetector, guard_dir: Path, tool: str
) -> None:
    ctx = write(tool, str(guard_dir / "policy.yaml"))
    assert await rules(detector, ctx) == ["guard_tamper"]


# --- Guard files: relative paths and cwd ------------------------------------------


async def test_relative_path_resolved_against_cwd(
    detector: CommandsDetector, guard_dir: Path
) -> None:
    assert await rules(detector, bash("rm logs/audit.jsonl", cwd=guard_dir)) == ["guard_tamper"]


async def test_relative_path_follows_cd(
    detector: CommandsDetector, guard_dir: Path, tmp_path: Path
) -> None:
    command = f"cd {guard_dir} && : > policy.yaml"
    assert await rules(detector, bash(command, cwd=tmp_path)) == ["guard_tamper"]


async def test_relative_path_follows_relative_cd(
    detector: CommandsDetector, guard_dir: Path
) -> None:
    command = "cd logs && rm audit.jsonl"
    assert await rules(detector, bash(command, cwd=guard_dir)) == ["guard_tamper"]


async def test_relative_write_tool_path(detector: CommandsDetector, guard_dir: Path) -> None:
    assert await rules(detector, write("Write", "policy.yaml", cwd=guard_dir)) == ["guard_tamper"]


async def test_relative_path_without_cwd_is_not_resolved(detector: CommandsDetector) -> None:
    # Proxy mode: the working directory of a tool call is unknown.
    assert await rules(detector, bash("rm logs/audit.jsonl")) == []


async def test_symlinked_path_is_resolved(
    detector: CommandsDetector, guard_dir: Path, tmp_path: Path
) -> None:
    link = tmp_path / "link"
    link.symlink_to(guard_dir)
    assert await rules(detector, bash(f"rm {link}/policy.yaml")) == ["guard_tamper"]


# --- Claude Code settings ---------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "echo '{}' > .claude/settings.json",
        "rm ~/.claude/settings.json",
        "jq 'del(.hooks)' s.json > /repo/.claude/settings.local.json",
        "mv .claude/settings.json /tmp/",
        "rm -rf .claude",
        "cp /tmp/x.json '/Library/Application Support/ClaudeCode/managed-settings.json'",
    ],
)
async def test_shell_tampering_with_claude_settings(
    detector: CommandsDetector, command: str
) -> None:
    found = await rules(detector, bash(command))
    assert [rule for rule in found if rule != "recursive_delete"] == ["guard_tamper"]


@pytest.mark.parametrize(
    "path", ["/repo/.claude/settings.json", "/Users/a/.claude/settings.local.json"]
)
async def test_file_tool_tampering_with_claude_settings(
    detector: CommandsDetector, path: str
) -> None:
    assert await rules(detector, write("Edit", path)) == ["guard_tamper"]


# --- Persistence through the shell ------------------------------------------------


@pytest.mark.parametrize(
    ("command", "rule"),
    [
        ("echo 'export PATH=/tmp/.x:$PATH' >> ~/.zshrc", "persistence_file_write"),
        ("printf 'alias ls=x' >> $HOME/.bashrc", "persistence_file_write"),
        ("echo x | tee -a ~/.zshenv", "persistence_file_write"),
        ("cp payload.sh .git/hooks/pre-commit", "persistence_file_write"),
        ("cp agent.plist ~/Library/LaunchAgents/com.x.plist", "persistence_file_write"),
        ("sudo tee -a /etc/hosts", "persistence_file_write"),
        ("(crontab -l; echo '* * * * * /tmp/x') | crontab -", "persistence_command"),
        ("crontab /tmp/jobs", "persistence_command"),
        ("launchctl load ~/Library/LaunchAgents/com.x.plist", "persistence_command"),
        ("systemctl --user enable backdoor.service", "persistence_command"),
    ],
)
async def test_shell_persistence(detector: CommandsDetector, command: str, rule: str) -> None:
    assert rule in await rules(detector, bash(command))


# --- Negative and false positives -------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat {g}/policy.yaml",
        "grep -c block {g}/logs/audit.jsonl",
        "uv run claude-guard report --file {g}/logs/audit.jsonl",
        "cp {g}/policy.yaml /tmp/policy-backup.yaml",
        "cat .claude/settings.json",
        "jq .hooks ~/.claude/settings.json",
        "echo hi > /tmp/out.txt",
        "ls 2>/dev/null > listing.txt",
        "cat ~/.zshrc",
        "sed 's/a/b/' ~/.bashrc",
        "crontab -l",
        "systemctl status nginx",
        "rm -r build dist",
        "mkdir -p {g}/../other && touch {g}/../other/file",
        "echo 'rm policy.yaml' > notes.txt",
    ],
)
async def test_no_tamper_findings(
    detector: CommandsDetector, guard_dir: Path, command: str
) -> None:
    assert await rules(detector, bash(command.format(g=guard_dir), cwd=guard_dir)) == []


async def test_reading_guard_files_with_file_tools(
    detector: CommandsDetector, guard_dir: Path
) -> None:
    assert await rules(detector, write("Read", str(guard_dir / "policy.yaml"))) == []


async def test_other_project_policy_file_is_not_protected(
    detector: CommandsDetector, tmp_path: Path
) -> None:
    other = tmp_path / "other-project"
    other.mkdir()
    assert await rules(detector, bash("echo x > policy.yaml", cwd=other)) == []


async def test_critical_rm_is_reported_once(detector: CommandsDetector) -> None:
    assert await rules(detector, bash("rm -rf ~")) == ["recursive_delete_critical"]


async def test_tamper_command_can_be_allowlisted(guard_dir: Path) -> None:
    policy = Policy(dangerous_commands=DangerousCommandsPolicy(allowlist=[r"^rm logs/audit"]))
    settings = Settings(
        policy_path=guard_dir / "policy.yaml", audit_path=guard_dir / "logs" / "audit.jsonl"
    )
    detector = CommandsDetector(policy, protected_paths(settings))
    assert await rules(detector, bash("rm logs/audit.jsonl", cwd=guard_dir)) == []


async def test_tamper_script_content_only_warns(
    detector: CommandsDetector, guard_dir: Path
) -> None:
    ctx = tool_ctx("Write", "content", f"#!/bin/sh\nrm {guard_dir}/logs/audit.jsonl\n")
    [finding] = await findings(detector, ctx)
    assert finding.rule == "guard_tamper"
    assert finding.action is Action.WARN
