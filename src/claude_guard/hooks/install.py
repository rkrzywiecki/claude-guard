"""Registers claude-guard hooks in a Claude Code settings.json.

Existing settings are preserved: only hook entries whose command runs `claude-guard hook` are
replaced, everything else (other hooks, permissions, env) is left as is. The previous file is
copied to `settings.json.bak-<timestamp>` before it is changed, and a file that is not valid
JSON is never touched.
"""

from __future__ import annotations

import json
import shlex
import shutil
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from claude_guard.config import Settings
from claude_guard.hooks.handlers import HookEvent

MARKER = "claude-guard hook"
TOOL_EVENTS = frozenset({HookEvent.PRE_TOOL_USE, HookEvent.POST_TOOL_USE})
HOOK_TIMEOUT_SECONDS = {
    HookEvent.USER_PROMPT_SUBMIT: 15,
    HookEvent.PRE_TOOL_USE: 15,
    HookEvent.POST_TOOL_USE: 15,
    HookEvent.STOP: 30,
}

JsonObject = dict[str, JsonValue]


class InstallError(Exception):
    """The settings file cannot be updated safely."""


def guard_root() -> Path:
    """The claude-guard project directory (where pyproject.toml lives)."""
    return Path(__file__).resolve().parents[3]


def settings_file(scope: str, cwd: Path | None = None) -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    return (cwd or Path.cwd()) / ".claude" / "settings.json"


def hook_command(event: HookEvent, settings: Settings, root: Path) -> str:
    """Shell command for one event, with absolute paths so it works from any project."""

    def absolute(path: Path) -> str:
        return shlex.quote(str(path if path.is_absolute() else root / path))

    return (
        f"GUARD_POLICY_PATH={absolute(settings.policy_path)} "
        f"GUARD_AUDIT_PATH={absolute(settings.audit_path)} "
        f"uv run --quiet --project {shlex.quote(str(root))} claude-guard hook {event.value}"
    )


def merge_hooks(existing: JsonObject, settings: Settings, root: Path) -> JsonObject:
    """Return `existing` with claude-guard hook entries added or replaced."""
    merged = dict(existing)
    hooks_value = merged.get("hooks", {})
    if not isinstance(hooks_value, dict):
        raise InstallError('"hooks" in settings.json is not an object')
    hooks: JsonObject = dict(hooks_value)

    for event in HookEvent:
        groups_value = hooks.get(event.value, [])
        if not isinstance(groups_value, list):
            raise InstallError(f'"hooks.{event.value}" in settings.json is not a list')
        groups: list[JsonValue] = [
            g for g in (_without_guard(group) for group in groups_value) if g is not None
        ]
        entry: JsonObject = {
            "hooks": [
                {
                    "type": "command",
                    "command": hook_command(event, settings, root),
                    "timeout": HOOK_TIMEOUT_SECONDS[event],
                }
            ]
        }
        if event in TOOL_EVENTS:
            entry = {"matcher": "*", **entry}
        groups.append(entry)
        hooks[event.value] = groups

    merged["hooks"] = hooks
    return merged


def install(path: Path, settings: Settings, root: Path | None = None) -> Path | None:
    """Write merged settings to `path`. Returns the backup path, if a file was replaced."""
    root = root or guard_root()
    existing: JsonObject = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8") or "{}")
        except ValueError as exc:
            raise InstallError(f"{path} is not valid JSON; fix it first ({exc})") from exc
        if not isinstance(loaded, dict):
            raise InstallError(f"{path} must contain a JSON object")
        existing = loaded

    merged = merge_hooks(existing, settings, root)
    backup = None
    if path.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(f"{path.name}.bak-{stamp}")
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return backup


def _without_guard(group: JsonValue) -> JsonValue:
    """Drop claude-guard commands from a matcher group; None if nothing is left."""
    if not isinstance(group, dict):
        return group
    commands = group.get("hooks")
    if not isinstance(commands, list):
        return group
    kept = [
        hook
        for hook in commands
        if not (isinstance(hook, dict) and MARKER in str(hook.get("command", "")))
    ]
    if not kept:
        return None
    return {**group, "hooks": kept}
