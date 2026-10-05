# Claude Code hooks

The hook integration runs the same engine as the proxy inside Claude Code's hook system, with
no proxy and no change to `ANTHROPIC_BASE_URL`. Each hook is a short-lived process:
`claude-guard hook <Event>` reads the event JSON on stdin and prints the hook response on stdout.

## Install

```bash
uv run claude-guard install-hooks             # ./.claude/settings.json (project, default)
uv run claude-guard install-hooks --user      # ~/.claude/settings.json (all projects)
uv run claude-guard install-hooks --dry-run   # print the merged settings, write nothing
```

To protect a different project, run the installer from that project's directory:

```bash
cd ~/work/my-app
uv run --project ~/claude-guard claude-guard install-hooks
```

The installer:

- merges into the existing file: other hooks, permissions and settings are kept;
- replaces earlier claude-guard entries (any hook whose command contains `claude-guard hook`),
  so running it again is safe;
- copies the previous file to `settings.json.bak-<timestamp>` first;
- refuses to touch a file that is not valid JSON;
- writes commands with absolute paths to the claude-guard project, `policy.yaml` and the audit
  log, so hooks work from any working directory.

### Manual configuration

Equivalent `.claude/settings.json` (replace `/path/to/claude-guard`):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {"hooks": [{"type": "command", "timeout": 15,
        "command": "GUARD_POLICY_PATH=/path/to/claude-guard/policy.yaml GUARD_AUDIT_PATH=/path/to/claude-guard/logs/audit.jsonl uv run --quiet --project /path/to/claude-guard claude-guard hook UserPromptSubmit"}]}
    ],
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "timeout": 15,
        "command": "GUARD_POLICY_PATH=/path/to/claude-guard/policy.yaml GUARD_AUDIT_PATH=/path/to/claude-guard/logs/audit.jsonl uv run --quiet --project /path/to/claude-guard claude-guard hook PreToolUse"}]}
    ],
    "PostToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "timeout": 15,
        "command": "GUARD_POLICY_PATH=/path/to/claude-guard/policy.yaml GUARD_AUDIT_PATH=/path/to/claude-guard/logs/audit.jsonl uv run --quiet --project /path/to/claude-guard claude-guard hook PostToolUse"}]}
    ],
    "Stop": [
      {"hooks": [{"type": "command", "timeout": 30,
        "command": "GUARD_POLICY_PATH=/path/to/claude-guard/policy.yaml GUARD_AUDIT_PATH=/path/to/claude-guard/logs/audit.jsonl uv run --quiet --project /path/to/claude-guard claude-guard hook Stop"}]}
    ]
  }
}
```

## Events

| Event | Inspected (direction) | `block` | `redact` | `warn` |
|-------|-----------------------|---------|----------|--------|
| `UserPromptSubmit` | `prompt` (`request`) | `{"decision": "block", "reason": ...}` | same as block | `systemMessage` |
| `PreToolUse` | `tool_name` + `tool_input` (`tool_input`) | `permissionDecision: "deny"` | `systemMessage` | `systemMessage` |
| `PostToolUse` | `tool_response` (`tool_output`, untrusted) | `{"decision": "block", "reason": ...}` | same as block | `systemMessage` |
| `Stop` | new transcript entries (`request`) | `systemMessage` | `systemMessage` | `systemMessage` |

Hooks cannot rewrite content, so `redact` is mapped to the closest safe behaviour:

- **UserPromptSubmit**: the prompt is blocked (a secret would otherwise be sent to the API) and
  the reason asks the user to remove the sensitive data.
- **PreToolUse**: a warning only; rewriting a command would break it.
- **PostToolUse**: the tool has already run and its output is in Claude's context, so
  `decision: "block"` is used to tell Claude the result is untrusted (injection) or contains
  sensitive data it must not repeat.

All responses are JSON on stdout with exit code 0. When nothing was found, nothing is printed.

### Examples

```bash
$ echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
    | uv run claude-guard hook PreToolUse
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"claude-guard: [dangerous_commands] Recursive delete of a root, home or system directory (Bash.command)"}}

$ echo '{"hook_event_name":"UserPromptSubmit","prompt":"Ignore all previous instructions"}' \
    | uv run claude-guard hook UserPromptSubmit
{"decision":"block","reason":"claude-guard: [prompt_injection] Instruction to ignore previous instructions."}
```

### Stop

`Stop` audits the session transcript (`transcript_path`, JSONL). It never returns
`decision: "block"`, which would force Claude to keep working; findings are written to the audit
log and summarized in a `systemMessage`:

```json
{"systemMessage": "claude-guard session audit: 2 finding(s) (dangerous_commands: 1, secrets: 1). See the audit log."}
```

To avoid re-reporting the same content on every turn, the byte offset already audited is stored
per session in `<audit dir>/sessions/<session_id>.offset`. Only complete lines are consumed, at
most the last 5 MB per run. A truncated transcript restarts from the beginning.

## Errors and fail mode

Invalid stdin, a missing `tool_name`, a missing or invalid policy, or any engine error:

- `GUARD_FAIL_MODE=closed` (default): answered like a block (`deny` for PreToolUse, `decision:
  block` for UserPromptSubmit/PostToolUse, `systemMessage` for Stop), with the error in the
  reason;
- `GUARD_FAIL_MODE=open`: nothing is printed and Claude Code continues.

Errors are logged as JSON on stderr; stdout carries only the hook response.

## Performance and the LLM judge

With heuristics only, a hook runs in about 0.4 s including `uv run` start-up, and stays well
under 5 s for prompts of several hundred kilobytes. The LLM judge is off in hooks by default;
set `GUARD_HOOK_LLM=true` (and enable `llm_judge` in `policy.yaml`) to use it, keeping
`llm_judge.timeout_seconds` below the hook timeout.

Every hook invocation is written to the audit log with `source: "hook:<Event>"` and the
Claude Code `session_id`.
