# Threat model

This document describes what claude-guard protects, from whom, where it draws trust boundaries
and what it deliberately leaves out. It complements the list of known gaps in
[README.md](../README.md#limitations). To report a weakness, see [SECURITY.md](../SECURITY.md).

claude-guard is **one layer of defense**. It reduces the chance that a manipulated or careless
agent leaks data or damages a system. It does not guarantee this, and it does not replace Claude
Code permissions, sandboxing, least-privilege credentials or code review.

## Setting

An agent (Claude Code, an Agent SDK app or your own application) sends conversations to the
Claude API and runs tools on the user's machine or infrastructure. The agent's context mixes
content of different origins: the user's instructions, the operator's system prompt, and data
the agent pulls in itself: files, command output, web pages, documents, MCP servers. The model
cannot reliably tell instructions from data, so anyone who controls a piece of that data can try
to steer the agent.

claude-guard sits on the two paths where that can be observed:

- **Proxy**: between the client and the Claude API. It sees every request (full context) and
  every response (text and tool calls).
- **Hooks**: inside Claude Code. They see the user's prompt, every tool call before it runs,
  every tool result after it runs and, at the end of a turn, the transcript.

## Assets

| Asset | Examples |
|-------|----------|
| Secrets and personal data | API keys, tokens, private keys, passwords, payment cards, PESEL, IBAN, `.env`, `~/.ssh` |
| User data and code | repository contents, customer files, databases reachable from the machine |
| Integrity of the system | files, git history, cloud resources, production branches |
| Integrity of the guard | `policy.yaml`, the audit log, hook entries in Claude Code settings |
| Audit trail | `logs/audit.jsonl`, alerts |

## Trust levels

| Source | Trust | How claude-guard treats it |
|--------|-------|----------------------------|
| Operator content: system prompt, built-in tool descriptions | trusted | Not inspected for injection |
| User prompt | trusted intent, may leak by mistake | Secrets redacted (proxy) or blocked (hooks); direct injection and jailbreak patterns flagged |
| Model output: text and `tool_use` | not trusted to be safe | Dangerous commands, exfiltration, tamper and per-tool policy checked before the call runs |
| Tool results, documents, fetched web content | **untrusted** | Indirect injection rules with a confidence boost; optional LLM judge on every tool result (`mode: untrusted`) |
| MCP tool definitions (`mcp__*`) | **untrusted** | Tool poisoning rules (proxy only), `warn` by default |
| Conversation history | inspected when it was new | Older findings capped at `warn` so one old result cannot block a session forever |

## Adversaries in scope

1. **Author of untrusted content.** Anyone who can place text where the agent will read it: a
   web page, an issue, a README in a dependency, an email, a file in the repository, a tool
   result. Goal: make the agent follow their instructions (indirect prompt injection).
2. **Malicious or compromised MCP server.** Supplies tool descriptions with hidden instructions
   (tool poisoning) or returns injected results.
3. **Hijacked or mistaken agent.** The model itself, after an injection or by error, attempts
   to:
   - exfiltrate data (uploads, data in URLs, markdown images, inline scripts using the network),
   - run destructive commands (`rm -rf`, `git reset --hard`, `terraform destroy`, ...),
   - set up persistence (shell startup files, cron, LaunchAgents, `authorized_keys`),
   - disable the guard (edit `policy.yaml` or Claude Code settings, delete the audit log).
4. **Careless user.** Pastes a secret or personal data into a prompt, which would otherwise be
   sent to the API and kept in the conversation.
5. **Network client of an exposed proxy.** When the proxy listens beyond loopback: someone on
   the network who uses it without authorization or reads traffic. Mitigated by
   `GUARD_PROXY_TOKEN` and mandatory TLS on non-loopback binds.

## What claude-guard aims to ensure

- With the proxy in `buffer` mode, a response with a `block` verdict never reaches the client,
  and a request with a `block` verdict is never sent to the API.
- Secrets found in a request are redacted before it leaves the machine through the proxy.
- In hooks, a tool call with a `block` verdict is denied before it runs.
- Endpoints the proxy cannot inspect are refused by default (`GUARD_PASSTHROUGH=block`).
- An engine error blocks by default (`GUARD_FAIL_MODE=closed`).
- Secrets are masked in the audit log, application logs and alerts.
- The agent cannot switch off the guard by writing to its known files through file tools or
  common shell write commands (`guard_tamper`).

## Out of scope

- **A malicious local user or another process** running as the user or as root. They can stop
  the proxy, edit the policy, remove hooks or call the API directly. claude-guard protects
  against what the agent does, not against the person at the keyboard.
- **A malicious operator.** The system prompt and built-in tool descriptions are trusted.
- **Clients that bypass the proxy.** Only traffic sent to `ANTHROPIC_BASE_URL` is inspected.
  Enforcing that (egress firewall, removing direct API access) is a deployment decision.
- **A determined attacker who adapts to the heuristics.** Rules catch known patterns and common
  obfuscation; paraphrases, new encodings and multi-step attacks can get through. The LLM judge
  narrows the gap at extra cost but is itself a model that can be fooled.
- **Effects of a tool that already ran.** `PostToolUse` sees a result after the tool executed;
  it warns Claude but cannot undo the action.
- **Tampering through code.** A script that writes guard files by itself
  (`python -c "open('policy.yaml', 'w')"`) is not recognized as tampering.
- **Content moderation.** Harmful or policy-violating text unrelated to injection, secrets or
  agent actions is left to the model's own safeguards and `custom_rules`.
- **The Claude API, Claude Code and dependencies.** Their correctness and supply chain are
  assumed. Hook failures (a crash or a timeout) are handled by Claude Code, which treats them as
  non-blocking errors; `GUARD_FAIL_MODE` only covers errors claude-guard itself catches.
- **Uninspected content**: images, base64 PDFs, thinking blocks, files referenced by `file_id`,
  and the other items listed in [README.md](../README.md#limitations).

## Integrations compared

| Property | Proxy (`buffer`) | Proxy (`audit`) | Hooks |
|----------|------------------|-----------------|-------|
| Blocks a dangerous tool call before it runs | yes (response blocked) | no, logged only | yes (`deny`) |
| Redacts secrets before they reach the API | yes | yes | no, the prompt is blocked |
| Inspects tool results before the model reads them | yes (next request) | yes (next request) | flagged to Claude after the tool ran |
| Inspects MCP tool definitions | yes | yes | no, Claude Code does not pass them |
| Covers clients other than Claude Code | yes | yes | no |
| Extra latency | until the response completes | none for the client | about 0.4 s per hook |

Using both integrations together gives the widest coverage: the proxy sees the full context and
redacts secrets, the hooks stop tool calls inside Claude Code even when the proxy is not in the
path.

## Deployment recommendations

- Keep the defaults: `GUARD_FAIL_MODE=closed`, `GUARD_STREAM_MODE=buffer`,
  `GUARD_PASSTHROUGH=block`.
- Keep Claude Code permission prompts and sandboxing on; claude-guard adds to them.
- Enable the LLM judge in `untrusted` mode when the agent reads content from the open web or
  third-party MCP servers.
- Do not give the agent credentials it does not need; a blocked exfiltration is still worse than
  a key that was never there.
- Bind the proxy to loopback. If it must be reachable from the network, set `GUARD_PROXY_TOKEN`
  and TLS.
- Route alerts (`GUARD_ALERT_WEBHOOK_URL`) somewhere a person reads them and review
  `claude-guard report` regularly.
