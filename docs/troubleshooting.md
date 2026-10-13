# Troubleshooting

## Installation and startup

**`uv: command not found`**
Install uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`) and open a new shell, or add
`~/.local/bin` to `PATH`.

**`PolicyError: policy file not found: policy.yaml`**
`GUARD_POLICY_PATH` is relative to the current directory. Run from the claude-guard directory or
set an absolute path, e.g. `GUARD_POLICY_PATH=/path/to/claude-guard/policy.yaml`.

**`invalid policy policy.yaml: ... Extra inputs are not permitted`**
A key in `policy.yaml` is misspelled or not supported for that category. The error names the
field; [policy.md](policy.md) lists every valid key.

**`[Errno 48] error while attempting to bind on address ('127.0.0.1', 8787): address already in use`**
Another process uses port 8787. Pick another one: `uv run claude-guard serve --port 8788` (and
use that port in `ANTHROPIC_BASE_URL`), or find the process with `lsof -iTCP:8787`.

**`error: refusing to serve plain HTTP on non-loopback address '0.0.0.0'`**
`serve` does not expose unencrypted traffic to the network. Configure TLS
(`--tls-certfile`/`--tls-keyfile`), bind to `127.0.0.1`, or, if TLS is terminated in front of the
proxy, set `GUARD_ALLOW_INSECURE_BIND=true`. See [proxy.md](proxy.md#tls).

**`error: TLS needs both a certificate and a key`** / **`TLS file not found`** /
**`cannot load TLS certificate ...`**
Set both `GUARD_TLS_CERTFILE` and `GUARD_TLS_KEYFILE`, check the paths (relative to the current
directory), and that the key belongs to the certificate and is not passphrase-protected.

## Proxy

**Every request returns `502 claude-guard could not reach the upstream API`**
The proxy cannot connect to `GUARD_UPSTREAM_URL`. Check network access and proxies:
`curl -sI https://api.anthropic.com`.

**`401 authentication_error` through the proxy**
The proxy forwards `x-api-key` / `authorization` from the client unchanged; the key itself is
wrong or missing. Check `ANTHROPIC_API_KEY` in the client's environment, not the proxy's.

**`TypeError: Could not resolve authentication method` in the Python SDK**
The SDK needs credentials before it sends anything, even to the proxy. Export
`ANTHROPIC_API_KEY` (or log in with `ant auth login`).

**Certificate errors in the client with TLS enabled**
`self-signed certificate`, `unable to verify the first certificate` (Claude Code / Node.js) or
`CERTIFICATE_VERIFY_FAILED` (Python) mean the client does not trust the proxy certificate. Point
it at the CA: `NODE_EXTRA_CA_CERTS` for Claude Code, `SSL_CERT_FILE` for the Python SDK (see
[proxy.md](proxy.md#local-certificates-mkcert)). `Hostname mismatch` / `IP address mismatch`:
the host in `ANTHROPIC_BASE_URL` is not in the certificate's `subjectAltName`; reissue it with
that name (e.g. `mkcert localhost 127.0.0.1 my-host`).

**`Server disconnected without sending a response` / `Empty reply from server`**
The client uses `http://` but the proxy serves HTTPS. Change `ANTHROPIC_BASE_URL` to `https://`.

**`403 permission_error: claude-guard does not forward POST /v1/files`**
The endpoint carries content the proxy cannot inspect (Files API uploads, unknown endpoints).
Upload the file without the proxy, or set `GUARD_PASSTHROUGH=allow` and accept that it is not
inspected. See [proxy.md](proxy.md#uninspected-endpoints).

**`401 authentication_error: missing or invalid x-claude-guard-token header`**
`GUARD_PROXY_TOKEN` is set on the proxy. Send the same value in the `x-claude-guard-token`
header: `ANTHROPIC_CUSTOM_HEADERS="x-claude-guard-token: <token>"` for Claude Code,
`default_headers` for the SDKs. `/healthz` needs no token.

**`413 request_too_large: claude-guard: request body exceeds ... bytes`**
The body is above `GUARD_MAX_BODY_BYTES` (32 MiB). Raise it, e.g. for large Message Batches.

**Streamed response ends with `response too large to inspect`**
The stream exceeded `GUARD_MAX_STREAM_BYTES` in `buffer` mode and `GUARD_FAIL_MODE=closed`.
Raise the limit, or use `GUARD_FAIL_MODE=open` to deliver such responses uninspected.

**A legitimate request is blocked**
Find out which rule fired: the error message lists it, and so does the audit log
(`uv run claude-guard report --since 1h`). Then:

- reproduce it with `uv run claude-guard scan --file request.json`;
- raise that category's `threshold`, set an action override in `direction_actions`, add an
  `allowlist` regex (`secrets`, `dangerous_commands`) or an `allowed_hosts` entry
  (`data_exfiltration`);
- or disable the category.

**`upload_file` blocks an upload to GitHub, PyPI or the Anthropic API**
No host may receive uploads by default, since these services can carry data out as well. Add
the exact host you upload to under `data_exfiltration.allowed_hosts` (e.g. `uploads.github.com`).
`foreign_api_credential` is different: it fires when a command calls the Anthropic API with a
key other than `$ANTHROPIC_API_KEY` and is not lifted by `allowed_hosts`.

**A session keeps getting blocked after one injection attempt**
Only the current turn (messages after the last assistant message) can block. If the injection is
in the newest tool result, the request is blocked until that result is gone: rewind or clear the
conversation in the client.

**Streaming feels slow**
In `buffer` mode nothing is shown until the full response has been generated and inspected; the
proxy only sends `ping` events meanwhile. Use `GUARD_STREAM_MODE=audit` for live streaming,
accepting that responses are then only logged, not blocked.

**Requests through the proxy get slower as the session grows**
Every request carries the whole conversation and all of it is scanned: about 0.6 ms per KB of
context on an Apple M5 Pro. `uv run claude-guard bench -s proxy` shows the cost on your machine
(see [performance.md](performance.md)); custom rules with expensive regexes add to it.

**`audit_mode_violation` warnings in the log**
With `GUARD_STREAM_MODE=audit` a streamed response violated the policy after it was delivered.
Check the audit log entry with `source: "proxy:audit"`.

**No alerts arrive**
Check `GUARD_ALERT_WEBHOOK_URL` (https, or http on a loopback host; anything else fails
validation at startup) and `GUARD_ALERT_MIN_ACTION` (default: only `block`). Failed deliveries
are logged as `alert_failed` with the HTTP status or error type; `alert_rate_limited` means the
per-process cap (`GUARD_ALERT_MAX_PER_MINUTE`) was hit. `claude-guard scan` never alerts.

## Hooks

**`Modification of claude-guard files or Claude Code settings` when Claude edits settings or the
policy**
Intended: an agent could otherwise remove the hooks or relax the policy. Make the change
yourself; for a recurring shell command add a narrow regex to `dangerous_commands.allowlist`.
See [policy.md](policy.md#guard-tampering).

**Hooks do nothing**
- Check `.claude/settings.json` contains the claude-guard entries (`/hooks` in Claude Code
  lists them).
- Run a hook by hand from the project directory with the exact command from settings.json:
  `echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | <command>`.
- Hooks only print something when there is a finding; empty output means "allow".

**Every tool call is denied with `could not inspect this (fail mode closed)`**
The hook itself failed: the reason contains the error (often a missing policy file because of a
relative path). Re-run `install-hooks`, which writes absolute paths, or fix the command. Use
`GUARD_FAIL_MODE=open` only if availability matters more than protection.

**`install-hooks` says the file is not valid JSON**
The installer never overwrites a file it cannot parse. Fix the JSON (`python -m json.tool
.claude/settings.json` shows where it breaks) and run it again.

**Hooks are slow**
Heuristic hooks take about 0.4 s per event, almost all of it starting Python and importing
modules (`uv run` itself adds about 15 ms); the inspection takes a few milliseconds. Measure it
with `uv run claude-guard bench -s hooks` (see [performance.md](performance.md)). If you enabled
`GUARD_HOOK_LLM=true`, each hook may also call the judge; keep `llm_judge.timeout_seconds` below
the hook `timeout` (15 s; 30 s for Stop).

**The Stop summary reports the same thing again**
Stop audits only transcript lines added since its last run, tracked in
`logs/sessions/<session_id>.offset`. Deleting that file makes the next Stop audit the whole
transcript again.

## LLM judge

**Findings with rule `judge_unavailable`**
The judge timed out, hit an API error, refused, or returned invalid output after retries. With
`GUARD_FAIL_MODE=closed` this blocks. Check `ANTHROPIC_API_KEY`, `GUARD_JUDGE_MODEL` and
`llm_judge.timeout_seconds`; the log line `llm_judge_failed` names the error type.

**The judge never runs**
In `mode: untrusted` (default) it runs when the current turn contains untrusted content (tool
results, fetched documents) or the heuristics are unsure; a plain prompt with no findings is not
judged. In `mode: uncertain` it only runs when the strongest heuristic confidence is inside
`uncertain_range` (default 0.3–0.7). Use `mode: always` to judge every payload (more cost and
latency). It is also off in hooks unless `GUARD_HOOK_LLM=true`.

**The judge makes every agent turn slower or costs too much**
In `mode: untrusted` nearly every agent request carries a tool result and is judged. Switch to
`mode: uncertain` to judge only borderline cases, lower `max_input_chars`, or keep the judge off
in hooks (`GUARD_HOOK_LLM=false`).

## Audit log

**`report` shows no inspections**
`report` reads `GUARD_AUDIT_PATH` relative to the current directory. Hooks installed by
`install-hooks` write to the claude-guard directory's `logs/audit.jsonl`; pass
`--file /path/to/claude-guard/logs/audit.jsonl` when running elsewhere.

**Does the log contain secrets?**
No. Excerpts, messages, errors and notes are passed through the secret scanner before writing;
only masked previews such as `sk-ant-***abcd` are stored.
