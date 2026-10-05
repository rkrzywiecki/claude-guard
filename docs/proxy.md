# Proxy

The proxy is an Anthropic Messages API compatible server. Point any client at it with
`ANTHROPIC_BASE_URL` and every `POST /v1/messages` is inspected on the way out and on the way
back.

```bash
uv run claude-guard serve                     # GUARD_HOST:GUARD_PORT, default 127.0.0.1:8787
uv run claude-guard serve --host 0.0.0.0 --port 9000
export ANTHROPIC_BASE_URL=http://localhost:8787
```

## Endpoints

| Endpoint | Behaviour |
|----------|-----------|
| `POST /v1/messages` | Inspected request and response (query string such as `?beta=true` is kept) |
| `GET /healthz` | `{"status": "ok", "stream_mode": ..., "fail_mode": ...}` |
| `GET /metrics` | Prometheus text format counters (below) |
| any other `/v1/*` | Forwarded to the upstream **without inspection** (e.g. `/v1/messages/count_tokens`, `/v1/models`) |

## Headers

Forwarded upstream: `x-api-key`, `authorization`, every `anthropic-*` header (`anthropic-version`,
`anthropic-beta`, ...), `content-type`, `accept`. Everything else (cookies, custom headers) is
dropped. Header values are never logged.

Returned to the client: the upstream headers (`request-id`, rate-limit headers, `retry-after`,
...) except hop-by-hop and encoding headers, plus:

| Header | Value |
|--------|-------|
| `x-claude-guard-request-action` | verdict for the request: `allow`, `warn`, `redact` |
| `x-claude-guard-response-action` | verdict for the response (non-streaming only) |

## Request inspection

| Verdict | Effect |
|---------|--------|
| `allow`, `warn` | Original body forwarded unchanged |
| `redact` | Body re-serialized with `[REDACTED:<rule>]` in place of each secret |
| `block` | HTTP 400, nothing sent upstream |

A blocked request returns the Anthropic error format, so SDKs raise `BadRequestError`:

```json
{"type": "error", "error": {"type": "invalid_request_error",
 "message": "claude-guard blocked the request: [prompt_injection] Instruction to ignore previous instructions"}}
```

A body that is not a JSON object also gets HTTP 400. If the upstream is unreachable the proxy
returns HTTP 502 with error type `api_error`. Upstream errors (401, 429, 529, ...) are passed
through with their status, body and headers.

## Response inspection

| Verdict | Effect |
|---------|--------|
| `allow`, `warn` | Upstream response returned unchanged |
| `redact` | Secrets replaced in text and tool inputs |
| `block` | Content replaced by one text block, `stop_reason: "end_turn"` |

A blocked response keeps its `id`, `model` and `usage` but its content becomes:

```json
[{"type": "text", "text": "[claude-guard] Response blocked: [dangerous_commands] Recursive delete of a root, home or system directory (Bash.command)"}]
```

Returning a valid message (instead of an HTTP error) means the dangerous `tool_use` is never
executed, while agent loops such as Claude Code keep running and show the notice.

## Streaming

Selected with `GUARD_STREAM_MODE` for requests with `"stream": true`.

### `buffer` (default)

1. The upstream stream is collected in full. Meanwhile the proxy sends `ping` events every
   10 seconds, so clients do not time out.
2. The events are assembled into a complete message (text, tool inputs from `input_json_delta`,
   thinking, citations) and inspected like a non-streamed response.
3. `allow`/`warn`: the original events are replayed byte for byte. `redact`/`block`: a new,
   valid event sequence is generated from the changed message.

Safer, but the client sees no tokens until generation has finished. If the upstream connection
drops mid-stream the client receives an SSE `error` event.

### `audit`

Events are passed to the client as they arrive. The assembled message is inspected after the
stream ends; the verdict goes to the audit log (`source: "proxy:audit"`), metrics and a
`audit_mode_violation` warning log line. Nothing can be blocked or redacted in this mode.
If the client disconnects before the end, the response is not inspected.

## Metrics

```
claude_guard_verdicts_total{direction="request",action="block"} 3
claude_guard_verdicts_total{direction="response",action="redact"} 1
claude_guard_requests_total 42
claude_guard_upstream_errors_total 0
claude_guard_guard_errors_total 0
```

`verdicts_total` has a series for every direction/action pair. `guard_errors_total` counts
verdicts that carry an engine error (fail mode applied). Counters are per process and reset on
restart.

## Logging

Logs are JSON lines on stderr (`GUARD_LOG_LEVEL`). Blocked requests and responses log the rule
names only, never content or credentials. Every inspection is also written to the audit log
(see [architecture.md](architecture.md#audit-log)).
