# Proxy

The proxy is an Anthropic Messages API compatible server. Point any client at it with
`ANTHROPIC_BASE_URL` and every `POST /v1/messages` is inspected on the way out and on the way
back.

```bash
uv run claude-guard serve                     # GUARD_HOST:GUARD_PORT, default 127.0.0.1:8787
uv run claude-guard serve --port 9000
uv run claude-guard serve --tls-certfile cert.pem --tls-keyfile key.pem   # HTTPS, see TLS
export ANTHROPIC_BASE_URL=http://localhost:8787
```

## Endpoints

| Endpoint | Behaviour |
|----------|-----------|
| `POST /v1/messages` | Inspected request and response (query string such as `?beta=true` is kept) |
| `GET /healthz` | `{"status": "ok", "stream_mode": ..., "fail_mode": ..., "policy_version": ...}` (`policy_version`: first 12 hex digits of the policy file's SHA-256) |
| `GET /metrics` | Prometheus text format counters (below) |
| `POST /v1/messages/count_tokens` | Secrets redacted; never blocked (no model runs) |
| `POST /v1/messages/batches` | Every `requests[].params` inspected as a request (see [Message Batches](#message-batches)) |
| `GET /v1/messages/batches/{id}/results` | Every succeeded message inspected as a response |
| `GET /v1/messages/batches[/{id}]`, `POST .../{id}/cancel` | Forwarded; `results_url` rewritten to the proxy |
| `GET /v1/models[/{id}]`, `GET /v1/files[/{id}[/content]]`, `DELETE /v1/files/{id}`, `DELETE /v1/messages/batches/{id}` | Forwarded **without inspection** (no prompt content) |
| any other `/v1/*` | `GUARD_PASSTHROUGH=block` (default): HTTP 403 `permission_error`; `allow`: forwarded without inspection |

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

## Message Batches

`POST /v1/messages/batches` inspects each request's `params` exactly like `POST /v1/messages`:

- one blocked request rejects the whole batch with HTTP 400 naming its `custom_id`, and nothing
  is sent upstream;
- secrets are redacted per request; `x-claude-guard-request-action` carries the strictest
  verdict.

Results (`GET /v1/messages/batches/{id}/results`, JSON Lines) are inspected line by line: a
blocked message is replaced by the same notice as a blocked response, a redacted one is
rewritten, everything else (errored, canceled, expired results, clean messages) is returned
byte for byte. `x-claude-guard-response-action` carries the strictest verdict.

SDKs download results from the batch's `results_url`, an absolute URL to the API. The proxy
rewrites it to its own address in every batch object it returns (create, retrieve, list,
cancel), so results fetched through the SDK are inspected too. The rewritten URL uses the
address the client connected to; behind a reverse proxy, run uvicorn with forwarded headers or
the URL may have the wrong scheme or host. Results fetched from the API directly bypass the
proxy.

## Uninspected endpoints

Endpoints that carry no prompt content (model list, batch and file metadata, deletes) are
forwarded as is. Everything else under `/v1/` that the proxy cannot inspect, notably
**Files API uploads** (`POST /v1/files`, whose content could later be referenced from a
`document` block by `file_id`), is refused by default:

```json
{"type": "error", "error": {"type": "permission_error",
 "message": "claude-guard does not forward POST /v1/files: the endpoint is not inspected (set GUARD_PASSTHROUGH=allow to forward it)"}}
```

`GUARD_PASSTHROUGH=allow` forwards them without inspection. Refusals are counted in
`claude_guard_passthrough_blocked_total` and logged as `passthrough_blocked` (method and path
only).

`count_tokens` sends the whole prompt to the API, so secrets are redacted there as well
(the count may differ by a few tokens). Injection findings are recorded in the audit log
(`source: "proxy:count_tokens"`) but do not block: no model reads the content.

## TLS

The proxy -> `api.anthropic.com` leg always uses TLS. The client -> proxy leg is plain HTTP unless
`serve` gets a certificate and key:

| Setting | CLI option | Meaning |
|---------|------------|---------|
| `GUARD_TLS_CERTFILE` | `--tls-certfile` | Certificate chain, PEM |
| `GUARD_TLS_KEYFILE` | `--tls-keyfile` | Private key, PEM (unencrypted) |
| `GUARD_ALLOW_INSECURE_BIND` | – | Allow plain HTTP on a non-loopback address |

Both files must be set together. They are loaded before the server starts, so a missing file or
a key that does not match the certificate is reported as a one-line error (exit code 2).

### Rules

| Host | TLS configured | Result |
|------|----------------|--------|
| loopback (`127.0.0.0/8`, `::1`, `localhost`) | no | plain HTTP (default) |
| loopback | yes | HTTPS |
| any other address (`0.0.0.0`, LAN IP, ...) | yes | HTTPS |
| any other address | no | **refused**, unless `GUARD_ALLOW_INSECURE_BIND=true` |

TLS stays optional on loopback: traffic never leaves the machine, and anyone who can read it
there can usually read the API key from the client's environment too. It is required as soon as
the proxy is reachable from the network.

### Local certificates (mkcert)

```bash
mkcert -install                       # once: adds a local CA to the system trust store
mkcert localhost 127.0.0.1            # localhost+1.pem, localhost+1-key.pem
uv run claude-guard serve --tls-certfile localhost+1.pem --tls-keyfile localhost+1-key.pem
export ANTHROPIC_BASE_URL=https://localhost:8787
```

Clients that do not use the system trust store need the CA explicitly:

| Client | Variable |
|--------|----------|
| Claude Code (Node.js) | `NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"` |
| Python SDK (httpx) | `SSL_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"` |
| curl | `curl --cacert "$(mkcert -CAROOT)/rootCA.pem" https://localhost:8787/healthz` |

A self-signed certificate from `openssl` works the same way; the certificate itself is then the
CA file. It must list the host the client uses in `subjectAltName`:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout key.pem -out cert.pem
```

### Reverse proxy

When Caddy, nginx or a service mesh terminates TLS and forwards to claude-guard, keep the proxy
on loopback if they run on the same host (no extra settings). If the forwarder reaches it over
the network, bind to that interface and set `GUARD_ALLOW_INSECURE_BIND=true`; `serve` then logs
an `insecure_bind` warning at startup. Make sure only the forwarder can reach that port.

## Client authentication

By default anyone who can reach the proxy can use it (with their own API key). Set
`GUARD_PROXY_TOKEN` to require a shared secret in the `x-claude-guard-token` header on every
endpoint except `/healthz` (so liveness probes keep working; `/metrics` is protected). The check
runs before the body is read; the header is never forwarded upstream or logged. A missing or
wrong token gets HTTP 401 `authentication_error`.

```bash
export GUARD_PROXY_TOKEN="$(openssl rand -hex 32)"
uv run claude-guard serve --host 0.0.0.0 --tls-certfile cert.pem --tls-keyfile key.pem

# Claude Code
export ANTHROPIC_CUSTOM_HEADERS="x-claude-guard-token: $GUARD_PROXY_TOKEN"
# Python SDK
client = anthropic.Anthropic(base_url="https://guard.example:8787",
                             default_headers={"x-claude-guard-token": token})
```

`serve` logs a `proxy_without_token` warning when it listens on a non-loopback address without a
token.

## Limits

| Setting | Default | Exceeded |
|---------|---------|----------|
| `GUARD_MAX_BODY_BYTES` | 32 MiB | HTTP 413 `request_too_large`, nothing is inspected or forwarded (checked against `content-length` and while reading chunked bodies) |
| `GUARD_MAX_STREAM_BYTES` | 32 MiB | `buffer` mode stops buffering: with `GUARD_FAIL_MODE=closed` the client gets an SSE `error` event; with `open` everything is delivered, uninspected |

32 MiB matches the Messages API request limit. Message Batches can be larger: raise
`GUARD_MAX_BODY_BYTES` if you send big batches through the proxy. Exceeded limits are counted in
`claude_guard_limit_exceeded_total` and logged as `request_too_large` / `stream_too_large`.

## Metrics

```
claude_guard_verdicts_total{direction="request",action="block"} 3
claude_guard_verdicts_total{direction="response",action="redact"} 1
claude_guard_requests_total 42
claude_guard_upstream_errors_total 0
claude_guard_guard_errors_total 0
claude_guard_passthrough_blocked_total 0
claude_guard_limit_exceeded_total 0
claude_guard_unauthorized_total 0
claude_guard_inspection_cache_hits_total 1260
claude_guard_inspection_cache_misses_total 96
claude_guard_inspection_cache_entries 96
claude_guard_policy_reloads_total 2
claude_guard_policy_reload_errors_total 0
```

`verdicts_total` has a series for every direction/action pair. `guard_errors_total` counts
verdicts that carry an engine error (fail mode applied). The `inspection_cache` series count
request units (messages, tool definitions, system prompt) whose findings were reused or had to
be computed, and the units cached now (see
[architecture.md](architecture.md#inspection-cache)); they are absent with
`GUARD_INSPECTION_CACHE_SIZE=0`. `policy_reloads_total` and `policy_reload_errors_total` count
policy reloads (see [Policy reload](#policy-reload)). Counters are per process and reset on
restart.

## Policy reload

The proxy applies changes to `policy.yaml` without a restart:

- **On change:** before handling a request, at most every `GUARD_POLICY_RELOAD_INTERVAL` seconds
  (default 2), the proxy compares the file's modification time, size and inode with the last
  version it loaded. `0` turns the check off.
- **On SIGHUP:** `kill -HUP <pid>` reloads at once, also with the check off.

A changed file is parsed and validated first. Only a valid policy replaces the running one; an
invalid, unreadable or missing file keeps the current policy, logs `policy_reload_failed` with
the error (once per file version) and counts `claude_guard_policy_reload_errors_total`. Saving
the file again retries. A save that leaves the content unchanged does nothing. A successful
reload logs `policy_reloaded` with the old and new `policy_version` (also in `/healthz`).

Requests already being inspected finish with the previous policy. The inspection cache starts
empty after a reload, since findings depend on the policy. The guard tamper rules keep an agent
from editing the policy file through the proxy or hooks (see
[policy.md](policy.md#guard-tampering)).

## Logging

Logs are JSON lines on stderr (`GUARD_LOG_LEVEL`). Blocked requests and responses log the rule
names only, never content or credentials. Every inspection is also written to the audit log
(see [architecture.md](architecture.md#audit-log)).
