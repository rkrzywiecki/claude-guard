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
