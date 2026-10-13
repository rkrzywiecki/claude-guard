# Performance

`claude-guard bench` measures how much latency claude-guard adds on your machine, with your
`policy.yaml`. Nothing is sent to the Anthropic API except in the opt-in `judge` scenario.

```bash
uv run claude-guard bench                      # engine, proxy, hooks (about a minute)
uv run claude-guard bench -s proxy             # one scenario (repeatable: -s engine -s hooks)
uv run claude-guard bench --idle-ms 500        # pause before each call, like real traffic (~7 min)
uv run claude-guard bench --iterations 100     # more samples per case (~6 min)
uv run claude-guard bench -s judge             # real LLM judge calls (costs tokens)
uv run claude-guard bench --json > bench.json  # machine-readable results
```

Progress goes to stderr; the table or JSON to stdout. Each row reports the **added** latency
(p50, p95, p99, mean) in milliseconds and the number of samples.

## Scenarios

| Scenario | What runs | What it tells you |
|---|---|---|
| `engine` | `GuardEngine.inspect` in process, heuristic detectors, audit log write | The floor of every integration, per direction and payload size |
| `proxy` | HTTP calls to a local fake Messages API, directly and through the proxy (uvicorn on loopback) | Added latency per request; `direct p50` is the same call without the proxy |
| `hooks` | One hook invocation in process, as the venv script, and as the `uv run` command `install-hooks` writes | Added latency per prompt and per tool call in Claude Code |
| `judge` | `LlmJudgeDetector` on a 4 KB tool result against the real API | Cost of `llm_judge.enabled: true` (not run by default) |

Payloads are synthetic Claude Code requests: a system prompt, eight tool definitions and *n*
`Read` round trips whose results are claude-guard's own source files (realistic code, no
secrets). Sizes: `small` 1 turn (12 KB), `medium` 10 turns (122 KB), `large` 50 turns (461 KB);
they change slightly with the source tree, and so does the size of each turn's new tool result.
Files the shipped policy flags (detectors quote attack patterns) are left out, so every case
takes the clean `allow` path that ordinary traffic takes.

Details of the method:

- **Audit log.** Each inspection appends to an audit log, as in production, but to a temporary
  directory: the real `logs/audit.jsonl` is not touched. Alerts are off.
- **LLM judge.** Off in `engine`, `proxy` and `hooks` even if `policy.yaml` enables it; measure
  it separately with `-s judge` and add it to the request rows.
- **Inspection cache.** Requests are measured twice. `first` is the first request of a
  conversation, inspected in full (the engine runs without cache). `next turn` is a request
  whose previous turn was inspected just before (the cache is cleared and the request without
  its last two messages is inspected, unmeasured), as in a running session: only the newest
  assistant message and tool result are new. Streams are inspected in full.
- **Proxy.** The fake upstream answers immediately; streams send 20 text deltas 5 ms apart
  (about 110 ms of "generation"). The added latency is the difference between the *n*-th proxied
  and the *n*-th direct sample. Streams are measured for the `medium` request in both stream
  modes: *first token* is the time to the first `text_delta`, *total* the time to the end of the
  stream.
- **Hooks.** Claude Code starts a new process per hook event, so the *venv script* and *uv run*
  rows are what a user waits for. `python -c pass` shows the interpreter start-up alone.
- **Warm-up.** A few unmeasured calls run first (engine 5, proxy 3, hooks 1).

## Reference results

Apple M5 Pro, macOS, Python 3.12, shipped `policy.yaml`, `claude-guard bench` (no idle gap).
Your numbers will differ; run the benchmark on the target machine.

| Scenario | Case | Payload | p50 ms | p95 ms |
|---|---|---|---:|---:|
| engine | request small (1 tool turn), first | 12 KB | 2.4 | 2.5 |
| engine | request medium (10 tool turns), first | 122 KB | 71 | 72 |
| engine | request large (50 tool turns), first | 461 KB | 274 | 275 |
| engine | request small, next turn (0.1 KB new) | 12 KB | 0.3 | 0.3 |
| engine | request medium, next turn (35 KB new) | 122 KB | 21 | 22 |
| engine | request large, next turn (5 KB new) | 461 KB | 4.6 | 4.7 |
| engine | response (text + tool_use) | 0.7 KB | 0.4 | 0.5 |
| engine | tool_input (Bash) | 0.1 KB | 0.2 | 0.2 |
| engine | tool_output (Read, 37 KB file) | 37 KB | 21 | 21 |
| proxy | non-streaming, request small, first | 12 KB | 3.4 | 3.6 |
| proxy | non-streaming, request small, next turn | 12 KB | 1.2 | 1.3 |
| proxy | non-streaming, request medium, first | 122 KB | 73 | 74 |
| proxy | non-streaming, request medium, next turn | 122 KB | 23 | 23 |
| proxy | non-streaming, request large, first | 461 KB | 282 | 286 |
| proxy | non-streaming, request large, next turn | 461 KB | 6.7 | 7.0 |
| proxy | stream `buffer`, first token | 122 KB | 190 | 192 |
| proxy | stream `buffer`, total | 122 KB | 82 | 85 |
| proxy | stream `audit`, first token | 122 KB | 82 | 83 |
| proxy | stream `audit`, total | 122 KB | 82 | 84 |
| hooks | `python -c pass` (interpreter floor) | | 11 | 21 |
| hooks | PreToolUse, in process | 0.3 KB | 1.8 | 1.9 |
| hooks | PreToolUse, venv script | 0.3 KB | 129 | 130 |
| hooks | PreToolUse, `uv run` (as installed) | 0.3 KB | 144 | 148 |
| hooks | PostToolUse, `uv run` (as installed) | 37 KB | 167 | 169 |
| hooks | UserPromptSubmit, `uv run` (as installed) | 0.2 KB | 144 | 145 |

"New" is the size of the tool result added by the next turn: the cost of a next turn follows
the new content, not the whole context.

With `--idle-ms 500` (a pause before every call, as between real requests) CPU-bound work is
slower because the CPU leaves its high-performance state while idle: in the proxy the medium
request goes from 73 to about 111 ms (first) and from 23 to about 53 ms (next turn), a small one
from 3.4 to 11 ms, and hooks from about 144 to about 187 ms. Real traffic has such gaps (the
model takes seconds to answer), so treat the idle numbers as the realistic ones on laptops and
the default ones as a lower bound.

On a busy machine the numbers rise: a first run here, with something else using the CPU, gave
hooks about 15 % slower. Run the benchmark twice and compare before drawing conclusions.

## Reading the results

- **Proxy: the first request of a conversation pays for the whole context, about 0.6 ms per
  KB; next turns pay for the new messages.** Each request carries the whole conversation, but
  the inspection cache (`GUARD_INSPECTION_CACHE_SIZE`) keeps the findings of every message,
  tool definition and system prompt already inspected, so a next turn pays for its new
  messages at about the same rate: with 461 KB of context and a 5 KB new tool result it adds
  7 ms instead of 282 ms; a 35 KB tool result costs 23 ms. Extracting and hashing the rest of
  the payload adds a little that grows slowly with the context. The response side is cheap
  (under 1 ms for a typical message).
- **`buffer` streaming delays the first token by the whole generation time**, plus inspection.
  In the table the fake generation takes about 110 ms; with a real model it is the full response
  time (seconds). `audit` mode only adds the request inspection to the first token.
- **Hooks cost about 0.15 s per event, almost all of it process start-up.** The inspection
  itself takes 2 ms for a tool call (20 ms for a 37 KB tool result); `uv run` adds about 15 ms;
  the rest is starting Python and importing modules (about 100 ms, see `python -X importtime`).
  A session with 50 tool calls spends about 2 × 50 × 0.15 s = 15 s in `PreToolUse` and
  `PostToolUse` hooks. The Anthropic SDK (about 240 ms to import) is loaded only when the judge
  runs; before that change every hook took about 0.4 s.
- **The LLM judge is a model round trip.** Expect hundreds of milliseconds to seconds per judged
  payload, depending on the model and its load; run `-s judge` to measure it. In `untrusted`
  mode it runs on most agent turns.

## Comparing changes

Use `--json` to keep results and compare runs, for example before and after a policy or code
change:

```bash
uv run claude-guard bench -s engine --json > before.json
# ... change policy.yaml or the code ...
uv run claude-guard bench -s engine --json > after.json
jq -r '.results[] | "\(.case)\t\(.added.p50_ms)"' before.json after.json
```

Close other heavy applications and keep the machine on power for stable numbers; compare p50
values, since p95 and p99 are sensitive to background activity.
