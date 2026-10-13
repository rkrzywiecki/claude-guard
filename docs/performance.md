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
secrets). Sizes: `small` 1 turn (12 KB), `medium` 10 turns (110 KB), `large` 50 turns (450 KB).
Files the shipped policy flags (detectors quote attack patterns) are left out, so every case
takes the clean `allow` path that ordinary traffic takes.

Details of the method:

- **Audit log.** Each inspection appends to an audit log, as in production, but to a temporary
  directory: the real `logs/audit.jsonl` is not touched. Alerts are off.
- **LLM judge.** Off in `engine`, `proxy` and `hooks` even if `policy.yaml` enables it; measure
  it separately with `-s judge` and add it to the request rows.
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
| engine | request small (1 tool turn) | 12 KB | 2.4 | 2.4 |
| engine | request medium (10 tool turns) | 110 KB | 61 | 62 |
| engine | request large (50 tool turns) | 450 KB | 266 | 269 |
| engine | response (text + tool_use) | 0.7 KB | 0.4 | 0.5 |
| engine | tool_input (Bash) | 0.1 KB | 0.2 | 0.2 |
| engine | tool_output (Read, 37 KB file) | 37 KB | 21 | 21 |
| proxy | non-streaming, request small | 12 KB | 3.3 | 3.5 |
| proxy | non-streaming, request medium | 110 KB | 64 | 65 |
| proxy | non-streaming, request large | 450 KB | 275 | 276 |
| proxy | stream `buffer`, first token | 110 KB | 196 | 198 |
| proxy | stream `buffer`, total | 110 KB | 78 | 80 |
| proxy | stream `audit`, first token | 110 KB | 75 | 77 |
| proxy | stream `audit`, total | 110 KB | 76 | 80 |
| hooks | `python -c pass` (interpreter floor) | | 11 | 22 |
| hooks | PreToolUse, in process | 0.3 KB | 1.7 | 1.8 |
| hooks | PreToolUse, venv script | 0.3 KB | 130 | 135 |
| hooks | PreToolUse, `uv run` (as installed) | 0.3 KB | 145 | 146 |
| hooks | PostToolUse, `uv run` (as installed) | 37 KB | 166 | 170 |
| hooks | UserPromptSubmit, `uv run` (as installed) | 0.2 KB | 145 | 149 |

With `--idle-ms 500` (a pause before every call, as between real requests) CPU-bound work is
slower because the CPU leaves its high-performance state while idle: the medium request goes
from 64 to about 100 ms in the proxy, a small one from 3 to 14 ms, and hooks from about 145 to
about 180 ms. Real traffic has such gaps (the model takes seconds to answer), so treat the idle
numbers as the realistic ones on laptops and the default ones as a lower bound.

## Reading the results

- **Proxy cost grows with the context, about 0.6 ms per KB.** Each request carries the whole
  conversation and the heuristics scan all of it, including history that was inspected before.
  A long Claude Code session (hundreds of KB) adds a few hundred milliseconds per request, on top
  of a model time to first token that is usually one to several seconds. The response side is
  cheap (under 1 ms for a typical message).
- **`buffer` streaming delays the first token by the whole generation time**, plus inspection.
  In the table the fake generation takes about 110 ms; with a real model it is the full response
  time (seconds). `audit` mode only adds the request inspection to the first token.
- **Hooks cost about 0.15 s per event, almost all of it process start-up.** The inspection
  itself takes 2 ms for a tool call (20 ms for a 37 KB tool result); `uv run` adds about 15 ms;
  the rest is starting Python and importing modules (about 110 ms, see `python -X importtime`).
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
