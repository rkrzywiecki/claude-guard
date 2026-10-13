"""Latency benchmark: how much time claude-guard adds, for `claude-guard bench`.

Scenarios (each measures the added latency only; no request reaches the real API except in
`judge`):
- `engine`: `GuardEngine.inspect` in process, heuristic detectors, per direction and payload
  size. This is the floor of every integration. Requests are measured twice: `first` (inspected
  in full) and `next turn` (the previous request of the conversation was inspected before, so
  the inspection cache holds all but the two newest messages, as in a running session).
- `proxy`: HTTP round trips to a local fake Messages API, directly and through the proxy
  (uvicorn on loopback). The added latency is the difference between the n-th proxied and the
  n-th direct sample; both series run as blocks (alternating them puts the CPU in a different
  power state before each proxied call). Streams are measured in both stream modes; in
  `buffer` mode the first token waits for the whole upstream response.
- `hooks`: one Claude Code hook invocation, both in process and as the separate process Claude
  Code starts (the venv script, and `uv run` exactly as `install-hooks` writes it).
- `judge`: real LLM judge calls (costs tokens; never run by default).

Payloads are synthetic Claude Code-like conversations whose tool results are this package's
own source files: realistic text, deterministic, and free of secrets.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from contextlib import contextmanager
from enum import StrEnum
from functools import cache, partial
from pathlib import Path

import httpx
import uvicorn
from pydantic import BaseModel, JsonValue
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from claude_guard.config import Settings, load_policy
from claude_guard.detectors.llm_judge import LlmJudgeDetector
from claude_guard.engine import GuardEngine
from claude_guard.hooks.handlers import HookEvent, handle
from claude_guard.hooks.install import guard_root, hook_command
from claude_guard.models import Direction, InspectionContext
from claude_guard.payload import JsonObject, extract
from claude_guard.proxy.app import create_app

SIZES: dict[str, int] = {"small": 1, "medium": 10, "large": 50}  # tool-use turns
STREAM_SIZE = "medium"
DEFAULT_ITERATIONS = {"engine": 50, "proxy": 20, "hooks": 10, "judge": 5}
WARMUP = {"engine": 5, "proxy": 3, "hooks": 1, "judge": 0}
SERVER_START_TIMEOUT = 10.0


class Scenario(StrEnum):
    ENGINE = "engine"
    PROXY = "proxy"
    HOOKS = "hooks"
    JUDGE = "judge"


DEFAULT_SCENARIOS = (Scenario.ENGINE, Scenario.PROXY, Scenario.HOOKS)


class BenchError(Exception):
    """A scenario could not be run."""


class LatencyStats(BaseModel):
    samples: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float

    @classmethod
    def from_seconds(cls, values: Sequence[float]) -> LatencyStats:
        if not values:
            raise ValueError("no samples")
        ordered = sorted(v * 1000 for v in values)

        def rank(q: float) -> float:
            return round(ordered[max(0, math.ceil(q * len(ordered)) - 1)], 2)

        return cls(
            samples=len(ordered),
            mean_ms=round(sum(ordered) / len(ordered), 2),
            p50_ms=rank(0.50),
            p95_ms=rank(0.95),
            p99_ms=rank(0.99),
            max_ms=round(ordered[-1], 2),
        )


class BenchResult(BaseModel):
    scenario: Scenario
    case: str
    payload_bytes: int | None = None
    # Latency claude-guard adds (proxy: per-pair difference to the direct call).
    added: LatencyStats
    # Proxy only: the same call made directly to the fake upstream.
    baseline: LatencyStats | None = None


class BenchReport(BaseModel):
    python: str
    platform: str
    policy_path: str
    results: list[BenchResult]
    notes: list[str]


# Payloads


# Files the shipped policy flags: detectors quote attack patterns. Excluded so the benchmark
# measures the clean path (allow), the one ordinary traffic takes.
FLAGGED_FILES = frozenset({"injection.py", "llm_judge.py"})


@cache
def corpus() -> tuple[str, ...]:
    """This package's source files: realistic tool results without secrets."""
    root = Path(__file__).parent
    return tuple(
        path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.py"))
        if path.name not in FLAGGED_FILES
    )


TOOLS: list[JsonValue] = [
    {
        "name": name,
        "description": f"{name}: {description} " * 8,
        "input_schema": {
            "type": "object",
            "properties": {field: {"type": "string", "description": f"The {field}."}},
            "required": [field],
        },
    }
    for name, field, description in (
        ("Bash", "command", "Runs a shell command in the project directory."),
        ("Read", "file_path", "Reads a file from the local filesystem."),
        ("Edit", "file_path", "Performs an exact string replacement in a file."),
        ("Write", "file_path", "Writes a file to the local filesystem."),
        ("Grep", "pattern", "Searches file contents with a regular expression."),
        ("Glob", "pattern", "Finds files by name pattern."),
        ("WebFetch", "url", "Fetches a web page and returns it as markdown."),
        ("mcp__github__get_issue", "issue", "Reads a GitHub issue."),
    )
]

SYSTEM_PROMPT = (
    "You are a coding agent working in a Python repository. Follow the project conventions, "
    "keep changes small, run the tests before you finish and explain what you changed. "
) * 40


def conversation_request(turns: int, *, stream: bool = False) -> JsonObject:
    """A Claude Code-like request: system prompt, tools and `turns` Read tool round trips."""
    files = corpus()
    messages: list[JsonValue] = [
        {"role": "user", "content": "Review the claude_guard package and suggest improvements."}
    ]
    for turn in range(turns):
        tool_id = f"toolu_{turn:04d}"
        messages.append(
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Let me read the next module."},
                    {
                        "type": "tool_use",
                        "id": tool_id,
                        "name": "Read",
                        "input": {"file_path": f"src/claude_guard/module_{turn}.py"},
                    },
                ],
            }
        )
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": files[turn % len(files)],
                    }
                ],
            }
        )
    return {
        "model": "claude-opus-5-5",
        "max_tokens": 4096,
        "stream": stream,
        "system": SYSTEM_PROMPT,
        "tools": TOOLS,
        "messages": messages,
    }


RESPONSE_TEXT = (
    "The engine runs the heuristic detectors concurrently and aggregates the strictest action. "
) * 4

RESPONSE_MESSAGE: JsonObject = {
    "id": "msg_bench",
    "type": "message",
    "role": "assistant",
    "model": "claude-opus-5-5",
    "stop_reason": "tool_use",
    "stop_sequence": None,
    "usage": {"input_tokens": 1000, "output_tokens": 200},
    "content": [
        {"type": "text", "text": RESPONSE_TEXT},
        {
            "type": "tool_use",
            "id": "toolu_bench",
            "name": "Bash",
            "input": {"command": "uv run pytest -q tests/test_engine.py", "description": "Test"},
        },
    ],
}

BASH_INPUT: JsonObject = {
    "command": "uv run ruff check . && uv run pytest -q",
    "description": "Lint and test",
}


def largest_file() -> str:
    return max(corpus(), key=len)


def engine_cases() -> list[tuple[str, Direction, JsonObject]]:
    cases: list[tuple[str, Direction, JsonObject]] = [
        (
            f"request {size} ({turns} tool turn{'s' if turns > 1 else ''}), first",
            Direction.REQUEST,
            conversation_request(turns),
        )
        for size, turns in SIZES.items()
    ]
    cases += [
        ("response (text + tool_use)", Direction.RESPONSE, RESPONSE_MESSAGE),
        (
            "tool_input (Bash)",
            Direction.TOOL_INPUT,
            {"tool_name": "Bash", "tool_input": BASH_INPUT},
        ),
        (
            "tool_output (Read, largest file)",
            Direction.TOOL_OUTPUT,
            {"tool_name": "Read", "tool_response": largest_file()},
        ),
    ]
    return cases


def payload_size(payload: JsonObject) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode())


# Runner


class Bench:
    def __init__(
        self,
        settings: Settings,
        *,
        iterations: int | None = None,
        stream_events: int = 20,
        event_interval: float = 0.005,
        idle: float = 0.0,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self._workdir = Path(tempfile.mkdtemp(prefix="claude-guard-bench-"))
        # The audit log is part of the cost, but must not pollute the real one.
        self._settings = settings.model_copy(
            update={
                "policy_path": settings.policy_path.expanduser().resolve(),
                "audit_path": self._workdir / "audit.jsonl",
                "alert_webhook_url": None,
            }
        )
        self._policy = load_policy(self._settings.policy_path)
        self._iterations = iterations
        self._stream_events = stream_events
        self._event_interval = event_interval
        self._idle = idle
        self._progress = progress or (lambda _: None)
        self._notes: list[str] = []

    def run(self, scenarios: Sequence[Scenario]) -> BenchReport:
        runners = {
            Scenario.ENGINE: self.engine,
            Scenario.PROXY: self.proxy,
            Scenario.HOOKS: self.hooks,
            Scenario.JUDGE: self.judge,
        }
        results: list[BenchResult] = []
        try:
            for scenario in dict.fromkeys(scenarios):
                self._progress(f"running {scenario.value} ...")
                results += runners[scenario]()
        finally:
            shutil.rmtree(self._workdir, ignore_errors=True)
        return BenchReport(
            python=sys.version.split()[0],
            platform=sys.platform,
            policy_path=str(self._settings.policy_path),
            results=results,
            notes=self._notes,
        )

    def _collect[T](
        self,
        scenario: Scenario,
        measure: Callable[[], T],
        setup: Callable[[], object] | None = None,
    ) -> list[T]:
        warmup = WARMUP[scenario.value]
        iterations = self._iterations or DEFAULT_ITERATIONS[scenario.value]
        return _collect(measure, warmup, iterations, self._idle, setup)

    def _engine(self, *, cache: bool) -> GuardEngine:
        """cache=False: every request inspected in full; True: the configured cache."""
        return GuardEngine(
            self._policy, self._settings, use_llm_judge=False, cache_size=None if cache else 0
        )

    # engine

    def engine(self) -> list[BenchResult]:
        cold = self._engine(cache=False)
        warm = self._engine(cache=True)
        results = []
        with asyncio.Runner() as runner:
            for case, direction, payload in engine_cases():
                inspect = partial(cold.inspect, direction, payload, source="bench")
                samples = self._collect(Scenario.ENGINE, partial(_run_elapsed, runner, inspect))
                results.append(
                    BenchResult(
                        scenario=Scenario.ENGINE,
                        case=case,
                        payload_bytes=payload_size(payload),
                        added=LatencyStats.from_seconds(samples),
                    )
                )
            for size, turns in SIZES.items():
                payload = conversation_request(turns)
                previous = conversation_request(turns - 1)

                def prime(previous: JsonObject = previous) -> None:
                    if warm.cache is not None:
                        warm.cache.clear()
                    runner.run(warm.inspect(Direction.REQUEST, previous, source="bench"))

                inspect = partial(warm.inspect, Direction.REQUEST, payload, source="bench")
                samples = self._collect(
                    Scenario.ENGINE, partial(_run_elapsed, runner, inspect), setup=prime
                )
                results.append(
                    BenchResult(
                        scenario=Scenario.ENGINE,
                        case=f"request {size}, next turn",
                        payload_bytes=payload_size(payload),
                        added=LatencyStats.from_seconds(samples),
                    )
                )
        self._cache_note()
        return results

    def _cache_note(self) -> None:
        note = (
            "next turn: the previous request of the conversation was inspected first, so only "
            "the newest assistant message and tool result are new (inspection cache)."
        )
        if self._settings.inspection_cache_size == 0:
            note = "next turn: GUARD_INSPECTION_CACHE_SIZE=0, the cache is off."
        if note not in self._notes:
            self._notes.append(note)

    # proxy

    def proxy(self) -> list[BenchResult]:
        upstream_app = fake_upstream(self._stream_events, self._event_interval)
        results = []
        with serve(upstream_app) as upstream_url:
            settings = self._settings.model_copy(update={"upstream_url": upstream_url})
            buffer = settings.model_copy(update={"stream_mode": "buffer"})
            audit = settings.model_copy(update={"stream_mode": "audit"})
            session = self._engine(cache=True)
            with (
                serve(create_app(buffer, engine=self._engine(cache=False))) as buffer_url,
                serve(create_app(audit, engine=self._engine(cache=False))) as audit_url,
                serve(create_app(buffer, engine=session)) as session_url,
                httpx.Client(timeout=60, headers={"x-api-key": "bench"}) as client,
            ):
                for size, turns in SIZES.items():
                    body = conversation_request(turns)
                    previous = conversation_request(turns - 1)

                    def prime(previous: JsonObject = previous) -> None:
                        if session.cache is not None:
                            session.cache.clear()
                        _post(client, session_url, previous)

                    direct = self._collect(
                        Scenario.PROXY, partial(_post, client, upstream_url, body)
                    )
                    first = self._collect(Scenario.PROXY, partial(_post, client, buffer_url, body))
                    following = self._collect(
                        Scenario.PROXY, partial(_post, client, session_url, body), setup=prime
                    )
                    results.append(
                        _proxy_result(f"non-streaming, request {size}, first", body, direct, first)
                    )
                    results.append(
                        _proxy_result(
                            f"non-streaming, request {size}, next turn", body, direct, following
                        )
                    )

                body = conversation_request(SIZES[STREAM_SIZE], stream=True)
                for mode, url in (("buffer", buffer_url), ("audit", audit_url)):
                    direct_s = self._collect(
                        Scenario.PROXY, partial(_stream, client, upstream_url, body)
                    )
                    proxied_s = self._collect(Scenario.PROXY, partial(_stream, client, url, body))
                    for index, metric in enumerate(("first token", "total")):
                        results.append(
                            _proxy_result(
                                f"stream {mode}, {metric} (request {STREAM_SIZE})",
                                body,
                                [pair[index] for pair in direct_s],
                                [pair[index] for pair in proxied_s],
                            )
                        )
        self._notes.append(
            f"proxy: fake upstream streams {self._stream_events} text deltas every "
            f"{self._event_interval * 1000:g} ms; streams and 'first' rows are inspected in full; "
            "LLM judge excluded (see --scenario judge)."
        )
        self._cache_note()
        return results

    # hooks

    def hooks(self) -> list[BenchResult]:
        results = []
        settings = self._settings.model_copy(update={"hook_llm": False})
        inputs = hook_inputs(Path.cwd())
        script = Path(sys.executable).with_name("claude-guard")
        env = {
            **os.environ,
            "GUARD_POLICY_PATH": str(settings.policy_path),
            "GUARD_AUDIT_PATH": str(settings.audit_path),
            "GUARD_HOOK_LLM": "false",
            "GUARD_ALERT_WEBHOOK_URL": "",
        }
        uv = shutil.which("uv") is not None and (guard_root() / "pyproject.toml").is_file()

        def in_process(event: HookEvent, stdin: str) -> Callable[[], None]:
            def run() -> None:
                asyncio.run(handle(event, stdin, settings))

            return run

        def process(args: list[str] | str, stdin: str) -> Callable[[], None]:
            def run() -> None:
                # shell=True only for the uv variant: the exact command Claude Code runs.
                subprocess.run(  # noqa: S603
                    args,
                    input=stdin,
                    text=True,
                    capture_output=True,
                    check=True,
                    env=env,
                    shell=isinstance(args, str),
                )

            return run

        def add(case: str, stdin: str | None, fn: Callable[[], None]) -> None:
            samples = self._collect(Scenario.HOOKS, partial(_elapsed, fn))
            size = len(stdin.encode()) if stdin is not None else None
            results.append(
                BenchResult(
                    scenario=Scenario.HOOKS,
                    case=case,
                    payload_bytes=size,
                    added=LatencyStats.from_seconds(samples),
                )
            )

        add("python -c pass (interpreter floor)", None, process([sys.executable, "-c", "pass"], ""))
        for event, stdin in inputs.items():
            add(f"{event.value}: in process", stdin, in_process(event, stdin))
            if script.is_file():
                add(
                    f"{event.value}: venv script",
                    stdin,
                    process([str(script), "hook", event], stdin),
                )
            if uv:
                command = hook_command(event, settings, guard_root())
                add(f"{event.value}: uv run (as installed)", stdin, process(command, stdin))
        if not uv:
            self._notes.append("hooks: uv or the source checkout not found; uv run skipped.")
        self._notes.append(
            "hooks: Claude Code runs a new process per event, so the process rows are the "
            "latency added to each prompt and tool call."
        )
        return results

    # judge

    def judge(self) -> list[BenchResult]:
        policy = self._policy.model_copy(
            update={"llm_judge": self._policy.llm_judge.model_copy(update={"enabled": True})}
        )
        detector = LlmJudgeDetector(policy, self._settings)
        payload: JsonObject = {"tool_name": "Read", "tool_response": largest_file()[:4000]}
        extraction = extract(Direction.TOOL_OUTPUT, payload)
        ctx = InspectionContext(
            direction=Direction.TOOL_OUTPUT, segments=tuple(extraction.segments)
        )

        hint = "check ANTHROPIC_API_KEY and GUARD_JUDGE_MODEL"

        async def once() -> None:
            try:
                findings = await detector.detect(ctx)
            except Exception as exc:  # e.g. TypeError from the SDK when no credentials are set
                raise BenchError(
                    f"the LLM judge call failed: {type(exc).__name__} ({hint})"
                ) from exc
            if any(f.rule == "judge_unavailable" for f in findings):
                raise BenchError(f"the LLM judge call failed ({hint})")

        with asyncio.Runner() as runner:
            samples = self._collect(Scenario.JUDGE, partial(_run_elapsed, runner, once))
        self._notes.append(f"judge: model {self._settings.judge_model}, real API calls.")
        return [
            BenchResult(
                scenario=Scenario.JUDGE,
                case="tool_output (4 KB)",
                payload_bytes=payload_size(payload),
                added=LatencyStats.from_seconds(samples),
            )
        ]


def hook_inputs(cwd: Path) -> dict[HookEvent, str]:
    common = {
        "session_id": "bench",
        "transcript_path": str(cwd / "bench.jsonl"),
        "cwd": str(cwd),
    }
    events: dict[HookEvent, JsonObject] = {
        HookEvent.USER_PROMPT_SUBMIT: {"prompt": "Add a benchmark for the proxy latency."},
        HookEvent.PRE_TOOL_USE: {"tool_name": "Bash", "tool_input": BASH_INPUT},
        HookEvent.POST_TOOL_USE: {
            "tool_name": "Read",
            "tool_input": {"file_path": "src/claude_guard/engine.py"},
            "tool_response": largest_file(),
        },
    }
    return {
        event: json.dumps({**common, "hook_event_name": event.value, **fields})
        for event, fields in events.items()
    }


def _collect[T](
    measure: Callable[[], T],
    warmup: int,
    iterations: int,
    idle: float,
    setup: Callable[[], object] | None = None,
) -> list[T]:
    """Call `measure` warmup + iterations times, after `setup` (not measured) and a pause of
    `idle` seconds."""
    samples = []
    for i in range(warmup + iterations):
        if setup is not None:
            setup()
        if idle:
            time.sleep(idle)
        sample = measure()
        if i >= warmup:
            samples.append(sample)
    return samples


def _elapsed(fn: Callable[[], object]) -> float:
    started = time.perf_counter()
    fn()
    return time.perf_counter() - started


async def _elapsed_async(fn: Callable[[], Awaitable[object]]) -> float:
    started = time.perf_counter()
    await fn()
    return time.perf_counter() - started


def _run_elapsed(runner: asyncio.Runner, fn: Callable[[], Awaitable[object]]) -> float:
    """Time only the awaited call, not the event loop round trip."""
    return runner.run(_elapsed_async(fn))


def _proxy_result(
    case: str, body: JsonObject, direct: Sequence[float], proxied: Sequence[float]
) -> BenchResult:
    return BenchResult(
        scenario=Scenario.PROXY,
        case=case,
        payload_bytes=payload_size(body),
        added=LatencyStats.from_seconds([p - d for d, p in zip(direct, proxied, strict=True)]),
        baseline=LatencyStats.from_seconds(direct),
    )


def _post(client: httpx.Client, base_url: str, body: JsonObject) -> float:
    started = time.perf_counter()
    response = client.post(f"{base_url}/v1/messages", json=body)
    response.read()
    elapsed = time.perf_counter() - started
    if response.status_code != 200:
        raise BenchError(f"{base_url} answered HTTP {response.status_code}: {response.text[:200]}")
    return elapsed


def _stream(client: httpx.Client, base_url: str, body: JsonObject) -> tuple[float, float]:
    """(time to the first text delta, time to the end of the stream)."""
    started = time.perf_counter()
    first: float | None = None
    with client.stream("POST", f"{base_url}/v1/messages", json=body) as response:
        if response.status_code != 200:
            response.read()
            raise BenchError(f"{base_url} answered HTTP {response.status_code}")
        for line in response.iter_lines():
            if first is None and line.startswith("data:") and "text_delta" in line:
                first = time.perf_counter() - started
    total = time.perf_counter() - started
    if first is None:
        raise BenchError(f"{base_url} streamed no text")
    return first, total


# Fake upstream and servers


def _sse(name: str, data: JsonObject) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()


def fake_upstream(stream_events: int, event_interval: float) -> Starlette:
    """A Messages API stand-in: fixed reply, simulated token-by-token streaming."""
    text = RESPONSE_MESSAGE["content"][0]["text"]  # type: ignore[index,call-overload]
    assert isinstance(text, str)  # noqa: S101 (static payload)
    chunk = max(1, len(text) // stream_events)
    parts = [text[i : i + chunk] for i in range(0, len(text), chunk)]

    async def events() -> AsyncIterator[bytes]:
        start = {**RESPONSE_MESSAGE, "content": [], "stop_reason": None}
        yield _sse("message_start", {"type": "message_start", "message": start})
        yield _sse(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
        for part in parts:
            await asyncio.sleep(event_interval)
            delta: JsonObject = {"type": "text_delta", "text": part}
            yield _sse(
                "content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}
            )
        yield _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
        yield _sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 200},
            },
        )
        yield _sse("message_stop", {"type": "message_stop"})

    async def messages(request: Request) -> Response:
        body = json.loads(await request.body())
        if body.get("stream") is True:
            return StreamingResponse(events(), media_type="text/event-stream")
        return JSONResponse(RESPONSE_MESSAGE)

    return Starlette(routes=[Route("/v1/messages", messages, methods=["POST"])])


@contextmanager
def serve(app: Starlette) -> Iterator[str]:
    """Run an ASGI app with uvicorn on a free loopback port in a background thread."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, log_level="warning", access_log=False, lifespan="on")
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + SERVER_START_TIMEOUT
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise BenchError("the benchmark server did not start")
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(SERVER_START_TIMEOUT)
        sock.close()


def run_bench(
    settings: Settings,
    scenarios: Sequence[Scenario] = DEFAULT_SCENARIOS,
    *,
    iterations: int | None = None,
    idle: float = 0.0,
    progress: Callable[[str], None] | None = None,
) -> BenchReport:
    return Bench(settings, iterations=iterations, idle=idle, progress=progress).run(scenarios)
