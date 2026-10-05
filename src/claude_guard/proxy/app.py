"""FastAPI application: /v1/messages, /healthz, /metrics.

`POST /v1/messages` is inspected in both directions:
- request: `block` returns HTTP 400 in the Anthropic error format, `redact` rewrites the body
  before it goes upstream;
- response: `block` replaces the assistant message with a single text block explaining the
  block (so no tool call is executed and agent loops keep working), `redact` rewrites it.

Streaming (`"stream": true`) follows `GUARD_STREAM_MODE`:
- `buffer`: collect the whole upstream stream (sending `ping` events meanwhile), inspect, then
  replay the original events, or synthesize new ones when the message was changed;
- `audit`: pass events through live and inspect afterwards; the verdict only reaches the audit
  log, metrics and a warning log line.

Other `/v1/*` endpoints (e.g. `count_tokens`) are forwarded without inspection. Credential
headers are forwarded but never logged.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from claude_guard.config import Settings, get_settings
from claude_guard.engine import GuardEngine
from claude_guard.models import Action, Direction, Verdict
from claude_guard.payload import JsonObject
from claude_guard.proxy.streaming import (
    PING_EVENT,
    MessageAccumulator,
    SSEEvent,
    SSEParser,
    format_event,
    synthesize_events,
)

log = structlog.get_logger(__name__)

FORWARDED_HEADERS = frozenset({"x-api-key", "authorization", "content-type", "accept"})
FORWARDED_PREFIXES = ("anthropic-",)
DROPPED_RESPONSE_HEADERS = frozenset(
    {"content-length", "content-encoding", "transfer-encoding", "connection", "keep-alive"}
)
REQUEST_ACTION_HEADER = "x-claude-guard-request-action"
RESPONSE_ACTION_HEADER = "x-claude-guard-response-action"
DEFAULT_PING_INTERVAL = 10.0


class Metrics:
    """In-process counters exposed in Prometheus text format."""

    def __init__(self) -> None:
        self.verdicts: Counter[tuple[str, str]] = Counter()
        self.counters: Counter[str] = Counter()

    def record(self, verdict: Verdict) -> None:
        self.verdicts[(verdict.direction.value, verdict.action.value)] += 1
        if verdict.error:
            self.counters["guard_errors_total"] += 1

    def render(self) -> str:
        lines = [
            "# HELP claude_guard_verdicts_total Verdicts by direction and action.",
            "# TYPE claude_guard_verdicts_total counter",
        ]
        for direction in Direction:
            for action in Action:
                count = self.verdicts[(direction.value, action.value)]
                lines.append(
                    f'claude_guard_verdicts_total{{direction="{direction.value}",'
                    f'action="{action.value}"}} {count}'
                )
        for name in ("requests_total", "upstream_errors_total", "guard_errors_total"):
            lines.append(f"# TYPE claude_guard_{name} counter")
            lines.append(f"claude_guard_{name} {self.counters[name]}")
        return "\n".join(lines) + "\n"


def error_response(
    status_code: int, error_type: str, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    """An error body in the Anthropic API format."""
    return JSONResponse(
        {"type": "error", "error": {"type": error_type, "message": message}},
        status_code=status_code,
        headers=headers,
    )


def blocked_message(message: JsonObject, reason: str) -> JsonObject:
    """Replace a response's content with a notice; keep id, model and usage."""
    replaced = dict(message)
    replaced["content"] = [{"type": "text", "text": f"[claude-guard] Response blocked: {reason}"}]
    replaced["stop_reason"] = "end_turn"
    replaced["stop_sequence"] = None
    return replaced


def upstream_headers(request: Request) -> dict[str, str]:
    return {
        name: value
        for name, value in request.headers.items()
        if name in FORWARDED_HEADERS or name.startswith(FORWARDED_PREFIXES)
    }


def client_headers(upstream: httpx.Response, extra: dict[str, str]) -> dict[str, str]:
    headers = {
        name: value
        for name, value in upstream.headers.items()
        if name.lower() not in DROPPED_RESPONSE_HEADERS
    }
    headers.update(extra)
    return headers


def create_app(
    settings: Settings | None = None,
    *,
    engine: GuardEngine | None = None,
    upstream: httpx.AsyncClient | None = None,
    ping_interval: float = DEFAULT_PING_INTERVAL,
) -> FastAPI:
    settings = settings or get_settings()
    guard = engine or GuardEngine.from_settings(settings)
    owns_client = upstream is None
    client = upstream or httpx.AsyncClient(
        base_url=settings.upstream_url, timeout=settings.upstream_timeout
    )
    metrics = Metrics()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_client:
            await client.aclose()

    app = FastAPI(title="claude-guard", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {
            "status": "ok",
            "stream_mode": settings.stream_mode,
            "fail_mode": settings.fail_mode,
        }

    @app.get("/metrics")
    async def metrics_endpoint() -> PlainTextResponse:
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        raw = await request.body()
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return error_response(
                400, "invalid_request_error", "Request body must be a JSON object"
            )

        verdict = await guard.inspect(Direction.REQUEST, body, source="proxy")
        metrics.record(verdict)
        guard_headers = {REQUEST_ACTION_HEADER: verdict.action.value}
        if verdict.blocked:
            log.warning("request_blocked", rules=[f.rule for f in verdict.findings])
            return error_response(
                400,
                "invalid_request_error",
                f"claude-guard blocked the request: {guard.safe_reason(verdict)}",
                guard_headers,
            )
        if verdict.action is Action.REDACT:
            raw = json.dumps(guard.redact(body, verdict), ensure_ascii=False).encode()

        url = httpx.URL(path="/v1/messages", query=request.url.query.encode())
        headers = upstream_headers(request)
        if body.get("stream") is True:
            return await stream_messages(url, raw, headers, guard_headers)
        return await complete_messages(url, raw, headers, guard_headers)

    async def complete_messages(
        url: httpx.URL, raw: bytes, headers: dict[str, str], guard_headers: dict[str, str]
    ) -> Response:
        try:
            upstream_response = await client.post(url, content=raw, headers=headers)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        if upstream_response.status_code != 200:
            return passthrough_response(upstream_response, guard_headers)
        try:
            message = upstream_response.json()
        except ValueError:
            message = None
        if not isinstance(message, dict):
            return passthrough_response(upstream_response, guard_headers)

        verdict = await guard.inspect(Direction.RESPONSE, message, source="proxy")
        metrics.record(verdict)
        out_headers = client_headers(
            upstream_response, {**guard_headers, RESPONSE_ACTION_HEADER: verdict.action.value}
        )
        if verdict.blocked:
            log.warning("response_blocked", rules=[f.rule for f in verdict.findings])
            return JSONResponse(
                blocked_message(message, guard.safe_reason(verdict)), headers=out_headers
            )
        if verdict.action is Action.REDACT:
            return JSONResponse(guard.redact(message, verdict), headers=out_headers)
        return Response(
            upstream_response.content, media_type="application/json", headers=out_headers
        )

    async def stream_messages(
        url: httpx.URL, raw: bytes, headers: dict[str, str], guard_headers: dict[str, str]
    ) -> Response:
        upstream_request = client.build_request("POST", url, content=raw, headers=headers)
        try:
            upstream_response = await client.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        if upstream_response.status_code != 200:
            await upstream_response.aread()
            await upstream_response.aclose()
            return passthrough_response(upstream_response, guard_headers)

        events = (
            buffered_events(upstream_response)
            if settings.stream_mode == "buffer"
            else audited_events(upstream_response)
        )
        return StreamingResponse(
            events,
            media_type="text/event-stream",
            headers=client_headers(upstream_response, guard_headers),
            background=BackgroundTask(upstream_response.aclose),
        )

    async def buffered_events(upstream_response: httpx.Response) -> AsyncGenerator[bytes]:
        parser = SSEParser()
        accumulator = MessageAccumulator()
        received: list[SSEEvent] = []

        async def collect() -> None:
            async for chunk in upstream_response.aiter_bytes():
                for event in parser.feed(chunk):
                    received.append(event)
                    accumulator.add(event)
            for event in parser.flush():
                received.append(event)
                accumulator.add(event)

        task = asyncio.create_task(collect())
        try:
            while not (await asyncio.wait({task}, timeout=ping_interval))[0]:
                yield PING_EVENT
        finally:
            if not task.done():
                task.cancel()
        if task.exception() is not None:
            metrics.counters["upstream_errors_total"] += 1
            yield stream_error_event("claude-guard lost the upstream stream")
            return

        message = accumulator.result()
        if message is None:
            for event in received:  # e.g. only an upstream error event
                yield event.raw
            return

        verdict = await guard.inspect(Direction.RESPONSE, message, source="proxy")
        metrics.record(verdict)
        if verdict.action in (Action.ALLOW, Action.WARN):
            for event in received:
                yield event.raw
            return

        if verdict.blocked:
            log.warning("response_blocked", rules=[f.rule for f in verdict.findings])
            replacement = blocked_message(message, guard.safe_reason(verdict))
        else:
            replacement = guard.redact(message, verdict)
        for chunk in synthesize_events(replacement):
            yield chunk
        for event in received:
            if event.event == "error":
                yield event.raw

    async def audited_events(upstream_response: httpx.Response) -> AsyncGenerator[bytes]:
        parser = SSEParser()
        accumulator = MessageAccumulator()
        try:
            async for chunk in upstream_response.aiter_bytes():
                for event in parser.feed(chunk):
                    accumulator.add(event)
                yield chunk
        except httpx.HTTPError:
            metrics.counters["upstream_errors_total"] += 1
            yield stream_error_event("claude-guard lost the upstream stream")
        for event in parser.flush():
            accumulator.add(event)

        message = accumulator.result()
        if message is None:
            return
        verdict = await guard.inspect(Direction.RESPONSE, message, source="proxy:audit")
        metrics.record(verdict)
        if verdict.action is not Action.ALLOW:
            # Already delivered: audit mode can only report.
            log.warning(
                "audit_mode_violation",
                action=verdict.action.value,
                rules=[f.rule for f in verdict.findings],
            )

    def upstream_failure(exc: httpx.HTTPError) -> Response:
        metrics.counters["upstream_errors_total"] += 1
        log.error("upstream_request_failed", error_type=type(exc).__name__)
        return error_response(502, "api_error", "claude-guard could not reach the upstream API")

    def passthrough_response(
        upstream_response: httpx.Response, guard_headers: dict[str, str]
    ) -> Response:
        return Response(
            upstream_response.content,
            status_code=upstream_response.status_code,
            headers=client_headers(upstream_response, guard_headers),
        )

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def passthrough(path: str, request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        url = httpx.URL(path=f"/v1/{path}", query=request.url.query.encode())
        try:
            upstream_response = await client.request(
                request.method, url, content=await request.body(), headers=upstream_headers(request)
            )
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        return passthrough_response(upstream_response, {})

    return app


def stream_error_event(message: str) -> bytes:
    return format_event(
        "error", {"type": "error", "error": {"type": "api_error", "message": message}}
    )
