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

Other endpoints:
- `POST /v1/messages/count_tokens`: secrets are redacted (the prompt still reaches the API), but
  nothing is blocked, since no model runs;
- `POST /v1/messages/batches`: every `requests[].params` is inspected like a request; one
  blocked request rejects the batch;
- `GET /v1/messages/batches/{id}/results`: every succeeded message is inspected like a response;
  `results_url` in batch objects is rewritten to point at the proxy, since SDKs follow it;
- read-only and delete endpoints in `UNINSPECTED_ENDPOINTS` (models, batch and file metadata)
  are forwarded as is; any other `/v1/*` endpoint (e.g. Files API uploads) follows
  `GUARD_PASSTHROUGH`: `block` (default) answers 403, `allow` forwards it uninspected.

Credential headers are forwarded but never logged.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from collections import Counter
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import JsonValue
from starlette.background import BackgroundTask
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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
TOKEN_HEADER = "x-claude-guard-token"  # noqa: S105 (a header name, not a secret)
# Reachable without the proxy token: liveness probes.
OPEN_PATHS = frozenset({"/healthz"})
REQUEST_ACTION_HEADER = "x-claude-guard-request-action"
RESPONSE_ACTION_HEADER = "x-claude-guard-response-action"
DEFAULT_PING_INTERVAL = 10.0

# Endpoints that carry no prompt content to a model; forwarded without inspection.
UNINSPECTED_ENDPOINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GET", re.compile(r"/v1/models(?:/[^/]+)?")),
    ("DELETE", re.compile(r"/v1/messages/batches/[^/]+")),
    ("GET", re.compile(r"/v1/files(?:/[^/]+(?:/content)?)?")),
    ("DELETE", re.compile(r"/v1/files/[^/]+")),
)


def is_uninspected_endpoint(method: str, path: str) -> bool:
    return any(method == m and pattern.fullmatch(path) for m, pattern in UNINSPECTED_ENDPOINTS)


def rewrite_results_urls(data: JsonValue, base_url: str) -> JsonValue:
    """Point `results_url` of batch objects (single or listed) at the proxy."""
    if isinstance(data, dict):
        url = data.get("results_url")
        if isinstance(url, str):
            data["results_url"] = base_url + httpx.URL(url).raw_path.decode()
        items = data.get("data")
        if isinstance(items, list):
            for item in items:
                rewrite_results_urls(item, base_url)
    return data


def parse_object(raw: bytes) -> JsonObject | None:
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


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
        for name in (
            "requests_total",
            "upstream_errors_total",
            "guard_errors_total",
            "passthrough_blocked_total",
            "limit_exceeded_total",
            "unauthorized_total",
        ):
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


class TokenMiddleware:
    """Rejects requests without the shared proxy token (GUARD_PROXY_TOKEN), before any body is
    read. The token header is never forwarded upstream or logged."""

    def __init__(self, app: ASGIApp, token: str, metrics: Metrics) -> None:
        self._app = app
        self._token = token.encode()
        self._metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] not in OPEN_PATHS:
            supplied = dict(scope["headers"]).get(TOKEN_HEADER.encode(), b"")
            if not secrets.compare_digest(supplied, self._token):
                self._metrics.counters["unauthorized_total"] += 1
                log.warning("proxy_unauthorized", path=scope["path"])
                response = error_response(
                    401,
                    "authentication_error",
                    f"claude-guard: missing or invalid {TOKEN_HEADER} header",
                )
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


class BodyLimitMiddleware:
    """Reads the request body up to `max_bytes` and replays it to the app; larger bodies get
    HTTP 413 without reaching a handler."""

    def __init__(self, app: ASGIApp, max_bytes: int, metrics: Metrics) -> None:
        self._app = app
        self._max_bytes = max_bytes
        self._metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length", b"")
        too_large = declared.isdigit() and int(declared) > self._max_bytes
        chunks: list[bytes] = []
        size = 0
        while not too_large:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            too_large = size > self._max_bytes
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        if too_large:
            self._metrics.counters["limit_exceeded_total"] += 1
            log.warning("request_too_large", path=scope["path"], limit=self._max_bytes)
            response = error_response(
                413,
                "request_too_large",
                f"claude-guard: request body exceeds {self._max_bytes} bytes "
                "(GUARD_MAX_BODY_BYTES)",
            )
            await response(scope, receive, send)
            return

        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self._app(scope, replay, send)


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
        await guard.flush_alerts()
        if owns_client:
            await client.aclose()

    app = FastAPI(title="claude-guard", lifespan=lifespan)
    # Added last runs first: the token is checked before any body is read.
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes, metrics=metrics)
    token = settings.proxy_token.get_secret_value() if settings.proxy_token else ""
    if token:
        app.add_middleware(TokenMiddleware, token=token, metrics=metrics)

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
        body = parse_object(raw)
        if body is None:
            return invalid_body()

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
        chunks = upstream_response.aiter_bytes()
        overflow: list[bytes] = []

        async def collect() -> bool:
            """Buffer the stream; False when it exceeds GUARD_MAX_STREAM_BYTES."""
            size = 0
            async for chunk in chunks:
                size += len(chunk)
                if size > settings.max_stream_bytes:
                    overflow.append(chunk)  # kept raw: delivered as is if failing open
                    return False
                for event in parser.feed(chunk):
                    received.append(event)
                    accumulator.add(event)
            for event in parser.flush():
                received.append(event)
                accumulator.add(event)
            return True

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
        if not task.result():
            metrics.counters["limit_exceeded_total"] += 1
            log.warning(
                "stream_too_large", limit=settings.max_stream_bytes, fail_mode=settings.fail_mode
            )
            if settings.fail_mode == "closed":
                yield stream_error_event(
                    "claude-guard: response too large to inspect (GUARD_MAX_STREAM_BYTES)"
                )
                return
            # Fail open: deliver what was buffered, then the rest live, uninspected.
            for event in received:
                yield event.raw
            yield parser.take_pending()
            yield overflow[0]
            async for chunk in chunks:
                yield chunk
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

    def invalid_body() -> Response:
        return error_response(400, "invalid_request_error", "Request body must be a JSON object")

    def upstream_url(request: Request) -> httpx.URL:
        return httpx.URL(path=request.url.path, query=request.url.query.encode())

    async def forward(request: Request, content: bytes | None = None) -> httpx.Response:
        return await client.request(
            request.method,
            upstream_url(request),
            content=await request.body() if content is None else content,
            headers=upstream_headers(request),
        )

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        raw = await request.body()
        body = parse_object(raw)
        if body is None:
            return invalid_body()
        # Only secrets are acted on: the prompt reaches the API, but no model runs.
        verdict = await guard.inspect(Direction.REQUEST, body, source="proxy:count_tokens")
        if any(finding.action is Action.REDACT for finding in verdict.findings):
            raw = json.dumps(guard.redact(body, verdict), ensure_ascii=False).encode()
        try:
            upstream_response = await forward(request, raw)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        return passthrough_response(upstream_response, {})

    @app.post("/v1/messages/batches")
    async def create_batch(request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        body = parse_object(await request.body())
        if body is None:
            return invalid_body()
        items = body.get("requests")
        if not isinstance(items, list):
            return error_response(
                400, "invalid_request_error", "Batch body must contain a requests list"
            )

        verdicts: list[Verdict] = []
        for index, item in enumerate(items):
            params = item.get("params") if isinstance(item, dict) else None
            if not isinstance(item, dict) or not isinstance(params, dict):
                return error_response(
                    400, "invalid_request_error", f"requests[{index}].params must be an object"
                )
            verdict = await guard.inspect(Direction.REQUEST, params, source="proxy:batch")
            metrics.record(verdict)
            verdicts.append(verdict)
            if verdict.blocked:
                log.warning(
                    "batch_request_blocked", index=index, rules=[f.rule for f in verdict.findings]
                )
                return error_response(
                    400,
                    "invalid_request_error",
                    f"claude-guard blocked the batch: request {item.get('custom_id')!r}: "
                    f"{guard.safe_reason(verdict)}",
                    {REQUEST_ACTION_HEADER: Action.BLOCK.value},
                )
            if verdict.action is Action.REDACT:
                item["params"] = guard.redact(params, verdict)

        action = Action.strictest(v.action for v in verdicts)
        raw = json.dumps(body, ensure_ascii=False).encode()
        try:
            upstream_response = await forward(request, raw)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        return batch_object_response(request, upstream_response, action)

    @app.get("/v1/messages/batches")
    @app.get("/v1/messages/batches/{batch_id}")
    @app.post("/v1/messages/batches/{batch_id}/cancel")
    async def batch_objects(request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        try:
            upstream_response = await forward(request)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        return batch_object_response(request, upstream_response, None)

    def batch_object_response(
        request: Request, upstream_response: httpx.Response, action: Action | None
    ) -> Response:
        guard_headers = {REQUEST_ACTION_HEADER: action.value} if action else {}
        data = parse_object(upstream_response.content)
        if upstream_response.status_code != 200 or data is None:
            return passthrough_response(upstream_response, guard_headers)
        rewrite_results_urls(data, str(request.base_url).rstrip("/"))
        return JSONResponse(data, headers=client_headers(upstream_response, guard_headers))

    @app.get("/v1/messages/batches/{batch_id}/results")
    async def batch_results(request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        try:
            upstream_response = await forward(request)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        if upstream_response.status_code != 200:
            return passthrough_response(upstream_response, {})

        lines: list[bytes] = []
        actions: list[Action] = []
        for line in upstream_response.content.split(b"\n"):
            entry = parse_object(line) if line.strip() else None
            result = entry.get("result") if entry else None
            message = result.get("message") if isinstance(result, dict) else None
            if entry is None or not isinstance(result, dict) or not isinstance(message, dict):
                lines.append(line)
                continue
            verdict = await guard.inspect(Direction.RESPONSE, message, source="proxy:batch")
            metrics.record(verdict)
            actions.append(verdict.action)
            if verdict.blocked:
                log.warning("batch_result_blocked", rules=[f.rule for f in verdict.findings])
                result["message"] = blocked_message(message, guard.safe_reason(verdict))
            elif verdict.action is Action.REDACT:
                result["message"] = guard.redact(message, verdict)
            else:
                lines.append(line)
                continue
            lines.append(json.dumps(entry, ensure_ascii=False).encode())

        headers = client_headers(
            upstream_response, {RESPONSE_ACTION_HEADER: Action.strictest(actions).value}
        )
        return Response(b"\n".join(lines), headers=headers)

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def passthrough(path: str, request: Request) -> Response:
        metrics.counters["requests_total"] += 1
        endpoint = f"/v1/{path}"
        if settings.passthrough == "block" and not is_uninspected_endpoint(
            request.method, endpoint
        ):
            metrics.counters["passthrough_blocked_total"] += 1
            log.warning("passthrough_blocked", method=request.method, path=endpoint)
            return error_response(
                403,
                "permission_error",
                f"claude-guard does not forward {request.method} {endpoint}: the endpoint is not "
                "inspected (set GUARD_PASSTHROUGH=allow to forward it)",
            )
        try:
            upstream_response = await forward(request)
        except httpx.HTTPError as exc:
            return upstream_failure(exc)
        return passthrough_response(upstream_response, {})

    return app


def stream_error_event(message: str) -> bytes:
    return format_event(
        "error", {"type": "error", "error": {"type": "api_error", "message": message}}
    )
