"""Webhook alerts for strict verdicts (GUARD_ALERT_*).

Alerts are built from the audit record, which is already masked, so they never carry a secret.
Sending never blocks or fails an inspection:

- `notify` schedules the POST as a background task and returns at once (the proxy answers
  without waiting);
- `flush` waits for pending alerts, bounded by `alert_timeout`; short-lived processes (hooks)
  call it before exiting, the proxy at shutdown;
- errors are logged as `alert_failed` with the error type or status only (never the URL);
- at most `alert_max_per_minute` alerts are sent per process; the rest are counted and dropped.

Formats: `json` posts `{"source": "claude-guard", "hostname": ..., "record": <audit record>}`;
`slack` posts `{"text": ...}` for Slack (and compatible) incoming webhooks.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections import deque
from typing import Literal

import httpx
import structlog
from pydantic import JsonValue

from claude_guard.audit import AuditRecord
from claude_guard.config import Settings
from claude_guard.models import Action

log = structlog.get_logger(__name__)

SLACK_MAX_FINDINGS = 10
WINDOW_SECONDS = 60.0


class Alerter:
    """Posts alerts for verdicts at least as strict as `min_action`."""

    def __init__(
        self,
        url: str,
        *,
        fmt: Literal["json", "slack"] = "json",
        min_action: Action = Action.BLOCK,
        timeout: float = 5.0,
        max_per_minute: int = 30,
    ) -> None:
        self._url = url
        self._format = fmt
        self._min_action = min_action
        self._timeout = timeout
        self._max_per_minute = max_per_minute
        self._sent: deque[float] = deque()
        self._pending: set[asyncio.Task[None]] = set()
        self.dropped = 0

    @classmethod
    def from_settings(cls, settings: Settings) -> Alerter | None:
        if settings.alert_webhook_url is None:
            return None
        return cls(
            settings.alert_webhook_url.get_secret_value(),
            fmt=settings.alert_format,
            min_action=settings.alert_min_action,
            timeout=settings.alert_timeout,
            max_per_minute=settings.alert_max_per_minute,
        )

    def notify(self, record: AuditRecord) -> None:
        """Schedule an alert for `record` if it is strict enough and within the rate limit."""
        if record.action.rank < self._min_action.rank:
            return
        now = time.monotonic()
        while self._sent and now - self._sent[0] > WINDOW_SECONDS:
            self._sent.popleft()
        if len(self._sent) >= self._max_per_minute:
            self.dropped += 1
            log.warning("alert_rate_limited", dropped=self.dropped)
            return
        self._sent.append(now)
        task = asyncio.get_running_loop().create_task(self._send(record))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def flush(self) -> None:
        """Wait for pending alerts, at most `timeout` seconds."""
        if self._pending:
            await asyncio.wait(set(self._pending), timeout=self._timeout)

    def payload(self, record: AuditRecord) -> dict[str, JsonValue]:
        if self._format == "slack":
            return {"text": slack_text(record)}
        return {
            "source": "claude-guard",
            "hostname": socket.gethostname(),
            "record": record.model_dump(mode="json", exclude_none=True),
        }

    async def _send(self, record: AuditRecord) -> None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(self._url, json=self.payload(record))
        except httpx.HTTPError as exc:
            log.warning("alert_failed", error_type=type(exc).__name__)
            return
        if response.status_code >= 400:
            log.warning("alert_failed", status_code=response.status_code)


def slack_text(record: AuditRecord) -> str:
    where = ", ".join(part for part in (record.source, record.session_id) if part)
    lines = [
        f"*claude-guard {record.action.value.upper()}* {record.direction.value}"
        + (f" ({where})" if where else "")
    ]
    for finding in record.findings[:SLACK_MAX_FINDINGS]:
        location = f" at `{finding.location}`" if finding.location else ""
        lines.append(f"• [{finding.category.value}] {finding.message}{location}")
    if len(record.findings) > SLACK_MAX_FINDINGS:
        lines.append(f"… and {len(record.findings) - SLACK_MAX_FINDINGS} more")
    if record.error:
        lines.append(f"Error: {record.error}")
    return "\n".join(lines)
