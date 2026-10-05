"""Terminal rendering (rich) for `scan` and `report`.

Values come from audit records, so excerpts and messages are already secret-masked.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from claude_guard.audit import AuditRecord
from claude_guard.models import Action
from claude_guard.payload import JsonObject
from claude_guard.report import Report

ACTION_STYLES = {
    Action.ALLOW.value: "green",
    Action.WARN.value: "yellow",
    Action.REDACT.value: "magenta",
    Action.BLOCK.value: "bold red",
}


def _console() -> Console:
    return Console(soft_wrap=True)


def _action(value: str) -> Text:
    return Text(value.upper(), style=ACTION_STYLES.get(value, ""))


def print_verdict(record: AuditRecord, redacted_payload: JsonObject | None = None) -> None:
    console = _console()
    header = Text("Verdict: ")
    header.append_text(_action(record.action.value))
    header.append(f"  ({record.direction.value}, {len(record.findings)} finding(s))")
    console.print(header)
    if record.error:
        console.print(Text("Error: ", style="red") + Text(record.error))

    for finding in record.findings:
        line = Text("  ")
        line.append_text(_action(finding.action.value))
        line.append(f"  {finding.category.value}/{finding.rule}", style="bold")
        line.append(f"  {finding.severity.value}, confidence {finding.confidence:.2f}")
        console.print(line)
        console.print(f"    {finding.message}", highlight=False, markup=False)
        if finding.location:
            console.print(f"    at {finding.location}", highlight=False, markup=False)
        if finding.excerpt:
            console.print(f"    > {finding.excerpt}", highlight=False, markup=False)

    for note in record.notes:
        console.print(f"note: {note}", highlight=False, markup=False)

    if redacted_payload is not None:
        console.print("Redacted payload:")
        console.print(json.dumps(redacted_payload, indent=2, ensure_ascii=False), markup=False)


def print_report(report: Report, path: Path) -> None:
    console = _console()
    console.print(
        f"Audit log: {path}\n"
        f"Window: {report.since:%Y-%m-%d %H:%M} to {report.until:%Y-%m-%d %H:%M} UTC\n"
        f"Inspections: {report.total}   errors: {report.errors}"
        + (f"   unreadable lines: {report.skipped_lines}" if report.skipped_lines else ""),
        highlight=False,
        markup=False,
    )
    if report.total == 0:
        console.print("No inspections in this window.")
        return

    actions = Table(title="Verdicts by direction")
    actions.add_column("Direction")
    for action in Action:
        actions.add_column(action.value.upper(), justify="right")
    for direction, counts in report.by_direction.items():
        actions.add_row(direction, *(str(counts.get(a.value, 0)) for a in Action))
    actions.add_row(
        Text("total", style="bold"), *(str(report.by_action.get(a.value, 0)) for a in Action)
    )
    console.print(actions)

    if report.top_rules:
        rules = Table(title="Top rules")
        rules.add_column("Category")
        rules.add_column("Rule")
        rules.add_column("Count", justify="right")
        for item in report.top_rules:
            rules.add_row(item.category, item.rule, str(item.count))
        console.print(rules)

    sources = ", ".join(f"{name}: {count}" for name, count in report.by_source.items())
    console.print(f"Sources: {sources}", highlight=False, markup=False)
    if report.top_blocked_sessions:
        sessions = ", ".join(f"{sid} ({n})" for sid, n in report.top_blocked_sessions.items())
        console.print(f"Sessions with blocks: {sessions}", highlight=False, markup=False)
    if report.duration_ms_avg is not None:
        console.print(
            f"Inspection time: avg {report.duration_ms_avg} ms, p95 {report.duration_ms_p95} ms",
            highlight=False,
        )
