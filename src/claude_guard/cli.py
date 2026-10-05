"""Command-line interface: serve, scan, hook, install-hooks, report."""

import sys
from pathlib import Path
from typing import Annotated

import typer

from claude_guard.config import get_settings
from claude_guard.hooks.handlers import HookEvent
from claude_guard.log_config import configure_logging
from claude_guard.models import Action, Direction

app = typer.Typer(
    name="claude-guard",
    help="Security guard for Claude: API proxy and Claude Code hooks.",
    no_args_is_help=True,
)


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Listen address (default: GUARD_HOST).")] = None,
    port: Annotated[int | None, typer.Option(help="Listen port (default: GUARD_PORT).")] = None,
) -> None:
    """Run the guarding proxy (Anthropic Messages API compatible)."""
    import uvicorn

    from claude_guard.proxy.app import create_app

    settings = get_settings()
    configure_logging(settings.log_level)
    uvicorn.run(
        create_app(settings),
        host=host or settings.host,
        port=port or settings.port,
        log_level=settings.log_level.lower(),
    )


@app.command()
def scan(
    file: Annotated[
        str, typer.Option("--file", "-f", help="JSON payload to inspect; '-' reads stdin.")
    ],
    direction: Annotated[
        Direction | None,
        typer.Option(help="Payload direction (auto-detected when omitted)."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the verdict as JSON.")] = False,
    redacted: Annotated[
        bool, typer.Option("--redacted", help="Also print the payload with redactions applied.")
    ] = False,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Skip the LLM judge.")] = False,
    fail_on: Annotated[
        Action | None,
        typer.Option(help="Exit with code 1 when the verdict is at least this strict."),
    ] = None,
) -> None:
    """Inspect one request/response/tool payload and print the verdict."""
    import asyncio
    import json

    from claude_guard.audit import AuditLog
    from claude_guard.config import PolicyError
    from claude_guard.detectors.secrets import SecretScanner
    from claude_guard.engine import GuardEngine
    from claude_guard.payload import PayloadError, detect_direction

    settings = get_settings()
    configure_logging(settings.log_level)
    try:
        text = sys.stdin.read() if file == "-" else Path(file).read_text(encoding="utf-8")
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError("the payload must be a JSON object")
        resolved = direction or detect_direction(payload)
        engine = GuardEngine.from_settings(settings, use_llm_judge=not no_llm)
    except (OSError, ValueError, PayloadError, PolicyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    verdict = asyncio.run(engine.inspect(resolved, payload, source="cli:scan"))
    record = AuditLog(settings.audit_path, SecretScanner(engine.policy.secrets)).build_record(
        verdict
    )
    redacted_payload = engine.redact(payload, verdict) if redacted else None

    if as_json:
        output = record.model_dump(mode="json", exclude_none=True, exclude={"timestamp"})
        if redacted_payload is not None:
            output["redacted_payload"] = redacted_payload
        typer.echo(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        from claude_guard.render import print_verdict

        print_verdict(record, redacted_payload)

    if fail_on is not None and verdict.action.rank >= fail_on.rank:
        raise typer.Exit(1)


@app.command()
def hook(
    event: Annotated[HookEvent, typer.Argument(help="Claude Code hook event name.")],
) -> None:
    """Handle a Claude Code hook event: JSON on stdin, hook response on stdout."""
    from claude_guard.hooks.handlers import run_hook

    settings = get_settings()
    configure_logging(settings.log_level)
    stdout, code = run_hook(event, sys.stdin.read(), settings)
    if stdout:
        typer.echo(stdout)
    raise typer.Exit(code)


@app.command("install-hooks")
def install_hooks(
    user: Annotated[
        bool,
        typer.Option(
            "--user/--project",
            help="Write ~/.claude/settings.json (--user) or ./.claude/settings.json (--project).",
        ),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the merged settings without writing.")
    ] = False,
) -> None:
    """Register claude-guard hooks in a Claude Code settings.json (merging safely)."""
    import json

    from claude_guard.hooks.install import (
        InstallError,
        guard_root,
        install,
        merge_hooks,
        settings_file,
    )

    settings = get_settings()
    path = settings_file("user" if user else "project")
    try:
        if dry_run:
            existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            typer.echo(json.dumps(merge_hooks(existing, settings, guard_root()), indent=2))
            return
        backup = install(path, settings)
    except (InstallError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Installed claude-guard hooks in {path}")
    if backup:
        typer.echo(f"Backup of the previous file: {backup}")
    typer.echo("Events: " + ", ".join(e.value for e in HookEvent))


@app.command()
def report(
    since: Annotated[
        str, typer.Option(help="Time window: 30m, 24h, 7d, 2w or an ISO timestamp.")
    ] = "24h",
    file: Annotated[
        Path | None, typer.Option("--file", "-f", help="Audit log (default: GUARD_AUDIT_PATH).")
    ] = None,
    top: Annotated[int, typer.Option(min=1, help="Number of top rules and sessions.")] = 10,
    as_json: Annotated[bool, typer.Option("--json", help="Print the summary as JSON.")] = False,
) -> None:
    """Summarize the audit log."""
    from claude_guard.report import load_records, parse_since, summarize

    settings = get_settings()
    path = file or settings.audit_path
    try:
        start = parse_since(since)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    records, skipped = load_records(path, start)
    summary = summarize(records, start, skipped=skipped, top=top)
    if as_json:
        typer.echo(summary.model_dump_json(indent=2))
    else:
        from claude_guard.render import print_report

        print_report(summary, path)
