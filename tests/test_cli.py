"""Tests for the CLI: help, scan and report."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from claude_guard.cli import app
from claude_guard.config import get_settings
from tests.fixtures import FIXTURES, PLACEHOLDERS

GITHUB_TOKEN = PLACEHOLDERS["{{GITHUB_TOKEN}}"]


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo_root: Path) -> Path:
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("GUARD_POLICY_PATH", str(repo_root / "policy.yaml"))
    monkeypatch.setenv("GUARD_AUDIT_PATH", str(audit))
    get_settings.cache_clear()
    return audit


def run(*args: str, stdin: str | None = None) -> tuple[int, str, str]:
    result = CliRunner().invoke(app, list(args), input=stdin)
    return result.exit_code, result.stdout, result.stderr


def test_help_lists_commands() -> None:
    code, out, _ = run("--help")
    assert code == 0
    for command in ("serve", "scan", "hook", "install-hooks", "report"):
        assert command in out


# --- scan -------------------------------------------------------------------------


def test_scan_table_output(env: Path) -> None:
    code, out, _ = run("scan", "--file", str(FIXTURES / "request_injection_tool_result.json"))
    assert code == 0
    assert "Verdict: BLOCK  (request, 2 finding(s))" in out
    assert "prompt_injection/ignore_instructions" in out
    assert "at messages[2].content[0].content[0].text" in out


def test_scan_autodetects_direction(env: Path) -> None:
    for name, direction in [
        ("response_rm_rf", "response"),
        ("tool_input_bash", "tool_input"),
        ("tool_output_injection", "tool_output"),
    ]:
        code, out, _ = run("scan", "-f", str(FIXTURES / f"{name}.json"), "--json")
        assert code == 0
        assert json.loads(out)["direction"] == direction


def test_scan_explicit_direction(env: Path) -> None:
    payload = json.dumps({"content": [{"type": "text", "text": "hi"}]})
    code, out, _ = run("scan", "-f", "-", "--direction", "response", "--json", stdin=payload)
    assert code == 0
    assert json.loads(out) == {
        "direction": "response",
        "action": "allow",
        "notes": [],
        "findings": [],
    }


def test_scan_json_masks_secrets_and_prints_redacted_payload(env: Path, tmp_path: Path) -> None:
    payload = {"messages": [{"role": "user", "content": f"token {GITHUB_TOKEN}"}]}
    path = tmp_path / "req.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    code, out, _ = run("scan", "-f", str(path), "--json", "--redacted")
    assert code == 0
    data = json.loads(out)
    assert data["action"] == "redact"
    assert data["redacted_payload"]["messages"][0]["content"] == "token [REDACTED:github_token]"
    assert GITHUB_TOKEN not in out


def test_scan_table_never_prints_raw_secret(env: Path, tmp_path: Path) -> None:
    path = tmp_path / "req.json"
    path.write_text(
        json.dumps({"messages": [{"role": "user", "content": f"key {GITHUB_TOKEN}"}]}),
        encoding="utf-8",
    )
    code, out, _ = run("scan", "-f", str(path))
    assert code == 0
    assert GITHUB_TOKEN not in out
    assert "secrets/github_token" in out


@pytest.mark.parametrize(
    ("fixture", "fail_on", "expected"),
    [
        ("response_rm_rf", "block", 1),
        ("request_clean", "warn", 0),
        ("request_image", "warn", 1),
        ("request_image", "redact", 0),
    ],
)
def test_scan_fail_on(env: Path, fixture: str, fail_on: str, expected: int) -> None:
    code, _, _ = run("scan", "-f", str(FIXTURES / f"{fixture}.json"), "--fail-on", fail_on)
    assert code == expected


def test_scan_writes_audit_record(env: Path) -> None:
    run("scan", "-f", str(FIXTURES / "request_clean.json"))
    record = json.loads(env.read_text(encoding="utf-8"))
    assert record["source"] == "cli:scan"


@pytest.mark.parametrize(
    ("stdin", "message"),
    [
        ("not json", "error:"),
        ("[1, 2]", "JSON object"),
        ('{"foo": 1}', "cannot detect the payload direction"),
    ],
)
def test_scan_input_errors(env: Path, stdin: str, message: str) -> None:
    code, _, err = run("scan", "-f", "-", stdin=stdin)
    assert code == 2
    assert message in err


def test_scan_missing_file(env: Path, tmp_path: Path) -> None:
    code, _, err = run("scan", "-f", str(tmp_path / "nope.json"))
    assert code == 2
    assert "error:" in err


def test_scan_missing_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARD_POLICY_PATH", str(tmp_path / "missing.yaml"))
    get_settings.cache_clear()
    code, _, err = run("scan", "-f", str(FIXTURES / "request_clean.json"))
    assert code == 2
    assert "policy file not found" in err


# --- report -----------------------------------------------------------------------


def test_report_after_scans(env: Path) -> None:
    for name in ("request_clean", "request_injection_tool_result", "response_rm_rf"):
        run("scan", "-f", str(FIXTURES / f"{name}.json"))
    code, out, _ = run("report", "--since", "1h")
    assert code == 0
    assert "Inspections: 3" in out
    assert "Verdicts by direction" in out
    assert "ignore_instructions" in out
    assert "cli:scan: 3" in out


def test_report_json(env: Path) -> None:
    run("scan", "-f", str(FIXTURES / "response_rm_rf.json"))
    code, out, _ = run("report", "--json")
    assert code == 0
    data = json.loads(out)
    assert data["total"] == 1
    assert data["by_action"]["block"] == 1
    assert data["top_rules"][0]["rule"] == "recursive_delete_critical"


def test_report_custom_file_and_empty_window(env: Path, tmp_path: Path) -> None:
    code, out, _ = run("report", "--file", str(tmp_path / "empty.jsonl"))
    assert code == 0
    assert "No inspections in this window." in out


def test_report_invalid_since(env: Path) -> None:
    code, _, err = run("report", "--since", "yesterday")
    assert code == 2
    assert "invalid --since" in err


# --- serve ------------------------------------------------------------------------


def test_serve_refuses_plain_http_on_non_loopback(env: Path) -> None:
    code, _, err = run("serve", "--host", "0.0.0.0")
    assert code == 2
    assert "refusing to serve plain HTTP" in err


def test_serve_rejects_half_tls_config(env: Path, tmp_path: Path) -> None:
    code, _, err = run("serve", "--tls-certfile", str(tmp_path / "cert.pem"))
    assert code == 2
    assert "both a certificate and a key" in err
