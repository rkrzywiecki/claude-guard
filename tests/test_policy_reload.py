"""Tests for policy hot reload (proxy)."""

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx

from claude_guard.config import Settings, load_policy
from claude_guard.engine import GuardEngine
from claude_guard.models import Action, Direction
from claude_guard.policy_reload import PolicyReloader
from claude_guard.proxy.app import create_app
from tests.fixtures import load

UPSTREAM = "https://api.anthropic.test"
STRICT = "prompt_injection:\n  enabled: true\n"
LENIENT = "prompt_injection:\n  enabled: false\n"
INJECTION = "request_injection_tool_result"


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def write(path: Path, text: str) -> None:
    """Write and move the mtime forward, so the change is seen even within one clock tick."""
    previous = path.stat().st_mtime_ns if path.exists() else 0
    path.write_bytes(text.encode("utf-8", "surrogateescape"))
    stamp = max(path.stat().st_mtime_ns, previous + 1_000_000)
    os.utime(path, ns=(stamp, stamp))


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    write(path, STRICT)
    return path


@pytest.fixture
def settings(tmp_path: Path, policy_path: Path) -> Settings:
    return Settings(
        policy_path=policy_path, audit_path=tmp_path / "audit.jsonl", upstream_url=UPSTREAM
    )


@pytest.fixture
def engine(settings: Settings) -> GuardEngine:
    return GuardEngine(load_policy(settings.policy_path), settings, use_llm_judge=False)


@pytest.fixture
def clock() -> Clock:
    return Clock()


def reloader(
    engine: GuardEngine, path: Path, clock: Clock, interval: float = 2.0
) -> PolicyReloader:
    return PolicyReloader(engine, path, interval=interval, clock=clock)


async def injection_action(engine: GuardEngine) -> Action:
    return (await engine.inspect(Direction.REQUEST, load(INJECTION))).action


# --- reloader -----------------------------------------------------------------------


async def test_changed_file_is_reloaded(
    engine: GuardEngine, policy_path: Path, clock: Clock
) -> None:
    watcher = reloader(engine, policy_path, clock)
    first = watcher.version
    assert await injection_action(engine) is Action.BLOCK

    write(policy_path, LENIENT)
    clock.now += 2
    assert watcher.check() is True
    assert await injection_action(engine) is Action.ALLOW
    assert watcher.version != first
    assert (watcher.reloads, watcher.errors) == (1, 0)


def test_checks_are_throttled(engine: GuardEngine, policy_path: Path, clock: Clock) -> None:
    watcher = reloader(engine, policy_path, clock)
    write(policy_path, LENIENT)
    clock.now += 1
    assert watcher.check() is False  # interval not over yet
    clock.now += 1
    assert watcher.check() is True
    clock.now += 2
    assert watcher.check() is False  # nothing changed since


def test_unchanged_content_is_not_reloaded(
    engine: GuardEngine, policy_path: Path, clock: Clock
) -> None:
    watcher = reloader(engine, policy_path, clock)
    state = engine.policy
    write(policy_path, STRICT)  # new mtime, same bytes
    clock.now += 2
    assert watcher.check() is False
    assert engine.policy is state
    assert watcher.reloads == 0


@pytest.mark.parametrize(
    "broken",
    [
        "prompt_injection: [unclosed\n",  # YAML error
        "prompt_injection:\n  action: explode\n",  # validation error
        "- a list\n",  # wrong top level
        "\udcff",  # not UTF-8 once written with surrogateescape
    ],
)
async def test_invalid_policy_keeps_the_running_one(
    engine: GuardEngine,
    policy_path: Path,
    clock: Clock,
    broken: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    watcher = reloader(engine, policy_path, clock)
    version = watcher.version
    write(policy_path, broken)
    for _ in range(3):
        clock.now += 2
        assert watcher.check() is False
    assert await injection_action(engine) is Action.BLOCK
    assert watcher.version == version
    assert watcher.errors == 1  # logged once per file version, not on every check

    write(policy_path, LENIENT)
    clock.now += 2
    assert watcher.check() is True
    assert await injection_action(engine) is Action.ALLOW


def test_missing_file_is_ignored_until_it_returns(
    engine: GuardEngine, policy_path: Path, clock: Clock
) -> None:
    watcher = reloader(engine, policy_path, clock)
    policy_path.unlink()
    clock.now += 2
    assert watcher.check() is False
    assert watcher.errors == 0  # e.g. an editor replacing the file
    write(policy_path, LENIENT)
    clock.now += 2
    assert watcher.check() is True


def test_forced_reload_works_without_polling(
    engine: GuardEngine, policy_path: Path, clock: Clock
) -> None:
    watcher = reloader(engine, policy_path, clock, interval=0)
    write(policy_path, LENIENT)
    clock.now += 100
    assert watcher.check() is False
    assert watcher.reload() is True  # SIGHUP
    assert not engine.policy.prompt_injection.enabled


def test_forced_reload_of_missing_file_is_an_error(
    engine: GuardEngine, policy_path: Path, clock: Clock
) -> None:
    watcher = reloader(engine, policy_path, clock)
    policy_path.unlink()
    assert watcher.reload() is False
    assert watcher.errors == 1
    assert engine.policy.prompt_injection.enabled


# --- engine -------------------------------------------------------------------------


async def test_reload_starts_a_new_inspection_cache(
    engine: GuardEngine, settings: Settings
) -> None:
    await engine.inspect(Direction.REQUEST, load(INJECTION))
    assert engine.cache is not None and len(engine.cache) > 0
    engine.reload_policy(load_policy(settings.policy_path))
    assert engine.cache is not None and len(engine.cache) == 0


async def test_reload_switches_masking_rules(engine: GuardEngine, tmp_path: Path) -> None:
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        "custom_rules:\n"
        "  - name: ticket_secret\n"
        "    description: Internal ticket secret\n"
        "    pattern: 'TKT-[0-9]{6}'\n"
        "    category: secrets\n",
        encoding="utf-8",
    )
    assert engine.mask("ref TKT-123456") == "ref TKT-123456"
    engine.reload_policy(load_policy(custom))
    assert "TKT-123456" not in engine.mask("ref TKT-123456")
    verdict = await engine.inspect(
        Direction.REQUEST, {"messages": [{"role": "user", "content": "ref TKT-123456"}]}
    )
    assert verdict.action is Action.REDACT


# --- proxy --------------------------------------------------------------------------


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(
        settings.model_copy(update={"policy_reload_interval": 0.001}),
        engine=GuardEngine(load_policy(settings.policy_path), settings, use_llm_judge=False),
        upstream=httpx.AsyncClient(base_url=UPSTREAM),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://guard"
    ) as http:
        yield http


async def test_proxy_picks_up_a_changed_policy(
    client: httpx.AsyncClient, policy_path: Path
) -> None:
    reply = {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    with respx.mock(base_url=UPSTREAM) as router:
        router.post("/v1/messages").mock(return_value=httpx.Response(200, json=reply))
        version = (await client.get("/healthz")).json()["policy_version"]
        assert version
        assert (await client.post("/v1/messages", json=load(INJECTION))).status_code == 400

        write(policy_path, LENIENT)
        await asyncio.sleep(0.01)  # past GUARD_POLICY_RELOAD_INTERVAL
        assert (await client.post("/v1/messages", json=load(INJECTION))).status_code == 200
        assert (await client.get("/healthz")).json()["policy_version"] != version

        write(policy_path, "prompt_injection: [broken\n")
        await asyncio.sleep(0.01)
        assert (await client.post("/v1/messages", json=load(INJECTION))).status_code == 200
        metrics = (await client.get("/metrics")).text
    assert "claude_guard_policy_reloads_total 1" in metrics
    assert "claude_guard_policy_reload_errors_total 1" in metrics
