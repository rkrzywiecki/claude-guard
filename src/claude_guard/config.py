"""Settings (env: GUARD_*) and policy.yaml loading."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from claude_guard.models import Action, Category, Direction, Severity

# Single source of the default judge model; override with GUARD_JUDGE_MODEL.
DEFAULT_JUDGE_MODEL = "claude-haiku-4-5"

# Example credentials published in vendor documentation; never real secrets.
DEFAULT_SECRET_ALLOWLIST = (
    r"AKIAIOSFODNN7EXAMPLE",
    r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)


def is_loopback(host: str) -> bool:
    """True for addresses reachable only from this machine (localhost, 127.0.0.0/8, ::1)."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    """Runtime settings read from the environment (prefix GUARD_) and an optional .env file."""

    # Empty values (`GUARD_TLS_CERTFILE=` as in .env.example) mean "not set", not "".
    # Validation errors never echo values: some settings hold secrets (API key, proxy token,
    # webhook URL).
    model_config = SettingsConfigDict(
        env_prefix="GUARD_",
        env_file=".env",
        extra="ignore",
        env_ignore_empty=True,
        hide_input_in_errors=True,
    )

    policy_path: Path = Path("policy.yaml")
    fail_mode: Literal["closed", "open"] = "closed"
    judge_model: str = DEFAULT_JUDGE_MODEL
    host: str = "127.0.0.1"
    port: int = Field(default=8787, ge=1, le=65535)
    # TLS for the client -> proxy leg; both files or neither. Required on non-loopback binds
    # unless allow_insecure_bind is set (TLS terminated by a reverse proxy in front).
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    allow_insecure_bind: bool = False
    upstream_url: str = "https://api.anthropic.com"
    upstream_timeout: float = Field(default=600.0, gt=0)
    stream_mode: Literal["buffer", "audit"] = "buffer"
    # Endpoints the proxy cannot inspect (e.g. Files API uploads): refuse or forward them.
    passthrough: Literal["block", "allow"] = "block"
    # Proxy limits: larger request bodies get HTTP 413; a buffered stream above the limit is not
    # inspected (fail mode applies).
    max_body_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)
    max_stream_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)
    # Shared secret clients send in the x-claude-guard-token header; required when set.
    proxy_token: SecretStr | None = None
    hook_llm: bool = False
    audit_path: Path = Path("logs/audit.jsonl")
    # Rotate the audit log at this size (0 disables rotation), keeping this many old files.
    audit_max_bytes: int = Field(default=10 * 1024 * 1024, ge=0)
    audit_backups: int = Field(default=5, ge=1, le=100)
    # Alerts: POST to a webhook for verdicts at least as strict as alert_min_action. The URL can
    # embed a token (Slack), so it is a secret and never logged.
    alert_webhook_url: SecretStr | None = None
    alert_format: Literal["json", "slack"] = "json"
    alert_min_action: Action = Action.BLOCK
    alert_timeout: float = Field(default=5.0, gt=0, le=60)
    alert_max_per_minute: int = Field(default=30, ge=1)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # Read without the prefix so .env can hold it; when unset the Anthropic SDK falls back to
    # its own credential resolution (environment, `ant auth login` profile).
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")

    @field_validator("alert_webhook_url")
    @classmethod
    def _check_webhook_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        # Messages never echo the URL: it may carry a token.
        try:
            parts = urlsplit(value.get_secret_value())
        except ValueError:
            raise ValueError("alert_webhook_url is not a valid URL") from None
        host = parts.hostname or ""
        if parts.scheme == "https" and host:
            return value
        if parts.scheme == "http" and host and is_loopback(host):
            return value
        raise ValueError("alert_webhook_url must use https (http only for loopback hosts)")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def protected_paths(settings: Settings) -> tuple[Path, ...]:
    """Guard files an agent must not modify: the policy, the audit log (with rotated copies) and
    Stop offsets."""
    audit = settings.audit_path.expanduser()
    rotated = (audit.with_name(f"{audit.name}.{n}") for n in range(1, settings.audit_backups + 1))
    return (settings.policy_path.expanduser(), audit, *rotated, audit.parent / "sessions")


class PolicyError(Exception):
    """Raised when policy.yaml is missing, unparsable or invalid."""


class CategoryPolicy(BaseModel):
    """Action and threshold for one category.

    A finding whose confidence reaches `threshold` gets the category `action`; below it the
    finding is downgraded to `warn`. Findings below `min_severity` are dropped.
    `direction_actions` overrides `action` for specific directions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    action: Action
    threshold: float = Field(ge=0.0, le=1.0)
    min_severity: Severity = Severity.LOW
    direction_actions: dict[Direction, Action] = Field(default_factory=dict)

    def resolve_action(self, direction: Direction, confidence: float, severity: Severity) -> Action:
        """Map a detector finding to the action this policy prescribes."""
        if not self.enabled or severity.rank < self.min_severity.rank:
            return Action.ALLOW
        if confidence < self.threshold:
            return Action.WARN
        return self.direction_actions.get(direction, self.action)


def _compile_patterns(patterns: list[str]) -> list[str]:
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
    return patterns


class SecretsPolicy(CategoryPolicy):
    action: Action = Action.REDACT
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    entropy_min_length: int = Field(default=24, ge=8)
    entropy_threshold: float = Field(default=4.0, gt=0.0)
    allowlist: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SECRET_ALLOWLIST),
        description="Regexes for known-safe values (e.g. example keys from vendor docs).",
    )

    _check_allowlist = field_validator("allowlist")(_compile_patterns)


class PromptInjectionPolicy(CategoryPolicy):
    action: Action = Action.BLOCK
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class DangerousCommandsPolicy(CategoryPolicy):
    action: Action = Action.BLOCK
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    allowlist: list[str] = Field(
        default_factory=list, description="Regexes for commands that are always allowed."
    )

    _check_allowlist = field_validator("allowlist")(_compile_patterns)


class DataExfiltrationPolicy(CategoryPolicy):
    action: Action = Action.BLOCK
    threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    # Hosts that may receive data from tools. Empty by default: well-known services are
    # exfiltration channels too (Files API with another account's key, gists).
    allowed_hosts: list[str] = Field(default_factory=list)


class ToolsPolicy(CategoryPolicy):
    """Which tools may be called, by name glob (`Bash`, `mcp__github__*`).

    `deny` is checked first, then `allow` (when non-empty, every other tool is denied), then
    `warn`. Applies to tool calls about to run (hooks) and to tool_use blocks in responses.
    """

    action: Action = Action.BLOCK
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    deny: list[str] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)
    warn: list[str] = Field(default_factory=list)

    @field_validator("deny", "allow", "warn")
    @classmethod
    def _check_globs(cls, value: list[str]) -> list[str]:
        if any(not glob.strip() for glob in value):
            raise ValueError("tool name globs must not be empty")
        return value


class LlmJudgePolicy(CategoryPolicy):
    """LLM judge settings. The model itself comes from GUARD_JUDGE_MODEL."""

    enabled: bool = False
    action: Action = Action.BLOCK
    threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    mode: Literal["always", "untrusted", "uncertain"] = "untrusted"
    uncertain_range: tuple[float, float] = (0.3, 0.7)
    timeout_seconds: float = Field(default=10.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=10)
    max_input_chars: int = Field(default=50_000, ge=1_000)

    @field_validator("uncertain_range")
    @classmethod
    def _check_range(cls, value: tuple[float, float]) -> tuple[float, float]:
        low, high = value
        if not 0.0 <= low < high <= 1.0:
            raise ValueError("uncertain_range must satisfy 0 <= low < high <= 1")
        return value


_RULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
CUSTOM_RULE_CATEGORIES = (
    Category.SECRETS,
    Category.PROMPT_INJECTION,
    Category.DANGEROUS_COMMANDS,
    Category.DATA_EXFILTRATION,
)


class CustomRule(BaseModel):
    """A user-defined regex rule. Its action and threshold come from its category's policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    description: str
    category: Category
    pattern: str
    severity: Severity = Severity.HIGH
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    ignore_case: bool = False
    directions: list[Direction] = Field(
        default_factory=list, description="Directions to inspect; empty means all."
    )
    tools: list[str] = Field(
        default_factory=list,
        description="Tool name globs (e.g. Bash, mcp__*); only those tool call inputs are matched.",
    )
    fields: list[str] = Field(
        default_factory=list,
        description="Tool input fields (e.g. command, url); only those are matched.",
    )
    untrusted_only: bool = Field(
        default=False, description="Only match untrusted content (tool results, fetched data)."
    )

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if not _RULE_NAME.fullmatch(value):
            raise ValueError("name must be lowercase letters, digits and _ (start with a letter)")
        return value

    @field_validator("category")
    @classmethod
    def _check_category(cls, value: Category) -> Category:
        if value not in CUSTOM_RULE_CATEGORIES:
            allowed = ", ".join(c.value for c in CUSTOM_RULE_CATEGORIES)
            raise ValueError(f"category must be one of: {allowed}")
        return value

    @model_validator(mode="after")
    def _check_pattern(self) -> CustomRule:
        try:
            compiled = re.compile(self.pattern, re.IGNORECASE if self.ignore_case else 0)
        except re.error as exc:
            raise ValueError(f"invalid regex {self.pattern!r}: {exc}") from exc
        if compiled.fullmatch(""):
            raise ValueError(f"pattern {self.pattern!r} matches the empty string")
        return self

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE if self.ignore_case else 0)


class Policy(BaseModel):
    """Root of policy.yaml. Defaults mirror the shipped policy.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    secrets: SecretsPolicy = Field(default_factory=SecretsPolicy)
    prompt_injection: PromptInjectionPolicy = Field(default_factory=PromptInjectionPolicy)
    dangerous_commands: DangerousCommandsPolicy = Field(default_factory=DangerousCommandsPolicy)
    data_exfiltration: DataExfiltrationPolicy = Field(default_factory=DataExfiltrationPolicy)
    tools: ToolsPolicy = Field(default_factory=ToolsPolicy)
    llm_judge: LlmJudgePolicy = Field(default_factory=LlmJudgePolicy)
    custom_rules: list[CustomRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_custom_rule_names(self) -> Policy:
        names = [rule.name for rule in self.custom_rules]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate custom rule names: {', '.join(duplicates)}")
        return self

    @model_validator(mode="after")
    def _check_redact_usage(self) -> Policy:
        # Redaction rewrites matched spans; only secrets detection yields spans worth replacing.
        for category in Category:
            if category is Category.SECRETS:
                continue
            policy = self.for_category(category)
            actions = [policy.action, *policy.direction_actions.values()]
            if Action.REDACT in actions:
                raise ValueError(f"{category}: 'redact' is not supported, use 'warn' or 'block'")
        return self

    def for_category(self, category: Category) -> CategoryPolicy:
        policy: CategoryPolicy = getattr(self, category.value)
        return policy


def load_policy(path: Path) -> Policy:
    """Read and validate a policy file, raising PolicyError with a readable message."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"cannot parse {path}: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: top level must be a mapping")

    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(f"invalid policy {path}:\n{exc}") from exc
