"""Dangerous command detector for tool_use inputs (Bash, Write, Edit).

Only segments that come from a tool call input (`tool_name` set) are inspected:
- `command` fields are shell commands and get the full rule set,
- path fields (`file_path`, `path`, `notebook_path`) are checked for sensitive files,
- content fields (`content`, `new_string`) are checked for dangerous commands written into
  scripts, with reduced confidence since writing is not executing.

Files modified by a tool call (Write/Edit paths, and shell write targets such as `>`, `tee`,
`cp`, `mv`, `rm`, `sed -i`) are checked for persistence locations and for guard tampering: the
policy, the audit log and Claude Code settings (which hold the hooks). Relative paths are
resolved against the tool call's `cwd` (known in hooks), following `cd` within the command.
"""

from __future__ import annotations

import codecs
import os
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, replace
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from claude_guard.config import Policy
from claude_guard.detectors.base import build_finding, snippet
from claude_guard.detectors.obfuscation import decoded_candidates
from claude_guard.models import Category, Finding, InspectionContext, Severity, TextSegment

COMMAND_FIELDS = frozenset({"command", "cmd", "script"})
PATH_FIELDS = frozenset({"file_path", "path", "notebook_path"})
CONTENT_FIELDS = frozenset({"content", "new_string", "new_source"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
CONTENT_CONFIDENCE_FACTOR = 0.7


@dataclass(frozen=True)
class CommandRule:
    name: str
    description: str
    pattern: re.Pattern[str]
    category: Category
    severity: Severity
    confidence: float


@dataclass(frozen=True)
class Hit:
    rule: str
    description: str
    category: Category
    severity: Severity
    confidence: float
    start: int
    end: int


_SENSITIVE_PATH = (
    r"(?:~|\$HOME|\$\{HOME\}|/(?:Users|home)/[^/\s]+|/root)/\.ssh\b"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.aws/credentials\b|\.kube/config\b|\.docker/config\.json\b|\.gnupg\b"
    r"|\.netrc\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b"
    r"|/etc/(?:shadow|sudoers|gshadow)\b"
    r"|(?<![\w.-])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?(?![\w.-])"
)
SENSITIVE_PATH = re.compile(_SENSITIVE_PATH)

# Files whose modification gives persistence or privilege.
PERSISTENCE_PATH = re.compile(
    r"\.ssh/authorized_keys\b"
    r"|(?:^|/)\.(?:bashrc|bash_profile|bash_login|zshrc|zshenv|zprofile|zlogin|profile)$"
    r"|^/etc/|\.git/hooks/|/LaunchAgents/|/LaunchDaemons/|crontab|/etc/cron"
)

# Claude Code settings hold the hooks, so changing them can switch the guard off.
CLAUDE_SETTINGS_PATH = re.compile(
    r"(?:^|/)\.claude/settings(?:\.local)?\.json$|(?:^|/)managed-settings\.json$"
)
CLAUDE_DIR = re.compile(r"(?:^|/)\.claude/?$")
GUARD_TAMPER_DESCRIPTION = "Modification of claude-guard files or Claude Code settings"
PERSISTENCE_DESCRIPTION = "Write to a startup, cron, hook or authorized_keys file"

_DOWNLOADER = r"\b(?:curl|wget|fetch)\b"
_INTERPRETER = r"(?:sudo\s+)?(?:ba|z|k|da|fi)?sh\b|(?:sudo\s+)?(?:python[0-9.]*|perl|ruby|node)\b"

RULES: tuple[CommandRule, ...] = (
    CommandRule(
        "pipe_to_shell",
        "Downloaded content piped into a shell or interpreter",
        re.compile(rf"{_DOWNLOADER}[^|;&\n]{{0,500}}\|\s*(?:{_INTERPRETER})"),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.95,
    ),
    CommandRule(
        "shell_from_download",
        "Shell executing downloaded content",
        re.compile(
            rf"\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:\$\(|`|<\()\s*{_DOWNLOADER}"
            rf"|\b(?:eval|source|\.)\s+[\"']?(?:\$\(|`|<\()\s*{_DOWNLOADER}"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.95,
    ),
    CommandRule(
        "world_writable",
        "World-writable or overly permissive permissions",
        re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*(?:0?777|0?666|a\+rwx|ugo\+rwx|o\+w|a\+w)\b"),
        Category.DANGEROUS_COMMANDS,
        Severity.HIGH,
        0.85,
    ),
    CommandRule(
        "setuid",
        "Setting setuid/setgid bit",
        re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*(?:[ug]\+s|[2467][0-7]{3})\b"),
        Category.DANGEROUS_COMMANDS,
        Severity.HIGH,
        0.8,
    ),
    CommandRule(
        "force_push_protected",
        "Force push to a protected branch",
        re.compile(
            r"\bgit\s+push\b(?=[^\n;&|]{0,500}(?:\s--force(?!-with-lease)\b|\s-f\b|\s\+))"
            r"(?=[^\n;&|]{0,500}\b(?:main|master|prod|production|release)\b)[^\n;&|]{0,500}"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.95,
    ),
    CommandRule(
        "force_push",
        "Force push rewrites remote history",
        re.compile(r"\bgit\s+push\b[^\n;&|]{0,500}(?:\s--force(?!-with-lease)\b|\s-f\b|\s\+\S)"),
        Category.DANGEROUS_COMMANDS,
        Severity.HIGH,
        0.8,
    ),
    CommandRule(
        "force_push_with_lease",
        "Force push with lease",
        re.compile(r"\bgit\s+push\b[^\n;&|]{0,500}\s--force-with-lease\b"),
        Category.DANGEROUS_COMMANDS,
        Severity.MEDIUM,
        0.5,
    ),
    CommandRule(
        "push_to_production",
        "Push to a production branch",
        re.compile(r"\bgit\s+push\s+(?:-\S+\s+)*\S+\s+(?:\S+:)?(?:prod|production|release)\b"),
        Category.DANGEROUS_COMMANDS,
        Severity.MEDIUM,
        0.6,
    ),
    CommandRule(
        "disk_destruction",
        "Command that destroys disks or filesystems",
        re.compile(
            r"\bdd\b[^\n;&|]{0,500}\bof=/dev/(?!null\b|zero\b|stdout\b|stderr\b)\w+"
            r"|\bmkfs(?:\.\w+)?\s+/dev/|>\s*/dev/(?:sd[a-z]|nvme\d|disk\d|hd[a-z])\b"
            r"|\bshred\b[^\n;&|]{0,500}\s/dev/|\bdiskutil\s+(?:erase\w*|zeroDisk|secureErase)\b"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.95,
    ),
    CommandRule(
        "fork_bomb",
        "Fork bomb",
        re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.99,
    ),
    CommandRule(
        "decoded_to_shell",
        "Decoded base64 piped into a shell or interpreter",
        re.compile(
            r"\bbase64\s+(?:-d|--decode|-D)\b[^\n;&]{0,500}?\|\s*(?:sudo\s+)?"
            r"(?:(?:ba|z|k|da)?sh|python[0-9.]*|perl|ruby|node)\b"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.9,
    ),
    CommandRule(
        "download_then_execute",
        "Downloaded file executed",
        re.compile(
            r"\b(?:curl|wget)\b[^\n;&|]{0,500}?(?:\s-o|\s-O|--output|>)\s*(?P<file>[^\s;&|]+)"
            r"[^\n]{0,500}?(?:&&|;|\n)\s*(?:sudo\s+)?"
            r"(?:(?:ba|z|k|da)?sh|source|\.|chmod\s+\+x|python[0-9.]*)\s+(?P=file)"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.9,
    ),
    CommandRule(
        "rmtree_critical",
        "Recursive delete of a root or home directory from a script",
        re.compile(
            r"\bshutil\.rmtree\(\s*(?:r?[\"'](?:/|~|/home|/Users)/?[\"']|os\.path\.expanduser)"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.9,
    ),
    CommandRule(
        "find_delete_critical",
        "find deleting from a root or home directory",
        re.compile(
            r"\bfind\s+(?:/|/\*|~/?|\$HOME/?|\$\{HOME\}/?)(?=\s)[^\n;&|]{0,500}?"
            r"(?:\s-delete\b|\s-exec(?:dir)?\s+(?:sudo\s+)?(?:/bin/)?rm\b)"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.9,
    ),
    CommandRule(
        "sensitive_file_access",
        "Access to credentials or secret files",
        SENSITIVE_PATH,
        Category.DANGEROUS_COMMANDS,
        Severity.HIGH,
        0.75,
    ),
    CommandRule(
        "persistence_command",
        "Scheduled task or service installed (persistence)",
        re.compile(
            r"\bcrontab\s+(?!-l\b)\S|\blaunchctl\s+(?:load|bootstrap|enable|submit)\b"
            r"|\bsystemctl\s+(?:--user\s+)?(?:enable|link)\b"
        ),
        Category.DANGEROUS_COMMANDS,
        Severity.HIGH,
        0.85,
    ),
    CommandRule(
        "dns_exfiltration",
        "Command substitution inside a DNS lookup",
        re.compile(r"\b(?:dig|nslookup|host)\b[^\n;&|]{0,500}(?:\$\(|`)"),
        Category.DATA_EXFILTRATION,
        Severity.HIGH,
        0.7,
    ),
)

# Data-sending commands. Matches are dropped when every URL/host in the command is allowed.
EXFIL_RULES: tuple[CommandRule, ...] = (
    CommandRule(
        "upload_file",
        "File uploaded to an external host",
        re.compile(
            r"\bcurl\b[^\n;&|]{0,500}(?:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)[\s=]*"
            r"[\"']?[\w-]*=?(?:@|\$\(|`)|\s(?:-T|--upload-file)\s)"
            r"|\bwget\b[^\n;&|]{0,500}(?:--post-file|--post-data[\s=]*[\"']?[^\s\"']*(?:\$\(|`))"
        ),
        Category.DATA_EXFILTRATION,
        Severity.HIGH,
        0.85,
    ),
    CommandRule(
        "pipe_to_network",
        "Local data piped to a network client",
        re.compile(
            r"\b(?:cat|tar|zip|base64|env|printenv|gzip|find)\b[^\n;&|]{0,500}\|[^\n;&]{0,500}?"
            r"\b(?:curl|wget|nc|ncat|netcat|socat)\b"
        ),
        Category.DATA_EXFILTRATION,
        Severity.HIGH,
        0.85,
    ),
    CommandRule(
        "netcat_send",
        "File sent with netcat",
        re.compile(r"\b(?:nc|ncat|netcat)\b[^\n;&|]{0,500}<\s*\S+"),
        Category.DATA_EXFILTRATION,
        Severity.HIGH,
        0.85,
    ),
    CommandRule(
        "remote_copy",
        "Files copied to a remote host",
        re.compile(
            r"\b(?:scp|rsync)\b[^\n;&|]{0,500}\s(?:[\w.-]+@)?(?P<host>[\w-]+(?:\.[\w-]+)+):"
        ),
        Category.DATA_EXFILTRATION,
        Severity.MEDIUM,
        0.7,
    ),
)

_URL = re.compile(r"https?://[^\s\"'`|;&)]+")
ANTHROPIC_API_HOST = "anthropic.com"
# Environment variables that hold the user's own Anthropic credentials.
OWN_ANTHROPIC_CREDENTIALS = re.compile(
    r"^(?:Bearer\s+)?\$(?:\{)?(?:ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN)\b(?:\})?$",
    re.IGNORECASE,
)
_CREDENTIAL_HEADER = re.compile(r"^\s*(x-api-key|authorization)\s*:\s*(.*?)\s*$", re.IGNORECASE)
_HTTP_CLIENTS = frozenset({"curl", "wget"})
_REMOTE_HOST = re.compile(r"(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+):")  # matched per word
_WRAPPERS = frozenset({"sudo", "doas", "command", "exec", "nohup", "env", "time", "xargs", "nice"})
# Wrapper options that take a value, e.g. `sudo -u root`, `nice -n 10`.
_OPTIONS_WITH_VALUE = frozenset({"-u", "-g", "-C", "-h", "-p", "-U", "-n", "-D"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_COMMAND_BREAKS = frozenset({";", "&", "|", "&&", "||", "|&", ";;", "(", ")"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_COMMAND_FLAG = re.compile(r"-[a-zA-Z]*c[a-zA-Z]*")
MAX_NESTING = 2
_CRITICAL_RM_TARGETS = re.compile(
    r"^(?:/|/\*|~|~/|~/\*|\$HOME/?|\$\{HOME\}/?|\.|\./|\.\.|\*|/(?:bin|boot|dev|etc|home|lib|opt"
    r"|private|root|sbin|System|usr|Users|var|Library|Applications)/?\*?)$"
)


class CommandsDetector:
    """Flags destructive commands, sensitive file access and data exfiltration in tool calls."""

    name = "commands"

    def __init__(self, policy: Policy, protected_paths: Iterable[Path] = ()) -> None:
        self._protected = tuple(os.path.realpath(path) for path in protected_paths)
        self._commands_policy = policy.dangerous_commands
        self._exfil_policy = policy.data_exfiltration
        self._allowlist = [re.compile(p) for p in policy.dangerous_commands.allowlist]
        self._allowed_hosts = {host.lower() for host in policy.data_exfiltration.allowed_hosts}

    async def detect(self, ctx: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for segment in ctx.segments:
            if segment.tool_name is None or segment.tool_field is None:
                continue
            for hit in self._hits(segment, ctx.cwd):
                policy = (
                    self._exfil_policy
                    if hit.category is Category.DATA_EXFILTRATION
                    else self._commands_policy
                )
                finding = build_finding(
                    detector=self.name,
                    category=hit.category,
                    policy=policy,
                    direction=ctx.direction,
                    rule=hit.rule,
                    message=f"{hit.description} ({segment.tool_name}.{segment.tool_field})",
                    severity=hit.severity,
                    confidence=hit.confidence,
                    segment=segment,
                    excerpt=snippet(segment.text, hit.start, hit.end),
                )
                if finding:
                    findings.append(finding)
        return findings

    def _hits(self, segment: TextSegment, cwd: str | None) -> list[Hit]:
        field = segment.tool_field
        text = segment.text
        if field in COMMAND_FIELDS:
            if any(pattern.search(text) for pattern in self._allowlist):
                return []
            return self._command_hits(text, cwd)
        if field in PATH_FIELDS:
            return self._path_hits(segment.tool_name or "", text, cwd)
        if field in CONTENT_FIELDS:
            return [
                Hit(
                    h.rule,
                    f"{h.description} written to a file",
                    h.category,
                    h.severity,
                    h.confidence * CONTENT_CONFIDENCE_FACTOR,
                    h.start,
                    h.end,
                )
                for h in self._command_hits(text, cwd)
                if h.rule != "sensitive_file_access"
            ]
        return []

    def _command_hits(self, command: str, cwd: str | None, depth: int = 0) -> list[Hit]:
        command = _expand_obfuscation(command)
        commands = _simple_commands(command)
        hits = self._rm_hits(commands)
        hits.extend(self._write_hits(commands, cwd))
        seen_force_push = False
        for rule in RULES:
            match = rule.pattern.search(command)
            if not match:
                continue
            # The protected-branch rule supersedes the generic force-push rules.
            if rule.name.startswith("force_push"):
                if seen_force_push:
                    continue
                seen_force_push = True
            hits.append(_hit(rule, match.start(), match.end()))

        if not self._all_hosts_allowed(command):
            for rule in EXFIL_RULES:
                match = rule.pattern.search(command)
                if match:
                    hits.append(_hit(rule, match.start(), match.end()))
        hits.extend(_foreign_credential_hits(commands))

        if depth < MAX_NESTING:
            # `bash -c "..."`, `eval "..."`: analyze the inner command.
            for simple in commands:
                for inner in _nested_commands(simple.words):
                    hits.extend(
                        replace(
                            hit,
                            description=f"{hit.description} (nested shell)",
                            start=simple.start,
                            end=simple.end,
                        )
                        for hit in self._command_hits(inner, cwd, depth + 1)
                    )
            # Base64 literals that decode to commands, e.g. `echo cm0gLXJmIC8= | base64 -d | sh`.
            for decoded in decoded_candidates(command, encodings=("base64",)):
                hits.extend(
                    replace(
                        hit,
                        description=f"{hit.description} (base64-encoded)",
                        start=decoded.start,
                        end=decoded.end,
                    )
                    for hit in self._command_hits(decoded.text, cwd, depth + 1)
                )
        return hits

    def _rm_hits(self, commands: list[SimpleCommand]) -> list[Hit]:
        hits: list[Hit] = []
        for simple in commands:
            words = _strip_wrappers(simple.words)
            if not words or words[0].rsplit("/", 1)[-1] != "rm":
                continue
            flags = [w for w in words[1:] if w.startswith("-")]
            targets = [w for w in words[1:] if not w.startswith("-")]
            short = "".join(f[1:] for f in flags if not f.startswith("--"))
            recursive = "r" in short or "R" in short or "--recursive" in flags
            force = "f" in short or "--force" in flags
            if not recursive:
                continue
            if "--no-preserve-root" in flags or any(_CRITICAL_RM_TARGETS.match(t) for t in targets):
                hits.append(
                    Hit(
                        "recursive_delete_critical",
                        "Recursive delete of a root, home or system directory",
                        Category.DANGEROUS_COMMANDS,
                        Severity.CRITICAL,
                        0.95,
                        simple.start,
                        simple.end,
                    )
                )
            elif force:
                hits.append(
                    Hit(
                        "recursive_delete",
                        "Forced recursive delete",
                        Category.DANGEROUS_COMMANDS,
                        Severity.LOW,
                        0.4,
                        simple.start,
                        simple.end,
                    )
                )
        return hits

    def _write_hits(self, commands: list[SimpleCommand], cwd: str | None) -> list[Hit]:
        """Shell commands that modify guard files or persistence locations."""
        hits: list[Hit] = []
        for simple in commands:
            words = _strip_wrappers(simple.words)
            if words and words[0] == "cd":
                cwd = _change_directory(words[1:], cwd)
                continue
            for target in _write_targets(simple.words):
                hits.extend(self._target_hits(target, cwd, simple.start, simple.end))
        return hits

    def _target_hits(self, target: WriteTarget, cwd: str | None, start: int, end: int) -> list[Hit]:
        resolved = _resolve_path(target.path, cwd)
        names = [target.path] if resolved is None else [target.path, resolved]
        hits: list[Hit] = []
        if self._tampers(target, resolved, names):
            hits.append(_guard_tamper_hit(start, end))
        if not target.removes and any(PERSISTENCE_PATH.search(name) for name in names):
            hits.append(_persistence_hit(start, end))
        return hits

    def _tampers(self, target: WriteTarget, resolved: str | None, names: list[str]) -> bool:
        if any(CLAUDE_SETTINGS_PATH.search(name) for name in names):
            return True
        if target.removes and any(CLAUDE_DIR.search(name) for name in names):
            return True
        if resolved is None:
            return False
        has_glob = any(char in resolved for char in "*?[")
        for protected in self._protected:
            if resolved == protected or resolved.startswith(f"{protected}/"):
                return True
            # Deleting or moving a parent directory takes the protected file with it. Root and
            # home targets are already reported as recursive_delete_critical.
            if (
                target.removes
                and not _CRITICAL_RM_TARGETS.match(target.path)
                and protected.startswith(f"{resolved.rstrip('/')}/")
            ):
                return True
            if has_glob and fnmatch(protected, resolved):
                return True
        return False

    def _path_hits(self, tool_name: str, path: str, cwd: str | None) -> list[Hit]:
        hits: list[Hit] = []
        if tool_name in WRITE_TOOLS:
            hits.extend(self._target_hits(WriteTarget(path, removes=False), cwd, 0, len(path)))
        match = SENSITIVE_PATH.search(path)
        if match:
            hits.append(
                Hit(
                    "sensitive_file_access",
                    "Access to credentials or secret files",
                    Category.DANGEROUS_COMMANDS,
                    Severity.HIGH,
                    0.75,
                    match.start(),
                    match.end(),
                )
            )
        return hits

    def _all_hosts_allowed(self, command: str) -> bool:
        hosts = {(urlparse(url).hostname or "").lower() for url in _URL.findall(command)}
        for word in (w for simple in _simple_commands(command) for w in simple.words):
            remote = _REMOTE_HOST.match(word)
            if remote and "://" not in word:
                hosts.add(remote.group(1).lower())
        return bool(hosts) and all(self._host_allowed(host) for host in hosts)

    def _host_allowed(self, host: str) -> bool:
        return any(_host_matches(host, allowed) for allowed in self._allowed_hosts)


def _foreign_credential_hits(commands: list[SimpleCommand]) -> list[Hit]:
    """Anthropic API calls with a key other than the user's own (data sent to another account).

    Applies even when the API host is in `allowed_hosts`: the host is trusted, the account is not.
    """
    hits: list[Hit] = []
    for simple in commands:
        words = _strip_wrappers(simple.words)
        if not words or words[0].rsplit("/", 1)[-1] not in _HTTP_CLIENTS:
            continue
        hosts = {(urlparse(url).hostname or "").lower() for url in _URL.findall(" ".join(words))}
        if not any(_host_matches(host, ANTHROPIC_API_HOST) for host in hosts):
            continue
        for value in _header_values(words[1:]):
            header = _CREDENTIAL_HEADER.match(value)
            if header and not OWN_ANTHROPIC_CREDENTIALS.match(header.group(2)):
                hits.append(
                    Hit(
                        "foreign_api_credential",
                        "Anthropic API called with a credential other than ANTHROPIC_API_KEY",
                        Category.DATA_EXFILTRATION,
                        Severity.HIGH,
                        0.85,
                        simple.start,
                        simple.end,
                    )
                )
                break
    return hits


def _header_values(args: list[str]) -> list[str]:
    """Values of `-H x`, `-Hx`, `--header x` and `--header=x`."""
    values: list[str] = []
    for index, arg in enumerate(args):
        if arg in ("-H", "--header") and index + 1 < len(args):
            values.append(args[index + 1])
        elif arg.startswith("--header="):
            values.append(arg.removeprefix("--header="))
        elif arg.startswith("-H") and len(arg) > 2:
            values.append(arg[2:])
    return values


def _host_matches(host: str, allowed: str) -> bool:
    return host == allowed or host.endswith(f".{allowed}")


def _guard_tamper_hit(start: int, end: int) -> Hit:
    return Hit(
        "guard_tamper",
        GUARD_TAMPER_DESCRIPTION,
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.95,
        start,
        end,
    )


def _persistence_hit(start: int, end: int) -> Hit:
    return Hit(
        "persistence_file_write",
        PERSISTENCE_DESCRIPTION,
        Category.DANGEROUS_COMMANDS,
        Severity.CRITICAL,
        0.85,
        start,
        end,
    )


def _hit(rule: CommandRule, start: int, end: int) -> Hit:
    return Hit(
        rule.name, rule.description, rule.category, rule.severity, rule.confidence, start, end
    )


@dataclass(frozen=True)
class SimpleCommand:
    """Words of one command between `;`, `&&`, `|`, ...; offsets are those of its line."""

    words: list[str]
    start: int
    end: int


def _tokenize(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes
        return line.split()


def _simple_commands(command: str) -> list[SimpleCommand]:
    """Split a shell command into simple commands, respecting quotes."""
    result: list[SimpleCommand] = []
    offset = 0
    for line in command.split("\n"):
        start, end = offset, offset + len(line)
        offset = end + 1
        current: list[str] = []
        for token in _tokenize(line):
            if token in _COMMAND_BREAKS:
                if current:
                    result.append(SimpleCommand(current, start, end))
                current = []
            else:
                current.append(token)
        if current:
            result.append(SimpleCommand(current, start, end))
    return result


_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_VARIABLE_REFERENCE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
MAX_EXPANDED_VARIABLES = 32
_SIMPLE_ASSIGNMENT = re.compile(r"(?:^|[;&|\s])([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|$`]+)")


def _expand_obfuscation(command: str) -> str:
    """Undo `$'\\x72\\x6d'` quoting and `X=rm; $X ...` indirection before analysis.

    Offsets may shift; findings point at the whole command line, so this only affects excerpts.
    """

    def decode_ansi_c(match: re.Match[str]) -> str:
        try:
            decoded = codecs.decode(match.group(1), "unicode_escape")
        except UnicodeDecodeError:
            return match.group()
        return shlex.quote(decoded)

    expanded = _ANSI_C.sub(decode_ansi_c, command)
    if "$" not in expanded:
        return expanded
    variables: dict[str, str] = {}
    for match in _SIMPLE_ASSIGNMENT.finditer(expanded):
        variables[match.group(1)] = match.group(2).strip("'\"")
        if len(variables) >= MAX_EXPANDED_VARIABLES:
            break
    if not variables:
        return expanded
    # One pass over the text, whatever the number of variables.
    return _VARIABLE_REFERENCE.sub(
        lambda m: variables.get(m.group(1) or m.group(2), m.group()), expanded
    )


def _strip_wrappers(words: list[str]) -> list[str]:
    """Drop `sudo -u root`, `env A=1`, `nice -n 10`, ... in front of the real command."""
    index = 0
    while index < len(words):
        word = words[index]
        if word in _WRAPPERS or _ASSIGNMENT.fullmatch(word):
            index += 1
        elif word.startswith("-"):
            index += 2 if word in _OPTIONS_WITH_VALUE else 1
        else:
            break
    return words[index:]


def _nested_commands(words: list[str]) -> list[str]:
    words = _strip_wrappers(words)
    if not words:
        return []
    name = words[0].rsplit("/", 1)[-1]
    if name in _SHELLS:
        for index, word in enumerate(words[1:-1], start=1):
            if _SHELL_COMMAND_FLAG.fullmatch(word):
                return [words[index + 1]]
    if name == "eval":
        return [" ".join(words[1:])]
    return []


@dataclass(frozen=True)
class WriteTarget:
    """A path a shell command writes; `removes` when it may be deleted or moved away."""

    path: str
    removes: bool


_REDIRECTIONS = frozenset({">", ">>", ">|", "&>", "&>>"})
_REMOVE_COMMANDS = frozenset({"rm", "unlink", "rmdir", "shred"})
_MODIFY_COMMANDS = frozenset({"tee", "touch", "truncate", "chmod", "chown", "chgrp"})
_COPY_COMMANDS = frozenset({"cp", "ln", "install"})
_IN_PLACE_EDITORS = frozenset({"sed", "perl", "ruby"})
_IN_PLACE_FLAG = re.compile(r"-[a-zA-Z]*i|--in-place")


def _write_targets(words: list[str]) -> list[WriteTarget]:
    """Paths one simple command may modify: redirections plus known file-changing commands."""
    targets: list[WriteTarget] = []
    args: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in _REDIRECTIONS and index + 1 < len(words):
            targets.append(WriteTarget(words[index + 1], removes=False))
            index += 2
            continue
        args.append(word)
        index += 1

    args = _strip_wrappers(args)
    if not args:
        return targets
    name = args[0].rsplit("/", 1)[-1]
    flags = [arg for arg in args[1:] if arg.startswith("-")]
    operands = [arg for arg in args[1:] if arg and not arg.startswith("-")]
    if name in _REMOVE_COMMANDS:
        targets.extend(WriteTarget(operand, removes=True) for operand in operands)
    elif name == "mv" and operands:
        targets.extend(WriteTarget(operand, removes=True) for operand in operands[:-1])
        targets.append(WriteTarget(operands[-1], removes=False))
    elif name in _COPY_COMMANDS and operands:
        targets.append(WriteTarget(operands[-1], removes=False))
    elif name in _MODIFY_COMMANDS or (
        name in _IN_PLACE_EDITORS and any(_IN_PLACE_FLAG.match(flag) for flag in flags)
    ):
        targets.extend(WriteTarget(operand, removes=False) for operand in operands)
    elif name == "dd":
        targets.extend(
            WriteTarget(arg.removeprefix("of="), removes=False)
            for arg in args[1:]
            if arg.startswith("of=")
        )
    return targets


_HOME_PREFIXES = ("~", "$HOME", "${HOME}")


def _resolve_path(path: str, cwd: str | None) -> str | None:
    """Absolute, symlink-free form of `path`; None when it is relative and `cwd` is unknown."""
    for prefix in _HOME_PREFIXES:
        if path == prefix or path.startswith(f"{prefix}/"):
            path = str(Path.home()) + path[len(prefix) :]
            break
    if not os.path.isabs(path):
        if cwd is None:
            return None
        path = os.path.join(cwd, path)
    return os.path.realpath(path)


def _change_directory(args: list[str], cwd: str | None) -> str | None:
    operands = [arg for arg in args if not arg.startswith("-") or arg == "-"]
    if not operands:
        return str(Path.home())
    if operands[0] == "-":
        return None
    return _resolve_path(operands[0], cwd)
