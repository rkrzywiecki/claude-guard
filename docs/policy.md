# Policy

`policy.yaml` controls what claude-guard does with each detector finding. The file is validated
on load: unknown keys, out-of-range thresholds, invalid regexes and unsupported actions are
rejected with a readable error.

Changes apply without a restart. Hooks and `scan` read the file on every run. The proxy checks
it for changes at most every `GUARD_POLICY_RELOAD_INTERVAL` seconds (default 2, on incoming
requests) and reloads at once on `kill -HUP <pid>`; see [proxy.md](proxy.md#policy-reload).

## How a finding becomes an action

Each detector reports findings with a **category**, a **severity** (`low`, `medium`, `high`,
`critical`) and a **confidence** (0–1). The category policy then decides the action:

1. Category disabled, or severity below `min_severity` → `allow` (the finding is dropped).
2. Confidence below `threshold` → `warn`.
3. Otherwise → `direction_actions[direction]` if set, else `action`.

The verdict for a payload is the strictest action among its findings:
`block` > `redact` > `warn` > `allow`.

| Action   | Effect |
|----------|--------|
| `allow`  | Nothing happens. |
| `warn`   | Logged in the audit log; the content passes. |
| `redact` | The matched span is replaced with `[REDACTED:<rule>]`. Only valid for `secrets`. |
| `block`  | The request/response/tool call is rejected. |

Directions: `request` (context sent to the API), `response` (model output), `tool_input`
(a tool call about to run) and `tool_output` (a tool result, treated as untrusted).

## Common keys

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Turn the category on or off. |
| `action` | action | Action for findings at or above `threshold`. |
| `threshold` | 0–1 | Minimum confidence for `action`; lower-confidence findings only warn. |
| `min_severity` | severity | Findings below this severity are ignored. |
| `direction_actions` | map | Per-direction override of `action`, e.g. `{tool_output: warn}`. |

## `secrets`

Default: `action: redact`, `threshold: 0.5`. Applies to every text segment in every direction.

Extra keys:

| Key | Default | Description |
|-----|---------|-------------|
| `entropy_min_length` | 24 | Minimum length for the generic high-entropy rule. |
| `entropy_threshold` | 4.0 | Minimum Shannon entropy (bits per character). |
| `allowlist` | AWS documentation example keys | Regexes; matching values are never reported. |

Specific rules run first and claim their spans. Generic rules skip anything already claimed, so
each value is reported at most once.

Obfuscation handling:

- Zero-width, soft-hyphen and Unicode tag characters are removed before matching, and spans are
  mapped back to the original text, so `sk-ant-<U+200B>api03-...` is still redacted in full.
- Base64 runs that decode to readable text are scanned too; if they contain a secret, the whole
  encoded run is reported as `encoded_secret` and redacted.

| Rule | Severity | Confidence | Detection |
|------|----------|------------|-----------|
| `private_key` | critical | 0.99 | PEM `-----BEGIN ... PRIVATE KEY-----` block (also truncated) |
| `anthropic_api_key` | critical | 0.99 | `sk-ant-...` |
| `openai_api_key` | critical | 0.90 | `sk-...`, `sk-proj-...`, `sk-svcacct-...` (32+ chars) |
| `aws_access_key_id` | high | 0.95 | `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 chars |
| `aws_secret_access_key` | critical | 0.90 | 40-char value assigned to an `aws...secret` name |
| `github_token` | critical | 0.98 | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| `slack_token` | high | 0.95 | `xoxb-`, `xoxp-`, ... |
| `stripe_live_key` | critical | 0.98 | `sk_live_`, `rk_live_` |
| `gitlab_token` | critical | 0.95 | `glpat-`, `gldt-`, `glptt-`, `glrt-`, `glcbt-`, `gloas-`, `glft-`, `glimt-`, `glagent-`, `glsoat-` + 20+ chars |
| `huggingface_token` | high | 0.90 | `hf_` + 30+ alphanumerics |
| `npm_token` | critical | 0.95 | `npm_` + 36 alphanumerics |
| `pypi_token` | critical | 0.98 | `pypi-AgEIcHlwaS5vcmc...` (PyPI macaroon) |
| `sendgrid_api_key` | high | 0.95 | `SG.<22>.<43>` |
| `url_credentials` | high | 0.85 | password in `scheme://user:password@host` (`postgres://`, `redis://:pw@`, `https://`, ...); only the password is redacted; placeholders (`password`, `${VAR}`, `<token>`) are ignored |
| `google_api_key` | high | 0.95 | `AIza` + 35 chars |
| `jwt` | high | 0.90 | three base64url parts; header must decode to JSON with `alg` |
| `iban` | high | 0.90 | IBAN with per-country length and mod-97 checksum |
| `nrb` | high | 0.75 | Polish 26-digit account number (mod-97 as `PL` IBAN) |
| `payment_card` | high | 0.85 | 13–19 digits, known issuer prefix, Luhn checksum |
| `pesel` | high | 0.80 | 11 digits, PESEL checksum and valid encoded birth date |
| `credential_assignment` | high | 0.65 | `password`/`secret`/`api_key`/`*_token = value`; placeholders (`${VAR}`, `<your-key>`, `changeme`, `***`), env lookups and code references are ignored, and so are `key: value` matches that are type annotations (`api_key: SecretStr \| None`) or prose (`a secret: detectors ...`); quoted values and `=` assignments always count |
| `encoded_secret` | as the decoded rule | as the decoded rule | base64 run that decodes to text containing any rule above (e.g. an encoded `.env`) |
| `high_entropy` | medium | 0.40 | Mixed-case alphanumeric token with a digit, not hex, entropy ≥ `entropy_threshold`. Paths (`/...`, `~/.../`) are judged per segment, and slugs of short words joined by `-`/`_` (like Claude Code project directory names) are skipped. Below the default threshold on purpose, so it only warns. |

## `prompt_injection`

Default: `action: block`, `threshold: 0.7`.

- The system prompt and built-in tool definitions are operator content and are not inspected.
  MCP tool definitions (`mcp__*`: the tool description and every `description` in its
  `input_schema`) come from third-party servers and are inspected for tool poisoning, see
  [Tool definitions](#tool-definitions-tool-poisoning).
- Every rule is tried on several readings of the text, so obfuscation does not hide it:
  - NFKC-normalized with zero-width, soft-hyphen and Unicode tag characters removed
    (`ig<U+200B>nore`, full-width letters);
  - Cyrillic/Greek homoglyphs folded to Latin (`ignоre` with a Cyrillic `о`);
  - leetspeak undone inside words (`1gn0r3 4ll pr3v10us`);
  - letter-spacing collapsed (`i g n o r e`, `i.g.n.o.r.e`).

  Findings from a changed reading carry no span.
- Base64, hex and percent-encoded runs (up to two layers, e.g. base64 of base64) are decoded and
  matched; a hit is reported as `encoded_instructions` with the decoded excerpt.
- Sibling blocks of one message (e.g. several text blocks in a `tool_result`) are also joined, so
  a phrase split across blocks is found; the finding message ends with
  "(split across content blocks)".
- Untrusted segments (tool results, fetched content) get **+0.1 confidence** and two extra
  rules (fake role tags and turns). Trusted user content legitimately contains tags such as
  Claude Code's `<system-reminder>`.

| Rule | Severity | Confidence | Detection |
|------|----------|------------|-----------|
| `ignore_instructions` | high | 0.85 | "ignore/disregard/forget/override/bypass" + previous/above/your/system + instructions/rules/prompt; "ignore the above" |
| `ignore_instructions_pl` | high | 0.85 | Polish equivalent ("zignoruj poprzednie instrukcje") |
| `ignore_instructions_multilingual` | high | 0.85 | German, Spanish, French, Italian, Portuguese, Russian, Chinese, Japanese and Korean equivalents |
| `encoded_instructions` | as the decoded rule | as the decoded rule | any rule above matched inside a decoded base64/hex/percent-encoded run |
| `jailbreak_persona` | high | 0.80 | DAN / "do anything now", developer/god mode, "you are now unrestricted" |
| `new_instructions` | medium | 0.60 | "New instructions:", "From now on, you will" |
| `prompt_extraction` | medium | 0.75 | "reveal/print/repeat your system prompt" |
| `special_tokens` | high | 0.80 | `<\|im_start\|>`, `<<SYS>>`, `[INST]` and similar control tokens |
| `fake_role_tag` | high | 0.75 | `<system>`, `</assistant>`, `<system-reminder>` — untrusted only |
| `fake_role_turn` | high | 0.70 | line starting with `Human:` / `Assistant:` / `System:` — untrusted only |
| `hidden_html_comment` | medium | 0.70 | HTML comment mentioning AI/assistant/instructions/run |
| `hidden_html_element` | medium | 0.65 | text inside an element styled `display:none`, `visibility:hidden`, `font-size:0`, `opacity:0` |
| `markdown_comment` | medium | 0.60 | `[//]: # (...)` comment with instruction-like words |
| `tool_hidden_action` | high | 0.85 | MCP tool definitions only: "do not tell the user", "without informing the user", "the user must not know", "do not mention that ... user" |
| `tool_sensitive_file` | high | 0.75 | MCP tool definitions only: credential files (as `sensitive_file_access`), `mcp.json`, `claude_desktop_config.json`, `.cursor/`, `.claude/settings` |
| `tool_instruction_tag` | high | 0.80 | MCP tool definitions only: `<IMPORTANT>`, `<instructions>`, `<system>`, `<secret>`, `<hidden>` tags |
| `tool_shadowing` | medium | 0.50 | MCP tool definitions only: instructions about another tool ("when you call the send_email tool, always ..."); never blocks on its own |
| `markdown_image_exfil` | high | 0.75 | `![](https://host/?q={...})` — templated query used to leak data when rendered |
| `unicode_tag_characters` | high | 0.90 | U+E0000–U+E007F; the hidden ASCII text is decoded into the excerpt |
| `zero_width_characters` | medium | 0.60 | 3 or more zero-width characters (a leading BOM is ignored) |
| `bidi_control_characters` | medium | 0.65 | bidirectional overrides/isolates (Trojan Source) |

### Tool definitions (tool poisoning)

A malicious or compromised MCP server can hide instructions in its tool descriptions or
parameter descriptions. They are sent to the model with every request, before any tool runs.
The proxy inspects MCP tool definitions (`mcp__*`, untrusted) with all rules above plus the
`tool_*` rules; built-in tools stay operator content. Hooks never see tool definitions.

| Key | Default | Description |
|-----|---------|-------------|
| `tool_definitions` | `warn` | `off`: not inspected; `warn`: findings are capped at `warn` (logged, reported in `x-claude-guard-request-action`, the request goes through); `block`: findings follow the category action, so every request is refused while the poisoned tool is offered |

`warn` is the default because tool definitions are in every request: a false positive in
`block` mode would stop the whole session until the MCP server is removed. Watch the audit log
for `tool_*` rules (`claude-guard report`) and switch to `block` once your MCP servers pass
cleanly.

## `dangerous_commands`

Default: `action: block`, `threshold: 0.7`. Inspects only tool call inputs:

- `command` fields (Bash): full rule set below.
- `file_path` / `path` / `notebook_path`: sensitive file access; for `Write`, `Edit`,
  `MultiEdit`, `NotebookEdit` also persistence targets and guard tampering.
- `content` / `new_string`: the command rules at **0.7× confidence** (writing a script is not
  running it), so they usually only warn.

Extra key: `allowlist` — regexes; a command matching any of them is not inspected.

Shell parsing and evasion handling:

- Commands are split on `;`, `&&`, `||`, `|`, `&` and newlines with a quote-aware tokenizer, so
  `echo 'rm -rf /'` is not a delete, while `ls && rm -rf /` is.
- Wrappers are skipped, including their options: `sudo -u root`, `env A=1`, `nice -n 10`,
  `nohup`, `xargs`, `command`, `exec`.
- Inner commands are analyzed recursively (two levels): `bash -c "..."`, `sh -lc '...'`,
  `eval "..."`, and base64 literals that decode to commands (`echo cm0gLXJmIC8= | base64 -d`).
  Their findings mention "(nested shell)" or "(base64-encoded)".
- ANSI-C quoting (`$'\x72\x6d' -rf /`) is decoded and simple variable indirection
  (`X=rm; $X -rf /`) is expanded before matching.
- Files a command modifies are collected: redirection targets (`>`, `>>`, `>|`, `&>`), `tee`,
  `touch`, `truncate`, `chmod`/`chown`, the destination of `cp`/`ln`/`install`, `dd of=`,
  files edited in place (`sed -i`, `perl -pi`), and files removed or moved away (`rm`,
  `unlink`, `shred`, `mv` sources). They are checked for `guard_tamper` and
  `persistence_file_write`.

### Guard tampering

An agent that can rewrite the guard's configuration can switch it off. `guard_tamper` flags
writes to, and removal of:

- the policy file (`GUARD_POLICY_PATH`), the audit log (`GUARD_AUDIT_PATH`) and the Stop hook
  offsets next to it (`sessions/`);
- Claude Code settings, which hold the hooks: `.claude/settings.json`,
  `.claude/settings.local.json` (any project and `~/.claude`) and `managed-settings.json`;
  removing a `.claude` directory counts too.

Paths are compared after expanding `~`/`$HOME` and resolving symlinks. Relative paths are
resolved against the tool call's working directory, which Claude Code passes to hooks (`cwd`),
following `cd` inside the command; in the proxy the working directory is unknown, so relative
guard paths are not recognized there (Claude Code settings are, by name). Removing or moving a
parent directory of a guard file (`rm -r logs`) is tampering as well. Reading these files is
allowed.

To change the policy or the settings, edit them yourself, or add a narrow regex to `allowlist`
for a specific shell command.

| Rule | Severity | Confidence | Detection |
|------|----------|------------|-----------|
| `recursive_delete_critical` | critical | 0.95 | `rm` with `-r` on `/`, `/*`, `~`, `$HOME`, `.`, `..`, `*`, system dirs, or `--no-preserve-root` (also via `sudo`, `xargs`, `/bin/rm`) |
| `recursive_delete` | low | 0.40 | other `rm -rf` (warn only) |
| `pipe_to_shell` | critical | 0.95 | `curl`/`wget` output piped to `sh`/`bash`/`python`/... |
| `shell_from_download` | critical | 0.95 | `bash -c "$(curl ...)"`, `bash <(curl ...)`, `eval $(curl ...)` |
| `world_writable` | high | 0.85 | `chmod 777`, `666`, `a+rwx`, `o+w` |
| `setuid` | high | 0.80 | `chmod u+s`, `g+s`, `4755`, ... |
| `force_push_protected` | critical | 0.95 | force push to `main`/`master`/`prod`/`production`/`release` |
| `force_push` | high | 0.80 | `git push --force`, `-f`, `+ref` |
| `force_push_with_lease` | medium | 0.50 | `--force-with-lease` (warn only) |
| `push_to_production` | medium | 0.60 | `git push <remote> prod|production|release` (warn only) |
| `disk_destruction` | critical | 0.95 | `dd of=/dev/...`, `mkfs /dev/...`, `> /dev/sda`, `shred /dev/...`, `diskutil eraseDisk` |
| `decoded_to_shell` | critical | 0.90 | `base64 -d ... \| sh` (or bash, python, perl, ruby, node) |
| `download_then_execute` | critical | 0.90 | `curl -o f ... && bash f`, `wget ... > f; chmod +x f` |
| `find_delete_critical` | critical | 0.90 | `find /` (or `~`, `$HOME`) with `-delete` or `-exec rm` |
| `rmtree_critical` | critical | 0.90 | `shutil.rmtree('/')`, `shutil.rmtree('~')`, `shutil.rmtree(os.path.expanduser(...))` |
| `fork_bomb` | critical | 0.99 | `:(){ :\|:& };:` |
| `sensitive_file_access` | high | 0.75 | `~/.ssh`, `id_rsa`, `.aws/credentials`, `.kube/config`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `/etc/shadow`, `.env` (not `.env.example`/`.sample`/`.template`/`.dist`) |
| `persistence_file_write` | critical | 0.85 | writing `authorized_keys`, shell startup files (`.bashrc`, `.bash_profile`, `.bash_login`, `.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`, `.profile`), `/etc/*`, `.git/hooks/*`, LaunchAgents/LaunchDaemons, cron; via file tools or shell write targets |
| `persistence_command` | high | 0.85 | `crontab <file>` / `crontab -` (not `crontab -l`), `launchctl load`/`bootstrap`/`enable`/`submit`, `systemctl [--user] enable`/`link` |
| `git_discard_changes` | high | 0.75 | `git reset --hard`, `git clean -f`/`--force`, `git checkout .`/`-- .`, `git restore .` (not `--staged` only), `git stash clear`/`drop`; parsed from the command's words, so a commit message mentioning them does not match |
| `infra_destroy` | critical | 0.90 | `terraform destroy`/`apply -destroy`, `pulumi`/`cdk destroy`, `kubectl delete namespace`/`all`/`--all`, `aws s3 rm --recursive`, `aws s3 rb --force`, `gsutil rm -r`, `gcloud projects delete`, `az group delete`, `gh repo delete`, `docker system`/`volume prune`, `docker volume rm` |
| `database_drop` | critical | 0.90 | `DROP DATABASE`/`SCHEMA`, `dropdb`, `FLUSHALL`/`FLUSHDB`, `dropDatabase()`; only when the command runs a data-store client (`psql`, `mysql`, `sqlite3`, `redis-cli`, `mongosh`, ...) |
| `table_destroy` | high | 0.75 | `DROP TABLE`, `TRUNCATE TABLE`, `DELETE FROM t` without `WHERE`; same client requirement (SQL in files and `grep` patterns is ignored) |
| `guard_tamper` | critical | 0.95 | writing or removing the policy, the audit log, Stop offsets or Claude Code settings (see above) |

## `data_exfiltration`

Default: `action: block`, `threshold: 0.6`. Reported by the commands detector (shell commands)
and the exfiltration detector (URLs in tool calls and images in assistant text).

Extra key: `allowed_hosts`, the hosts tools may send data to (default: none). Subdomains are
allowed too. Upload rules are skipped only when **every** host in the command is allowed.
Downloads are never flagged by these rules, so the list only matters for uploads.

URL checks decode each path segment, query value and fragment separately; only data that
decodes to readable text counts, so commit hashes, UUIDs, signatures and IDs pass. Known false
positives: base64-encoded JSON in a URL parameter (e.g. an OAuth `state`); allow that host if
it is trusted. Findings report the host and the size of the data, never the URL itself.

The list is empty on purpose: well-known services are exfiltration channels too. A Files API
upload to `api.anthropic.com` with someone else's key, a public gist on `api.github.com` or a
package upload all send local data out. Allow only the hosts you upload to, as narrowly as
possible (`uploads.github.com` rather than `github.com`).

| Rule | Severity | Confidence | Detection |
|------|----------|------------|-----------|
| `upload_file` | high | 0.85 | `curl -d @file`, `--data-binary @`, `-F x=@file`, `-T`, data from command output (`-d "$(cat f)"`, `` -d `...` ``), `wget --post-file`, `wget --post-data="$(...)"` |
| `pipe_to_network` | high | 0.85 | `cat`/`tar`/`base64`/`env`/... piped to `curl`/`nc`/`socat` |
| `netcat_send` | high | 0.85 | `nc host port < file` |
| `remote_copy` | medium | 0.70 | `scp`/`rsync` to `host:` |
| `dns_exfiltration` | high | 0.70 | `dig`/`nslookup`/`host` with command substitution (not affected by `allowed_hosts`) |
| `script_exfiltration` | high | 0.75 | inline script (`python -c`, `python - <<EOF`, `node -e`, `perl -e`, `ruby -e`, `deno`, `bun`) that both reads local data (`open(`, `read_text`, `os.environ`, `readFileSync`, `process.env`, `File.read`, `%ENV`) and uses the network (`urllib`, `requests`, `httpx`, `socket`, `fetch(`, `https.request`, `axios`, `Net::HTTP`, `LWP`) |
| `url_exfiltration` | high / medium | 0.80 / 0.50 | a URL in a tool call (any field except file paths and contents: WebFetch `url`, MCP arguments, `curl`/`wget` targets) to a host outside `allowed_hosts` that carries base64/hex data decoding to readable text (high), or a query longer than 300 characters (medium, warn only) |
| `image_exfiltration` | high / medium | 0.80 / 0.50 | the same check for markdown images (`![](url)`) and `<img src>` in assistant text: clients fetch images without a click. Links are not flagged |
| `foreign_api_credential` | high | 0.85 | `curl`/`wget` to `*.anthropic.com` with an `x-api-key` or `authorization` header other than `$ANTHROPIC_API_KEY` / `$ANTHROPIC_AUTH_TOKEN`: data would go to another account (not affected by `allowed_hosts`) |

## `tools`

Which tools may be called, by name glob (`Bash`, `WebFetch`, `mcp__github__*`; case-sensitive,
`*` and `?` as in shell globs). Default: every list empty, so every tool is allowed;
`action: block`.

| Key | Default | Description |
|-----|---------|-------------|
| `deny` | `[]` | Always denied, even if also listed in `allow` |
| `allow` | `[]` | When non-empty, every tool not listed is denied. List Claude Code's built-in tools too (`Read`, `Edit`, `Write`, `Bash`, `Grep`, `Glob`, `WebFetch`, ...) |
| `warn` | `[]` | Allowed, but each call is reported as a warning (e.g. `mcp__*` to watch MCP usage) |

| Rule | Severity | Action |
|------|----------|--------|
| `tool_denied` | high | category `action` (default block) |
| `tool_not_allowed` | high | category `action` (default block) |
| `tool_watched` | low | always `warn` |

Checked for tool calls about to run: `PreToolUse` in hooks (the call is denied) and `tool_use`
blocks in proxy responses (the response is replaced by a notice). Calls without arguments are
covered. Tool calls in a request are history and are not checked; a denied tool can still be
offered to the model in the request's `tools` list.

```yaml
tools:
  allow: [Read, Edit, Write, Bash, Grep, Glob, "mcp__github__*"]
  deny: ["mcp__github__delete_*"]
  warn: ["mcp__*"]
```

## `llm_judge`

Default: disabled, `action: block`, `threshold: 0.8`. Uses the model from `GUARD_JUDGE_MODEL`
(default `claude-haiku-4-5`) and the credentials the Anthropic SDK finds (`ANTHROPIC_API_KEY`).

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `untrusted` | `always`: every payload; `untrusted`: when the content sent to the judge includes untrusted segments (tool results, fetched documents), otherwise as `uncertain`; `uncertain`: only when the strongest heuristic confidence is inside `uncertain_range` |
| `uncertain_range` | `[0.3, 0.7]` | Confidence window `[low, high)` that triggers the judge in `untrusted` and `uncertain` mode |
| `timeout_seconds` | 10.0 | Upper bound for the whole judgement, retries included |
| `max_retries` | 2 | Retries for transient API errors (done by the SDK) and for missing/invalid judge output |
| `max_input_chars` | 50000 | Characters of content sent to the judge; see the budget rules below |

How it works:

- In `uncertain` mode the judge is skipped when the heuristics found nothing (confidence 0) or
  are already confident, so a paraphrased injection that no rule matches is never judged.
  `untrusted` mode (default) closes that gap for tool results and fetched content, where
  indirect injection lives: a turn that carries them is always judged. Plain prompts and
  responses still follow the `uncertain` logic. The judge never removes heuristic findings; it
  can only add its own.
- `max_input_chars` is shared so that padding cannot push an injection out of view: untrusted
  segments get their share first, segments within a group get max-min fair shares (short ones
  whole, long ones equal parts), and a segment longer than its share keeps its start and end
  with a `[... N characters omitted ...]` line in the middle. Such segments are marked
  `truncated="true"`.
- Judged categories are the enabled ones among `secrets`, `prompt_injection`,
  `dangerous_commands` and `data_exfiltration`. Operator segments (system
  prompt, tool descriptions) are not sent; for requests only the current turn is sent.
- The content is wrapped in `<untrusted_content_<random nonce>>` tags and the judge is told that
  everything inside is untrusted data it must not follow. The random tag name stops content from
  closing the wrapper.
- The judge answers through a strict tool (`report_findings`) with JSON findings: category,
  severity, confidence, segment index, evidence and explanation. `tool_choice` is `auto`
  (forced tool choice is rejected by some current models); a reply without a valid tool call is
  retried.
- Findings use category `llm_judge`, rule `judge:<category>`, and the `llm_judge` action and
  threshold. Evidence for `secrets` is masked.
- On timeout, API error, refusal or repeated invalid output the judge reports
  `judge_unavailable`: `block` when `GUARD_FAIL_MODE=closed`, `warn` when `open`.

## `custom_rules`

Your own regex rules, for things only you know about: internal hostnames, customer IDs, a
production cluster, a phrase attackers use against your app. Each rule belongs to a category
and gets that category's `enabled`, `action`, `threshold`, `min_severity` and
`direction_actions`, like a built-in rule. Findings are named `custom:<name>`.

```yaml
custom_rules:
  - name: internal_hostname            # lowercase letters, digits, _; unique
    description: Internal production hostname
    category: secrets                  # secrets | prompt_injection | dangerous_commands | data_exfiltration
    pattern: '\bdb-prod-\d+\.corp\.example\b'
    severity: medium                   # default high
    confidence: 0.9                    # default 0.9; below the category threshold it only warns
  - name: kubectl_prod
    description: kubectl against the production context
    category: dangerous_commands
    pattern: '\bkubectl\b.*--context[= ]prod\b'
    tools: [Bash, "mcp__k8s__*"]       # tool name globs: only these tool call inputs
    fields: [command]                  # only these tool input fields
  - name: agent_marker
    description: Text addressed to AI agents
    category: prompt_injection
    pattern: 'note to (the )?ai agent'
    ignore_case: true
    untrusted_only: true               # only tool results and fetched content
    directions: [request, tool_output] # default: all directions
```

| Key | Default | Description |
|-----|---------|-------------|
| `name` | required | Rule id, reported as `custom:<name>` |
| `description` | required | Message shown in verdicts, hook reasons and the audit log |
| `category` | required | Category whose policy decides the action |
| `pattern` | required | Python regex; must compile and must not match the empty string |
| `severity` | `high` | `low`, `medium`, `high`, `critical` |
| `confidence` | 0.9 | Compared with the category `threshold` |
| `ignore_case` | `false` | Case-insensitive matching |
| `directions` | all | `request`, `response`, `tool_input`, `tool_output` |
| `tools` | all | Tool name globs; when set, only tool call inputs of those tools are matched |
| `fields` | all | Tool input fields (`command`, `url`, `file_path`, ...) |
| `untrusted_only` | `false` | Only untrusted segments (tool results, fetched documents) |

Behaviour by category:

- `secrets` rules report every match and redact it as `[REDACTED:<name>]`; the excerpt is
  masked, and matches are also masked in the audit log, hook reasons and error messages. Like
  the built-in secret rules they inspect every segment, the system prompt included.
- Other categories report the first match per segment, skip operator content (system prompt,
  tool definitions), and are also matched against normalized text (invisible characters
  removed, homoglyphs and leetspeak folded), so simple obfuscation does not hide a match; the
  span is then not exact.

Patterns come from your policy file and run on every inspected text: keep them simple and avoid
nested quantifiers that can backtrack badly (`(a+)+`).

## Example

```yaml
version: 1
secrets:
  action: block          # refuse instead of redacting
  threshold: 0.8
prompt_injection:
  direction_actions:
    tool_output: warn    # only warn about injection in tool results
dangerous_commands:
  allowlist:
    - '^rm -rf \./(node_modules|dist|build)$'
data_exfiltration:
  allowed_hosts: [uploads.github.com, internal.example.com]
```

Omitted keys keep their defaults.
