# Policy

`policy.yaml` controls what claude-guard does with each detector finding. The file is validated
on load: unknown keys, out-of-range thresholds, invalid regexes and unsupported actions are
rejected with a readable error.

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
| `google_api_key` | high | 0.95 | `AIza` + 35 chars |
| `jwt` | high | 0.90 | three base64url parts; header must decode to JSON with `alg` |
| `iban` | high | 0.90 | IBAN with per-country length and mod-97 checksum |
| `nrb` | high | 0.75 | Polish 26-digit account number (mod-97 as `PL` IBAN) |
| `payment_card` | high | 0.85 | 13–19 digits, known issuer prefix, Luhn checksum |
| `pesel` | high | 0.80 | 11 digits, PESEL checksum and valid encoded birth date |
| `credential_assignment` | high | 0.65 | `password`/`secret`/`api_key`/`*_token = value`; placeholders (`${VAR}`, `<your-key>`, `changeme`, `***`), env lookups and code references are ignored |
| `encoded_secret` | as the decoded rule | as the decoded rule | base64 run that decodes to text containing any rule above (e.g. an encoded `.env`) |
| `high_entropy` | medium | 0.40 | Mixed-case alphanumeric token with a digit, not hex, entropy ≥ `entropy_threshold`. Paths (`/...`, `~/.../`) are judged per segment, and slugs of short words joined by `-`/`_` (like Claude Code project directory names) are skipped. Below the default threshold on purpose, so it only warns. |

## `prompt_injection`

Default: `action: block`, `threshold: 0.7`.

- Operator segments (role `system` and `tool_definition`: the system prompt and tool
  descriptions) are not inspected. Injection hidden in third-party (e.g. MCP) tool descriptions
  is therefore not detected; see the limitations in the README.
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
| `markdown_image_exfil` | high | 0.75 | `![](https://host/?q={...})` — templated query used to leak data when rendered |
| `unicode_tag_characters` | high | 0.90 | U+E0000–U+E007F; the hidden ASCII text is decoded into the excerpt |
| `zero_width_characters` | medium | 0.60 | 3 or more zero-width characters (a leading BOM is ignored) |
| `bidi_control_characters` | medium | 0.65 | bidirectional overrides/isolates (Trojan Source) |

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
| `guard_tamper` | critical | 0.95 | writing or removing the policy, the audit log, Stop offsets or Claude Code settings (see above) |

## `data_exfiltration`

Default: `action: block`, `threshold: 0.6`. Reported by the commands detector.

Extra key: `allowed_hosts` (default `api.anthropic.com`, `github.com`, `pypi.org`,
`files.pythonhosted.org`). Subdomains are allowed too. Upload rules are skipped only when
**every** host in the command is allowed.

| Rule | Severity | Confidence | Detection |
|------|----------|------------|-----------|
| `upload_file` | high | 0.85 | `curl -d @file`, `--data-binary @`, `-F x=@file`, `-T`, `wget --post-file` |
| `pipe_to_network` | high | 0.85 | `cat`/`tar`/`base64`/`env`/... piped to `curl`/`nc`/`socat` |
| `netcat_send` | high | 0.85 | `nc host port < file` |
| `remote_copy` | medium | 0.70 | `scp`/`rsync` to `host:` |
| `dns_exfiltration` | high | 0.70 | `dig`/`nslookup`/`host` with command substitution (not affected by `allowed_hosts`) |

## `llm_judge`

Default: disabled, `action: block`, `threshold: 0.8`. Uses the model from `GUARD_JUDGE_MODEL`
(default `claude-haiku-4-5`) and the credentials the Anthropic SDK finds (`ANTHROPIC_API_KEY`).

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `uncertain` | `always`, or only when the strongest heuristic confidence is inside `uncertain_range` |
| `uncertain_range` | `[0.3, 0.7]` | Confidence window `[low, high)` that triggers the judge in `uncertain` mode |
| `timeout_seconds` | 10.0 | Upper bound for the whole judgement, retries included |
| `max_retries` | 2 | Retries for transient API errors (done by the SDK) and for missing/invalid judge output |
| `max_input_chars` | 50000 | Characters of content sent to the judge; longer content is cut and marked `truncated` |

How it works:

- In `uncertain` mode the judge is skipped when the heuristics found nothing (confidence 0) or
  are already confident. It never removes heuristic findings; it can only add its own.
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
  allowed_hosts: [api.anthropic.com, internal.example.com]
```

Omitted keys keep their defaults.
