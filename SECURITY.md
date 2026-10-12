# Security policy

claude-guard is a security tool, so a weakness in it can leave its users exposed while they
believe they are protected. Please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Please do not open a public issue, pull request or discussion for a
vulnerability or a detection bypass.

Include:

- the claude-guard version or commit, and the integration (proxy, hooks or `scan`);
- the relevant settings (`GUARD_*`) and any changes to `policy.yaml`;
- a minimal payload or steps that reproduce the problem;
- the impact: what got through, leaked or was disabled.

Remove real secrets from the report. Fake values in a realistic format are enough.

We aim to acknowledge reports within 7 days and to agree on a disclosure date with you once a
fix is ready. Reporters are credited in the release notes unless they prefer otherwise.

## Supported versions

claude-guard is pre-1.0. Only the latest release (and `main`) receives security fixes.

## Scope

What claude-guard does and does not defend against is described in
[docs/threat-model.md](docs/threat-model.md). In short:

**Vulnerabilities**, please report privately:

- a protection that the documentation says is in place does not work, e.g. the proxy forwards an
  uninspected endpoint with `GUARD_PASSTHROUGH=block`, or a blocked verdict still reaches the
  client in `buffer` mode;
- secrets reach the audit log, application logs, alerts or error messages unmasked;
- input that makes the engine fail open while `GUARD_FAIL_MODE=closed`, or crashes or hangs the
  proxy or a hook;
- bypassing `GUARD_PROXY_TOKEN`, the TLS requirement for non-loopback binds, or `guard_tamper`
  for a file path it covers;
- `install-hooks` corrupting or weakening an existing `.claude/settings.json`.

**Detection bypasses**, please also report privately: a payload in a category the guard covers
(prompt injection, secrets, dangerous commands, exfiltration) that gets through. They are
handled as hardening and fixed with new rules and tests. Publishing them before a fix gives
attackers a ready-made recipe.

**Not vulnerabilities:**

- limitations already listed in [README.md](README.md#limitations) and the threat model, such
  as paraphrased injections without the LLM judge, inspection after the fact in
  `GUARD_STREAM_MODE=audit`, or uninspected images and PDFs;
- false positives (open a regular issue);
- behavior with `GUARD_FAIL_MODE=open`, `GUARD_PASSTHROUGH=allow` or a policy that lowers
  actions, when it matches the documentation;
- attacks that need control of the user's account, the operator's system prompt or the guard's
  own configuration (see "Out of scope" in the threat model).
