---
name: skill-check
description: >-
  Defensive security audit for Codex, Claude Code, and other AI skill/plugin
  folders. Use when Codex needs to scan, audit, review, or verify a skill,
  SKILL.md file, plugin bundle, bundled script, reference file, or AI
  instruction file for malware, backdoors, prompt injection, data exfiltration
  instructions, suspicious dependencies, obfuscation, hidden content, unsafe
  execution patterns, or supply-chain risks.
---

# Skill Check

Use this skill only for defensive analysis of existing skill or plugin files.
Do not use it to create bypasses, tune malicious samples, or hide indicators
from scanners.

## Core Workflow

1. Identify the target path: a `SKILL.md` file, a skill folder, or a plugin
   folder. If the user gave a folder, scan the whole folder recursively.
2. Run the bundled static scanner first:

   ```bash
   python scripts/scan_skill.py <target-path> --format markdown
   ```

   Use `--format json` when a machine-readable report is useful. Use
   `--fail-on high` in CI-style checks.
3. Read the target files yourself for semantic review. Treat the script output
   as triage, not a final verdict.
4. Inspect any finding in context. Security skills may contain dangerous terms
   as detector rules or educational examples; real risk depends on whether the
   skill instructs the agent to perform the action.
5. Produce a concise report with overall risk, evidence, locations,
   confidence, and remediation steps.

## What To Check

- **Structure:** unusual file size, invalid UTF-8, binary bytes, hidden Unicode
  controls, HTML comments, data URIs, JavaScript links, and long encoded blobs.
- **Executable payloads:** dynamic execution, shell download-and-run patterns,
  web shell signatures, deserialization payloads, obfuscation, suspicious
  script files, and polyglot-like Markdown/HTML/script mixtures.
- **AI instruction threats:** permission-boundary violations, concealed
  operation, prompt disclosure attempts, remote instruction delegation, and
  data-leakage behavior.
- **Reference chain:** local referenced files, bundled scripts, absolute system
  paths, path traversal, risky URLs, short links, direct IP URLs, risky TLDs,
  insecure protocols, and package-install commands that change registries or
  execute downloaded content.
- **Operational safety:** whether the skill asks Codex to execute target code,
  install dependencies, run network commands, disable protections, or write
  outside the intended workspace without explicit authorization.

## Severity Rules

- **Critical:** deterministic evidence of RCE, credential theft, destructive
  commands, web shells, encoded executable payloads, or explicit exfiltration.
- **High:** strong evidence of unsafe execution, hidden instructions, remote
  instruction control, download-then-run behavior, or unauthorized filesystem
  access.
- **Medium:** suspicious but contextual signals such as long encodings,
  risky URLs, dangerous APIs in examples, or bundled executable files.
- **Low:** structural anomalies, uncommon formatting, or weak indicators that
  need manual review.
- **Info:** inventory and baseline observations.

When the script flags detector-rule text inside a security scanner, do not
automatically downgrade the whole skill. Confirm whether the suspicious string
is merely a rule literal or is actually used as an instruction or payload.

## Report Format

Return this structure:

```markdown
## Skill Security Report

**Target:** <path>
**Overall rating:** SAFE / LOW RISK / MEDIUM RISK / HIGH RISK / CRITICAL
**Summary:** <one short paragraph>

### Findings

| Severity | Confidence | File:Line | Type | Evidence |
|---|---|---:|---|---|
| High | High | SKILL.md:42 | Remote prompt loading | `...` |

### Analysis

- Explain the highest-risk findings first.
- Distinguish rule references, examples, and actual operating instructions.
- Mention files that were skipped or could not be decoded.

### Remediation

1. Remove or rewrite unsafe instructions.
2. Delete embedded payloads instead of trying to clean them in place.
3. Replace risky external references with trusted, pinned sources.
4. Re-run `scripts/scan_skill.py` and manually review remaining findings.
```

## Safe Handling

- Never execute files from the target skill while auditing them.
- Prefer offline inspection. Do not resolve URLs or install dependencies unless
  the user explicitly requests it and the environment allows it.
- If a skill appears malicious, advise the user to stop using it, remove the
  affected copy, rebuild from a trusted source, and scan other copies.
