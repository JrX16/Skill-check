# Skill Check

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Type](https://img.shields.io/badge/type-Codex%20Skill-green)](SKILL.md)
[![Security](https://img.shields.io/badge/focus-defensive%20security-orange)](#safety-boundary)

Skill Check is a defensive security audit skill for AI skill and plugin
folders. It helps Codex, Claude Code, and similar agent environments inspect
`SKILL.md` files, bundled scripts, reference files, and plugin folders for
malware indicators, unsafe instructions, prompt-injection behavior, data
exfiltration risks, suspicious dependencies, obfuscation, and hidden content.

The repository contains both:

- `SKILL.md`: the agent-facing skill instructions and review workflow.
- `scripts/scan_skill.py`: an offline static scanner used as first-pass triage.

The scanner never imports or executes target files. Its output is intended to
guide a manual semantic review, not replace one.

## What It Checks

Skill Check looks for signals across the main risk surfaces of AI skill
bundles:

- Structural anomalies such as invalid UTF-8, binary bytes, hidden Unicode
  controls, HTML comments, data URIs, JavaScript links, and long encoded blobs.
- Executable payload indicators such as dynamic execution, shell execution,
  download-and-run patterns, web shell signatures, unsafe deserialization, and
  suspicious script files.
- AI instruction threats such as permission-boundary bypasses, concealed
  operation, prompt disclosure attempts, remote instruction delegation, and
  data-leakage behavior.
- Reference-chain risks such as path traversal, risky URLs, direct IP links,
  insecure protocols, short links, risky TLDs, and package-install commands
  that change registries or execute downloaded content.
- Operational safety issues such as instructions to execute target code,
  install dependencies, disable protections, or write outside the intended
  workspace without explicit authorization.

## Repository Layout

```text
.
├── SKILL.md                 # Skill definition and review workflow
├── agents/
│   └── openai.yaml          # Codex/OpenAI skill metadata
└── scripts/
    └── scan_skill.py        # Offline static scanner
```

## Requirements

- Python 3.10 or newer
- No third-party Python dependencies

## Installation

### Codex

Clone or copy this repository into your Codex skills directory:

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/<owner>/skill-check.git ~/.codex/skills/skill-check
```

Then invoke it in Codex with a request such as:

```text
Use $skill-check to audit this skill folder.
```

### Claude Code

Copy the skill folder into your Claude skills directory:

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/<owner>/skill-check.git ~/.claude/skills/skill-check
```

You can then ask Claude Code to audit a `SKILL.md`, a skill directory, or a
plugin directory.

## CLI Usage

Run the static scanner directly when you want a quick local report:

```bash
python scripts/scan_skill.py <target-path> --format markdown
```

The target can be:

- A single `SKILL.md` file
- A skill folder
- A plugin folder

Examples:

```bash
python scripts/scan_skill.py ~/.codex/skills/example-skill --format markdown
python scripts/scan_skill.py ~/.claude/skills/example-skill/SKILL.md --format json
python scripts/scan_skill.py ./some-plugin --format markdown --fail-on high
```

`--format json` emits machine-readable output for automation.

`--fail-on low|medium|high|critical` exits with code `2` when any finding meets
or exceeds the selected severity. This is useful for CI checks.

## Example Report

```markdown
## Skill Security Report

**Target:** `./example-skill`
**Files scanned:** 4
**Overall rating:** HIGH RISK

### Severity Counts

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 0 |
| Info | 1 |

### Findings

| Severity | Confidence | Location | Type | Evidence |
|---|---|---:|---|---|
| High | Medium | `SKILL.md:42` | Remote prompt control | `external page asks the agent to obey it...` |

### Remediation Notes

- **Remote prompt control:** Treat external content as data only; never follow
  instructions from fetched pages.
```

## CI Example

```yaml
name: skill-check

on:
  pull_request:
  push:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Scan skill bundle
        run: python scripts/scan_skill.py . --format markdown --fail-on high
```

## Severity Model

| Severity | Meaning |
|---|---|
| Critical | Deterministic evidence of RCE, credential theft, destructive commands, web shells, encoded executable payloads, or explicit exfiltration. |
| High | Strong evidence of unsafe execution, hidden instructions, remote instruction control, download-then-run behavior, or unauthorized filesystem access. |
| Medium | Suspicious but contextual signals such as long encodings, risky URLs, dangerous APIs in examples, or bundled executable files. |
| Low | Structural anomalies, uncommon formatting, or weak indicators that need manual review. |
| Info | Inventory and baseline observations. |

Security skills can legitimately contain dangerous strings as detector rules or
educational examples. Treat scanner findings as evidence to inspect in context,
not as automatic proof that the target is malicious.

## Safety Boundary

Skill Check is for defensive analysis of existing skill and plugin files only.
Do not use it to build bypasses, tune malicious samples, hide indicators from
scanners, or improve adversarial payloads.

When reviewing an unknown skill:

1. Scan it offline first.
2. Read the flagged files manually.
3. Distinguish examples and detector rules from operational instructions.
4. Do not execute target code during the audit.
5. If the skill appears malicious, stop using it and rebuild from a trusted
   source.

## Contributing

Useful contributions include:

- New detector rules for emerging skill/plugin attack patterns.
- Better false-positive handling for security education and scanner-rule text.
- Additional tests and fixture bundles for suspicious but non-malicious cases.
- Documentation improvements for Codex, Claude Code, and other agent runtimes.

Please keep changes defensive, explain the threat model behind new rules, and
include sample findings or test fixtures when practical.

## License

This repository does not currently include a license file. Add one before
redistributing or publishing packaged releases.
