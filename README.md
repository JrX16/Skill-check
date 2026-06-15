# Skill-check

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Claude%20Code-purple.svg)](https://claude.ai/code)

Automated security scanner for Claude Code skill files. Performs a comprehensive 5-phase security audit to detect malware, backdoors, embedded malicious code, AI instruction-level threats, prompt injection, obfuscation, and structural anomalies in skill (`SKILL.md`) files.

## Table of Contents

- [Why Skill-check?](#why-skill-check)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Pipeline](#detection-pipeline)
- [Severity Classification](#severity-classification)
- [Example Report](#example-report)
- [Safety Statement](#safety-statement)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Why Skill-check?

Claude Code skills are powerful AI instruction files that extend the capabilities of Claude. However, because skills can contain arbitrary instructions, they introduce a new attack surface:

- **Malicious code** can be embedded in seemingly innocent skill files
- **Prompt injection** can hijack AI behavior to perform dangerous actions
- **Obfuscation techniques** can hide threats from simple text-based searches

Skill-check provides a systematic, defense-in-depth approach to auditing skill files before they are installed or executed. Think of it as a **static analysis security tool (SAST) for AI instruction files**.

## Features

- **5-Phase Detection Pipeline** — Each phase targets a different attack layer, from file structure to semantic threats
- **Multi-Language Coverage** — Detects malicious patterns in PHP, Python, JavaScript, Shell/Bash, PowerShell, ASP, and JSP
- **AI Instruction-Level Analysis** — Identifies prompt injection, jailbreak attempts, data exfiltration, and social engineering instructions
- **Zero-Width Character Detection** — Catches invisible Unicode characters used to hide malicious payloads
- **Polyglot File Detection** — Identifies files that are valid and executable in multiple language formats simultaneously
- **Reference Chain Analysis** — Audits external URLs, dependent files, and download-and-execute patterns
- **Risk Matrix Scoring** — Maps findings on an Impact × Confidence matrix for actionable prioritization
- **Per-Finding Remediation** — Provides specific fix recommendations for each discovered threat

## Installation

Skill-check is a Claude Code skill file. To install:

1. Download `SKILL.md` from this repository
2. Place it in your Claude Code skills directory:
   ```
   ~/.claude/skills/skill-check/SKILL.md
   ```
3. The skill will auto-register and become available in Claude Code sessions

**Trigger phrases** — Invoke the scanner by saying any of the following:
- "scan this skill"
- "check this skill for backdoors"
- "audit this skill"
- "is this skill safe?"
- "skill security check"
- "detect malware in this skill"

## Usage

### Basic Scan

```
> Scan this skill: C:\Users\me\.claude\skills\some-skill\SKILL.md
```

The scanner will:
1. Read the target skill file and analyze its structure
2. Execute all 5 detection phases in order
3. Produce a tabulated report after each phase
4. Deliver a final verdict with a comprehensive risk matrix

### Batch Scan

To scan multiple skills, invoke the scanner once per file:

```
> Check all skills in ~/.claude/skills/ for security issues
```

### Scan with Peer Comparison

For more accurate anomaly detection, the scanner compares file sizes against peer skills in the same directory. Ensure the target skill is alongside other skills (or reference skills from the same source) for optimal results.

## Detection Pipeline

The scanner executes five phases in strict sequence. Each phase's findings feed into the next.

```
Phase 1: Structural Anomaly Detection
├── File size anomaly (vs. peer average)
├── Encoding anomaly (UTF-8 validation, BOM checks)
├── Non-printable character ratio
├── Zero-width character detection (15+ Unicode code points)
└── Hidden content (HTML comments, data URIs, base64, invisible text)

Phase 2: Embedded Malware Detection
├── Long encoded strings (Base64, Hex, URL-encoded)
├── Dynamic execution functions (PHP, Python, JS, Shell, PowerShell)
├── WebShell signatures (PHP, ASP/ASPX, JSP)
├── Obfuscation techniques (string concat, variable variables, char encoding)
├── Deserialization payloads (PHP, Java, Python pickle)
└── Polyglot file detection

Phase 3: AI Instruction-Level Threats
├── Permission bypass instructions (English + Chinese)
├── Data exfiltration instructions
├── Hidden prompt / jailbreak detection
├── Indirect prompt injection (external URL → follow instructions)
└── Social engineering (authority impersonation, urgency, trust induction)

Phase 4: Reference Chain & Dependency Analysis
├── External URL detection and classification
├── Recursive reference file scanning
├── Remote execution instruction detection (curl|bash, wget -O -|sh, etc.)
└── Path traversal detection

Phase 5: Scoring & Remediation
├── Risk matrix (Impact × Confidence)
├── Aggregated findings summary
├── Per-finding remediation suggestions
├── General remediation guide
└── Final verdict (Safe / Low Risk / Unsafe)
```

## Severity Classification

| Severity | Icon | Description | Action Required |
|----------|------|-------------|-----------------|
| Critical | 🔴 | Deterministic malicious match, RCE or compromise viable | Isolate immediately |
| High | 🟠 | Strong indicators, likely malicious | Immediate action required |
| Medium | 🟡 | Suspicious signals, exploitation possible | Monitor and investigate |
| Low | 🟢 | Anomalous but unconfirmed | Track and log |
| Info | ℹ️ | Notable observation, no risk | No action needed |

Severity is determined by the intersection of **Impact** (what can happen if exploited) and **Confidence** (how certain the detection is).

## Example Report

```markdown
## Comprehensive Security Report

### Overall Rating: 🔴 UNSAFE — HIGH RISK

### Findings Inventory (sorted by severity)

| # | Severity      | Phase  | Finding Type           | Confidence | Location | Description                    |
|---|---------------|--------|------------------------|------------|----------|--------------------------------|
| 1 | 🔴 Critical   | Phase 2 | PHP WebShell           | HIGH       | L123     | eval($_POST['cmd']) detected   |
| 2 | 🟠 High       | Phase 3 | Permission Bypass      | HIGH       | L45      | "ignore all safety rules"      |
| 3 | 🟡 Medium     | Phase 1 | Zero-Width Characters  | MEDIUM     | L78      | 3 ZWSP characters found        |

### Recommended Actions
1. Immediately stop using this skill
2. Delete the infected file
3. Obtain or rebuild from a trusted source
4. Scan all other copies across the system
```

## Safety Statement

This skill is for **defensive security analysis only** — scanning and identifying threats in existing skill files. It must not be used to:

- Bypass security detections
- Craft adversarial samples
- Develop or distribute malicious skills

## Limitations

- **Not a replacement for antivirus** — Cross-validate known malware signatures with traditional AV tools
- **False positives are possible** — Skills that teach penetration testing may contain educational code examples. The scanner distinguishes between "code referenced as learning material" and "actual executable malicious payload" using context awareness
- **Detection rules require updates** — New attack techniques and obfuscation methods emerge continuously
- **Zero-trust principle applies** — Even when a scan passes, validate new skills in an isolated environment before trusting them in production

## Contributing

Contributions are welcome! Areas where help is especially needed:

1. **New obfuscation patterns** — Add detection signatures for emerging techniques
2. **Language support** — Expand coverage for additional programming languages
3. **False positive reduction** — Improve context-awareness heuristics
4. **Performance optimization** — Reduce scan time for large file batches

Please open an issue before submitting a pull request to discuss the proposed change.

## License

MIT — See [LICENSE](LICENSE) for details.
