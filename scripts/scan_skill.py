#!/usr/bin/env python3
"""
Offline static scanner for AI skill/plugin folders.

The scanner reads files as bytes and text, never imports target modules, and
never executes target code. It is intended as a first-pass triage tool; manual
semantic review is still required for final safety decisions.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlparse


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ZERO_WIDTH = {
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
}

SCRIPT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".js",
    ".mjs",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".ts",
}


@dataclass(frozen=True)
class Rule:
    phase: str
    finding_type: str
    severity: str
    confidence: str
    pattern: str
    description: str
    remediation: str
    flags: int = re.IGNORECASE


@dataclass
class Finding:
    severity: str
    confidence: str
    phase: str
    file: str
    line: int | None
    column: int | None
    finding_type: str
    evidence: str
    description: str
    remediation: str


RULES: Sequence[Rule] = (
    Rule(
        "Phase 2",
        "Dynamic execution",
        "high",
        "high",
        r"(?<!\.)\b(eval|exec|compile)\s*\(",
        "Dynamic code execution can turn skill text into executable payloads.",
        "Remove dynamic execution or replace it with explicit, reviewed logic.",
    ),
    Rule(
        "Phase 2",
        "Shell execution",
        "high",
        "high",
        r"\b(os\.system|os\.popen|subprocess\.(Popen|run|call|check_output)|child_process\.(exec|spawn|fork))\b",
        "The skill or bundled file references direct shell/process execution.",
        "Avoid executing target-controlled commands; require explicit user approval for any shell action.",
    ),
    Rule(
        "Phase 2",
        "PowerShell execution",
        "high",
        "high",
        r"\b(Invoke-Expression|IEX|Invoke-Command|Start-Process|FromBase64String|EncodedCommand)\b",
        "PowerShell execution or encoded command behavior is present.",
        "Remove encoded or hidden PowerShell execution and document any legitimate administrative command.",
    ),
    Rule(
        "Phase 2",
        "Download and execute",
        "critical",
        "high",
        r"\b(curl|wget|irm|iwr|Invoke-WebRequest)\b.{0,120}(\|\s*(sh|bash|python|perl|ruby|node|php|iex)|Invoke-Expression)",
        "Download-and-execute behavior is a common compromise path.",
        "Replace with pinned, reviewed artifacts and separate download from execution.",
    ),
    Rule(
        "Phase 2",
        "Destructive command",
        "critical",
        "high",
        r"\brm\s+-rf\s+/(?:\s|$)|\bRemove-Item\b.{0,80}\b-Recurse\b.{0,80}\b-Force\b|\bdel\s+/[fsq]\b",
        "A destructive filesystem command appears in the skill bundle.",
        "Remove destructive commands or gate them behind explicit, narrow user approval and path validation.",
    ),
    Rule(
        "Phase 2",
        "Web shell signature",
        "critical",
        "high",
        r"(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "A PHP web shell-style user-input-to-execution pattern is present.",
        "Delete the payload and rebuild the skill from trusted source material.",
    ),
    Rule(
        "Phase 2",
        "Java web shell signature",
        "critical",
        "high",
        r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\().{0,120}(request\.getParameter|getParameter\s*\()",
        "A Java/JSP request-parameter-to-process-execution pattern is present.",
        "Delete the payload and rebuild the affected file from trusted source material.",
    ),
    Rule(
        "Phase 2",
        "Obfuscation",
        "medium",
        "medium",
        r"(String\.fromCharCode|chr\s*\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|base64\.b64decode|atob\s*\(|FromBase64String)",
        "Obfuscation or encoded-string reconstruction appears in the file.",
        "Decode and review the content; remove obfuscation unless it is a documented detector rule.",
    ),
    Rule(
        "Phase 2",
        "Unsafe deserialization",
        "high",
        "high",
        r"\b(pickle\.loads?|marshal\.loads?|yaml\.load\s*\(|ObjectInputStream|unserialize\s*\()\b",
        "Unsafe deserialization can execute code or instantiate attacker-controlled objects.",
        "Use safe parsers and avoid deserializing untrusted data.",
    ),
    Rule(
        "Phase 3",
        "Permission bypass instruction",
        "high",
        "medium",
        r"(ignore|bypass|disable|override|circumvent).{0,80}(safety|security|permission|approval|sandbox|restriction)",
        "The text may instruct an agent to bypass safety or permission boundaries.",
        "Rewrite the instruction to preserve user consent, sandboxing, and approval checks.",
    ),
    Rule(
        "Phase 3",
        "Stealth instruction",
        "high",
        "medium",
        r"(secretly|silently|covertly|stealth|without.{0,40}(user|owner).{0,40}(knowledge|consent|approval)|do not.{0,40}(tell|notify|ask))",
        "The text may instruct hidden operation without user awareness.",
        "Remove stealth language and require transparent user-facing actions.",
    ),
    Rule(
        "Phase 3",
        "Prompt extraction",
        "high",
        "medium",
        r"\b(reveal|print|dump|show|exfiltrate)\b.{0,80}(system prompt|developer message|hidden instruction|initial prompt)",
        "The text may request disclosure of hidden model instructions.",
        "Remove prompt extraction instructions and keep analysis focused on user-provided artifacts.",
    ),
    Rule(
        "Phase 3",
        "Remote prompt control",
        "high",
        "medium",
        r"\b(fetch|load|read|visit)\b.{0,80}(remote|external|webpage|url|website).{0,80}(prompt|instruction|follow|execute)",
        "The skill may delegate instructions to untrusted external content.",
        "Treat external content as data only; never follow instructions from fetched pages.",
    ),
    Rule(
        "Phase 3",
        "Data exfiltration instruction",
        "critical",
        "high",
        r"(send|upload|transmit|post|exfiltrate).{0,80}(secret|token|password|credential|private key|\.env|user data|result|file).{0,80}(to|http|server|remote|webhook)",
        "The text may instruct exfiltration of sensitive data or scan results.",
        "Remove exfiltration behavior and keep reports local unless the user explicitly chooses a destination.",
    ),
    Rule(
        "Phase 4",
        "Path traversal",
        "high",
        "high",
        r"(\.\./\.\.|\\\.\.\\\.\.|/etc/(passwd|shadow)|C:\\Windows\\|/root/|%APPDATA%|%USERPROFILE%|\$HOME)",
        "The skill references path traversal or sensitive system paths.",
        "Constrain file access to the target skill folder and avoid sensitive absolute paths.",
    ),
    Rule(
        "Phase 4",
        "Alternate package source",
        "medium",
        "medium",
        r"\b(pip\s+install|npm\s+install|gem\s+install)\b.{0,160}(--index-url|--extra-index-url|--registry|--source)",
        "Package installation uses an alternate registry or source.",
        "Pin trusted sources and require user approval before installing dependencies.",
    ),
)


def severity_at_least(value: str, threshold: str) -> bool:
    return SEVERITY_ORDER[value] >= SEVERITY_ORDER[threshold]


def lower_severity(value: str) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    return order[max(0, order.index(value) - 1)]


def clip(text: str, limit: int = 120) -> str:
    compact = " ".join(text.strip().split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def iter_target_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def line_col_from_offset(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def fenced_code_lines(lines: Sequence[str]) -> set[int]:
    in_fence = False
    result: set[int] = set()
    for index, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            result.add(index)
            in_fence = not in_fence
            continue
        if in_fence:
            result.add(index)
    return result


def is_rule_context(line: str) -> bool:
    markers = (
        "Rule(",
        "pattern=",
        "regex",
        "detection pattern",
        "detect",
        "signature",
        "indicator",
        "scanner",
    )
    return any(marker.lower() in line.lower() for marker in markers)


def is_protective_context(line: str) -> bool:
    protective = (
        "do not",
        "never",
        "must not",
        "forbid",
        "forbidden",
        "prohibit",
        "remove",
        "detect",
        "flag",
        "risk",
        "unsafe",
        "malicious",
        "suspicious",
        "safety",
        "defensive",
        "what to check",
        "instructions to",
    )
    return any(word in line.lower() for word in protective)


def scanner_source_rule_lines(file_name: str, lines: Sequence[str]) -> set[int]:
    """Return lines that are this scanner's own indicator catalog."""
    normalized = file_name.replace("\\", "/")
    if normalized != "scripts/scan_skill.py":
        return set()

    ranges: set[int] = set()
    in_catalog = False
    in_local_catalog = False
    local_indent = ""

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if "data.startswith((b" in stripped or "base64.b64decode" in stripped:
            ranges.add(line_number)
            continue
        if stripped.startswith("RULES:"):
            in_catalog = True
        if in_catalog:
            ranges.add(line_number)
            if stripped.startswith("def severity_at_least"):
                in_catalog = False
            continue

        if stripped.startswith(("payload_markers =", "hidden_patterns =", "url_pattern =", "shorteners =", "dynamic_dns =", "risky_tld =", "direct_ip =")):
            in_local_catalog = True
            local_indent = line[: len(line) - len(line.lstrip())]

        if in_local_catalog:
            ranges.add(line_number)
            if stripped.endswith(")") and line.startswith(local_indent) and not stripped.startswith(("re.compile", "(")):
                in_local_catalog = False

    return ranges


def add_finding(
    findings: list[Finding],
    severity: str,
    confidence: str,
    phase: str,
    file_name: str,
    line: int | None,
    column: int | None,
    finding_type: str,
    evidence: str,
    description: str,
    remediation: str,
) -> None:
    findings.append(
        Finding(
            severity=severity,
            confidence=confidence,
            phase=phase,
            file=file_name,
            line=line,
            column=column,
            finding_type=finding_type,
            evidence=clip(evidence),
            description=description,
            remediation=remediation,
        )
    )


def scan_structure(
    path: Path,
    root: Path,
    data: bytes,
    text: str,
    decode_error: UnicodeDecodeError | None,
    findings: list[Finding],
) -> None:
    file_name = rel(path, root)
    size = len(data)
    if size > 100_000:
        add_finding(
            findings,
            "critical",
            "high",
            "Phase 1",
            file_name,
            None,
            None,
            "Abnormal file size",
            f"{size} bytes",
            "Very large skill files often contain embedded data or payloads.",
            "Split legitimate references into separate files and remove embedded blobs.",
        )
    elif size > 50_000:
        add_finding(
            findings,
            "high",
            "medium",
            "Phase 1",
            file_name,
            None,
            None,
            "Large file size",
            f"{size} bytes",
            "The file is unusually large for a skill component.",
            "Review for embedded binaries, encoded content, or unrelated bulk data.",
        )
    elif size > 20_000:
        add_finding(
            findings,
            "low",
            "medium",
            "Phase 1",
            file_name,
            None,
            None,
            "Elevated file size",
            f"{size} bytes",
            "The file is larger than a typical concise skill file.",
            "Confirm the size is due to legitimate instructions or references.",
        )

    if decode_error is not None:
        add_finding(
            findings,
            "high",
            "high",
            "Phase 1",
            file_name,
            None,
            None,
            "Invalid UTF-8",
            str(decode_error),
            "Invalid text encoding can hide payloads or confuse review tools.",
            "Re-encode the file as clean UTF-8 from a trusted source.",
        )

    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        add_finding(
            findings,
            "high",
            "high",
            "Phase 1",
            file_name,
            1,
            1,
            "UTF-16 BOM",
            data[:4].hex(),
            "UTF-16 content in a Markdown skill can hide unexpected bytes.",
            "Convert the file to UTF-8 and review the decoded text.",
        )

    control_positions = [
        index for index, byte in enumerate(data) if (byte < 32 and byte not in (9, 10, 13))
    ]
    if control_positions:
        ratio = len(control_positions) / max(size, 1)
        severity = "critical" if ratio > 0.05 else "medium"
        add_finding(
            findings,
            severity,
            "high",
            "Phase 1",
            file_name,
            None,
            None,
            "Control bytes",
            f"{len(control_positions)} control bytes ({ratio:.2%})",
            "Non-text control bytes are unusual in skill files.",
            "Remove binary/control bytes and rebuild the file as plain UTF-8 text.",
        )

    for index, char in enumerate(text):
        codepoint = ord(char)
        if codepoint in ZERO_WIDTH:
            line, column = line_col_from_offset(text, index)
            add_finding(
                findings,
                "medium",
                "high",
                "Phase 1",
                file_name,
                line,
                column,
                "Hidden Unicode control",
                f"U+{codepoint:04X} {ZERO_WIDTH[codepoint]}",
                "Invisible Unicode controls can hide instructions or alter text rendering.",
                "Remove the invisible character unless there is a documented typography need.",
            )

    hidden_patterns = (
        (r"<!--.*?-->", "HTML comment", "HTML comments can hide instructions from casual review."),
        (r"data:[^)\s>]+", "Data URI", "Data URIs can embed executable or encoded content."),
        (r"\]\(\s*javascript:", "JavaScript link", "Markdown JavaScript links can execute in some renderers."),
    )
    scanner_catalog = scanner_source_rule_lines(file_name, text.splitlines())
    for pattern, finding_type, description in hidden_patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            line, column = line_col_from_offset(text, match.start())
            if line in scanner_catalog:
                continue
            add_finding(
                findings,
                "medium",
                "medium",
                "Phase 1",
                file_name,
                line,
                column,
                finding_type,
                match.group(0),
                description,
                "Remove hidden or active content from skill documentation.",
            )

    if path.name == "SKILL.md":
        if not text.startswith("---\n"):
            add_finding(
                findings,
                "medium",
                "high",
                "Phase 1",
                file_name,
                1,
                1,
                "Missing frontmatter",
                "SKILL.md does not start with YAML frontmatter",
                "Skills require frontmatter for reliable discovery.",
                "Add YAML frontmatter with only name and description fields.",
            )
        elif not re.search(r"(?m)^name:\s*\S+", text) or not re.search(
            r"(?m)^description:\s*", text
        ):
            add_finding(
                findings,
                "medium",
                "high",
                "Phase 1",
                file_name,
                1,
                1,
                "Incomplete frontmatter",
                "Missing name or description",
                "Incomplete metadata can cause incorrect skill triggering.",
                "Add both name and description fields to frontmatter.",
            )

    if path.suffix.lower() in SCRIPT_SUFFIXES and path.name != "scan_skill.py":
        add_finding(
            findings,
            "low",
            "medium",
            "Phase 2",
            file_name,
            None,
            None,
            "Bundled executable file",
            path.suffix.lower(),
            "Executable files in skills deserve manual review even when no pattern matches.",
            "Confirm the script is deterministic, defensive, and never executes target-controlled code.",
        )


def scan_encoded_content(
    path: Path,
    root: Path,
    text: str,
    fence_lines: set[int],
    findings: list[Finding],
) -> None:
    file_name = rel(path, root)
    payload_markers = (
        b"MZ",
        b"\x7fELF",
        b"<?php",
        b"<script",
        b"#!/bin/",
        b"eval(",
        b"Invoke-Expression",
        b"child_process",
    )
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])", text):
        line, column = line_col_from_offset(text, match.start())
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        severity = "medium"
        description = "A long base64-like string appears in the file."
        if decoded and any(marker in decoded for marker in payload_markers):
            severity = "critical"
            description = "Base64 content decodes to executable or script-like bytes."
        elif line in fence_lines:
            severity = "low"
        add_finding(
            findings,
            severity,
            "medium",
            "Phase 2",
            file_name,
            line,
            column,
            "Long base64 string",
            token[:80],
            description,
            "Decode and review the content; remove embedded payloads or move legitimate samples to references.",
        )

    hex_patterns = (
        r"(?:\\x[0-9a-fA-F]{2}){16,}",
        r"(?<![0-9a-fA-F])[0-9a-fA-F]{80,}(?![0-9a-fA-F])",
    )
    for pattern in hex_patterns:
        for match in re.finditer(pattern, text):
            line, column = line_col_from_offset(text, match.start())
            token = match.group(0)
            raw = token.replace("\\x", "")
            decoded = b""
            try:
                decoded = bytes.fromhex(raw)
            except ValueError:
                pass
            severity = "medium"
            description = "A long hex-encoded string appears in the file."
            if decoded and any(marker in decoded for marker in payload_markers):
                severity = "critical"
                description = "Hex content decodes to executable or script-like bytes."
            elif line in fence_lines:
                severity = "low"
            add_finding(
                findings,
                severity,
                "medium",
                "Phase 2",
                file_name,
                line,
                column,
                "Long hex string",
                token[:80],
                description,
                "Decode and review the content; remove hidden payloads.",
            )


def scan_rules(
    path: Path,
    root: Path,
    text: str,
    fence_lines: set[int],
    findings: list[Finding],
) -> None:
    file_name = rel(path, root)
    lines = text.splitlines()
    scanner_catalog = scanner_source_rule_lines(file_name, lines)
    for rule in RULES:
        compiled = re.compile(rule.pattern, rule.flags)
        for line_number, line in enumerate(lines, start=1):
            if line_number in scanner_catalog:
                continue
            for match in compiled.finditer(line):
                severity = rule.severity
                confidence = rule.confidence
                description = rule.description
                if line_number in fence_lines or is_rule_context(line) or is_protective_context(line):
                    severity = lower_severity(severity)
                    confidence = "medium"
                    description = (
                        rule.description
                        + " The local context looks like an example, prohibition, or detector rule; verify manually."
                    )
                add_finding(
                    findings,
                    severity,
                    confidence,
                    rule.phase,
                    file_name,
                    line_number,
                    match.start() + 1,
                    rule.finding_type,
                    match.group(0),
                    description,
                    rule.remediation,
                )


def scan_urls(path: Path, root: Path, text: str, findings: list[Finding]) -> None:
    file_name = rel(path, root)
    scanner_catalog = scanner_source_rule_lines(file_name, text.splitlines())
    url_pattern = re.compile(
        r"\b(?:https?|ftp|file)://[^\s<>)\"']+|\b(?:javascript|data):[^\s<>)\"']+",
        re.IGNORECASE,
    )
    shorteners = re.compile(r"(bit\.ly|t\.co|tinyurl\.com|ow\.ly|is\.gd|buff\.ly|goo\.gl)", re.I)
    dynamic_dns = re.compile(r"(duckdns\.org|no-ip\.com|ddns\.net|hopto\.org|zapto\.org)", re.I)
    risky_tld = re.compile(r"\.(tk|ml|ga|cf|gq|xyz|top|work|date|loan|win)$", re.I)
    direct_ip = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip(".,;]")
        line, column = line_col_from_offset(text, match.start())
        if line in scanner_catalog:
            continue
        parsed = urlparse(url)
        host = parsed.hostname or ""
        reasons: list[str] = []
        if parsed.scheme in {"file", "ftp", "javascript", "data"}:
            reasons.append(f"dangerous protocol {parsed.scheme}:")
        if direct_ip.match(host):
            reasons.append("direct IP host")
        if parsed.port and parsed.port not in {80, 443, 3000, 5000, 8000, 8080, 8443}:
            reasons.append(f"unusual port {parsed.port}")
        if shorteners.search(host):
            reasons.append("URL shortener")
        if dynamic_dns.search(host):
            reasons.append("dynamic DNS")
        if risky_tld.search(host):
            reasons.append("risky TLD")
        if reasons:
            add_finding(
                findings,
                "medium",
                "medium",
                "Phase 4",
                file_name,
                line,
                column,
                "Suspicious URL",
                url,
                "The URL has suspicious characteristics: " + ", ".join(reasons) + ".",
                "Replace with trusted, pinned, official references or remove the URL.",
            )
        else:
            add_finding(
                findings,
                "info",
                "medium",
                "Phase 4",
                file_name,
                line,
                column,
                "External URL",
                url,
                "External references should be treated as untrusted data unless verified.",
                "Confirm the URL is needed and points to a trusted source.",
            )


def scan_file(path: Path, root: Path, findings: list[Finding]) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        add_finding(
            findings,
            "medium",
            "high",
            "Phase 1",
            rel(path, root),
            None,
            None,
            "Unreadable file",
            str(exc),
            "Unreadable files cannot be audited.",
            "Fix permissions or remove unexpected files.",
        )
        return

    decode_error: UnicodeDecodeError | None = None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        decode_error = exc
        text = data.decode("utf-8", errors="replace")

    scan_structure(path, root, data, text, decode_error, findings)
    lines = text.splitlines()
    fence_lines = fenced_code_lines(lines)
    scan_encoded_content(path, root, text, fence_lines, findings)
    scan_rules(path, root, text, fence_lines, findings)
    scan_urls(path, root, text, findings)


def summarize(files: Sequence[Path], findings: Sequence[Finding]) -> dict[str, object]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    max_severity = "info"
    for finding in findings:
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[max_severity]:
            max_severity = finding.severity
    rating = {
        "info": "SAFE",
        "low": "LOW RISK",
        "medium": "MEDIUM RISK",
        "high": "HIGH RISK",
        "critical": "CRITICAL",
    }[max_severity]
    return {
        "files_scanned": len(files),
        "finding_counts": counts,
        "max_severity": max_severity,
        "overall_rating": rating,
    }


def markdown_report(target: Path, files: Sequence[Path], findings: Sequence[Finding]) -> str:
    summary = summarize(files, findings)
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER[item.severity],
            item.file,
            item.line or 0,
            item.finding_type,
        ),
    )
    lines: list[str] = [
        "## Skill Security Report",
        "",
        f"**Target:** `{target}`",
        f"**Files scanned:** {summary['files_scanned']}",
        f"**Overall rating:** {summary['overall_rating']}",
        "",
        "### Severity Counts",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    counts = summary["finding_counts"]
    assert isinstance(counts, dict)
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.title()} | {counts[severity]} |")

    if not sorted_findings:
        lines.extend(
            [
                "",
                "### Findings",
                "",
                "No findings were detected by the static scanner. Manual review is still recommended.",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "",
            "### Findings",
            "",
            "| Severity | Confidence | Location | Type | Evidence |",
            "|---|---|---:|---|---|",
        ]
    )
    for finding in sorted_findings:
        location = finding.file
        if finding.line is not None:
            location += f":{finding.line}"
        evidence = finding.evidence.replace("|", "\\|")
        lines.append(
            f"| {finding.severity.title()} | {finding.confidence.title()} | "
            f"`{location}` | {finding.finding_type} | `{evidence}` |"
        )

    lines.extend(["", "### Remediation Notes", ""])
    seen: set[tuple[str, str]] = set()
    for finding in sorted_findings:
        if finding.severity in {"info", "low"}:
            continue
        key = (finding.finding_type, finding.remediation)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- **{finding.finding_type}:** {finding.remediation}")

    lines.extend(
        [
            "",
            "### Integrity",
            "",
            "| File | SHA-256 |",
            "|---|---|",
        ]
    )
    root = target if target.is_dir() else target.parent
    for path in files:
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = "unreadable"
        lines.append(f"| `{rel(path, root)}` | `{digest}` |")
    return "\n".join(lines)


def json_report(target: Path, files: Sequence[Path], findings: Sequence[Finding]) -> str:
    root = target if target.is_dir() else target.parent
    payload = {
        "target": str(target),
        "summary": summarize(files, findings),
        "files": [rel(path, root) for path in files],
        "findings": [asdict(finding) for finding in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline static scanner for AI skill/plugin folders.")
    parser.add_argument("target", help="Path to a SKILL.md file, skill folder, or plugin folder.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        help="Exit with code 2 when any finding meets or exceeds this severity.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    root = target if target.is_dir() else target.parent
    files = iter_target_files(target)
    findings: list[Finding] = []
    for path in files:
        scan_file(path, root, findings)

    if args.format == "json":
        print(json_report(target, files, findings))
    else:
        print(markdown_report(target, files, findings))

    if args.fail_on and any(severity_at_least(item.severity, args.fail_on) for item in findings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
