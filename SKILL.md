---
name: skill-check
description: >-
  Automated security scanner for Claude Code skill files. Performs comprehensive
  5-phase security audit to detect malware, backdoors, embedded malicious code,
  AI instruction-level threats, prompt injection, obfuscation, and structural
  anomalies in skill (SKILL.md) files. Use whenever the user wants to scan, audit,
  check, or verify the security of a skill file, plugin, or AI instruction file.
  Trigger on phrases like "scan this skill", "check for backdoors", "audit skill",
  "is this skill safe", "skill security", "detect malware in skill", or any request
  to verify the safety of a SKILL.md or similar AI instruction file.
---

# Skill Security Scanner

Performs a systematic 5-phase security audit on Claude Code skill files to detect
malicious code, backdoors, embedded threats, AI instruction-level attacks,
obfuscation techniques, and structural anomalies.

## Safety Statement

This skill is for **defensive security analysis only** — scanning and identifying
threats in existing skill files. It must not be used to bypass security detections
or craft adversarial samples.

---

## Five-Phase Detection Pipeline

Execute each phase in strict order. Each phase's findings feed into the next.
Produce a structured report upon completion.

```
Phase 1: Structural Anomaly Detection    →  File-level baseline anomalies
Phase 2: Embedded Malware Detection      →  Technical payloads and virus signatures
Phase 3: AI Instruction-Level Threats    →  Prompt injection and semantic attacks
Phase 4: Reference Chain & Dependency    →  External resource risks
Phase 5: Scoring & Remediation           →  Risk matrix + per-item fix plan
```

---

## Phase 1: Structural Anomaly Detection

**Objective:** Discover anomalous signals at the file level, independent of
content semantics.

### 1.1 File Size Anomaly

```
Detection Rules:
- < 5KB    : Normal (concise skill)
- 5–20KB   : Normal (detailed skill with examples)
- 20–50KB  : Suspicious ⚠️  — investigate for non-skill bulk content
- 50–100KB : High Risk 🔴   — highly likely contains embedded data
- > 100KB  : Critical 🚨     — near-certain hidden payload

Detection Method:
1. Check actual file size in bytes
2. Compare against the average size of peer skills in the same directory
3. If file exceeds 3× the peer average, flag as anomalous
4. Record the ratio of file size to visible text content
```

### 1.2 Encoding Anomaly

```
Detection Rules:
- Verify the file is pure UTF-8 encoded
- Detect BOM (Byte Order Mark) anomalies: UTF-16 BOM (0xFF 0xFE) inside a
  UTF-8-declared file
- Detect mixed encoding: multiple encoding fragments within one file
- Detect non-standard bytes: 0x00–0x08, 0x0B, 0x0C, 0x0E–0x1F (non-printable
  control characters)
- Detect orphan bytes in the 0x80–0xFF range that violate UTF-8 sequence rules

Detection Method:
1. Use file-type detection tools to check actual encoding
2. Scan for non-UTF-8 byte sequences throughout the file
3. Check for encoding masquerade (file declares UTF-8 but contains other encodings)
```

### 1.3 Non-Printable Character Ratio

```
Detection Rules:
- Count characters outside the printable ASCII range (>0x7E or <0x20,
  excluding \n \r \t)
- Ratio > 5%:  Suspicious ⚠️
- Ratio > 15%: High Risk 🔴
- Ratio > 30%: Critical 🚨 (almost certainly binary or encrypted payload)

Detection Method:
1. Perform byte-level analysis of file content
2. Calculate the non-printable character ratio
3. Locate regions with high concentrations of non-printable characters
```

### 1.4 Zero-Width Character Detection

```
Zero-Width Character Catalog (Unicode):
- U+200B : ZERO WIDTH SPACE
- U+200C : ZERO WIDTH NON-JOINER
- U+200D : ZERO WIDTH JOINER
- U+200E : LEFT-TO-RIGHT MARK
- U+200F : RIGHT-TO-LEFT MARK
- U+FEFF : ZERO WIDTH NO-BREAK SPACE (BOM)
- U+202A : LEFT-TO-RIGHT EMBEDDING
- U+202B : RIGHT-TO-LEFT EMBEDDING
- U+202C : POP DIRECTIONAL FORMATTING
- U+202D : LEFT-TO-RIGHT OVERRIDE
- U+202E : RIGHT-TO-LEFT OVERRIDE
- U+2060 : WORD JOINER
- U+2061–U+2064 : INVISIBLE OPERATORS
- U+180E : MONGOLIAN VOWEL SEPARATOR

Detection Method:
1. Scan character-by-character, matching the above Unicode code points
2. Report each zero-width character's position (line:col) and type
3. Zero-width characters are commonly used for:
   - Hidden instructions (embedding control commands between invisible chars)
   - Watermark tracking (embedding user IDs for traceability)
   - Evading string-matching-based detection

⚠️ Any zero-width character appearing in an unexpected position must be flagged
   as suspicious.
```

### 1.5 Hidden Content Detection

```
Detection Rules:
- HTML comments: <!-- ... --> (skill files should never contain HTML comments)
- Markdown comment variants: [//]: # (...) containing suspicious content
- Invisible text: foreground-color = background-color (in CSS/HTML)
- Tiny font: font-size < 1px text blocks
- Collapsed/hidden blocks: HTML <details>/<summary> containing non-documentation code
- Data URIs: data:text/html;base64,... embedded content
- Base64 in unexpected positions: outside code blocks, length > 200 characters

Detection Method:
1. Search for <!-- and --> markers
2. Search for data: prefixed URIs
3. Check Markdown links for hidden references: [text](javascript:...)
4. Check for long base64 strings outside fenced code blocks
```

### Phase 1 Output Format

```markdown
## Phase 1: Structural Anomaly Detection — Results

| Check Item       | Result      | Details                          |
|------------------|-------------|----------------------------------|
| File Size        | ✅/⚠️/🔴     | X KB, peer average Y KB          |
| Encoding         | ✅/⚠️/🔴     | UTF-8 / anomaly detected         |
| Non-Printable    | ✅/⚠️/🔴     | X% ratio                         |
| Zero-Width Chars | ✅/⚠️/🔴     | N found (position list)          |
| Hidden Content   | ✅/⚠️/🔴     | Found / not found                |

**Phase 1 Verdict:** [PASS / Needs Further Analysis / Anomaly Found]
```

---

## Phase 2: Embedded Malware Detection

**Objective:** Detect technical malicious payloads embedded within the skill text.

### 2.1 Long Encoded String Detection

```
Base64 Patterns:
  regex: [A-Za-z0-9+/]{100,}={0,2}
  regex: [A-Za-z0-9+/]{200,}

  Detection Method:
  1. Extract all matching base64 strings
  2. Attempt to decode each match
  3. Check decoded output for executable code signatures
  4. Flag decoded results matching these categories:
     - Script code (<?php, <script, #!/bin/, import, def)
     - Shell commands (wget, curl, nc, /bin/bash, cmd.exe)
     - Serialized objects (O:number:, a:number:{)
     - PE headers (MZ marker)
     - ELF headers (\x7fELF)

Hex Encoding Patterns:
  regex: (0x[0-9A-Fa-f]{2}[0-9A-Fa-f]{10,})  (long hex string)
  regex: (\\x[0-9A-Fa-f]{2}){20,}             (escaped hex byte sequence)
  regex: [0-9A-Fa-f]{64,}                      (raw hex, 64+ chars)

  Detection Method:
  1. Extract hex-encoded strings
  2. Decode to raw bytes
  3. Match decoded bytes against malicious signatures

URL-Encoded Obfuscation:
  regex: (%[0-9A-Fa-f]{2}){20,}  (long URL-encoded sequence)

  Detection Method:
  1. URL-decode the sequence
  2. Check decoded result for suspicious commands
```

### 2.2 Known Malicious Pattern Detection

```
Dynamic Execution Functions (HIGH RISK):
  Search for the following patterns and all their variants:

  PHP:
    eval\s*\(
    assert\s*\(
    preg_replace\s*\(.*\/e
    create_function\s*\(
    call_user_func\s*\(
    system\s*\(
    exec\s*\(
    shell_exec\s*\(
    passthru\s*\(
    popen\s*\(
    proc_open\s*\(
    \$_GET\[
    \$_POST\[
    \$_REQUEST\[
    \$_COOKIE\[
    \$_FILES\[
    file_get_contents\s*\(
    file_put_contents\s*\(
    include\s*\(\s*\$_(GET|POST)
    require\s*\(\s*\$_(GET|POST)

  Python:
    exec\s*\(
    eval\s*\(
    compile\s*\(
    __import__\s*\(\s*['\"]os['\"]
    subprocess\.(call|Popen|run|check_output)
    os\.(system|popen)
    pickle\.loads?\s*\(
    marshal\.loads?\s*\(
    base64\.b64decode\s*\(
    getattr\s*\(

  JavaScript / Node:
    eval\s*\(
    Function\s*\(
    new\s+Function
    child_process\.(exec|spawn|fork)
    require\(['\"](child_process|net|fs)
    process\.binding\(
    vm\.(runInNewContext|runInThisContext|Script)
    setTimeout\s*\(\s*['\"].*['\"]\s*\)
    setInterval\s*\(\s*['\"].*['\"]\s*\)

  Shell / Bash:
    \|\s*(sh|bash|zsh|ksh)
    \|\s*(nc|netcat|ncat)
    >\/dev\/tcp\/
    \|\s*base64\s+(-d|--decode)
    rm\s+-rf\s+\/
    curl.*\|\s*(sh|bash)
    wget.*-O\s*-\s*\|\s*(sh|bash)
    chmod\s+\+x
    \/dev\/(tcp|udp)\/

  PowerShell:
    Invoke-Expression
    IEX\s*\(
    Invoke-Command
    -EncodedCommand\s+
    -enc\s+
    FromBase64String
    New-Object\s+Net\.WebClient
    New-Object\s+Net\.Sockets\.TCPClient
    DownloadString\s*\(
    DownloadFile\s*\(
    Start-Process\s+.*-WindowStyle\s+Hidden

⚠️ Context Awareness: Skill files may legitimately discuss these functions
   (e.g., in security education contexts).
   Discrimination criteria: Check whether the function appears inside a fenced
   code block (```...```) as an educational reference, or outside code blocks
   as a payload. Educational references typically have explanatory comments and
   surrounding context.
```

### 2.3 WebShell Signature Detection

```
PHP WebShell Signatures:
  Combinatorial patterns (match any = flag):
  - eval + ($_GET | $_POST | $_REQUEST)
  - assert + ($_GET | $_POST | $_REQUEST)
  - system/exec/shell_exec + ($_GET | $_POST | $_REQUEST)
  - file_put_contents + ($_GET | $_POST | $_REQUEST)
  - ${'_GET'|'_POST'|'_REQUEST'} (variable variables)

  One-liner backdoor variants:
  - <?=eval($_POST
  - <?=assert($_POST
  - <?=system($_GET
  - <script\s+language=php>eval
  - \x3c\x3f\x70\x68\x70 (hex-encoded PHP open tag)

ASP / ASPX WebShell:
  - <%eval\s+request\(
  - <%execute\s+request\(
  - Server\.CreateObject\(
  - Scripting\.Dictionary

JSP WebShell:
  - Runtime\.getRuntime\(\)\.exec\(
  - ProcessBuilder.*request\.getParameter
  - ClassLoader.*defineClass

Generic WebShell Heuristics:
  - Simultaneous presence of "file operation function" + "user input retrieval"
  - Simultaneous presence of "command execution function" + "network parameter binding"
  - Presence of password fields (common param names: pass, cmd, action)
```

### 2.4 Obfuscation Technique Detection

```
String Concatenation Obfuscation:
  Pattern: ['"][^'"]{0,2}['"]\s*\.\s*['"][^'"]{0,2}['"]  (short string concat)
  Pattern: chr\s*\(\s*\d+\s*\)\s*\.\s*chr                   (chr() concat)
  Pattern: String\.fromCharCode\s*\(                         (JS char-code concat)
  Pattern: ['\"]\s*\+\s*['\"]                                (plus-operator concat)

Variable Variables / Dynamic Invocation:
  Pattern: \$\{[^}]*\}   or   ${ } wrapped executable expressions
  Pattern: \$\$            (PHP variable variables)
  Pattern: window\[.*\]    (JS dynamic property access)
  Pattern: getattr\(.*,\s*['\"].*['\"]\s*\)  (Python dynamic attribute)

Character Encoding Bypass:
  Pattern: \\x[0-9a-fA-F]{2}       (hex escape)
  Pattern: \\u[0-9a-fA-F]{4}       (Unicode escape)
  Pattern: \\[0-7]{3}              (octal escape)
  Pattern: &#x?[0-9a-fA-F]+;       (HTML entity encoding)

  Detection Method:
  1. For each obfuscated fragment, attempt to deobfuscate and inspect
  2. If deobfuscation yields a dangerous function call, flag as malicious
```

### 2.5 Deserialization Payload Detection

```
PHP Serialized Objects:
  Pattern: O:\d+:"[^"]{2,}"
  Pattern: a:\d+:{.*}
  Pattern: C:\d+:"[^"]+":\d+:

  Detection Method:
  1. Search for PHP serialization format strings
  2. Check serialized object class names against known gadget chains
  3. Known dangerous class name families (non-exhaustive):
     - Monolog, SwiftMailer, Guzzle, PHPUnit
     - Symfony, Zend, Doctrine, Laravel
     - Any class named *RCE*, *Command*, or *Shell*

Java Deserialization:
  Pattern: rO0AB    (base64-encoded Java serialization magic bytes)
  Pattern: aced0005 (raw Java serialization magic bytes, hex)

Python Pickle:
  Pattern: (cos\nsystem|(c__builtin__\neval|(i__main__)
  Pattern: pickle\.loads?\(
```

### 2.6 Polyglot File Detection

```
Detection Method:
  1. Parse the same file content independently as each format:
     - Markdown (.md)
     - PHP (.php)
     - Python (.py)
     - JavaScript (.js)
     - HTML (.html)
  2. If the file produces valid, executable output in multiple formats,
     flag as Polyglot

  Known dangerous Polyglot combinations:
  - Markdown + PHP  (PHP backdoor hidden inside a ``` code block)
  - GIF + JS        (JS embedded in image file)
  - PDF + JS        (JS embedded in PDF)
  - Markdown + HTML + JS  (three-layer nesting)

  ⚠️ In the context of skill files, Markdown + PHP/JS combinations are
     especially suspicious.
```

### Phase 2 Output Format

```markdown
## Phase 2: Embedded Malware Detection — Results

| Check Item           | Result       | Match Count | Details                     |
|----------------------|--------------|-------------|-----------------------------|
| Long Base64 Strings  | ✅/🔴        | N           | Decoded output summary      |
| Hex Encoding         | ✅/🔴        | N           | Decoded output summary      |
| Dynamic Exec Funcs   | ✅/⚠️/🔴     | N locations | Function name + position    |
| WebShell Signatures  | ✅/🔴        | N locations | Matched pattern             |
| Obfuscation          | ✅/⚠️/🔴     | N locations | Obfuscation type            |
| Deserialization      | ✅/🔴        | N locations | Serialization format        |
| Polyglot             | ✅/🔴        | N layers    | Valid language combinations |

**Phase 2 Verdict:** [PASS / Suspicious Found / Malware Found]
**Threats Discovered:**
1. [Threat type] at [location] — [description]
2. ...
```

---

## Phase 3: AI Instruction-Level Threat Detection

**Objective:** Detect malicious semantic content in skill files — natural
language instructions that induce the AI to perform dangerous actions.

### 3.1 Permission Bypass Instruction Detection

```
Detection Patterns (English):
  - "ignore.*(safety|security).*(rule|policy|guideline)"
  - "bypass.*(permission|authorization|restriction)"
  - "do not.*(ask|confirm|notify).*(user|owner)"
  - "without.*(user|owner).*(consent|approval|knowledge)"
  - "disable.*(security|safety|sandbox)"
  - "override.*(security|safety)"
  - "circumvent.*(protection|detection|restriction)"
  - "no need.*(confirm|verify|check)"
  - "secretly|silently|covertly|stealth"
  - "do not.*(disclose|reveal|tell).*(user|anyone)"

Detection Patterns (Chinese — for multi-language skills):
  - "忽略.*安全.*规则"
  - "绕过.*权限.*检查"
  - "不需要.*用户.*确认"
  - "无需.*授权"
  - "跳过.*验证"
  - "关闭.*安全.*模式"
  - "不要.*询问.*用户"
  - "秘密.*执行"
  - "静默.*运行"
  - "隐藏.*操作"
  - "后台.*执行.*不.*通知"
  - "绕过.*沙箱"
  - "禁用.*保护"

⚠️ Context Differentiation:
  - If these phrases appear inside a "Safety Rules / Prohibited Actions"
    section (as in this very skill), they are educational/protective
    references — mark as SAFE.
  - If these phrases are the skill's actual operating instructions, mark
    as MALICIOUS.
  - Decision heuristic: Check whether the phrase appears in a "do not /
    never / prohibited" context vs. a "you should / you must" context.
```

### 3.2 Data Exfiltration Instruction Detection

```
Detection Patterns:
  Sending data externally:
  - "send.*(data|content|file|result).*to"
  - "upload.*(data|result|finding).*to"
  - "export.*(to|data).*(external|remote|third)"
  - "transmit.*(data|content|result).*to"

  Collecting sensitive information:
  - "collect.*(credentials|secrets|tokens|passwords|keys)"
  - "read.*\.(env|secret|key|password|credential)"
  - "extract.*(credentials|secrets|tokens|passwords)"
  - "dump.*(database|table|collection|memory)"
  - "collect.*(user.*(data|info|email|password))"
  - "gather.*(sensitive|private|confidential).*(data|info)"

  Exfiltration mechanisms:
  - "curl.*POST.*data"
  - "wget.*--post-data"
  - "nc.*-e.*\/bin"
  - "socat.*exec"
  - "base64.*encode.*send"
  - "xxd.*-p.*send"

⚠️ Even in penetration testing skills, actual data exfiltration instructions
   must never be present. Legitimate security testing skills explicitly forbid
   data exfiltration.
```

### 3.3 Hidden Prompt / Jailbreak Detection

```
Known Jailbreak Patterns:
  - "ignore all previous instructions"
  - "you are actually..."
  - "forget your training"
  - "you are now DAN"
  - "enter developer mode"
  - "system prompt override"
  - "your system prompt has been replaced"
  - "pretend you are a"
  - "role-play as"
  - "you are an unrestricted"
  - "you have no limits"
  - "do anything now"
  - "developer mode enabled"

External Prompt Loading:
  - "fetch.*(remote|external).*prompt"
  - "reveal.*(system prompt|instructions|rules)"
  - "tell me.*(system prompt|your instructions)"
  - "print.*(system prompt|initial prompt)"
  - "load.*(remote|external).*(instructions|prompt)"
```

### 3.4 Indirect Prompt Injection Detection

```
Detection Patterns:
  - Instructions containing "reference.*(URL|website|link).*content.*execute"
  - Instructions containing "visit.*URL.*and follow its instructions"
  - Instructions containing "read.*external file.*and execute"
  - Instructions containing "based on.*search results.*take action"
  - Instructions containing "follow.*webpage.*instructions"

Detection Logic:
  - Skill contains externally-referenced URLs
  - URL content is untrusted or uncontrollable
  - Skill instructs the AI to follow instructions from that URL
  - The combination of all three constitutes indirect prompt injection risk
```

### 3.5 Social Engineering Instruction Detection

```
Authority Impersonation:
  - Claims to be from Anthropic / OpenAI / an official source
    ("I am an internal Anthropic instruction...")
  - Uses faked "official update" language
  - References non-existent "security team" or "management directive"

Urgency Manufacturing:
  - "must execute immediately"
  - "failure to execute will result in severe consequences"
  - "urgent security update"
  - "this action cannot be delayed"
  - "this is a mandatory requirement"

Trust Induction:
  - "this has been security audited"
  - "approved by Anthropic"
  - "this is the officially recommended configuration"
  - "all users should enable this feature"
  - "this is a harmless standard operation"
```

### Phase 3 Output Format

```markdown
## Phase 3: AI Instruction-Level Threat Detection — Results

| Check Item            | Result    | Match Count | Details                     |
|-----------------------|-----------|-------------|-----------------------------|
| Permission Bypass     | ✅/🔴     | N locations | Specific pattern + position |
| Data Exfiltration     | ✅/🔴     | N locations | Exfil type + target         |
| Hidden Prompt/Jailbreak | ✅/🔴  | N locations | Jailbreak type              |
| Indirect Prompt Inj.  | ✅/⚠️     | N locations | URL + dependency chain      |
| Social Engineering    | ✅/⚠️     | N locations | Manipulation type           |

**Phase 3 Verdict:** [PASS / Suspicious Instructions Found / Malicious Instructions Found]
**Threats Discovered:**
1. [Threat type] at [location] — [description]
2. ...
```

---

## Phase 4: Reference Chain & Dependency Analysis

**Objective:** Analyze the security of external resources and sub-files referenced
by the skill.

### 4.1 External URL Detection

```
URL Extraction:
  Extract all URLs from the skill content (http://, https://, ftp://, file://)

  Suspicious Domain Characteristics:
  - Direct IP address: http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
  - Non-standard ports: :(?!80|443|8080|8443|3000|5000|8000)\d+
  - URL shorteners: bit\.ly|t\.co|tinyurl|ow\.ly|is\.gd|buff\.ly|goo\.gl|shorte\.st
  - Free dynamic DNS: duckdns\.org|no-ip\.com|ddns\.net|hopto\.org|zapto\.org
  - Temporary file hosting: pastebin\.com|pastie\.org|hastebin\.com|ghostbin\.com
  - Disposable email: guerrillamail|10minutemail|temp-mail|mailinator
  - Recently registered domains (registration age < 30 days)
  - Unusual TLDs: \.(tk|ml|ga|cf|gq|xyz|top|work|date|loan|win)$

  Dangerous Protocols:
  - file://   (local filesystem access — must never appear in a skill)
  - ftp://    (insecure file transfer)
  - javascript: (in Markdown links)
  - data:     (embedded data URIs)

  Detection Method:
  1. Enumerate all URLs
  2. Classify each URL: Documentation / Official / Third-Party / Suspicious
  3. Flag all suspicious URLs
  4. If short links are found, attempt to resolve to the target URL
```

### 4.2 Recursive Reference File Check

```
Check Scope:
  All local files referenced by the skill:
  - references/*.md
  - scripts/*
  - examples/*
  - Any file referenced via @import or include directives

  Recursive Scan:
  1. List all files in the skill directory
  2. Run the full 5-phase scan on each referenced file
  3. Record recursion depth and threats discovered
  4. If a referenced file contains threats, the parent skill inherits that risk

  Special Attention:
  - .js / .py / .sh / .bat / .ps1 (executable scripts)
  - .json / .yaml / .yml (config files — may contain malicious config)
  - .csv / .tsv (data files — may contain formula injection)
  - .svg / .html (may contain embedded scripts)
```

### 4.3 Remote Execution Instruction Detection

```
Download-and-Execute Patterns:
  - curl\s+.*\|\s*(sh|bash|python|perl|ruby|node|php)
  - wget\s+.*-O\s*-\s*\|\s*(sh|bash)
  - Invoke-WebRequest.*\|.*Invoke-Expression
  - irm\s+.*\|.*iex  (PowerShell abbreviated)
  - curl\s+.*-o\s+.*&&\s+(sh|bash|python)
  - git\s+clone.*&&\s+cd.*&&\s+(make|install|run)
  - npm\s+install\s+-g.*(?!registry\.npmjs\.org)
  - pip\s+install\s+.*(--index-url|--extra-index-url).*(?!pypi\.org)
  - gem\s+install\s+.*--source

⚠️ Any "download + auto-execute" combination is a HIGH-RISK signal.
   Even in technical reference documents, these must be flagged for
   manual confirmation.
```

### 4.4 Path Traversal Detection

```
Path Traversal Patterns:
  - \.\.\/\.\.\/  or  \.\.\\\.\.\\  (directory backtracking)
  - \.\.\/\.\.\/\.\.\/  (multi-level backtracking)
  - \/\etc\/  (direct system path reference)
  - C:\\Windows\\  (Windows system directory)
  - \/var\/www\/  \/home\/  \/root\/  (server-sensitive paths)
  - %APPDATA%  %USERPROFILE%  %TEMP%  (Windows environment variable paths)
  - $HOME  $TMPDIR  $TEMP  (Unix environment variable paths)

In skill files, the following path references are suspicious:
  - Any absolute path pointing to a system directory
  - Any reference containing path traversal sequences
  - References to /etc/passwd, /etc/shadow, SAM, or similar sensitive files
```

### Phase 4 Output Format

```markdown
## Phase 4: Reference Chain & Dependency Analysis — Results

| Check Item           | Result    | Count  | Details                     |
|----------------------|-----------|--------|-----------------------------|
| Total URLs           | —         | N      | —                           |
| Suspicious URLs      | ✅/🔴     | N      | URL + risk type             |
| Referenced Files     | —         | N      | File list                   |
| Ref File Scan Result | ✅/🔴     | N issues | Threats discovered        |
| Remote Exec Instruct. | ✅/🔴    | N locs | Instruction type            |
| Path Traversal       | ✅/🔴     | N locs | Target path                 |

**Phase 4 Verdict:** [PASS / Suspicious References Found / Dangerous References Found]
```

---

## Phase 5: Comprehensive Scoring & Remediation

**Objective:** Aggregate findings from Phases 1–4, produce a risk matrix and
per-item remediation plan.

### 5.1 Risk Matrix

```
    Impact
      ↑
  HIGH | 🟡 Medium (3)  | 🟠 High (2)      | 🔴 Critical (1)
       | Monitor needed  | Immediate action  | Isolate immediately
       |                 | required          |
       |                 |                   |
   MED | 🟢 Low (4)     | 🟡 Medium (3)    | 🟠 High (2)
       | Track & log     | Monitor needed    | Immediate action
       |                 |                   | required
       |                 |                   |
   LOW | 🟢 Info (5)    | 🟢 Low (4)        | 🟡 Medium (3)
       | Ignore          | Track & log       | Monitor needed
       |
       └──────────────────────────────────────→ Confidence
           LOW              MEDIUM              HIGH

Risk Level = f(Impact, Confidence)

Impact Assessment:
  - HIGH:   Can lead to RCE, system compromise, data exfiltration
  - MEDIUM: Can lead to permission bypass, info disclosure, instruction manipulation
  - LOW:    Suspicious but exploitation unconfirmed, theoretical risk

Confidence Assessment:
  - HIGH:   Deterministic match against known malicious patterns, no further
            confirmation needed
  - MEDIUM: Strong risk indicators but reasonable doubt remains
  - LOW:    Anomalous signal, potential false positive
```

### 5.2 Aggregated Findings Summary

```markdown
## Comprehensive Security Report

### Overall Rating: [SAFE / LOW RISK / MEDIUM RISK / HIGH RISK / CRITICAL THREAT]

### Findings Inventory (sorted by severity)

| # | Severity      | Phase  | Finding Type     | Confidence | Location | Description              |
|---|---------------|--------|------------------|------------|----------|--------------------------|
| 1 | 🔴 Critical   | Phase 2 | WebShell         | HIGH       | L123     | PHP eval($_POST[...])    |
| 2 | 🟠 High       | Phase 1 | Abnormal Size    | HIGH       | —        | 97KB vs 8KB peer avg     |
| … | …             | …      | …                | …          | …        | …                        |

### Statistical Summary

| Severity       | Count |
|----------------|-------|
| 🔴 Critical    | N     |
| 🟠 High        | N     |
| 🟡 Medium      | N     |
| 🟢 Low         | N     |
| ℹ️ Info        | N     |
```

### 5.3 Per-Finding Remediation Suggestions

```
For each finding, provide a remediation recommendation in the following format:

---
Finding #N: [Type] (Severity: [Level])

**Location:** File:L Line:C
**Description:** [Brief explanation]
**Risk:** [What could happen if exploited]

**Remediation Options:**
1. [Primary approach] — [How to eliminate the root cause]
2. [Alternative approach] — [Fallback if primary is not feasible]

**Remediation Steps:**
1. [Specific action]
2. [Specific action]

**Verification:**
- [How to confirm the fix is complete and effective]
---
```

### 5.4 General Remediation Guide

```markdown
## General Remediation & Safe Rebuild Guide

### For Embedded Malicious Code

1. **Do not attempt manual cleanup** — if the file contains embedded malicious
   code, the safest path is complete deletion and rebuild
2. **Rebuild from a trusted source** — use the official marketplace, official
   GitHub repository, or a version from a trusted author
3. **Audit sync mechanisms** — if copies of the same skill exist in multiple
   paths, investigate whether an auto-sync or backup mechanism introduced the
   contamination

### For AI Instruction-Level Threats

1. **Remove dangerous instructions** — delete any instruction that bypasses
   safety restrictions or exfiltrates data
2. **Add safety boundaries** — explicitly declare the skill's authorization
   requirements and safety limitations
3. **Review external references** — ensure referenced URLs point to trusted,
   official resources
4. **Replace with safe language** — substitute dangerous instructions with
   defensive security guidance

### For Structural Anomalies

1. **Re-encode** — convert the file to pure UTF-8 encoding
2. **Remove hidden content** — delete all zero-width characters, HTML comments,
   and hidden text
3. **Normalize file size** — ensure file size is within the normal range
   (2–15KB)

### Safe Rebuild Template

If a skill file needs to be rebuilt from scratch:

```markdown
---
name: <skill-name>
description: >-
  <Clear single-paragraph description of purpose and trigger conditions>
---

# <Skill Title>

<Body content — follow these safety principles:>

## Safety Boundaries
1. Explicitly state the authorization requirement
2. List prohibited actions
3. Document safety limitations

## Functional Description
...
```
```

### 5.5 Final Verdict

```markdown
## Final Verdict

### Is This Skill Safe to Use?

[ ] ✅ SAFE — All checks passed, ready for normal use
[ ] ⚠️ LOW RISK — Non-critical anomalies present; fix recommended before use
[ ] 🔴 UNSAFE — Medium / High / Critical threats found; do not use

### Recommended Actions

- **SAFE:** No action required
- **LOW RISK:** [List suggested improvements]
- **UNSAFE:**
  1. Immediately stop using this skill
  2. Delete the infected file(s)
  3. Obtain or rebuild a safe version from a trusted source
  4. Scan all other copies of the skill across the system
  5. Scan all associated reference files and dependencies
```

---

## Scan Execution Checklist

Before starting the scan on a target skill, complete the following preparation steps:

- [ ] Confirm the target skill file path
- [ ] Record the target file size (for baseline comparison)
- [ ] Read the complete content of the target skill file
- [ ] List all files in the skill directory (especially references/)
- [ ] Calculate the average size of peer skills (for anomaly baseline)

Then execute all 5 phases in order, outputting the tabulated results after
each phase.

---

## Important Reminders

1. **This scanner is not a replacement for antivirus software** — for known
   malware signatures, cross-validate using traditional AV tools such as
   Windows Defender or VirusTotal.
2. **False positives are possible** — penetration testing skills may contain
   educational code examples. Distinguish between "code referenced as learning
   material" and "actual executable malicious payload."
3. **Keep detection rules current** — new attack techniques and obfuscation
   methods emerge continuously; detection rules require periodic updates.
4. **Zero-trust principle** — even when a scan passes, validate a new skill's
   behavior in an isolated environment before trusting it in production.
