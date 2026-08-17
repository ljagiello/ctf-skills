---
name: binary-analysis
description: Analyze binary files (exe, dll, sys, bin, ocx, scr, cpl, drv) to assess if they are malicious, perform decompilation, extract strings/imports/exports, detect malware, and provide threat assessment. Use this skill when user asks to analyze, examine, check, or assess any binary file, asks if a file is malicious/suspicious/safe, or provides a file path to a binary. Trigger for phrases like "Is [file] malicious?", "Analyze [file]", "What does [binary] do?", or any request involving binary file analysis.
---

# Binary Analysis

This skill enables deep analysis of suspicious binary files using remote Ghidra tools and sandbox environments. You HAVE TO upload binary files to the remote first before calling any Ghidra or sandbox tools.

## When to Use This Skill

Use this skill when you need to:
- Analyze suspicious executable files (.exe, .dll, .sys)
- Decompile binaries to understand their behavior
- Extract strings, imports, and exports from files
- Identify malware capabilities and techniques
- Perform static analysis on unknown binaries
- Investigate potential trojans, ransomware, or other malware
- Generate threat assessment reports

## Workflow

### Step 1: Perform Analysis

Use available Ghidra MCP tools to analyze the uploaded binary:

- **Decompilation**: Convert assembly to pseudo-C code
- **String Analysis**: Extract readable strings for IoC identification
- **Import/Export Analysis**: Identify API calls and dependencies
- **Function Analysis**: Map out program logic and control flow
- **Behavioral Indicators**: Identify suspicious patterns (registry manipulation, network calls, process injection)

### Step 2: Generate Report

Provide a comprehensive analysis including:
- File metadata (size, hash, compilation timestamp)
- Identified capabilities (network, file system, registry, process manipulation)
- Suspicious indicators
- Malware classification (if applicable)
- Recommended actions

## Analysis Techniques

### Static Analysis
- PE header examination
- Section analysis (.text, .data, .rdata, .rsrc)
- Import Address Table (IAT) review
- String artifact extraction
- Code signature verification

### Behavioral Indicators
Look for:
- Anti-debugging techniques
- Obfuscation/packing
- Suspicious API calls (CreateRemoteThread, WriteProcessMemory, etc.)
- Network communication patterns
- Persistence mechanisms
- Privilege escalation attempts

### Malware Classification
Common categories:
- Trojan/RAT (Remote Access Trojan)
- Ransomware
- Adware/PUP (Potentially Unwanted Program)
- Rootkit
- Worm
- Spyware
- Browser hijacker

## Safety Considerations

- **Never execute** the binary on local system
- All analysis occurs in remote sandbox environment
- Files are automatically isolated
- Use Ghidra static analysis tools only
- Document all findings for incident response

## Output Format

```markdown
## Binary Analysis Report

**File Information**
- Name: [filename]
- Size: [bytes]
- MD5: [hash]
- SHA256: [hash]

**Analysis Summary**
[Brief overview of findings]

**Detailed Findings**
1. [Finding category]
   - Evidence: [specific data]
   - Significance: [what it means]

**Threat Assessment**
- Severity: [Critical/High/Medium/Low]
- Classification: [malware type]
- Confidence: [High/Medium/Low]

**Recommendations**
1. [Action item]
2. [Action item]
```

## Example Usage

User: "I found a suspicious file called setup_installer.exe. Can you analyze it?"

Response:
1. Run Ghidra analysis on the full local path of setup_installer.exe
2. Extract strings, imports, and decompiled code
3. Identify malicious behavior (if any)
4. Provide detailed report with recommendations
