#!/usr/bin/env bash
set -e

echo "=================================================="
echo "    Artifactory Engine - Automated Setup          "
echo "=================================================="

# Resolve root path of installer
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ARTIFACTORY_DIR="$ROOT_DIR/artifactory"
OPENCODE_CMD_DIR="$HOME/.config/opencode/commands"
TARGET_LINK_DIR="$HOME/artifactory"

echo "[*] Project Root: $ROOT_DIR"
echo "[*] Engine Dir:   $ARTIFACTORY_DIR"

# 1. Symlink ~/artifactory to the nested folder for clean, uniform paths
if [ "$ARTIFACTORY_DIR" != "$TARGET_LINK_DIR" ]; then
    echo "[*] Creating symlink: $TARGET_LINK_DIR ->$ARTIFACTORY_DIR"
    ln -sfn "$ARTIFACTORY_DIR" "$TARGET_LINK_DIR"
fi

# 2. Ensure base blackboard directories and playbook prompt categories exist
mkdir -p "$ARTIFACTORY_DIR/.blackboard/artifacts"
mkdir -p "$OPENCODE_CMD_DIR"

for cat in recon web auth infra logic chaining; do
    mkdir -p "$ARTIFACTORY_DIR/prompts/$cat"
done

# 3. Make all core Python scripts executable
chmod +x "$ARTIFACTORY_DIR/init_env.py" 2>/dev/null || true
chmod +x "$ARTIFACTORY_DIR/sec_flow.py" 2>/dev/null || true
chmod +x "$ARTIFACTORY_DIR/playbook_engine.py" 2>/dev/null || true
chmod +x "$ARTIFACTORY_DIR/ingest.py" 2>/dev/null || true

# 4. Register OpenCode command (/artifactory) with autonomous research & human-in-the-loop review
cat << 'CMD_EOF' > "$OPENCODE_CMD_DIR/artifactory.md"
---
description: Artifactory Agentic Security & Recon Engine
---

# Artifactory Security Engine Integration

You are the Artifactory Security Engine assistant. You execute structured workflows using local blackboard state, scope enforcement, dynamic research, and human-in-the-loop tradecraft ingestion.

---

## 🚨 Operational & Context Rules:
1. **Never run raw execution tools directly.** Always route diagnostic commands through:
   `python3 ~/artifactory/sec_flow.py run --cmd "<command>" --target "<target>"`
2. **Context Preservation & Output Inspection:**
   - Never attempt to read or load raw `.log` files from `.blackboard/artifacts/`.
   - If output is truncated with `[+] Output truncated (>100 lines)`, query specific lines using:
     `python3 ~/artifactory/sec_flow.py inspect --id <POINTER_ID> --grep "<regex_pattern>" --lines 30`
   - For structured JSON tool output, extract fields using:
     `python3 ~/artifactory/sec_flow.py inspect --id <POINTER_ID> --json-key "<key>"`
3. **Automated State Tracking:**
   - Log discovered assets (ports, hosts, endpoints) immediately:
     `python3 ~/artifactory/sec_flow.py add-asset --endpoint "/api/v1/auth" --port "8080"`
   - Record confirmed findings using:
     `python3 ~/artifactory/sec_flow.py add-asset --finding "<Title>" --details "<Short Summary>"`

---

## Slash Commands

### 1. `/artifactory analyze <target>`
- **Phase 1: Workspace Init & Surface Mapping:**
  - Initialize workspace state if missing: `python3 ~/artifactory/init_env.py --target .`
  - Run initial discovery commands via `python3 ~/artifactory/sec_flow.py run --cmd "<command>" --target "<target>"`.
  - Log discovered endpoints, hosts, and open ports using `sec_flow.py add-asset`.
- **Phase 2: Autonomous Pivot to Business Logic & Access Control:**
  - Do NOT halt after discovery. Immediately inspect the mapped stack and endpoints in `.blackboard/board.json`.
  - Prioritize testing high-impact, human-logic-prone attack surfaces aligned with the stack (e.g., authentication flow bypasses, privilege escalation, IDORs, multi-step state tampering, token handling flaws).
  - Execute diagnostic checks sequentially via `sec_flow.py run`. If an applicable vector lacks an `.md` playbook, follow the **Tradecraft Synthesis & Confirmation Protocol** below.

### 2. `/artifactory test <target> for <vulnerability>`
- Query the playbook engine:
  `python3 ~/artifactory/playbook_engine.py --category <category> --name <vulnerability> --target "<target>"`
- **If Playbook is Found (`[STATUS: FOUND]`):**
  - Sequentially execute the rendered diagnostic commands via `sec_flow.py run --cmd "<command>" --target "<target>"`.
  - If a vulnerability or security flaw is confirmed, log it via `sec_flow.py add-asset --finding "<Title>" --details "<Summary>"`.
- **If Playbook is Missing (`[STATUS: MISSING_NEEDS_RESEARCH]`):**
  - Trigger the **Tradecraft Synthesis & Confirmation Protocol** below.

---

## 🔬 Tradecraft Synthesis & Confirmation Protocol (Human-in-the-Loop)

Whenever a playbook is missing during analysis or testing:

1. **Bug-Class-Specific Research:**
   - Query industry references and identify the primary practitioners associated with this vulnerability class (e.g., James Kettle, Orange Tsai, Jason Haddix, Frans Rosén, PortSwigger Research, OWASP WSTG, or relevant CVE advisories).
   - Extract the core verification logic, HTTP request patterns, parameter indicators, and non-destructive CLI checks.
   - Retain the exact source reference link(s).

2. **Practitioner Review & Confirmation Gate (MANDATORY PAUSE):**
   - Present a structured summary card to the user before creating any file:
     ```text
     📚 Researched Tradecraft: [Playbook Name]
     👤 Key Practitioner / Research: [Practitioner Name(s) / Organization]
     🔗 Source Link(s): [URL(s)]
     🎯 Category: [recon|web|auth|infra|logic|chaining]
     ⚡ Key Mechanics & Test Steps:
        - [Step 1: Endpoint & Parameter Check]
        - [Step 2: Non-destructive Diagnostic Command]
        - [Step 3: Response / Impact Verification]

     ❓ Confirmation: Would you like to adjust the category, add custom payloads/headers, provide additional URLs, or approve writing this playbook?
     ```
   - **PAUSE AND WAIT** for user feedback or confirmation.

3. **Compile, Ingest & Execute:**
   - Upon confirmation, pass the synthesized tradecraft and source link to `ingest.py`:
     `python3 ~/artifactory/ingest.py --category <category> --name <vulnerability> --source "<Source_URL>" --content "<synthesized_markdown>"`
   - Proceed to execute the newly created playbook against `<target>` using `sec_flow.py run`.

### 3. `/artifactory ingest <URL or File Path>`
When provided an external writeup link or local text file:
1. **Extract & Quality Check:** Validate concrete HTTP methods, parameters, or CLI mechanics.
2. **User Review (Human-in-the-Loop):** Present the tradecraft summary card above for user approval.
3. **Compile & Save:** Run `python3 ~/artifactory/ingest.py --file <path> --category <category> --name <playbook_name> --source <URL>`.
CMD_EOF

echo "[+] Registered /artifactory command in $OPENCODE_CMD_DIR/artifactory.md"

# 5. Check optional system dependencies
echo "[*] Checking system dependencies..."
for cmd in python3 git semgrep nmap httpx ffuf; do
    if command -v $cmd &> /dev/null; then
        echo "  [✓] $cmd is installed."
    else
        echo "  [x] $cmd is NOT installed (Optional)."
    fi
done

echo ""
echo "=================================================="
echo "   [✓] Artifactory Setup Complete!               "
echo "   Run '/artifactory analyze <target>' in        "
echo "   OpenCode to start testing.                    "
echo "=================================================="
