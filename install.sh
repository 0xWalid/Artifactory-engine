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

# 1. Symlink ~/.artifactory or ~/artifactory to the nested folder for clean execution paths
if [ "$ARTIFACTORY_DIR" != "$TARGET_LINK_DIR" ]; then
    echo "[*] Creating symlink: $TARGET_LINK_DIR ->$ARTIFACTORY_DIR"
    ln -sfn "$ARTIFACTORY_DIR" "$TARGET_LINK_DIR"
fi

# 2. Ensure base blackboard directories exist
mkdir -p "$ARTIFACTORY_DIR/.blackboard/artifacts"
mkdir -p "$OPENCODE_CMD_DIR"

# 3. Make core Python scripts executable
chmod +x "$ARTIFACTORY_DIR/sec_flow.py" 2>/dev/null || true
chmod +x "$ARTIFACTORY_DIR/playbook_engine.py" 2>/dev/null || true

# 4. Register OpenCode command (/artifactory)
cat << 'CMD_EOF' > "$OPENCODE_CMD_DIR/artifactory.md"
---
description: Artifactory Agentic Security & Recon Engine
---

# Command: /artifactory (Agentic Security Engine)

Execute security analysis using the local Artifactory Blackboard Architecture.

## Phase 0: Target Initialization & Scope Check (MANDATORY)
Upon invocation with a target (e.g., `/artifactory target.com`):
1. **Pause execution** and prompt the user for:
   - **In-Scope Targets:** Allowed domains, subdomains, or IP ranges.
   - **Out-of-Scope Targets:** Expressly forbidden targets/endpoints.
   - **Test Constraints ("Do Not Do"):** Rate limits, destructive test prohibitions.
   - **Authentication:** Custom headers, cookies, or API keys.
2. Write/update `.blackboard/scope.json` with confirmed rules before running tools.

---

## Phase 1: Execution Mode Selection

### Mode 1: Autonomous Target Analysis (Default)
When given a target without a specific attack vector:
1. **Recon & Surface Mapping:** Run discovery via `python3 ~/artifactory/sec_flow.py`.
2. **Priority Matrix:** Identify core assets and build testing queue.
3. **Dynamic Playbook Execution:** 
   - Check `python3 ~/artifactory/playbook_engine.py --category <cat> --name <name>`.
   - If missing, ask practitioner for tradecraft / draft template in `prompts/`.
   - Log findings to `.blackboard/board.json`.

### Mode 2: Urgent / Direct Vector Testing
When testing a single vector (e.g., `/artifactory test HTTP Smuggling on target.com`):
1. Verify target scope via `scope.json`.
2. Check `python3 ~/artifactory/playbook_engine.py --category <cat> --name <name>`.
3. If missing, draft practitioner playbook and execute immediately.

---

## Safety & Context Isolation:
- **Hard Gate:** Pass all commands through `python3 ~/artifactory/sec_flow.py`.
- **Pointer-Based Logs:** Save raw CLI output to `.blackboard/artifacts/` via `sec_flow.py`.
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
echo "   Run '/artifactory analyze target.com' in       "
echo "   OpenCode to start testing.                    "
echo "=================================================="
