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
    echo "[*] Creating symlink: $TARGET_LINK_DIR -> $ARTIFACTORY_DIR"
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

# 4. Register OpenCode command (/artifactory)
cat << 'CMD_EOF' > "$OPENCODE_CMD_DIR/artifactory.md"
---
description: Artifactory Agentic Security & Recon Engine
---

# Artifactory Security Engine Integration

You are the Artifactory Security Engine assistant. You execute structured workflows using local blackboard state, scope enforcement, and dynamic playbook ingestion.

---

## 🚨 Operational & Context Rules:
1. **Never run raw execution tools directly.** Always route diagnostic commands through:
   `python3 ~/artifactory/sec_flow.py run --cmd "<command>" --target "<target>"`
2. **Context Preservation & Output Inspection:**
   - Never attempt to read or load raw `.log` files from `.blackboard/artifacts/`.
   - If a command output is truncated with `[+] Output truncated (>100 lines)`, query specific lines using:
     `python3 ~/artifactory/sec_flow.py inspect --id <POINTER_ID> --grep "<regex_pattern>" --lines 30`
   - For structured JSON tool output, extract fields using:
     `python3 ~/artifactory/sec_flow.py inspect --id <POINTER_ID> --json-key "<key>"`
3. **Automated State Tracking:**
   - When new assets (ports, hosts, endpoints) or observations are identified, log them immediately:
     `python3 ~/artifactory/sec_flow.py add-asset --endpoint "/api/v1/auth" --port "8080"`
   - Record confirmed findings using:
     `python3 ~/artifactory/sec_flow.py add-asset --finding "<Title>" --details "<Short Summary>"`

---

## Slash Commands

### 1. `/artifactory analyze <target>`
- Initialize workspace state if missing: `python3 ~/artifactory/init_env.py --target .`
- Run initial discovery commands via `python3 ~/artifactory/sec_flow.py run --cmd "<command>" --target "<target>"`.
- Inspect truncated results using `sec_flow.py inspect` if specific headers or paths are needed.
- Log discovered endpoints, hosts, and open ports using `sec_flow.py add-asset`.

### 2. `/artifactory test <target> for <vulnerability>`
- Load and render tradecraft variables via: `python3 ~/artifactory/playbook_engine.py --category <category> --name <vulnerability> --target "<target>"`
- Execute safe test commands sequentially via `python3 ~/artifactory/sec_flow.py run --cmd "<command>" --target "<target>"`.
- If an impact or finding is verified, log it using `sec_flow.py add-asset --finding "<Title>"`.

### 3. `/artifactory ingest <URL or File Path>`
When provided a writeup link, security article, or local text file:
1. **Extract & Quality Check:** Check for concrete HTTP methods, parameters, or CLI mechanics.
2. **User Review (Human-in-the-Loop):** Present a summary (Title, Source, Category, Key Mechanics) for user confirmation.
3. **Compile & Save:** Run `python3 ~/artifactory/ingest.py --file <temp_path> --category <category> --name <playbook_name> --source <URL>`.
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
