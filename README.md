---

# 🏴‍☠️ Artifactory Security Engine

Artifactory is a practitioner-first, autonomous AI security testing engine built on the **Sovereign Blackboard Architecture (SBA)**. Designed for native integration with terminal-based AI agents like **OpenCode**, it enables structured, scope-enforced, and token-efficient security assessments.

Instead of dumping massive, raw CLI output into LLM context windows or executing unverified, risky commands directly, Artifactory manages execution through local safety wrappers, automated CIDR/domain scope gates, pointer-based artifact indexing, and dynamic tradecraft playbook synthesis.

---

## 💡 Why Artifactory? (The Architectural Edge)

| Capability | Standard AI Agent Prompting | Artifactory SBA Pipeline |
| --- | --- | --- |
| **Scope Enforcement** | Relies purely on system prompt compliance | **Hard-gated local checks** (`sec_flow.py`) matching hosts, domains, and CIDR subnets against `scope.json`. |
| **Command Execution** | Raw, vulnerable `shell=True` execution | **POSIX tokenized subprocess execution** (`shlex.split`, `shell=False`) to mitigate injection risks. |
| **Context Window Control** | Dumps 100+ lines of raw tool output into context | Logs output to `.blackboard/artifacts/` under pointer IDs (`MSG_XXXX`), exposing only 20-line previews and targeted regex/JSON inspection. |
| **State Persistence** | Transient chat memory | Shared local state (`board.json`) updated via dedicated CLI helpers (`add-asset`) to prevent token waste. |
| **Tradecraft Library** | Static or unverified dynamic commands | Parameterized Markdown playbooks in `prompts/` with **Autonomous Research Synthesis** when playbooks are missing. |

---

## 📁 Repository Structure

```text
artifactory-engine/
├── install.sh                  <-- Automated installer & OpenCode slash-command setup
├── README.md                   <-- Documentation
└── artifactory/                <-- Core Engine Pipeline
    ├── init_env.py             <-- Workspace initializer (creates .blackboard/, schemas, scope)
    ├── sec_flow.py             <-- Safe runner, CIDR gate, log inspection & asset tracker
    ├── playbook_engine.py      <-- Parameterized playbook renderer & research trigger
    ├── ingest.py               <-- Tradecraft parameterizer, quality-checker & writer
    └── prompts/                <-- Reusable Tradecraft Playbook Library
        ├── recon/              <-- Discovery & mapping tradecraft
        ├── web/                <-- Web app testing procedures
        ├── auth/               <-- Authentication & session checks
        ├── infra/              <-- Cloud & infrastructure playbooks
        ├── logic/              <-- Business logic & access control flaws
        └── chaining/           <-- Multi-vector chaining strategies

```

---

## 🚀 Installation & Setup

```bash
git clone https://github.com/0xWalid/artifactory-engine.git
cd artifactory-engine
chmod +x install.sh
./install.sh

```

### What `install.sh` Does:

1. Creates a path symlink: `~/artifactory` -> `artifactory-engine/artifactory`.
2. Creates the prompt category directories and local storage paths.
3. Sets execution permissions across all core Python scripts (`init_env.py`, `sec_flow.py`, `playbook_engine.py`, `ingest.py`).
4. Registers the `/artifactory` custom command under `~/.config/opencode/commands/artifactory.md`.

---

## 🛠 Workflows & OpenCode Slash Commands

Run `opencode` inside any target workspace directory and invoke the engine on demand.

### 1. Stack-Driven Surface Analysis

```text
/artifactory analyze <target>

```

* **Discovery:** Initializes `.blackboard/` (if missing) and executes non-intrusive enumeration via `sec_flow.py run`.
* **State Tracking:** Records open ports, hosts, and endpoints to `board.json` via `sec_flow.py add-asset`.
* **Stack Queue:** Reads detected technologies (e.g., GraphQL, Express, Spring Boot, Redis) and automatically executes relevant playbooks from `prompts/`.

---

### 2. Targeted Vector Testing & Autonomous Research

```text
/artifactory test <target> for <vulnerability>

```

* **Parameter Rendering:** Loads `prompts/<category>/<vulnerability>.md` and substitutes dynamic target variables (`{{TARGET_URL}}`, `{{TARGET_HOST}}`, `{{AUTH_TOKEN}}`).
* **Autonomous Fallback:** If the playbook does not exist (`[STATUS: MISSING_NEEDS_RESEARCH]`), the agent automatically queries standard references (OWASP WSTG, PortSwigger, CVE advisories), extracts non-destructive test steps, saves the playbook via `ingest.py`, and immediately runs the test.
* **Safe Execution:** Runs diagnostic commands via `sec_flow.py run` and logs findings to `.blackboard/board.json`.

---

### 3. Tradecraft Ingestion Pipeline

```text
/artifactory ingest <URL or File Path>

```

* **Quality Gate:** Checks that input contains actionable technical details (HTTP methods, parameters, CLI tools).
* **Sanitization:** Replaces hardcoded domains, IPs, and bearer tokens with generic template variables (`{{TARGET_HOST}}`, `{{TARGET_URL}}`, `{{AUTH_TOKEN}}`).
* **Human-in-the-Loop Review:** Summarizes extracted mechanics and category before writing to `prompts/<category>/<name>.md`.

---

## 🛡 Security Guardrails & CLI Utilities

### Scope Enforcement & Safe Execution (`sec_flow.py run`)

Validates domains, hosts, and IP subnets before executing commands:

```bash
python3 ~/artifactory/sec_flow.py run --cmd "curl -s http://127.0.0.1:8080" --target "127.0.0.1"

```

### Context-Preserving Log Inspection (`sec_flow.py inspect`)

Inspects large artifact logs (`>100 lines`) on demand using targeted regex or structured JSON parsing:

```bash
# Query lines matching a specific pattern
python3 ~/artifactory/sec_flow.py inspect --id MSG_A1B2C3D4 --grep "HTTP/1.1 200" --lines 20

# Extract a specific field from structured JSON tool outputs
python3 ~/artifactory/sec_flow.py inspect --id MSG_A1B2C3D4 --json-key "host"

```

### Blackboard Asset Recording (`sec_flow.py add-asset`)

Updates local workspace state without loading or rewriting full JSON files in memory:

```bash
python3 ~/artifactory/sec_flow.py add-asset --endpoint "/api/v1/auth" --port "8080/tcp"
python3 ~/artifactory/sec_flow.py add-asset --finding "Exposed Metrics Endpoint" --details "Found unprotected /metrics route"

```
