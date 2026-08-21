---

# 🏴‍☠️ Artifactory Security Engine

Artifactory is a practitioner-first, autonomous AI security testing engine built on the **Sovereign Blackboard Architecture (SBA)**. Designed for native integration with terminal-based AI agents like **OpenCode**, it enables structured, scope-enforced, and token-efficient security assessments.

Instead of dumping massive, raw CLI output into LLM context windows or executing unverified, risky commands directly, Artifactory manages execution through local safety wrappers, automated CIDR/domain scope gates, pointer-based artifact indexing, and dynamic tradecraft playbook synthesis.

---

## 💡 Why Artifactory? (The Architectural Edge)

| Capability | Standard AI Agent Prompting | Artifactory SBA Pipeline |
| --- | --- | --- |
| **Scope Enforcement** | Relies purely on system prompt compliance | **Fail-closed, hard-gated local checks** (`sec_flow.py`): an empty/missing `scope.json` grants nothing, and every command requires an explicit in-scope `--target` matched against hosts, domains, and CIDR subnets. |
| **Command Execution** | Raw, vulnerable `shell=True` execution | **POSIX tokenized subprocess execution** (`shlex.split`, `shell=False`) with a wall-clock timeout, to mitigate injection and hung-tool risks. |
| **Safety Interlocks** | None | **Canary tripwire** (blocks/flags commands that reach do-not-touch data) and a **destructive-action block** (`rm -r/-f`, `dd`, `mkfs*`, `shutdown`, raw-disk writes, fork bombs) gated on `scope.json` `disallowed_actions`. |
| **Context Window Control** | Dumps 100+ lines of raw tool output into context | Logs output to `.blackboard/artifacts/` under pointer IDs (`MSG_XXXX`), exposing only 20-line previews and targeted regex/JSON inspection. |
| **Cognition Split** | One expensive model reads every line of tool output | **Two-tier:** a background **Scout** (deterministic-first + optional free model) digests raw output into ranked **leads**; the operator model consumes the short lead list, not the firehose. Heavy scans run detached (`run --bg`). |
| **State Persistence** | Transient chat memory | Shared local state (`board.json`) updated via dedicated CLI helpers (`add-asset`) to prevent token waste. |
| **Reporting** | Manual write-up | Recording a finding auto-triggers `report_engine.py`, compiling a per-vulnerability advisory correlated to the exact commands that proved it. |
| **Tradecraft Library** | Static or unverified dynamic commands | Parameterized Markdown playbooks in `prompts/` with **human-in-the-loop methodology synthesis** (identify the bug-class authority, request sources, confirm) when a playbook is missing. |

---

## 📁 Repository Structure

```text
artifactory-engine/
├── install.sh                  <-- Automated installer & OpenCode slash-command setup
├── README.md                   <-- Documentation
└── artifactory/                <-- Core Engine Pipeline
    ├── init_env.py             <-- Workspace initializer (creates .blackboard/, schemas, scope, canary)
    ├── sec_flow.py             <-- Safe runner, fail-closed scope gate, canary + destructive guards, log inspection & asset tracker
    ├── playbook_engine.py      <-- Parameterized playbook renderer & methodology-synthesis trigger
    ├── ingest.py               <-- Tradecraft parameterizer, quality-checker & writer
    ├── report_engine.py        <-- Per-finding advisory & evidence-log generator (auto-run on new findings)
    ├── triage.py               <-- Background triage + Scout brain: raw output -> ranked leads
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
git clone https://github.com/0xWalid/Artifactory-engine.git
cd Artifactory-engine
chmod +x install.sh
./install.sh

```

### What `install.sh` Does:

1. Creates a path symlink: `~/artifactory` -> `Artifactory-engine/artifactory` (so the engine code runs live from the repo).
2. Creates the prompt category directories and local storage paths.
3. Sets execution permissions across all core Python scripts (`init_env.py`, `sec_flow.py`, `playbook_engine.py`, `ingest.py`, `report_engine.py`).
4. Registers the `/artifactory` custom command under `~/.config/opencode/commands/artifactory.md`.
5. Checks for optional external tools (`python3`, `git`, `semgrep`, `nmap`, `httpx`, `ffuf`) — it reports which are missing but does **not** install them.

> **Note:** The Python engine runs live through the symlink, so editing a `.py` file takes effect immediately. The `/artifactory` command doc is a **copy**, so after changing it (or `install.sh`) you must re-run `./install.sh` to refresh it.

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
* **Methodology Synthesis (human-in-the-loop):** If the playbook does not exist (`[STATUS: MISSING_NEEDS_RESEARCH]`), the agent follows a structured directive: identify the authority for the bug class (e.g. James Kettle/PortSwigger, Orange Tsai, Jason Haddix), **request additional writeup URLs, files, and payloads from the operator and pause**, synthesize a sectioned parameterized methodology (Preconditions → Enumeration → Diagnostic Checks → Verification & Impact → Escalation & Chaining), present a confirmation card, and only then save it via `playbook_engine.py --save-content` and run the test.
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

Fail-closed: a missing/empty `scope.json` permits nothing, and every command must declare an in-scope `--target`. Validates domains, hosts, and IP subnets (with DNS resolution) before executing:

```bash
python3 ~/artifactory/sec_flow.py run --cmd "curl -s http://127.0.0.1:8080" --target "127.0.0.1"

```

Three hard interlocks are enforced in the runner, and refusals are surfaced (never silently bypassed):

* **`[!] SCOPE ERROR`** — target not authorized in `.blackboard/scope.json`.
* **`[!] CANARY TRIPWIRE`** — a command references the workspace canary token (do-not-touch data); a post-run scan also flags `CANARY TRIPWIRE HIT` and logs it if the token appears in output.
* **`[!] DESTRUCTIVE-ACTION BLOCK`** — irreversible host/data destruction (`rm -r/-f`, `dd`, `mkfs*`, `shutdown`/`reboot`, raw-disk writes, fork bombs), gated on `DESTRUCTIVE_WRITE` in `scope.json` `disallowed_actions`.

Every command also runs under a wall-clock timeout so a hung tool cannot stall the engine.

### Operating Policy (authorized targets only)

Artifactory is for testing **targets you are authorized to assess**. Within an in-scope engagement, aggressive-but-legal tradecraft is in play (rate-limited brute force, old-backup/source review, feature-logic bypass, and novel techniques synthesized as needed), and proof-of-concept data retrieval is permitted when a test incidentally proves impact. Availability/DoS-class bugs may be **discovered and minimally proven**, but deliberate sustained flooding is out of scope. The host/CIDR scope gate and the destructive-action block are the hard boundaries.

### Automated Per-Finding Reporting (`report_engine.py`)

Recording a finding auto-compiles a markdown advisory plus an evidence log under `./reports/`, correlated to the exact pointer IDs that proved it. Regenerate manually with:

```bash
python3 ~/artifactory/report_engine.py

```

### Two-Tier Cognition: Background Scout & Ranked Leads

The expensive operator model should make decisions, not read the firehose of tool output. Artifactory splits cognition in two:

* **Operator** (your interactive agent) — consumes only a short, ranked **leads** list and drives strategy/exploitation.
* **Scout** (background) — digests every command's raw output into leads on `board.json`. It is **deterministic-first** (endpoints, open ports, subdomains, tech banners, and high-signal anomalies like SQL errors or leaked `/etc/passwd` are parsed for free, instantly), with an **optional cheap/free model** for smarter ranking.

Run heavy enumeration detached so nothing blocks, then pull the digest:

```bash
# Launch a scan in the background (returns immediately; results + leads land on the board when done)
python3 ~/artifactory/sec_flow.py run --bg --cmd "ffuf -u http://127.0.0.1:8080/FUZZ -w list.txt" --target "127.0.0.1"

# Consume the ranked leads instead of raw logs (anomaly > port/endpoint > tech)
python3 ~/artifactory/sec_flow.py leads --status new

# Mark a lead as you work it
python3 ~/artifactory/sec_flow.py leads --id LEAD_ABC123 --set-status testing

```

The **Scout model is optional and provider-agnostic**. Deterministic triage always runs for free; to add model-based ranking, set `enabled: true` in `.blackboard/scout.json` and point its OpenAI-compatible `base_url`/`model` at any free tier (e.g. Groq, or an OpenRouter `:free` model) with the API key it names. If it's disabled or unreachable, leads still populate — the engine never blocks on it.

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
