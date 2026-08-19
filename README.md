
# 🏴‍☠️ Artifactory Security Engine

Artifactory is a practitioner-first, multi-agent security analysis engine built around a **Sovereign Blackboard Architecture**. Designed for AI-assisted security testing, it structures execution into deterministic recon, dynamic playbook selection, and context-isolated tool execution.

Instead of throwing unconstrained CLI outputs directly into LLM context windows or running without scope constraints, Artifactory uses local execution safety wrappers, strict scope enforcement, and pointer-based log management.

---

## 💡 Why Artifactory? (The Architecture Edge)

Artifactory addresses common friction points in automated security workflows through structured local execution:

| Architectural Feature | Traditional AI Wrapper | Artifactory Engine |
| :--- | :--- | :--- |
| **Scope Safety** | Relies solely on system prompts | Hard-gated local checks (`sec_flow.py`) against `scope.json` before commands execute. |
| **Context Management** | Dumps raw stdout/stderr into context | Saves raw CLI logs to `.blackboard/artifacts/` and references lightweight pointer IDs (`[MSG_XXXX]`). |
| **Playbook Mechanics** | Generates unverified, dynamic commands | Executes pre-tested markdown tradecraft playbooks from `prompts/` via `playbook_engine.py`. |
| **Multi-Agent Flow** | Single monolithic prompt loop | Shared local blackboard state file (`board.json`) across specialized agent tasks. |

---

## 📁 Repository Structure

```text
artifactory-engine/
├── install.sh                  <-- Automated setup script
├── README.md                   <-- Engine documentation
└── artifactory/                <-- Core Engine Subfolder
    ├── sec_flow.py             <-- Execution wrapper & scope gate
    ├── playbook_engine.py      <-- Tradecraft playbook loader
    ├── .blackboard/            <-- Local state, scope rules & artifacts
    │   ├── scope.json
    │   ├── board.json
    │   └── artifacts/          <-- Raw execution logs
    └── prompts/                <-- Playbook Libraries
        ├── web/                <-- Web app testing procedures
        ├── api/                <-- API testing playbooks
        ├── cloud/              <-- Cloud configuration checks
        └── network/            <-- Network enumeration guides

```

---

## 🚀 Automated Installation

Artifactory includes an automated installer script that configures local directories and integration paths.

```bash
git clone https://github.com/0xWalid/artifactory-engine.git
cd artifactory-engine
./install.sh

```

### Setup Tasks Executed by `install.sh`:

1. Creates a symlink from `~/artifactory` to `artifactory-engine/artifactory` for path consistency.
2. Initializes local storage directories (`.blackboard/artifacts/`).
3. Sets execution permissions for wrapper scripts (`sec_flow.py`, `playbook_engine.py`).
4. Configures command definition files in `~/.config/opencode/commands/artifactory.md`.

---

## 🛠 Workflows & Integration

### 1. Attack Surface Analysis Workflow

Used to define boundaries, map assets, and prioritize evaluation areas.

```text
/artifactory analyze example.com
```

**Execution Flow:**

1. **Scope Verification:** Prompts for explicitly allowed domains, excluded targets, rate limits, and authentication details. Updates `.blackboard/scope.json`.
2. **Reconnaissance:** Executes passive asset enumeration and HTTP probing via `sec_flow.py`.
3. **Priority Assessment:** Categorizes endpoints, unusual ports, and technology stacks to build an evaluation queue.
4. **Playbook Execution:** References corresponding documentation in `prompts/` for target testing.

---

### 2. Direct Vector Testing Workflow

Used for targeted evaluation of specific vulnerability classes or configurations.

```text
/artifactory test example.com for HTTP Request Smuggling
```

**Execution Flow:**

1. Verifies target host boundaries against `.blackboard/scope.json`.
2. Queries `playbook_engine.py` for matching playbooks in `prompts/web/`.
3. Sequentially executes verified test steps defined in the playbook.
4. Saves raw output to `.blackboard/artifacts/` and updates `.blackboard/board.json`.

---

## 🛡 Guardrails & Log Management

* **Local Scope Enforcement:** Commands are parsed by `python3 ~/artifactory/sec_flow.py "<command>"` before execution. Target domains and IP addresses are validated against `.blackboard/scope.json`.
* **Log Offloading:** Tool output is captured under `.blackboard/artifacts/raw_output_<id>.log`. Summaries and pointer IDs are returned to the session context to maintain efficient context limits.

