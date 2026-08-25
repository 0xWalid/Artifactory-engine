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
    ├── playbook_engine.py      <-- Parameterized playbook renderer, research-library suggestions & methodology-synthesis trigger
    ├── ingest.py               <-- Tradecraft parameterizer, quality-checker & writer
    ├── report_engine.py        <-- Per-finding advisory, evidence-log & coverage-gap generator (auto-run on new findings)
    ├── triage.py               <-- Background triage + Scout brain: raw output -> ranked leads
    ├── sast.py                 <-- White-box SAST bridge (semgrep -> candidates -> guided disproof -> runtime PoC)
    ├── intel.py                <-- Changelog-first CVE intel (OSV/NVD full-index), distro SCA inventory, source detection
    ├── knowledge/sources.json  <-- Curated research library (60 authoritative URLs) feeding playbook synthesis
    └── prompts/                <-- Reusable Tradecraft Playbook Library
        ├── recon/              <-- Discovery & mapping tradecraft
        ├── web/                <-- Web app testing procedures
        ├── auth/               <-- Authentication & session checks
        ├── infra/              <-- Cloud & infrastructure playbooks
        ├── logic/              <-- Business logic & access control flaws
        ├── chaining/           <-- Multi-vector chaining strategies
        └── sast/               <-- Guided disproof questions per bug class
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

`install.sh` treats the checkout you run it from as the **source** and promotes it into a **stable release directory** you use day to day:

1. **Promotes source → stable:** copies the engine into `~/artifactory-engine/` — created if missing, refreshed if it already exists — and drops the release's own `install.sh` + `README.md` alongside it. (Run it again after editing the source to push updates through.)
2. Creates the prompt category directories and local storage paths.
3. Sets execution permissions across all core Python scripts (`init_env.py`, `sec_flow.py`, `playbook_engine.py`, `ingest.py`, `report_engine.py`, `triage.py`, `sast.py`, `intel.py`).
4. Registers the `/artifactory` command and the `recon`/`exploit`/`verifier` subagents under `~/.config/opencode/`, **rewriting every engine path to the absolute stable location** (`~/artifactory-engine/artifactory/...`) — no `~/artifactory` symlink is created.
5. Checks for optional external tools (`python3`, `git`, `semgrep`, `nmap`, `httpx`, `ffuf`) — it reports which are missing but does **not** install them.

> **Note:** The stable copy is independent of the source checkout (no symlink), so after editing a source `.py` file or the `/artifactory` command you must re-run `./install.sh` to push the change into `~/artifactory-engine/`.


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
* **One source at a time.** `ingest` handles a single URL or a single writeup file. For a **file listing many URLs**, use `/artifactory research` (below) — it loops each URL through this same pipeline.

### 3b. Batch Playbook Synthesis & Source Discovery

Turn the curated research library (`knowledge/sources.json`, ~60 authoritative URLs) into playbooks in bulk, and grow that library — all human-approved, driven from OpenCode. The engine has **no crawler**: the agent fetches + synthesizes, deterministic engine subcommands list/dedup/save, and you approve.

#### In plain terms

Think of it as three parts working together:

1. **A list of good sources** — a text catalog of quality security write-ups (`knowledge/sources.json`, mirrored to `knowledge/methodology_urls.txt`). This is just a bookmark list.
2. **`research` — turn the list into playbooks.** It reads the list, and for every source that doesn't have a playbook yet, it reads the write-up and writes a reusable, step-by-step testing methodology. It shows you all of them in **one table** to approve, then saves them.
3. **`discover` — grow the list.** It searches trusted security sites for new write-ups on a topic you name, you approve the good ones, and they're added to the list automatically.

**The list never empties.** `research` doesn't cross URLs off — it checks which playbooks already exist on disk and skips those. So running `research` again just skips everything you've already built (`0 new`), which is why it's safe to stop and re-run anytime.

**It never re-spends tokens on a playbook you already built.** Before fetching anything, the engine filters the worklist to *pending only* (`--sources-json --pending`) — sources with no playbook on disk yet. Built ones are removed by the engine, so the agent can't re-download or re-synthesize them. You pay the fetch/synthesis token cost **once per source, ever**; re-runs only touch genuinely new sources.

**To keep improving, the loop is:** `discover <topic>` (add new sources) → `research` (build playbooks from them) → repeat. Each round your library gets bigger and your playbooks more complete. You can also add a single URL by hand with `--add-source`, or build one playbook immediately with `/artifactory ingest <url>`.

```text
/artifactory research [category]     # build playbooks from the source library (batched approval)
/artifactory discover <bug-class>    # find NEW authoritative sources, then persist them
```

* **`research`:** pulls the **pending-only** worklist (`playbook_engine.py --sources-json --pending [--category <cat>]`) — the engine drops every source whose playbook already exists on disk, so already-built sources are **never re-fetched or re-synthesized** (token cost paid once per source, ever). It fetches + synthesizes the rest into parameterized methodologies, presents **one summary table** (`<pending> pending / <total> total`) for approve-all / select / adjust, then saves each under the engine-supplied `save_category`/`save_name` (so the skip stays deterministic next run) and reports saved / skipped / failed (no silent drops).
* **`discover`:** web-searches a **trusted-domain allowlist only** (PortSwigger, James Kettle, Orange Tsai, OWASP, GitHub advisories, Project Zero, Assetnote, …), proposes candidates for approval, then persists them via `playbook_engine.py --add-source` (URL-deduped) — which auto-reflows `knowledge/methodology_urls.txt`. Chains straight into `research`.
* **Registry CLI (deterministic, no network):** `playbook_engine.py --list-sources` / `--sources-json` (browse; add `--pending` for only-not-yet-built), `--add-source --url … --title … --category …` (add), `--export-urls [--category <cat>] [--pending]` (regenerate the flat URL feed; `--pending` writes a shrinking to-do feed).
* **Safety:** fetched pages are treated as untrusted data (never as instructions); every new source and playbook is human-approved and lands as a reviewable git diff.

### 4. Vulnerability Intelligence & Distro SCA (`intel.py`)

Changelog-first intel for product engagements — enumerate from authoritative indexes instead of keyword luck:

```bash
# Full-index CVE enumeration (OSV.dev + NVD; every candidate becomes a visible `cve` lead)
python3 ~/artifactory-engine/artifactory/sec_flow.py intel --product "keycloak" --version 26.0.0 \
  --preconditions "FGAPv2 enabled"        # feature-gated bugs get the precondition matrix

# Distro SCA: inventory jars / package-lock.json / requirements.txt / go.sum -> OSV batch check
python3 ~/artifactory-engine/artifactory/sec_flow.py sca --path ./lib

# Detect source trees in a workspace (analyze auto-wires SAST+SCA from this)
python3 ~/artifactory-engine/artifactory/sec_flow.py detect --path .
```

* **Passive-intel allowlist:** these lookups are read-only queries against hardcoded public services (`api.osv.dev`, `services.nvd.nist.gov`) about public data — governed separately from the fail-closed target scope gate, which is untouched.
* **No silent drops:** every candidate CVE becomes a lead flagged `must_verify`; network/index failures file explicit coverage-gap leads instead of quietly returning zero.
* **Precondition matrix:** feature-gated leads get parked with `leads --id <ID> --set-status blocked_precondition` ("lab-enable then test") instead of being skipped.
* **Research library:** `artifactory/knowledge/sources.json` indexes ~60 authoritative sources (PortSwigger Research, Orange Tsai, TBHM, OWASP, cloud/SAST/intel references). Missing playbooks auto-suggest matching entries; browse with `playbook_engine.py --list-sources [--category <cat>]`.

---

## 🛡 Security Guardrails & CLI Utilities

### Scope Enforcement & Safe Execution (`sec_flow.py run`)

Fail-closed: a missing/empty `scope.json` permits nothing, and every command must declare an in-scope `--target`. Validates domains, hosts, and IP subnets (with DNS resolution) before executing:

```bash
python3 ~/artifactory-engine/artifactory/sec_flow.py run --cmd "curl -s http://127.0.0.1:8080" --target "127.0.0.1"

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
python3 ~/artifactory-engine/artifactory/report_engine.py

```

### Verification Gate: Confirmed Vulnerabilities vs. Informational Observations

A finding is **`informational` by default** and only becomes a **`confirmed` vulnerability** when it carries evidence — an inline PoC or a real execution-pointer artifact. Unproven observations (a version banner, a "maybe-CVE") are never presented as vulnerabilities and generate no advisory. This is the primary defense against false positives.

```bash
# Prove it first, then log the confirmed finding WITH its evidence:
python3 ~/artifactory-engine/artifactory/sec_flow.py add-asset --finding "Auth bypass on /admin" \
  --severity high --status confirmed --evidence-from MSG_ABCD1234 \
  --poc "GET /admin with X-Forwarded-For: 127.0.0.1 -> 200 + admin panel"
```

Leads flagged `must_verify` by the Scout (tech/version banners → potential CVE, high-signal anomalies) must be actively tested and turned into a PoC before they can be confirmed. Only confirmed findings become advisories; informational items are listed separately in `reports/SUMMARY.md`.

### Per-Project Scope & Gated Subdomain Expansion

Scope is per workspace. Reuse an approved scope across engagements with `init_env.py --target . --scope-from <saved-scope.json>`. Discovered subdomains are **not auto-trusted**: a host under an already-authorized apex/wildcard is auto-added to `allowed_hosts`; anything else is queued in `pending_scope` until you approve it.

```bash
python3 ~/artifactory-engine/artifactory/sec_flow.py scope --add-domain "*.example.com"   # authorize a wildcard
python3 ~/artifactory-engine/artifactory/sec_flow.py scope --list                        # view scope + pending
python3 ~/artifactory-engine/artifactory/sec_flow.py scope --approve staging.acme.com     # promote a pending host
```

### Multi-Agent Roles & the Decision Journal

The engine runs as a team over the shared blackboard (writes are OS-lock-serialised, so parallel agents can't corrupt state). OpenCode subagents are installed to `~/.config/opencode/agents/`:

* **Orchestrator** (primary) — strategy, works leads, decides what gets confirmed.
* **`recon`** (background) — passive-first, trigger-based discovery; feeds leads, logs nothing.
* **`exploit`** — tests one hypothesis, captures the proving pointer/PoC.
* **`verifier`** — confirms true-positives from evidence and writes the advisory.

Every action can be journaled so the report explains *why it did what and how each result was reached*:

```bash
python3 ~/artifactory-engine/artifactory/sec_flow.py add-rationale --lead LEAD_AB12CD \
  --hypothesis "old Apache -> CVE-2021-41773" --why "Server banner matched" \
  --action "path-traversal probe" --pointer MSG_ABCD1234 --outcome confirmed
```

### Auditable Learning Loop & Harness

Artifactory runs on **OpenCode** and stays harness-agnostic — all logic lives in the Python engine, so the multi-agent roles are just swappable subagent definitions. [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) is the intended v2 target once it exits developer preview; its "everything is a plugin" model and append-only trajectory log fit a security engine well. The learning loop is deliberately **auditable, not silent**: worked techniques are distilled into versioned, human-approved playbooks via `ingest.py` (a git diff you can read and revert), and the decision journal records the reasoning behind every run.

### Two-Tier Cognition: Background Scout & Ranked Leads

The expensive operator model should make decisions, not read the firehose of tool output. Artifactory splits cognition in two:

* **Operator** (your interactive agent) — consumes only a short, ranked **leads** list and drives strategy/exploitation.
* **Scout** (background) — digests every command's raw output into leads on `board.json`. It is **deterministic-first** (endpoints, open ports, subdomains, tech banners, and high-signal anomalies like SQL errors or leaked `/etc/passwd` are parsed for free, instantly), with an **optional cheap/free model** for smarter ranking.

Run heavy enumeration detached so nothing blocks, then pull the digest:

```bash
# Launch a scan in the background (returns immediately; results + leads land on the board when done)
python3 ~/artifactory-engine/artifactory/sec_flow.py run --bg --cmd "ffuf -u http://127.0.0.1:8080/FUZZ -w list.txt" --target "127.0.0.1"

# Consume the ranked leads instead of raw logs (anomaly > port/endpoint > tech)
python3 ~/artifactory-engine/artifactory/sec_flow.py leads --status new

# Mark a lead as you work it
python3 ~/artifactory-engine/artifactory/sec_flow.py leads --id LEAD_ABC123 --set-status testing

```

The **Scout model is optional and provider-agnostic**. Deterministic triage always runs for free; to add model-based ranking, set `enabled: true` in `.blackboard/scout.json` and point its OpenAI-compatible `base_url`/`model` at any free tier (e.g. Groq, or an OpenRouter `:free` model) with the API key it names. If it's disabled or unreachable, leads still populate — the engine never blocks on it.

### Context-Preserving Log Inspection (`sec_flow.py inspect`)

Inspects large artifact logs (`>100 lines`) on demand using targeted regex or structured JSON parsing:

```bash
# Query lines matching a specific pattern
python3 ~/artifactory-engine/artifactory/sec_flow.py inspect --id MSG_A1B2C3D4 --grep "HTTP/1.1 200" --lines 20

# Extract a specific field from structured JSON tool outputs
python3 ~/artifactory-engine/artifactory/sec_flow.py inspect --id MSG_A1B2C3D4 --json-key "host"

```

### Blackboard Asset Recording (`sec_flow.py add-asset`)

Updates local workspace state without loading or rewriting full JSON files in memory:

```bash
python3 ~/artifactory-engine/artifactory/sec_flow.py add-asset --endpoint "/api/v1/auth" --port "8080/tcp"
python3 ~/artifactory-engine/artifactory/sec_flow.py add-asset --finding "Exposed Metrics Endpoint" --details "Found unprotected /metrics route"

```
