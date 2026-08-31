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
    ├── sec_flow.py             <-- Safe runner, fail-closed scope gate + HMAC scope signing, canary + destructive guards, rate limiter, nuclei bridge, fingerprint cache, chain graph
    ├── scope_sig.py            <-- Scope tamper-evidence library (HMAC-sign/verify scope.json; key outside workspace)
    ├── auth_manager.py         <-- Auth-state manager (sessions-as-pointers) + role-diff BAC/IDOR engine
    ├── oob.py                  <-- OOB callback engine: tagged payloads, HTTP+DNS listener, attribution
    ├── tokens.py               <-- Token ledger: per-role budgets + proven-vulns-per-1M-tokens metric
    ├── eval_engine.py          <-- Learning loop: engine suite, engagement score + A/B compare, lab manifests (incl. hold-out), promotion gate
    ├── vuln_lab.py             <-- Seeded lab 1 (BAC/IDOR/blind-SSRF/anomaly; ground truth)
    ├── vuln_lab2.py            <-- Seeded lab 2 (secret-in-JS/redirect/traversal/mass-assign)
    ├── vuln_lab3.py            <-- HOLD-OUT lab 3 (header-bypass/debug-leak/CORS — final gate only)
    ├── burp_bridge.py         <-- Burp Suite bridge: history->inventory, scanner issues->leads, Pro REST scan driver
    ├── zap_bridge.py          <-- Headless ZAP fallback (docker one-shot, same lead contract)
    ├── crawl.py                <-- Deterministic endpoint crawler (auto-builds role-diff inventory)
    ├── debrief.py              <-- Automated post-engagement debrief + episodic lessons store
    ├── patch_diff.py           <-- 1-day variant engine: upstream fix diff -> sink extraction -> hunt leads
    ├── metrics.py              <-- Global metrics rollup (cross-engagement trend curve)
    ├── interaction_growth.py  <-- Advisory co-occurrence mining -> new interaction-pair proposals
    ├── component_aliases.py    <-- Product -> embedded-component map (appliance intel broadening)
    ├── fuzz_driver.py          <-- Grammar fuzzing + libFuzzer harness scaffolding
    ├── redact.py               <-- Egress redaction layer (secrets never leave the engine in context)
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
        ├── logic/              <-- Business logic & access control flaws (role_diff methodology)
        ├── chaining/           <-- Multi-vector chaining strategies (chain_methodology)
        ├── sast/               <-- Guided disproof questions per bug class + fuzz-harness generation
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
* **`[!] SCOPE SIGNATURE INVALID`** — scope.json's authorization fields (hosts/domains/cidrs/code_paths/actions) are HMAC-signed with a key stored OUTSIDE the workspace (`~/.artifactory/scope_signing.key`, 0600). Silent tampering fails every gate; operator-driven scope edits (`scope --add-*`, `--approve`, subdomain auto-expansion) re-sign automatically. Legacy unsigned workspaces still run — re-run `init_env.py` to enable tamper evidence.

Every command also runs under a wall-clock timeout so a hung tool cannot stall the engine, and an optional **per-host rate limiter** (`scope.json` → `rate_limit.min_interval_seconds`) paces consecutive commands against the same host in code — not policy text.

### 1-Day Template Corpus & Target Fingerprints (`sec_flow.py nuclei|fingerprint`)

* `nuclei --target <t>` fires the community template corpus at an in-scope target; every matcher hit becomes a `must_verify` `cve` lead (a template match is a candidate, never a finding — the verification gate still applies). If nuclei isn't installed, a visible coverage-gap lead is filed — no silent drops.
* `fingerprint --host <h> --tech '<banner>' --record` / `fingerprint --host <h>` caches target tech per host (14-day TTL) so a stack is never re-learned twice; `--all` lists the cache. Recon consults the cache before re-probing; CVE enumeration can key off it.

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
* **`skeptic`** — the adversary in the escalation ladder: attacks the evidence behind a proposed confirmed finding (innocent explanations, repro faults, severity inflation). A high-impact claim should SURVIVE the skeptic before it reaches the report.

**Escalation ladder** (cheap second opinions before expensive ones): deterministic re-inspect → exploit/verifier re-derivation → skeptic review → operator. Stuck-detection and disagreement escalate up the ladder; each rung costs more than the last, so the cheap ones run first.

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

### Auth-State Manager & Role-Diff (`auth_manager.py`)

Sessions are first-class blackboard artifacts: credentials live in `.blackboard/sessions/<SESS_ID>.json`, the board keeps only pointers — auth state never bloats context. Roles form a matrix (anon + every authenticated role), with optional refresh hooks for rotating tokens.

**Role-diff** is the mechanical BAC/IDOR sweep: replay the endpoint inventory under every role, normalize volatile content (CSRF tokens, nonces, timestamps — deterministic, not LLM), and every response DELTA lands as a `rolediff` lead. Broken access control is OWASP #1 and invisible to injection scanners; this finds it at near-zero token cost.

```bash
python3 ~/artifactory-engine/artifactory/auth_manager.py add --role admin --auth-type cookie \
  --target "http://127.0.0.1:8080" --credential "session=admin-abc"
python3 ~/artifactory-engine/artifactory/auth_manager.py role-diff --base-url "http://127.0.0.1:8080" \
  --roles SESS_XXXXXX,SESS_YYYYYY --endpoints endpoints.txt   # baseline first
```

### OOB Callback Engine (`oob.py`)

Blind-vulnerability confirmation (SSRF/XXE/SSTI/blind-RCE) with payload-tag attribution and no external infrastructure: mints tagged probe URLs, runs an HTTP+DNS listener, and files every callback as a high-confidence anomaly lead tied to its originating probe. For internet-facing targets, point payloads at interactsh and keep the same tag discipline.

```bash
python3 ~/artifactory-engine/artifactory/oob.py generate --host <listener-host> --purpose "blind SSRF via importer"
python3 ~/artifactory-engine/artifactory/oob.py listen        # or --dns for the DNS observer
python3 ~/artifactory-engine/artifactory/oob.py status         # poll hits -> leads
```

### Token Accounting (`tokens.py`) — the north-star metric

Every model spend is ledgered (`.blackboard/tokens.jsonl`) by role and purpose, with per-role budgets and the framework's optimization target: **proven vulns per 1M tokens**.

```bash
python3 ~/artifactory-engine/artifactory/tokens.py log --role operator --purpose "recon phase" --amount 12000
python3 ~/artifactory-engine/artifactory/tokens.py budget --role operator --limit 200000
python3 ~/artifactory-engine/artifactory/tokens.py report      # spend breakdown + north-star
```

### Chain Graph (`sec_flow.py chains`) — finding composition

Findings carry directed chain edges (`--chain-to` on `add-asset`, or `chains --link A,B --note ...`); `chains` renders every demonstrated attack path and highlights the longest — leaked token → auth bypass → IDOR → data reach becomes a walkable graph, not prose. Chain methodology lives in `prompts/chaining/chain_methodology.md` (when does A's primitive satisfy B's need?).

### Eval Loop: Lab Suite, Scoring, Promotion Gate (`vuln_lab*.py` + `eval_engine.py`)

The learning flywheel, eval-gated end to end — **labs only for promotion; live engagements feed scores but never promote**:

* **Lab 1** (`vuln_lab.py`, :8099): BAC, IDOR, blind SSRF, anomaly leak. **Lab 2** (`vuln_lab2.py`, :8100): secret-in-JS, open redirect, path traversal, mass-assignment — a different bug flavor so the gate can't overfit one lab. **Lab 3** (`vuln_lab3.py`, :8101) is **HOLD-OUT**: header auth bypass, debug leak, CORS misconfig; only `eval_engine.py gate --final` ever touches it.
* **Engine suite** (`eval_engine.py suite engine`): 30 deterministic machinery checks — scope gate, signing (tamper + sig-deletion), destructive block, verification gate, triage, role-diff, OOB attribution, token ledger, chains, rate limiter, fingerprints, nuclei (mocked real path + coverage-gap), redaction, crawler, mining, report rendering.
* **Scoring** (`eval_engine.py score --label <run>`): north-star + precision + coverage, appended to `evals/scores.jsonl`; **`compare`** A/B-diffs the last two runs (deterministic verdict: B WINS / REGRESSION / EQUIVALENT).
* **Promotion**: `gate --candidate <x>` (labs 1-2 iteration) → `gate --final` (engine suite + hold-out lab3). Candidates that regress anything are rejected; every decision lands in `evals/manifest.json`.

### Burp Suite Bridge (`burp_bridge.py`) — Burp-first, any edition

Your manual Burp browsing is the engine's baseline inventory, at zero token cost:

* **`ingest-history --file history.xml`** — Burp "Save items" export → unique `endpoint` leads + raw traffic stored as a verifiable evidence artifact + `endpoints.txt` (the role-diff baseline). Out-of-scope hosts in the history are flagged, never silently dropped. Workflow: browse as the highest-privilege role → ingest → `role-diff` replays your surface across every other role.
* **`ingest-issues --file issues.xml`** — Burp Pro Scanner issues export → `must_verify` leads (scanner candidates are never findings; the verification gate applies).
* **`scan --target <url>`** — drives a scan via Burp Pro's REST API (:1337), polls, files issues as leads; API unreachable → visible coverage-gap lead.
* ZAP remains the headless docker fallback (`zap_bridge.py --target <url>`), same lead contract — scanners are swappable behind the same board interface.

```bash
python3 ~/artifactory-engine/artifactory/burp_bridge.py ingest-history --file history.xml
python3 ~/artifactory-engine/artifactory/auth_manager.py role-diff --base-url <base> \
  --roles SESS_ADMIN,SESS_USER --endpoints endpoints.txt
```

### Compound Metrics & Growth Tools

* **Global metrics** (`metrics.py scan|show`): every workspace's scores roll into one cross-engagement history (`~/.artifactory/metrics_history.jsonl`) with a first-half vs recent-half trend — the actual "getting better" curve on the north-star metric.
* **Interaction-table growth** (`interaction_growth.py mine|local`): NVD advisory co-occurrence mining proposes new component pairs with CVE evidence; approvals land in `knowledge/interactions_local.json` (loaded on top of built-ins, which now include HTTP/2/h2c classes).
* **Component aliasing** (`component_aliases.py`): product → embedded-component map (gitlab→nginx/workhorse/...); intel hints embedded-component broadening for appliances.
* **Fuzz driver** (`fuzz_driver.py grammar|scaffold`): deterministic mutation fuzzing of request seeds against in-scope targets (anomaly leads on 5xx/hangs) + libFuzzer C harness scaffolding for white-box campaigns.
* **Per-payload IDs** (`payload_corpus.py`): P1..Pn per line; `note --payload-id` for fine-grained wins (families stay primary).
* **Watch mode** (`maintenance.py --watch N`): freshness loop on a poll interval (≥300s floor).
* **Skeptic contract** (lab3 manifest): a confirmed finding without evidence structurally fails the hold-out gate — the skeptic can't argue its way past proof.

### Researcher Behaviors (freshness, prioritization, interactions, corpus)

* **Source freshness** (`playbook_engine.py --refresh`): every built source's page is content-hashed; changed pages re-queue into the pending synthesis worklist. The research library is live, not a snapshot. Sources carry quality tiers (primary/advisory/report/guide).
* **CISA KEV** (`kev.py mark|list`): board cve leads matching the known-exploited catalog become PRIORITY-1 (conf 0.85) — real-world prioritization, cached for offline runs.
* **Stack-interaction hypotheses** (`stack_interactions.py hypothesize|pairs`): fingerprint pairs (nginx+tomcat, cache+app, parser+parser...) become must_verify leads — smuggling/poisoning/differential candidates. Researchers attack where components meet.
* **Variant propagation** (automatic on confirm): a confirmed finding queues same-class sweeps across the endpoint inventory — the "test every object endpoint" reflex, in code.
* **Payload corpus** (`payload_corpus.py list|note|retire-review`): curated, tagged payloads ranked by proven wins per stack; debrief feeds it, retirement review flags dead families.
* **Dead-ends store** (`debrief.py deadends`): negative knowledge — classes that died on a stack, with kill reasons, consulted before re-burning tokens.
* **CVE→patch auto-chain**: intel leads carry OSV FIX references; hand the commit URL to `patch_diff.py --diff` to hunt the same bug family on your surface.
* **Lab mutation** (`vuln_lab*.py --seed N`): paths/cookies/IDs/header-names jitter deterministically — evals can't be passed by memorization. Same seed = same lab (reproducible scoring).
* **Maintenance** (`maintenance.py [--suite]`): the cron-able freshness loop — source re-hash, KEV refresh, fingerprint prune, retirement flags (+ optional suite).

* **Crawler** (`crawl.py`): deterministic endpoint discovery (HTML links + JS route literals) that auto-builds the role-diff inventory — the BAC/IDOR sweep is now hands-off, zero model tokens, scope-gated with politeness pacing.
* **Debrief** (`debrief.py`): deterministic post-engagement analysis (lead-type conversion, coverage gaps, token efficiency, chain discipline) → REVIEW CARD for human approval → persisted to the episodic lessons store (`.blackboard/lessons.jsonl` + global `~/.artifactory/lessons.jsonl`). Browse with `debrief.py lessons`.
* **Patch-diff 1-day engine** (`patch_diff.py`): upstream security-fix diff/advisory → bug-class sink extraction (deterministic) → variant-hunt commands for your codebase as `cve` leads.
* **Chain mining** (`sec_flow.py chains --mine`): deterministic primitive/needs matching proposes composition edges ("leaked credential → auth bypass"); accept with `--link` or `--auto-link`.
* **Redaction layer** (`redact.py`): everything the engine emits (previews, inspect output) is scrubbed of cookies/bearer tokens/JWTs/private keys/session credentials; raw artifacts stay byte-identical for verification.

```bash
python3 ~/artifactory-engine/artifactory/vuln_lab.py --port 8099 --selfcheck   # lab 1 ground truth
python3 ~/artifactory-engine/artifactory/vuln_lab2.py --port 8100 --selfcheck  # lab 2 (different flavor)
python3 ~/artifactory-engine/artifactory/eval_engine.py suite engine           # 30 machinery checks
python3 ~/artifactory-engine/artifactory/eval_engine.py score                  # north-star
python3 ~/artifactory-engine/artifactory/eval_engine.py compare               # A/B the last two runs
python3 ~/artifactory-engine/artifactory/eval_engine.py gate --candidate "role-diff playbook v2"
python3 ~/artifactory-engine/artifactory/eval_engine.py gate --candidate "v2" --final  # + hold-out lab 3
```



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

---

# The Newest Layer: Ground Truth on Demand, Knowledge Quality & Operator Interop

## Bug greenhouse & playbook acceptance (knowledge tested before use)
- **Greenhouse** (`greenhouse.py list|grow <class>|grow-all`) — 14 planted-bug recipes (web-core: xss/sqli/traversal/ssrf · logic: bac/idor/mass-assignment/race · auth: jwt-alg-none/weak-tokens/oauth-redirect · advanced: ssti/xxe/deser). Every lab selfchecks; every class has a deterministic evidence marker.
- **Acceptance harness** (`eval_engine.py acceptance --category <c> --name <n>`) — a new/revised methodology must map to greenhouse ground truth, the planted vuln must selfcheck, and the playbook must reference the observable signature. Verdicts: ACCEPTED / GROUND-TRUTH-ONLY / NO-RECIPE / SELF-CHECK-FAILED.
- **PoC delta miner** (`poc_delta.py mine --finding <FID> --playbook <c>/<n>`) — working-PoC-vs-playbook-steps diff → patch cards (missing steps, ingest-approval routed).

## Source accountability (sources earn trust)
- **Lineage** (`lineage.py record|reliability|apply|chain <id>|divergence <c>/<n>`) — the `source → playbook → leads → outcomes` chain is walkable; tiers are EARNED from field wins/losses per class; demotions flagged for review; step-level divergence pinpoints WHICH playbook section kills leads.
- **Evidence hierarchy** — fix-commits (patch_diff) over prose whenever a CVE+patch exists for the class; primary-tier sources preferred in synthesis; allowlist expansion only via operator-approved proposals with provenance.

## One-lookup knowledge & visibility
- **CWE cross-index** (`cross_index.py lookup <class>|map|gaps`) — class → ground truth, methodologies, payloads, rates, lineage, dead-ends in one card; the coverage map shows blind spots pre-engagement (also surfaced in `sec_flow.py status`).

## Production verification, skepticism & interop
- **Tripwires** (`tripwires.py plant|check`) — planted decoys verify detect→redact→report in production; misses expose coverage holes.
- **Skeptic scorecard** (`skeptic_ledger.py record|resolve|stats`) — persona-rotated skeptic verdicts vs eventual ground truth (over-kill / rubber-stamp rates).
- **Importers** (`importers.py har|nmap|nessus|inventory-diff`) — zero-token inventory from scans you already ran; role inventory-diff finds admin-only paths.
- **Cross-operator merge** (`board_merge.py merge --from <ws>`) — conflict-detected board merges; scope never merges.
- **Client report** (`client_report.py export`) — self-contained HTML: CVSS templates, Mermaid attack paths, coverage honesty.
- **Doctor** (`doctor.py [--suite|--json]`) — new-machine readiness in one command.
- **Flight recorder** (`tokens.py flamechart`) — per-step context growth; **debrief replay** (counterfactual learning audit) and **fresh-eyes** (untried families per stack) close the loop.
- **Latency fuzz** (`fuzz_driver.py grammar --timing`) — timing-distribution outliers catch time-based blinds.

**Engine suite: dynamic count — `eval_engine.py suite engine` prints its own executed total (`suite-total`); this README cites the suite, never a stale number.** All new behavior is regression-locked.

---

# Master Plan Implementation (consolidate + 3 upgrades)

## Part A — Consolidation
- **Per-workflow commands**: the ~30KB monolith is now 15 lazily-loaded files (`/artifactory analyze|test|intel|scan-code|research|discover|roles|oob|chains|eval-lab|nuclei|burp|patchdiff|tokens|catalog`), each ≤4KB with a shared auto-emitted preamble. `/artifactory catalog` indexes every non-major workflow — nothing disappeared.
- **Doc drift killed**: suite prints its own `suite-total`; single sed pass; skeptic agent deduped.
- **Wiring self-check**: `doctor.py --wiring` — true orphan modules (undocumented AND untested) fail the doctor; libraries are exempt by list.

## Part B — Upgrades
- **B0 `model_router.py`**: role→tier routing (existing ROLES + planner) over OpenAI-compatible providers; unset/unreachable tiers fall back cheaper; no config = deterministic-only, never blocks. `.blackboard/models.json` (workspace) over `~/.artifactory/models.json` (global).
- **B1 `chain_planner.py`**: multi-hop capability-graph planning (`chains --plan --goal RCE|data_exfil|auth_bypass|priv_esc`). Dijkstra with `-log(confidence)` weights (most-probable path), confidence floor 0.05, unconfirmed-node penalties, GOALS table with glob matching, top-N DIVERSE paths. `hypo_edges` (board-level, provenance-tagged) hold planner proposals — **never** `chain_to`; reports render Hypothesized paths separately with resolved lead labels (dashed Mermaid).
- **B2 `mcp_broker.py`**: MCP behind the engine — schemas never enter context. stdio JSON-RPC handshake in stdlib; config at `~/.artifactory/mcp.json` (out-of-workspace, operator-approved, capability-declared); net/fs-capable servers REQUIRE in-scope `--target` per call ("passive" is a property of the call); `describe` emits arg names+types only; results = MSG_* pointers + redacted leads, treated as data.
- **B3 `lab_runner.py` + `self_improve.py`**: headless golden-path lab play (deterministic, includes the blind-SSRF OOB flow) and the full propose pipeline (suite + labs + compare → gate). **Review card by default**; auto-merge ONLY for DATA-only diffs with `--auto-merge` + an HMAC-signed consent (workspace+ref+24h-expiry bound — expired/replayed/mismatched consents reject). Playbooks/poc-deltas are executable tradecraft → always review cards. Safety files → forced review. Merges are auditable commits; canary/replay tasks registered; install.sh re-run promotes stable.

**Engine suite: 86 checks** (`eval_engine.py suite engine` prints its own total — this README cites the suite, never a stale count).
