# 🏴‍☠️ Artifactory Security Engine

Artifactory is an autonomous, token-efficient AI security-testing engine that runs **inside [OpenCode](https://github.com/sst/opencode)** (a terminal AI coding agent). You talk to it in plain English with `/artifactory` slash commands; it does the tradecraft — scoped, safe, and repeatable.

It is built on the **Sovereign Blackboard Architecture (SBA)**: instead of dumping raw tool output into the model's context or letting the AI run risky commands directly, every action goes through a local Python engine that enforces scope, blocks destructive commands, stores big outputs as pointers, and hands the model only short, ranked "leads."

> **New here? Read [Quick Start](#-quick-start) then the [Command Cheat-Sheet](#-command-cheat-sheet-when-to-run-what). That's all you need to run your first engagement.**

---

## 🧠 The Mental Model (how the pieces fit)

```text
   You (operator)
       │  type:  /artifactory analyze https://target
       ▼
   OpenCode agent  ────────────────┐   reads your slash command,
   (the AI you chat with)          │   decides which engine tools to run
       │                           │
       │  runs:  art.py <tool> ... │   ← ONE entry point for everything
       ▼                           ▼
   Artifactory engine (Python)   Subagents: recon · exploit · verifier · skeptic · planner
       │                             (specialists the agent delegates to)
       ▼
   .blackboard/   ← per-target workspace: scope.json, board.json, leads, artifacts, reports
```

Three things to remember:

1. **You drive it through OpenCode slash commands** — `/artifactory <something>`. You rarely type raw Python.
2. **Everything the engine does runs through one dispatcher: `art.py <tool>`.** The slash commands are just instructions that tell the AI which engine tools to run and in what order.
3. **State lives on disk in `.blackboard/`, not in the chat.** Scope, findings, and evidence survive across turns and sessions — the model only ever sees short summaries, which is why it stays cheap.

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/0xWalid/Artifactory-engine.git
cd Artifactory-engine
chmod +x install.sh
./install.sh
```

`install.sh` does four things:

1. **Promotes this checkout into a stable release dir** at `~/artifactory-engine/` (copies the engine, refreshes it if it already exists, leaves your live `.blackboard/` intact). You edit code here in the checkout, then re-run `./install.sh` to push changes to the stable dir.
2. **Registers the `/artifactory` command and the specialist subagents** into `~/.config/opencode/` (1 dispatcher command file + 5 agent files), rewriting every path to the absolute stable location. `/artifactory <workflow>` routes to one of 15 workflow bodies (`artifactory/workflows/*.md`), loaded lazily so each invocation costs one short workflow, not a monolith.
3. **Makes all engine tools executable** and checks for optional external tools (`python3`, `git`, `semgrep`, `nmap`, `httpx`, `ffuf`) — it *reports* what's missing but does not install anything.
4. Everything the commands run points at one entry point: `~/artifactory-engine/artifactory/art.py <tool>`.

### 2. Run your first engagement

```bash
cd /path/to/your/target-workspace   # a scratch dir for THIS target
opencode                            # start the OpenCode agent here
```

Then, inside OpenCode:

```text
/artifactory analyze https://target-you-are-authorized-to-test.com
```

That single command runs the whole happy path for you: it initializes the `.blackboard/` workspace, sets scope, does passive recon, discovers leads, works the ranked leads into tested findings, and writes advisories. **Watch it work and answer any approval prompts** — the human-in-the-loop gates (approving new scope, confirming a synthesized playbook) are intentional.

> ⚠️ **Authorized targets only.** Scope is fail-closed: an empty/missing `scope.json` permits nothing, and every command must name an in-scope `--target`. Use this only on systems you own or are contracted to test.

---

## 📋 Command Cheat-Sheet: when to run what

All commands are typed inside an `opencode` session in your target workspace. If you only remember one, remember `/artifactory analyze` (it drives everything) and `/artifactory catalog` (it lists everything).

### Start here — the main driver

| Command | When to run it |
| --- | --- |
| `/artifactory analyze <target>` | **The main event.** Kicks off a full assessment: init → scope → recon → work leads → test → debrief. Start every engagement here. |
| `/artifactory catalog` | "What can this thing do?" A one-line index of every tool, grouped by category. Run it anytime you're looking for a capability a bigger command didn't surface. |

### Set up your knowledge (do once, then occasionally)

| Command | When to run it |
| --- | --- |
| `/artifactory discover <bug-class or topic>` | **Grow your source library.** Searches a trusted-domain allowlist (PortSwigger, Orange Tsai, OWASP, Project Zero…) for quality write-ups, proposes them, and saves the ones you approve. |
| `/artifactory research [category]` | **Turn sources into playbooks.** Reads sources that don't have a playbook yet, synthesizes a reusable step-by-step methodology from each, shows you one approval table, and saves them. Safe to re-run — it skips anything already built. |

### Per-engagement testing (pick what fits the target)

| Command | When to run it |
| --- | --- |
| `/artifactory intel <product> [version]` | You know the product/version (e.g. `keycloak 26.0.0`). Enumerates CVE candidates from OSV+NVD, distro SCA, and CISA KEV (known-exploited) prioritization. |
| `/artifactory test <target> for <vuln>` | Probe **one** specific bug class. Loads the matching playbook and runs it; if none exists, it walks you through synthesizing one (with your approval) then tests. |
| `/artifactory roles` | **Access-control testing (BAC/IDOR).** Registers your role/credential matrix and mechanically replays every endpoint as every role to find who-can-see-what leaks. OWASP #1, near-zero token cost. |
| `/artifactory scan-code <path>` | **White-box / SAST**, when you have authorized source access. Runs semgrep, has the AI disprove false positives, and proves survivors with a real runtime PoC. |
| `/artifactory nuclei <target>` | Fire the community 1-day template corpus and fingerprint the stack. Matches become "must-verify" candidates (never auto-confirmed). |
| `/artifactory oob` | **Blind bugs** (blind SSRF/XXE/SSTI/RCE). Mints tagged callback payloads, runs a listener, and attributes each hit back to its probe. |
| `/artifactory burp` | You're driving traffic manually through **Burp**. Ingests proxy history into an endpoint inventory + evidence, role-diffs it, and pulls in Pro scanner issues. |
| `/artifactory patchdiff` | An upstream project shipped a **security fix** and you want to hunt the same bug family (variants) on your surface. |
| `/artifactory chains` | Compose individual findings into an **attack path** (leaked token → auth bypass → IDOR → data reach), rendered as a graph in the report. |

### Housekeeping & the engine's own quality

| Command | When to run it |
| --- | --- |
| `/artifactory tokens` | Track spend, set budgets, and see the north-star metric (**proven vulns per 1M tokens**). The debrief reads this ledger. |
| `/artifactory eval-lab` | **For improving the engine itself, never live targets.** Runs the built-in vuln labs, the machinery test suite, scoring, and the promotion gate for new tradecraft. |

---

## 👥 The Team (subagents OpenCode delegates to)

Artifactory runs as a small team over the shared blackboard. The **orchestrator** is the slash command you invoked (it's allowed to pause and ask you things). It delegates to five specialist subagents that run autonomously, return one answer, and **cannot** pause for input — every human approval gate lives in the orchestrator, not here.

| Subagent | Job |
| --- | --- |
| **recon** | Passive-first attack-surface discovery. Builds the endpoint inventory and feeds ranked leads. Never exploits, never logs findings. |
| **exploit** | Takes ONE hypothesis and proves or kills it with a minimal PoC. Draws from the deterministic payload corpus. Doesn't record findings itself. |
| **verifier** | The gate against false positives and the advisory writer. Confirms a finding *only* when evidence proves impact, then writes the report. |
| **skeptic** | The adversary. Actively tries to **disprove** a proposed finding (default behavior? lab artifact? inflated severity?). A real finding survives the skeptic. |
| **planner** | Multi-hop chain planning toward a named goal (RCE / data_exfil / auth_bypass / priv_esc). Output is a **proposal only** — it never claims a hop is demonstrated. |

**Escalation ladder** (cheap opinions before expensive ones): deterministic re-inspect → exploit/verifier re-derivation → skeptic review → you. Each rung costs more, so the cheap ones run first.

---

## 🛡 Safety Guardrails

Every command the engine runs passes through `sec_flow`'s safe runner. Four hard interlocks are enforced in code (not prompt text), and refusals are always surfaced — never silently bypassed:

- **`[!] SCOPE ERROR`** — target not authorized in `.blackboard/scope.json`. Fail-closed: empty scope permits nothing.
- **`[!] SCOPE SIGNATURE INVALID`** — the scope's authorization fields are HMAC-signed with a key stored outside the workspace (`~/.artifactory/scope_signing.key`). Silent tampering fails every gate.
- **`[!] CANARY TRIPWIRE`** — a command touched do-not-touch data (the workspace canary token).
- **`[!] DESTRUCTIVE-ACTION BLOCK`** — irreversible destruction (`rm -r/-f`, `dd`, `mkfs*`, `shutdown`, raw-disk writes, fork bombs).

Commands also run under a wall-clock timeout and an optional per-host rate limiter. Findings are **`informational` by default** and only become a **`confirmed` vulnerability** when they carry evidence (an inline PoC or a real execution pointer) — this is the primary defense against false positives. Only confirmed findings become advisories.

---

## ⚙️ Under the Hood (for the curious)

The engine is a **microkernel + feature-package** layout. A tiny shared `core/` kernel plus ~49 CLI "plugin" tools, all launched through one dispatcher.

```text
artifactory/
├── art.py            ← the ONE entry point: art.py <tool> [args]
├── core/             ← kernel: registry, dispatcher bootstrap, scope signing, safe runner, redaction, token ledger
├── scanners/         ← sast, secrets, crawl, graphql, race, entropy, fuzz_driver, triage
├── intel/            ← intel (CVE), kev, patch_diff, SCA, importers, ingest
├── chaining/         ← chain_planner
├── integrations/     ← burp/zap bridges, auth_manager, oob, mcp_broker, model_router
├── report/           ← report_engine, client_report, debrief, metrics
├── knowledge/        ← playbook_engine, lineage, cross_index, skeptic_ledger, sources.json (curated library)
├── ops/              ← doctor, maintenance, snapshot, tripwires, payload_corpus, …
├── eval/             ← eval_engine (test suite), vuln labs, greenhouse, self_improve
├── workflows/        ← the 15 `/artifactory <workflow>` bodies, lazily loaded by `art.py workflow`
└── prompts/          ← the reusable tradecraft playbook library
```

**How `art.py` works:** it puts the kernel + every package dir on the path, looks the tool up in `core/registry.py` (the single source of truth mapping a tool name → its file), and runs it. Because invocation goes by *name* (`art.py sast`), not by file path, tools can be reorganized without breaking anything that calls them.

You normally never type this — OpenCode does it for you. But you can drive any tool directly:

```bash
# General form:
python3 ~/artifactory-engine/artifactory/art.py <tool> [args]

# Examples:
python3 ~/artifactory-engine/artifactory/art.py init_env --target .
python3 ~/artifactory-engine/artifactory/art.py sec_flow run --cmd "curl -s http://127.0.0.1:8080" --target "127.0.0.1"
python3 ~/artifactory-engine/artifactory/art.py sec_flow leads --status new
python3 ~/artifactory-engine/artifactory/art.py doctor --wiring     # health check
python3 ~/artifactory-engine/artifactory/art.py                     # no args → lists every tool
```

The engine ships a self-reporting regression suite (`art.py eval_engine suite engine` prints its own executed total). All behavior is regression-locked; this README never cites a stale check count.

---

## 📜 Operating Policy

Artifactory is for testing **targets you are authorized to assess**. Within an in-scope engagement, aggressive-but-legal tradecraft is in play, and proof-of-concept data retrieval is permitted when a test incidentally proves impact. Availability/DoS-class bugs may be discovered and minimally proven, but deliberate sustained flooding is out of scope. The host/CIDR scope gate and the destructive-action block are the hard boundaries.



