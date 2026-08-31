# Artifactory Engine — 3 Upgrades (implementation handoff)

For the implementing AI: this engine already exists (see README + `artifactory/*.py`).
Match existing style. Every new behavior MUST add a check to `eval_engine.py suite engine`.
Never touch scope/signing/destructive-block code. All new state goes on `board.json`
or `.blackboard/` via existing helpers (`board_io.py`, pointer artifacts `MSG_*`).

Reference code by SYMBOL name, not line number (line anchors drift between clone/stable).

Shared prerequisite (small, both #2 and #3 need it):
- `model_router.py` — role→tier matrix from `.blackboard/models.json`.
  Use the EXISTING `tokens.py` ROLES verbatim (operator/scout/exploit/verifier/skeptic/
  recon/synthesis/other) — do NOT invent new role names. Add `planner` once (for #1).
  Tiers: scout/recon=cheap-or-free, exploit/synthesis=mid, planner/verifier/skeptic/
  operator=capable. Provider-agnostic OpenAI-compatible (reuse the Scout pattern).
  Never blocks: if a tier is unset/unreachable, fall back to the next cheaper working one.

---

## Upgrade 1 — Capability-graph chaining planner (flagship)

**What & why:** Today `mine_chains()` in `sec_flow.py` does 1-hop keyword matching over
CONFIRMED findings only. Make it a multi-hop planner that searches for attack *paths*
toward a named goal, using both confirmed findings AND unconfirmed primitives. This is
the "chain small bugs into a big one" behavior.

**Where it plugs in:**
- `sec_flow.py`: `PRIMITIVE_NEEDS` table, `mine_chains()`, `manage_chains()`, and the
  `chain_to` edges on findings (reference by symbol; line numbers drift).
- `prompts/chaining/chain_methodology.md`.

**Build:**
- New module `chain_planner.py` (keep `mine_chains` as the 1-hop fallback).
- Capability model: each finding/lead can emit typed capabilities
  `{gives: ["file_read:/etc","cred:jwt"], needs: ["path_param"], confidence: 0-1, cost}`.
  Derive `gives`/`needs` from the existing keyword table first (deterministic, free);
  let the planner/exploit model propose extra edges (routed via `model_router`).
- Goals = named post-conditions: `RCE`, `auth_bypass`, `data_exfil`, `priv_esc`.
- Search: BFS/Dijkstra over capability edges; edge cost = `1/confidence`; return the
  top-N lowest-cost multi-hop paths from current facts → goal. Unconfirmed primitives
  allowed but carry lower confidence (so proven chains rank first).
- Two edge stores, kept separate: `chain_to` = evidence-backed hops only (unchanged
  contract); a NEW `hypo_edges` field holds planner-proposed unproven hops. Nothing the
  planner invents ever writes to `chain_to`.

**CLI contract:**
- `sec_flow.py chains --plan --goal RCE` → prints ranked paths `A→B→C→goal (conf, hops)`.
- `--auto-link` writes ONLY evidence-backed hops as `chain_to` edges (reuse the guarded
  path); unproven hops go to `hypo_edges`, never `chain_to`.
- Paths flow into the existing report Mermaid attack-path renderer (hypo hops dashed/labeled).

**Safety:** planner only PROPOSES; confirming a finding still needs evidence (verification
gate untouched). Unproven hops live in `hypo_edges` and render as `hypothetical (unproven)`
in both CLI and report — they never silently become confirmed `chain_to` edges.

**Done-when (add to engine suite):** first add a `data_exfil` post-condition with its own
`needs` entry (e.g. `data_reach`) to `PRIMITIVE_NEEDS` so the goal is reachable. Then seed
findings for leaked-token + auth-bypass + IDOR + data-reach → `chains --plan --goal
data_exfil` returns a ≥3-hop path; a graph with no path returns "no chain to goal" cleanly
(no crash).

---

## Upgrade 2 — MCP-as-backend broker (MCP without context bloat)

**What & why:** MCP tool schemas must NEVER enter the operator model's context. Keep MCP
servers behind the Python engine: the broker calls the tool, stores the raw result as a
`MSG_*` pointer artifact, and files a lead — exactly like `sec_flow.py run` does for shell.
The operator sees a pointer + lead, never the schema. Adds capability at ~zero token cost.

**Where it plugs in:**
- Mirror the `sec_flow.py run` pattern: artifact under `.blackboard/artifacts/MSG_*`,
  20-line preview (only when raw output >100 lines, same as `run`), triage → leads,
  redaction on egress (`redact.py`).
- Scope gate: EVERY MCP call is classified by the server's declared capabilities, not by a
  "passive" label. Any call that can reach the network or filesystem goes through the
  in-scope `--target` check. "Passive" is a property of the call, never assumed of a server.

**Build:**
- New module `mcp_broker.py`.
- Config lives OUTSIDE the workspace at `~/.artifactory/mcp.json` (or, if kept in
  `.blackboard/`, is signature-covered like scope). A tampered config must not be able to
  register an arbitrary-command server silently. Each server entry:
  `{name, transport, command|url, capabilities: [net|fs|local], trust: operator-approved}`.
  Loaded by the ENGINE only — never printed into model context.
- A local/stdio MCP server = arbitrary code execution; treat it with the same trust as
  running a tool binary. No server is usable until an operator approves it (allowlist).
- Lazy tool routing: a small map `lead-class → allowed tool names`. The operator is only
  told "tool <name> is available for this lead" (name + 1-line purpose), not the schema.
- Treat all MCP output as untrusted DATA, never as instructions.

**CLI contract:**
- `mcp_broker.py list` → server + tool names + 1-line purposes (no schemas).
- `mcp_broker.py call --server S --tool T --args '{...}' --target <in-scope>`
  → runs it, writes `MSG_*`, files lead, prints pointer + preview.

**Safety:** every server operator-approved with declared capabilities; scope gate enforced
on any net/fs-reaching call (no "passive" bypass); config signed or out-of-workspace; output
redacted; results are data, never instructions.

**Done-when (add to engine suite):** a MOCK MCP server (stdio) returning a fixed blob →
`call` produces a `MSG_*` artifact + one lead; `board.json` contains NO tool schema and NO
raw secret from the blob (redaction holds).

---

## Upgrade 3 — Autonomous self-improve driver (auto-apply non-safety on green)

**What & why:** The promotion gate exists (`eval_engine.py gate`) but nothing drives it
end-to-end, and the lab suite still needs an agent to *play* it. Build the driver that
proposes a change, runs the full gate HEADLESS, and auto-merges the git diff only if
nothing regresses — else files a human review card. Safety files are never eligible.

**Where it plugs in:**
- `eval_engine.py`: `suite engine`, `acceptance`, `validate-lab`, `gate --final`,
  `score`/`compare`. `greenhouse.py` labs. `poc_delta.py` patch cards (candidate source).

**Build (two modules):**
- `lab_runner.py` — plays greenhouse/vuln labs UNATTENDED (deterministic steps directly;
  LLM-in-loop steps via `model_router` cheap tier) so `validate-lab` has a board to score.
- `self_improve.py` — orchestrates: (1) take a candidate diff (from `poc_delta`, a source
  refresh, or a new/edited playbook); (2) apply on a temp git branch/worktree; (3) run
  `suite engine` + `lab_runner` on labs 1&2 + `acceptance`; (4) if all pass AND `compare`
  is not a REGRESSION vs incumbent → `gate --final` (hold-out lab3); (5) on PROMOTE,
  auto-merge the diff; else write a review card to `.blackboard/review/`.

**Safety (hard rules):**
- Path allowlist — the driver may only auto-merge changes under
  `prompts/`, `knowledge/`, `payloads/`. Any diff touching `sec_flow.py`, `scope_sig.py`,
  destructive/scope/signing code → forced human review, never auto-merged.
- Every change is an auditable git commit (revertible).
- A failing or regressing candidate is never merged.

**CLI contract:**
- `self_improve.py propose --from poc-delta|source-refresh|playbook <ref>` → runs the
  pipeline, prints PROMOTE/REJECT + reasons, merges or files review card.

**Done-when (add to engine suite):** a known-good candidate auto-promotes (green);
a deliberately-regressing candidate is REJECTED and NOT merged; a candidate touching a
safety file is routed to review even if tests pass.

---

## Build order
1. `model_router.py` (shared, small).
2. Upgrade 1 (self-contained, highest value).
3. Upgrade 2 (needs router).
4. Upgrade 3 (needs router + labs; biggest, do last).

Each upgrade lands with its engine-suite check before the next starts.
