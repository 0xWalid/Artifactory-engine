# Artifactory Engine — Master Plan (consolidate + 3 upgrades)

For the implementing AI: this engine already exists (README + `artifactory/*.py`). Match
existing style. Every new behavior MUST keep/add a check to `eval_engine.py suite engine`.
NEVER touch scope/signing/destructive-block code. All new state goes on `board.json` or
`.blackboard/` via existing helpers (`board_io.py`, pointer artifacts `MSG_*`). Reference
code by SYMBOL name, not line number (anchors drift between clone/stable).

**Build order (dependency-correct):**
`A1 → A2 → A3 → B0 → B1 → (A4 + A5 wiring) → A6 → B2 → B3`.
Each item lands with its engine-suite check before the next starts. A6 is practice, not a
blocking build item — fine anywhere at/after this point.

═══════════════════════════════════════════════════════════════════════════
PART A — Consolidate & OpenCode-integrate
═══════════════════════════════════════════════════════════════════════════

## A1. Split the mega-command (biggest token win)
- Problem: `~/.config/opencode/commands/artifactory.md` is one monolith (~199 lines / ~30KB)
  loaded on every invoke.
- Do: in `install.sh`, emit one command file PER workflow so each loads lazily:
  `analyze, test, intel, scan-code, research, discover, roles, oob, chains, eval-lab,
   nuclei, burp, patchdiff, tokens`. OpenCode has NO load-time include mechanism, so dedup
   at the GENERATOR level: one shared-preamble shell variable in `install.sh` emitted into
   each per-workflow file (keep it genuinely short). The token win comes from not loading
   the other workflows, not from cross-file includes.
- COVERAGE: the monolith has ~27 documented sections; the majors above are ~14. Do NOT drop
  the rest (greenhouse/acceptance, lineage, cross-index, tripwires, skeptic ledger, secrets,
  entropy, graphql, race, snapshot/diff, importers, doctor, client-report, maintenance,
  metrics, replay/fresh-eyes, kev, board-merge, ...). Either give each its own file, or emit a
  single `catalog` command that one-line-indexes every non-major (itself lazily loaded).
- Done-when: `/artifactory analyze` loads only its file + the emitted preamble; each emitted
  command file is ≤4KB (vs the ~30KB monolith); and NO documented workflow disappears from the
  split (majors have files, the rest live in `catalog`). Suite check (also the home for A2's
  check): smoke-run `install.sh` into a temp `$HOME`, assert per-file budget + full coverage
  (~1s, pure file ops).

## A2. Kill doc drift (defensive — count is currently in sync)
- Verified: suite prints 59 passed / README says 59 — IN SYNC today. My earlier "code has
  ~40" was stale. Note `eval_engine.py` has 64 `check()` call sites (some conditional/skipped),
  so when the count goes dynamic, decide which number is authoritative (executed checks, not
  raw call sites) or it prints 64 and creates fresh drift against the README's 59.
- The real bugs ARE present: duplicated `sed` block in `install.sh`, doubled paragraph in
  `skeptic.md`. Those are the actual work.
- Do: dedup the `sed` + skeptic text; make the count dynamic (suite prints its own total,
  README reads it) as DEFENSE against future drift, not a fix for a current mismatch.
- Done-when: one sed pass, no doubled skeptic paragraph; dynamic count == README and stays
  matched when a check is added/removed.

## A3. Wiring self-check
- Do: `doctor.py --wiring` (or a suite check) that fails if any `artifactory/*.py` module is
  not reachable from a command/agent doc AND not covered by a suite check.
- Library modules are NOT CLIs — a strict reachability check fails on them forever. Maintain
  a curated exemption/entrypoint list (e.g. `board_io.py`, `scope_sig.py`, `redact.py`,
  `component_aliases.py`) so only true orphans trip the check.
- Done-when: an orphan module (undocumented AND untested, not on the exemption list) fails it.

## A4. Add the `planner` subagent (file in A, done-when in B1)
- Do: new `~/.config/opencode/agents/planner.md`, `mode: subagent`, `edit: deny`,
  `question: deny`. Role: consume capabilities, call `chains --plan --goal <G>`, return
  ranked multi-hop paths. Same terse return-format contract as recon/exploit.
- The file can land now, but its behavior depends on the `chains --plan` flag from B1 —
  so its done-when is DEFERRED to B1 (can't be verified before B1 exists).

## A5. Model routing instead of jailbreaks (preamble in A, routing deferred to B0)
- Do NOT add jailbreak prompts (they don't bypass code-level scope/destructive gates, add
  hallucination, burn context). Instead:
  - Short authorized-pentest preamble (scope + authorization stated) in the shared header — lands now.
  - Route offensive roles to permissive/self-hosted open models via `model_router.py` (B0);
    capable model only at planner/verifier/skeptic/operator.
  - Keep payloads deterministic (`payload_corpus.py`) so the model never has to "agree" to emit one.
- Done-when (suite-checkable): router obeys the role→tier matrix and falls back cleanly when a
  tier is unset/unreachable. NOTE: "exploit role passes the labs on a cheap model" needs a
  live model — that is an INTEGRATION test, not an engine-suite check.

## A6. Grow ground truth from your CTFs/labs (compounding, non-blocking)
- Do: for each CTF/known bug, add a `greenhouse.py` recipe (planted bug + marker) and, where
  it's a new class, a hold-out lab3 case. Writeups → `ingest`/`research` → acceptance-gated playbooks.
- Done-when: each encoded CTF is a permanent regression test + an `acceptance` anchor.
  (Depends on CTFs you actually have — never gates the other items.)

═══════════════════════════════════════════════════════════════════════════
PART B — 3 Upgrades
═══════════════════════════════════════════════════════════════════════════

## B0. Shared prerequisite: `model_router.py`
- Role→tier matrix from `.blackboard/models.json`. Use the EXISTING `tokens.py` ROLES
  verbatim (operator/scout/exploit/verifier/skeptic/recon/synthesis/other) — do NOT invent
  role names. Add `planner` once (for B1).
- Tiers: scout/recon=cheap-or-free, exploit/synthesis=mid, planner/verifier/skeptic/operator=capable.
- Provider-agnostic OpenAI-compatible (reuse the Scout pattern). Never blocks: if a tier is
  unset/unreachable, fall back to the next cheaper working one.

## B1. Capability-graph chaining planner (flagship)
**What:** Today `mine_chains()` in `sec_flow.py` does 1-hop keyword matching over CONFIRMED
findings. Make it a multi-hop planner that searches attack *paths* toward a named goal, using
both confirmed findings AND unconfirmed primitives ("chain small bugs into a big one").

**Plugs in:** `sec_flow.py` (`PRIMITIVE_NEEDS`, `mine_chains()`, `manage_chains()`, `chain_to`
edges — by symbol); `prompts/chaining/chain_methodology.md`; report renderer
(`client_report._mermaid_chains` + SUMMARY renderer).

**Build:**
- New module `chain_planner.py` (keep `mine_chains` as the 1-hop fallback).
- Capabilities: each finding/lead emits `{gives:["file_read:/etc","cred:jwt"],
  needs:["path_param"], confidence:0-1, cost}`. Derive `gives`/`needs` from the existing
  keyword table first (deterministic, free); planner/exploit model may propose extra edges (via B0).
- **GOALS table** (the semantic core — the search's terminal predicate): goal → satisfying
  capability type. `RCE→code_exec`, `data_exfil→data_reach`, `auth_bypass→cred:*`,
  `priv_esc→role_admin`. Without this the planner has no stop condition. Add the goal's
  `needs` entry to `PRIMITIVE_NEEDS` so it is reachable (e.g. `data_exfil` needs `data_reach`).
- Search: Dijkstra with edge weight = **`-log(confidence)`** (so total cost = `-log(∏conf)`
  and the planner returns the MOST-PROBABLE path, not merely the fewest 1/conf). Clamp
  confidence to a floor (≥0.05) so near-zero primitives don't explode the weight. Tie-break
  by a per-unconfirmed-node penalty, then hops. Return top-N paths facts→goal.
- TWO edge stores, separate: `chain_to` = evidence-backed hops only (unchanged contract);
  NEW **board-level** `board["hypo_edges"] = [{from, to, why, confidence, source}]` holds
  planner-proposed unproven hops (board-level because paths traverse LEADS, which have no
  `chain_to` field). `source` is `"deterministic"` or `"model:<name>"` so hallucinated
  model-proposed edges stay debuggable. Nothing the planner invents ever writes `chain_to`.

**CLI:**
- `sec_flow.py chains --plan --goal RCE` → ranked paths `A→B→C→goal (conf, hops)`.
- `--auto-link` writes ONLY evidence-backed hops to `chain_to` (guarded path); unproven → `hypo_edges`.
- Paths flow into the Mermaid renderer with hypo hops dashed/labeled.

**Safety:** planner only PROPOSES; confirming still needs evidence (verification gate
untouched). Unproven hops live in `hypo_edges`, render as `hypothetical (unproven)` — never
silently become confirmed.

**Done-when (engine suite):** add `data_exfil`+`data_reach` to `PRIMITIVE_NEEDS`; seed
leaked-token + auth-bypass + IDOR + data-reach → `chains --plan --goal data_exfil` returns a
≥3-hop path; no-path graph returns "no chain to goal" cleanly (no crash); a lead-referencing
`hypo_edge` renders with a resolved lead label (not a bare `LEAD_xxx` / dangling node) —
i.e. `_mermaid_chains` and the SUMMARY renderer resolve lead IDs, not just finding IDs.

## B2. MCP-as-backend broker (MCP without context bloat)
**What:** MCP tool schemas must NEVER enter the operator's context. Keep servers behind the
engine: broker calls the tool, stores raw result as a `MSG_*` pointer, files a lead — exactly
like `sec_flow.py run`. Operator sees a pointer + lead, never the schema.

**Plugs in:**
- Mirror `sec_flow.py run`: artifact under `.blackboard/artifacts/MSG_*`, 20-line preview
  (only when raw output >100 lines, same as `run`), triage → leads, redaction (`redact.py`).
- Scope gate: EVERY MCP call classified by the server's declared capabilities, not a
  "passive" label. Any net/fs-reaching call goes through the in-scope `--target` check.
  "Passive" is a property of the call, never assumed of a server.

**Build:**
- New module `mcp_broker.py`. Its real complexity is the MCP **stdio JSON-RPC handshake**
  (`initialize → tools/list → tools/call`) implemented in stdlib — not the mock. Say so.
- Config OUTSIDE the workspace at `~/.artifactory/mcp.json` (or, if in `.blackboard/`,
  signature-covered like scope) so a tampered config can't silently register an
  arbitrary-command server. Entry: `{name, transport, command|url, capabilities:[net|fs|local],
  trust: operator-approved}`. Loaded by the ENGINE only — never printed into model context.
- A local/stdio MCP server = arbitrary code execution; same trust as a tool binary. No server
  usable until an operator approves it (allowlist).
- **Arg discovery without bloat** (the real token leak): `mcp_broker.py describe --tool T`
  emits arg names + types only (~1 line/arg, no doc schema). Without it the model
  guess-and-retries `--args '{...}'` and burns exactly the tokens the broker exists to save.
- Lazy tool routing: `lead-class → allowed tool names`. Operator told only "tool <name>
  available for this lead" (name + 1-line purpose). Treat all MCP output as untrusted DATA.

**CLI:**
- `mcp_broker.py list` → servers + tool names + 1-line purposes (no schemas).
- `mcp_broker.py describe --tool T` → arg names + types only.
- `mcp_broker.py call --server S --tool T --args '{...}' --target <in-scope>` → runs it,
  writes `MSG_*`, files lead, prints pointer + preview.

**Safety (config placement is the security-relevant part):** config signed or
out-of-workspace; every server operator-approved with declared capabilities; scope gate on any
net/fs call (no "passive" bypass); output redacted; results are data, never instructions.

**Done-when (engine suite):** a MOCK stdio MCP server returning a fixed blob → `call` produces
one `MSG_*` + one lead; `board.json` contains NO tool schema and NO raw secret (redaction holds).

## B3. Self-improve driver — review-card default, auto-merge opt-in
**What:** The promotion gate (`eval_engine.py gate`) exists but nothing drives it end-to-end,
and the lab suite needs an agent to *play* it. Build the driver that proposes a change, runs
the full gate HEADLESS, and files a human review card. Auto-merge is OFF by default; only
enabled behind an explicit flag + workspace consent, and NEVER for executable tradecraft.

**Plugs in:** `eval_engine.py` (`suite engine`, `acceptance`, `validate-lab`, `gate --final`,
`score`/`compare`); `greenhouse.py` labs; `poc_delta.py` patch cards.

**Build (two modules):**
- `lab_runner.py` — plays greenhouse/vuln labs UNATTENDED (deterministic steps directly;
  LLM-in-loop steps via B0 cheap tier) so `validate-lab` has a board to score.
- `self_improve.py` — orchestrates: (1) take a candidate diff (`poc_delta`, source-refresh,
  or a new/edited playbook); (2) apply on a temp git branch/worktree IN THE SOURCE REPO (the
  stable `~/artifactory-engine` has no `.git` — `install.sh` copies contents only); (3) run
  `suite engine` + `lab_runner` on labs 1&2 + `acceptance`; (4) all pass AND `compare` not a
  REGRESSION → `gate --final` (hold-out lab3); (5) on PROMOTE, file a review card by default.
  Auto-merge only if `--auto-merge` + workspace consent file + DATA-only diff (see rules), and
  the driver then RE-RUNS `install.sh` itself to promote source → stable.

**Safety (hard rules):**
- Path allowlist for auto-merge candidacy: `prompts/`, `knowledge/`, `payloads/`. Anything
  touching `sec_flow.py`, `scope_sig.py`, destructive/scope/signing code → forced human review.
- Auto-merge is DATA-only (knowledge lists / payload corpus). **Playbooks are executable
  tradecraft** (a behavioral-injection vector the gate tests machinery, not intent, for) →
  review card even when green.
- Source-refresh auto-merge is **metadata-only** (URL/title/hash fields in `sources.json`,
  nothing executable); any *synthesized* content from a refresh is a playbook → review.
  Lineage does NOT gate fresh content (it measures earned outcomes a new source lacks) — its
  role is the demotion side: refresh must REFUSE to re-queue a source carrying a demotion flag.
- The consent file lives at WORKSPACE ROOT and is HMAC-SIGNED with the out-of-workspace
  scope-signing key (`scope_sig.py`, key at `~/.artifactory/scope_signing.key`); the driver
  verifies the signature before any auto-merge. "Operator-created" is unenforceable alone (the
  agent can `touch` a file in its own workspace) — binding consent to the key-holder is what
  makes it real. Sign a payload that includes the workspace path + candidate ref + an expiry
  timestamp (e.g. ISO-8601, 24h default) so a signed consent can't be replayed to another repo,
  a different diff, or next week — an un-expiring signed consent is a permanent blank check for
  that ref. The driver rejects expired or payload-mismatched consents. (`self_improve.py consent
  --for <ref>` prints the exact payload to sign, making the ritual 2 steps.)
- Every change is an auditable, revertible git commit. Failing/regressing candidate never
  merged. Any auto-merged data diff registers a canary/replay task on the next lab run.

**CLI:** `self_improve.py propose --from poc-delta|source-refresh|playbook <ref> [--auto-merge]`
→ runs pipeline, prints PROMOTE/REJECT + reasons, files review card (or merges only under the
DATA-only + flag + consent conditions). Note: `poc-delta` and `playbook` candidates are
executable tradecraft → ALWAYS a review card, never auto-merged even with `--auto-merge`; only
DATA / metadata-only refresh candidates are ever eligible.

**Done-when (engine suite):** a known-good DATA candidate auto-promotes with `--auto-merge` +
valid signed consent (green); a lab-breaking playbook edit (the regression fixture — a pure
DATA candidate cannot regress the suite by construction, since it doesn't execute; a playbook
edit CAN regress `validate-lab`/`acceptance`) is REJECTED and NOT merged; a candidate touching
a safety file is routed to review even if tests pass. The regression fixture is doubly correct:
playbooks are executable tradecraft, so even on a false-green it lands as a review card, never a merge.

═══════════════════════════════════════════════════════════════════════════
This plan has converged: sequencing is dependency-correct and every design hole raised across
review has a named mechanism. Build in the stated order; each item lands with its suite check.
════════════════════════════════════════════════════════════════════════════




