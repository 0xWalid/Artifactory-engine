# Artifactory — Consolidate & OpenCode-Integrate (handoff)

Do this BEFORE the 3 upgrades (see ARTIFACTORY_3_UPGRADES_PLAN.md). Match existing style.
Rule: every change adds/keeps an `eval_engine.py suite engine` check. Never touch
scope/signing/destructive-block code.

## 1. Split the mega-command (biggest token win)
- Problem: `~/.config/opencode/commands/artifactory.md` is one ~400-line file loaded on every invoke.
- Do: in `install.sh`, emit one command file PER workflow so each loads lazily:
  `analyze, test, intel, scan-code, research, discover, roles, oob, chains, eval-lab,
   nuclei, burp, patchdiff, tokens`. Shared operational rules → a short `AGENTS.md`-style
   preamble each references, not copied inline.
- Done-when: invoking `/artifactory analyze` loads only its file + the shared preamble.

## 2. Kill doc drift
- README says "59 checks"; code has ~40. `install.sh` has a duplicated `sed` block and a
  doubled paragraph in `skeptic.md`.
- Do: make the count dynamic (suite prints its own total), dedup the `sed` + skeptic text.
- Done-when: README claim == suite's printed count; `install.sh` has one sed pass.

## 3. Wiring self-check
- Do: add `doctor.py --wiring` (or a suite check) that fails if any `artifactory/*.py`
  module is not reachable from a command/agent doc AND not covered by a suite check.
- Done-when: an orphan module (undocumented or untested) makes the check fail.

## 4. Add the `planner` subagent (for upgrade #1)
- Do: new `~/.config/opencode/agents/planner.md`, `mode: subagent`, `edit: deny`,
  `question: deny`. Role: consume capabilities, call `chains --plan --goal <G>`, return
  ranked multi-hop paths. Same terse return-format contract as recon/exploit.
- Done-when: orchestrator can delegate "plan a chain to <goal>" and get paths back.

## 5. Model routing for refusals (instead of jailbreaks)
- Do NOT add jailbreak prompts (they don't bypass the code-level scope/destructive gates,
  add hallucination, burn context). Instead:
  - `model_router.py` (shared w/ upgrades): route offensive roles to permissive/self-hosted
    open models; capable model only at planner/verifier/skeptic.
  - Short authorized-pentest preamble (scope + authorization stated) in the shared command header.
  - Keep payloads deterministic (`payload_corpus.py`) so the model never needs to "agree" to emit one.
- Done-when: exploit role runs on a cheap/permissive model and still passes the labs.

## 6. Grow ground truth from your CTFs/labs (compounding)
- Do: for each CTF/known bug you have, add a `greenhouse.py` recipe (planted bug + marker)
  and, where it's a new class, a hold-out lab3 case. Writeups → `ingest`/`research` →
  acceptance-gated playbooks.
- Done-when: each encoded CTF is a permanent regression test + an `acceptance` anchor.

## Order
1 → 2 → 3 (consolidate) → 4 → 5 → 6, then start ARTIFACTORY_3_UPGRADES_PLAN.md.
