# Workflow: eval-lab — the learning loop (labs only, NEVER live targets)
- **Labs:** lab1 :8099 (`art.py vuln_lab`: BAC/IDOR/SSRF/anomaly), lab2 :8100 (`art.py vuln_lab2`: JS-secrets/redirect/traversal/mass-assign), lab3 :8101 **HOLD-OUT** (`art.py vuln_lab3`: header-bypass/debug/CORS — only `gate --final` touches it). All take `--seed N` (no memorized passes).
- **Headless play:** `{{ART}} lab_runner play lab1|lab2 [--seed N]` — golden-path findings for validate-lab.
- **Suite/score/compare:** `art.py eval_engine suite engine` · `validate-lab --lab <l>` · `score --label <run>` · `compare`.
- **Gates:** `gate --candidate <x>` (labs 1-2) → `--final` (+ hold-out lab3). Regressions REJECT; decisions in `evals/manifest.json`.
- **Self-improve driver:** `art.py self_improve propose --from <src> [--auto-merge]` — headless pipeline; review card default; auto-merge = DATA diffs + signed consent only.
- **Greenhouse + acceptance:** `art.py greenhouse list|grow <class>|grow-all` (14 planted-bug recipes) · `art.py eval_engine acceptance --category <c> --name <n>` (ACCEPTED/GROUND-TRUTH-ONLY/NO-RECIPE/SELF-CHECK-FAILED).
