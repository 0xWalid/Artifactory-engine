# Workflow: tokens — accounting, budgets, north-star, flight recorder
- **Log spends:** `{{ART}} tokens log --role <role> --purpose '<what>' --amount <N>` (subagents estimate from own context; add `--context-bytes <n> --step <name>` for the flight recorder).
- **Budgets:** `art.py tokens budget --role operator --limit 200000`; dashboard `art.py tokens status` (bar + north-star).
- **Engagement end:** `art.py tokens report` — per-role/per-purpose breakdown + ★ proven-vulns-per-1M-tokens.
- **Flame-chart:** `art.py tokens flamechart` — per-step context growth; the jump bars are the optimization targets.
- **Debrief reads this ledger** — token hotspots (>50% purpose) become review-card items.
