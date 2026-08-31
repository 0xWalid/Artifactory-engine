# Workflow: patchdiff — 1-day variant hunting
Upstream project shipped a security fix? Extract the bug family deterministically, get variant-hunt commands for YOUR codebase ("same bug, different sink"):
- `{{ART}} patch_diff --diff <fix.diff> [--text "<advisory>"] --project <name>` → cve-type variant-hunt leads; exploit agent runs the greps, verifier proves survivors.
- Pairs with: `art.py sec_flow intel` (index candidates; OSV FIX refs on leads), `sca` (pinned inventory), `art.py kev mark` (prioritize exploited-in-wild).
- **Wordlist winnowing:** after content discovery, `{{ART}} wordlist_wins record`; next run `winnow --wordlist f.txt --out f_win.txt` keeps only proven-hit words.
