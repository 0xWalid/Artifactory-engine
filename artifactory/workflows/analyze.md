# Workflow: analyze <target>
**Phase 0 — Intel anchor (product targets):** named product w/ version? Fetch the vendor changelog of the first patched release AFTER target, then `art.py sec_flow intel --product "<n>" --version <v>` + `sca --path <dir>` if artifacts ship. Every candidate becomes a visible cve lead before testing.
**Phase 1 — Init & surface:**
- `{{ART}} init_env --target .` (if missing); confirm `<target>` is in scope — STOP for authorization if not.
- First stop: `{{ART}} sec_flow status` (resume dashboard).
- White-box auto-wire: `art.py sec_flow detect --path .` — found? Operator authorizes the code path once (`scope --add-code-path`), then `sast`+`sca` run in bg.
- Recon guide: `art.py playbook_engine --category recon --name methodology --target "<t>"` — triggered steps only, respect rate profiles. Missing? `/artifactory test` synthesis protocol.
- Discovery via `art.py sec_flow run` (`--bg` for slow); Scout files ranked leads — pull `art.py sec_flow leads`.
**Phase 2 — Pivot to testing (do NOT stop at recon):**
- Negative knowledge first: `{{ART}} debrief deadends --stack <tech>` — dead classes get ONE cheap re-check, not a re-burn.
- Leads top-down (anomaly > cve/sast > port/endpoint > tech); >=1 theory → START TESTING while scans run.
- Auth is first-class: with creds — bypasses, `art.py entropy`, reset poisoning, OAuth/JWT, IDOR on every ref; without — pre-auth + registration/recovery first (state the depth block).
- Missing playbook → `/artifactory test` synthesis protocol. Chain findings via the blackboard (leak → bypass → IDOR → reach); prefer demonstrated paths.
- **Wrap-up honesty:** `leads` residue (`new/testing/blocked_precondition`) = coverage gaps in SUMMARY.md.
- **Close with:** `{{ART}} debrief debrief --label <eng>` (review card, lessons, dead-ends, payload wins, playbook rates, snapshot).
