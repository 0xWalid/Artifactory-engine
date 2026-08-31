# Workflow: roles — auth-state manager + role-diff (BAC/IDOR at scale)
Sessions are POINTERS: credentials live in `.blackboard/sessions/`, the board keeps references only.
- **Register the role matrix:** `{{ART}} auth_manager add --role admin --auth-type cookie --target <base> --credential 'session=...'` (`--refresh-hook` holds the re-obtain command; 401s auto-heal once).
- **Inventory (zero tokens):** `art.py crawl --base-url <base> [--session <SESS>] --out endpoints.txt` (soft-404 calibrated, JS routes) — or `/artifactory burp` history ingest.
- **Role-diff (mechanical BAC/IDOR sweep):** `{{ART}} auth_manager role-diff --base-url <base> --roles SESS_ADMIN,SESS_USER,SESS_ANON --endpoints endpoints.txt` — normalized (CSRF/nonces masked); body/status/TIMING deltas file `rolediff` leads.
- **Verb matrix:** `art.py auth_manager verb-matrix --base-url <base> --session <SESS> --endpoints endpoints.txt` — OPTIONS/Allow + write-verbs on read routes + override headers.
- **Inventory-diff:** `art.py importers inventory-diff --base-url <base> --sessions SESS_A,SESS_B` — role-hidden paths.
- **Token quality:** `art.py entropy entropy --cmd "<curl login>" --target <t> --samples 6` — dupes, 64-bit bar, prefixes, JWT alg.
- Work deltas (`leads --type rolediff`): SHOULD this role differ? Verify → confirm with evidence. Methodology: `art.py playbook_engine --category logic --name role_diff`.
