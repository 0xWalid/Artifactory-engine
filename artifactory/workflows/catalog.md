# Workflow: catalog — every tool, one line
**Recon:** `art.py crawl --base-url <b>` calibrated crawler · `art.py importers har|nmap|nessus` inventory · `art.py snapshot snapshot|diff` retest deltas · `art.py wordlist_wins record|winnow` wordlists.
**BAC/logic:** `art.py auth_manager verb-matrix` verb probes · `art.py importers inventory-diff` hidden paths · `art.py graphql checks --url <g>` · `art.py race probe --url <u> --threads 20 --check "<cmd>"`.
**Auth:** `art.py entropy entropy --cmd "<c>"` token quality (dupes/entropy/prefixes/JWT).
**Blind:** `art.py oob generate|listen|status` tagged callbacks.
**1-day:** `art.py kev mark|list` in-wild priority · `art.py patch_diff --diff` variants · `art.py stack_interactions hypothesize|pairs` component pairs · `art.py interaction_growth mine` co-occurrence · `art.py component_aliases` embedded comps.
**White-box:** `art.py sec_flow sast` guided disproof · `art.py fuzz_driver grammar [--timing]|scaffold` mutation+latency fuzz, harness skeletons.
**Secrets:** `art.py secrets scan` artifact sweep (AWS/JWT/keys/conn-strings → family leads).
**Knowledge:** `art.py greenhouse list|grow|grow-all` planted-bug labs · `art.py eval_engine acceptance` · `art.py poc_delta mine` patch cards · `art.py lineage record|reliability|apply|chain|divergence` source accountability · `art.py cross_index lookup|map|gaps` · `art.py payload_corpus list|note|retire-review`.
**Learning:** `art.py debrief debrief|lessons|deadends|playbooks|replay|fresh-eyes` engagement loop · `art.py metrics scan|show` cross-engagement curve · `art.py maintenance [--suite] [--watch N]` freshness loop.
**Interop/close-out:** `art.py doctor [--suite|--json]` self-test · `art.py client_report export` HTML+CVSS+Mermaid · `art.py board_merge merge --from <ws>` · `art.py tripwires plant|check` chain verification · `art.py skeptic_ledger record|resolve|stats` · `art.py report_engine` advisories · `art.py sec_flow status` dashboard.
**Escalation ladder:** 1) deterministic re-inspect → 2) exploit/verifier re-derive → 3) `skeptic` adversarial review (personas) → 4) operator. Cheap before expensive.
