# Workflow: chains — finding composition into attack paths
- **Link demonstrated hops:** `{{ART}} sec_flow chains --link FINDING_A,FINDING_B --note "<why A enables B>"` (or `--chain-to` when recording the finding). `chain_to` = evidence-backed only.
- **View paths:** `art.py sec_flow chains` — longest demonstrated path highlighted; rendered in SUMMARY + client report (Mermaid).
- **Mine proposals (1-hop, deterministic):** `art.py sec_flow chains --mine [--auto-link]` — primitive/needs matching over confirmed findings.
- Methodology (when does A enable B?): `art.py playbook_engine --category chaining --name chain_methodology`.
- Confirmed findings auto-queue same-class variant sweeps over the inventory (the "test every object endpoint" reflex).
