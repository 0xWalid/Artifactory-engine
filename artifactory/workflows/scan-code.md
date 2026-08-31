# Workflow: scan-code <path> — scanner finds, you disprove, runtime proves
Deterministic scanners are consistent; LLMs are not. semgrep FINDS candidates — your job is DISPROVE false positives, then PROVE survivors at runtime. Never ask an LLM to "find bugs" in raw code.
- **Fail-closed code-path gate:** source only scanned under `scope.json allowed_code_paths` (authorize first — confirm you're allowed the source).
- **Scan:** `{{ART}} sec_flow sast --path "<dir>"` (no `--config auto`; target source never uploaded).
- **Consume sast leads** (`leads --type sast`), not SARIF. Each is must_verify, low confidence.
- **Guided disproof:** per lead, load `art.py playbook_engine --category sast --name <sqli|command_injection|path_traversal|ssrf|xss>`; answer data-flow questions FIRST (low temperature); pull context `inspect --id <PTR>`. Safe → `leads --id <ID> --set-status dead` (killing FPs is the goal).
- **Runtime proof for survivors:** static reasoning NEVER confirms. Minimal PoC against the in-scope live host → normal `add-asset ... --status confirmed --evidence-from <PTR>`.
- **Fuzz harnesses:** `art.py fuzz_driver scaffold` (libFuzzer C skeleton) — fill TARGET_BODY, run campaigns detached via sec_flow.
