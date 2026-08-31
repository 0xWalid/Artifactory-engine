# Workflow: test <target> for <vulnerability>
- `{{ART}} playbook_engine --category <cat> --name <vuln> --target "<t>"`
- **FOUND:** execute rendered diagnostic commands via `art.py sec_flow run`. Proven? Record confirmed WITH proof (`add-asset ... --status confirmed --evidence-from <PTR> --poc "<proof>"`). Not proven? Leave `informational` — never force it.
- **MISSING_NEEDS_RESEARCH → Tradecraft Synthesis & Confirmation Protocol:**
  1. Identify the authority (built-in library auto-suggested; browse `art.py playbook_engine --list-sources`). Prefer PRIMARY material (Kettle/PortSwigger, Orange Tsai, Project Zero, TBHM, WSTG).
  2. Ask the operator for sharpening inputs (URLs, files, payloads, scope notes) and PAUSE for reply/proceed.
  3. Synthesize parameterized sections using `{{TARGET_URL}}`/`{{TARGET_HOST}}`/`{{AUTH_TOKEN}}`: Preconditions & Indicators / Enumeration / Diagnostic Checks / Verification & Impact / Escalation & Chaining. When the class has a public CVE+patch, prefer the fix-commit (art.py patch_diff) over prose — advisories describe, diffs define.
  4. Present the summary card (name/practitioner/sources/category/steps) and WAIT for approval.
  5. Save via `art.py playbook_engine --category <c> --name <n> --author "<who>" --save-content "<md>"`, then ACCEPT it: `art.py eval_engine acceptance --category <c> --name <n>` (greenhouse ground truth required before field use). Then re-run the test.
