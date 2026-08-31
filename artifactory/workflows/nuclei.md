# Workflow: nuclei <target> — community 1-day corpus + target fingerprints
- **Fire the corpus** (matches are must_verify cve LEADS, never findings; missing binary files a visible coverage-gap lead):
  `{{ART}} sec_flow nuclei --target <t> [--severity critical,high] [--templates <dir>] [--bg]`
- **Pair with intel:** intel enumerates candidates, nuclei fires them, the verifier proves survivors.
- **Fingerprint cache (never re-learn a stack):** `art.py sec_flow fingerprint --host <h> --tech 'nginx 1.18' --record` / `--host <h>` / `--all` (14-day TTL).
- **Stack interactions:** after recording banners, `{{ART}} stack_interactions hypothesize` — component PAIRS (proxy+app, cache+app, parser+parser) become must_verify leads (smuggling/poisoning/differential candidates; incl. HTTP/2/h2c classes).
- **Scope tamper evidence:** scope.json authorization fields are HMAC-signed; a tampered scope refuses ALL commands. Operator edits re-sign automatically.
