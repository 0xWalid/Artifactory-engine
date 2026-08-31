# Workflow: burp — Burp-first workflow (any edition)
Your manual Burp browsing IS the baseline inventory. Browse as the HIGHEST-privilege role, then:
- **Proxy history → inventory:** Burp "Save items" export → `{{ART}} burp_bridge ingest-history --file history.xml` — unique endpoints as leads, raw traffic as verifiable evidence artifacts, endpoints.txt (role-diff baseline); out-of-scope hosts flagged, never silently dropped.
- **Role-diff your browsed surface:** `art.py auth_manager role-diff --base-url <base> --roles <BASE>,<OTHER...> --endpoints endpoints.txt`
- **Scanner issues (Pro export):** `art.py burp_bridge ingest-issues --file issues.xml` — must_verify leads; evidence gate still applies.
- **REST-driven scans (Pro, :1337):** `art.py burp_bridge scan --target <url>` — polls, files leads; unreachable → coverage-gap lead.
- **Other importers:** `{{ART}} importers har <f.har>` (DevTools HAR) · `nmap <f.xml>` (ports+banners → fingerprints auto) · `nessus <f.nessus>` (plugin findings → leads).
- **ZAP fallback (docker):** `art.py zap_bridge --target <url> [--full]` — same lead contract.
