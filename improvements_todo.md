btw why missed these what improvements you need?
+ Thought: 26.4s
Honest post-mortem — three distinct misses:
Why they were missed
1. Wrong intel anchor. I worked backwards from aggregator search results instead of pulling the single authoritative source: the 26.7.2 release notes (which you pasted) enumerate all seven fixes verbatim. One webfetch of the vendor changelog would have surfaced every item; my keyword search only surfaced whatever ranked highest (18963, 9803, 9689).
2. Version-range shortcuts. Advisories tagged "patched in RHBK 26.6.x / 26.4.x" got mentally filed as already-fixed without checking whether community 26.7.1 still carried them (#50616, #50966). CPE fragments ≠ ground truth.
3. No SCA instinct. jackson-databind 2.21.2 sat in lib/lib/main/ the whole time — semgrep p/default doesn't do dependency scanning, and I never ran a trivial jar inventory. Same blindness for OTel tracing being off-by-default (#49570).
Aggravating factor: I over-applied token discipline to intel gathering. Leads-not-raw-output applies to tool output; CVE enumeration rewards breadth.
Improvements I'll apply
Fix	Change
Changelog-first	Step 0 of product engagements: fetch release notes of the first patched version after target, enumerate every security issue as a lead
Distro SCA	Micro-step: inventory lib/**/*.jar versions, diff against fix list — catches dependency CVEs semgrep never sees
Full-index query	Query the RHSA/OpenCVE product index once per engagement instead of keyword searches
No silent drops	Every candidate CVE becomes a new lead on the board, so coverage gaps are visible
Precondition matrix	Feature-gated bugs (FGAPv2, vault, tracing) get scheduled as "lab-enable then test" instead of skipped
Applying them right now: logging all six as leads, and jackson-databind 2.21.2 < 2.21.5 is confirmable immediately (jar present = version condition met). Want me to proceed with #51832 (account-linking takeover) next — it needs only a malicious client we can create — followed by the FGAP pair with v2 enabled in the lab?
