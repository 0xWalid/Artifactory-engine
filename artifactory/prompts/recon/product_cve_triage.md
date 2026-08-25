# Micro-Playbook: Product CVE Triage
**Practitioner / Methodology:** Artifactory post-mortem (changelog-first intel discipline)
**Category:** recon

When the target is a **known product at a known version** (Keycloak, GitLab,
Artifactory, Confluence, a Spring app, …), do NOT start from keyword CVE
searches — they only surface whatever ranks highest and silently drop the rest.
Work from ground truth. This playbook is the "Step 0" of any product engagement.

## Preconditions & Indicators
- You can name the product AND a version (banner, `/version` endpoint, login
  page, `package.json`, jar filenames, `Server:` header).
- There is an authoritative changelog / release-notes / advisory index for it.

## Enumeration (establish ground truth — do these in order)
1. **Changelog-first.** Fetch the release notes of the **first patched version
   after the target's version**. That page enumerates every security fix
   verbatim. One authoritative fetch beats ten aggregator searches.
   - Vendor release notes / CHANGELOG (primary).
   - `python3 ~/artifactory/knowledge.py --class product-cve-triage` for the feed URLs.
2. **Full-index query (once per engagement).** Query the product's *entire* CVE
   index rather than keyword-searching:
   - OpenCVE by vendor/product, Red Hat RHSA (for RH-packaged builds), NVD CPE
     search, GitHub Security Advisories.
   - For OSS deps, OSV: `POST https://api.osv.dev/v1/query` with
     `{"package":{"name":"<pkg>","ecosystem":"<eco>"},"version":"<v>"}`.
3. **Distro / bundled SCA.** Inventory shipped dependencies — semgrep never sees
   these. Prefer the built-in scanner:
   `python3 ~/artifactory/sec_flow.py sca --path "<authorised_code_path>"`
   then work the `sca` leads (`sec_flow.py leads --type sca`). A present
   `foo-<ver>.jar` means the version precondition is already met.

## Diagnostic Checks
- **No silent drops.** Every candidate CVE from steps 1–3 becomes a lead on the
  board (via `sca`/`sast` triage or `add-rationale` notes), so coverage gaps are
  visible instead of being quietly forgotten.
- For each candidate, separate the version-match (necessary) from **reachability
  + preconditions** (sufficient). CPE/version match ≠ exploitable.
- **Precondition matrix.** Feature-gated bugs (a beta/v2 API, vault, tracing,
  account-linking, an optional auth flow) are NOT skipped — they are scheduled
  as **"lab-enable then test"**: note the required config, enable it in the lab
  build, then test. Skipping a feature-gated CVE is a silent drop.

## Verification & Impact
- A version banner or "maybe-CVE" is **informational** until actively proven.
- Build a minimal, non-destructive runtime PoC against the in-scope host, then:
  `python3 ~/artifactory/sec_flow.py add-asset --finding "<CVE-XXXX-YYYY: Title>" \
    --severity <sev> --status confirmed --evidence-from <POINTER_ID> --poc "<proof>"`
- Log the reasoning trail so coverage is auditable:
  `python3 ~/artifactory/sec_flow.py add-rationale --hypothesis "<CVE applies>" \
    --why "changelog step" --action "<what you ran>" --outcome "confirmed|dead|inconclusive"`

## Escalation & Chaining
- Chain a confirmed dependency/product CVE into deeper impact (auth bypass →
  token leak → IDOR → data reach). Prefer a demonstrated end-to-end path over a
  list of isolated version findings.
- Feed newly confirmed techniques back through `/artifactory learn` so the
  changelog-first discipline compounds over engagements.
