# Workflow: intel <product> [version] — changelog-first vulnerability intelligence
1. **Changelog anchor first:** vendor release notes of the first patched version AFTER target — every security fix becomes a candidate lead.
2. **Full-index pass:** `{{ART}} sec_flow intel --product "<n>" --version <v>` (OSV+NVD, keyless, no silent drops; `--cpe` for appliances; `--preconditions` for feature-gated bugs). Leads carry OSV FIX references → feed `art.py patch_diff --diff` for variant hunts.
3. **Distro SCA:** `art.py sec_flow sca --path <dir>` (fail-closed on allowed_code_paths; `--offline` when air-gapped).
4. **Prioritize by KEV:** `{{ART}} kev mark` — exploited-in-wild candidates become PRIORITY 1.
5. **Precondition matrix:** untestable-yet leads get `--set-status blocked_precondition` (scheduled, never skipped).
6. **Prove:** a cve lead stays a candidate until version condition holds at runtime AND a PoC exists (normal evidence gate).
- Component aliasing for appliances: `art.py component_aliases` (embedded-component broadening hints on leads).
