# Workflow: oob — blind vulnerability confirmation (SSRF/XXE/SSTI/blind RCE)
- **Mint a tagged payload per test:** `{{ART}} oob generate --host <listener-host-reachable-from-target> --purpose 'blind SSRF via importer'`
- **Listener:** `{{ART}} oob listen` (`--dns` for the DNS observer; run detached/another terminal).
- **Poll:** `{{ART}} oob status` — every hit files a 0.9-confidence anomaly lead attributed to its probe tag. A callback IS the blind-interaction proof; build the full PoC around it.
- Internet-facing target? Point payloads at an interactsh-style host, keep the tag discipline.
- GraphQL surface? `/artifactory catalog` → graphql checks (introspection/field-suggestions/batching).
