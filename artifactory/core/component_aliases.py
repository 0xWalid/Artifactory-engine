#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Component Aliasing (library)

Embedded/rebadged components: appliances and products ship nginx, curl,
openssl INSIDE themselves, and advisories describe the EMBEDDED component.
Intel-by-product-name misses those; this map translates product names to the
components they embed so intel queries and stack hypotheses can broaden.

Deterministic, curated, small. Used by intel (query broadening hints) and by
the operator (awareness). Extend the ALIASES dict as new products appear —
it's plain data.
"""

ALIASES = {
    # product/appliance -> components it embeds or rebadges
    "keycloak": ["undertow", "infinispan", "wildfly"],
    "jenkins": ["jetty", "groovy", "args4j"],
    "gitlab": ["nginx", "workhorse", "rails", "redis", "gitaly"],
    "sonarqube": ["jetty", "elasticsearch"],
    "artifactory": ["tomcat", "nginx", "jackrabbit"],
    "nexus": ["jetty", "karaf"],
    "confluence": ["tomcat", "atlassian-seraph", "struts"],
    "wordpress": ["php", "mysql"],
    "minio": ["go", "nginx"],
    "grafana": ["go", "sqlite"],
    "exchange": ["iis", "h2"],
    "apache-httpd": ["apr", "mod_proxy", "mod_security"],
}

# Reverse index: component -> products that embed it (built at import).
REVERSE = {}
for product, comps in ALIASES.items():
    for c in comps:
        REVERSE.setdefault(c, []).append(product)


def broaden(product: str) -> list:
    """Components embedded in a product (for wider intel queries)."""
    return list(ALIASES.get((product or "").lower().strip(), []))


def products_with(component: str) -> list:
    """Products known to embed a component (for stack-aware hypothesis)."""
    return list(REVERSE.get((component or "").lower().strip(), []))


def alias_hint(product: str) -> str:
    comps = broaden(product)
    if not comps:
        return ""
    return (f" | embedded components: {', '.join(comps)} — also run intel per "
            f"component for embedded-CVE classes")


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    if which:
        print(f"{which}: embeds {broaden(which)}")
    else:
        print(f"{len(ALIASES)} products mapped. Products per component:")
        for comp, prods in sorted(REVERSE.items()):
            print(f"  {comp:<14} -> {', '.join(prods)}")
