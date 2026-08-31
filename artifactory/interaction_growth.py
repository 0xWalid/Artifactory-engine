#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Interaction Table Growth

The hand-curated INTERACTIONS table grows a mechanical supplement: propose NEW
component-pair hypotheses mined from public CVE/advisory data (no LLM).

Method (deterministic, cheap):
  1. Pull recent CVEs from the NVD keyword feed for component names already
     known to the table (nginx, envoy, tomcat, varnish, ...).
  2. For each hit, scan the description for OTHER component names in our
     component vocabulary — a co-occurrence ("smuggling between A and B",
     "bypass when deployed behind B") is a candidate interaction.
  3. Propose pairs not already in the table, as REVIEW PROPOSALS — the table
     itself only changes through the operator's diff (same contract as every
     learning loop here). Approved entries get added to a user-extensible
     sidecar file: knowledge/interactions_local.json, which stack_interactions
     loads ON TOP of the built-ins.

No silent table mutation; every growth is a readable, revertable change.
"""

import argparse
import json
import sys
import urllib.request
import urllib.parse
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)


def _find_engine_root():
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent


_ENGINE_ROOT = _find_engine_root()

LOCAL_TABLE = _ENGINE_ROOT / "knowledge" / "interactions_local.json"

# Component vocabulary: the names we mine for + the aliases seen in advisories.
COMPONENTS = [
    "nginx", "apache", "tomcat", "jetty", "iis", "haproxy", "envoy", "traefik",
    "varnish", "squid", "cloudflare", "akamai", "fastly", "cloudfront",
    "node", "express", "php", "django", "flask", "spring", "rails",
    "keycloak", "graphql", "kafka", "redis", "memcached",
]

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_component_cves(component: str, results: int = 20) -> list:
    q = urllib.parse.urlencode({"keywordSearch": component, "resultsPerPage": results})
    try:
        req = urllib.request.Request(f"{NVD_URL}?{q}",
                                    headers={"User-Agent": "artifactory-growth/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            doc = json.loads(r.read().decode())
        return doc.get("vulnerabilities", [])
    except Exception:
        return []


def _desc_of(vuln: dict) -> str:
    cve = vuln.get("cve", {})
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def mine_pairs(components: list = None, per_component: int = 10):
    """Co-occurrence mining: for each vocabulary component, find recent CVEs
    whose description ALSO names another component + an interaction keyword."""
    import stack_interactions as si
    known = {(a, b) for a, b, _, _ in si.INTERACTIONS}

    interaction_words = ["smuggl", "bypass", "differen", "behind", "in front",
                         "proxy", "cache", "parser", "desync", "traversal"]
    proposals = []
    for comp in (components or COMPONENTS[:8]):  # keep fetch volume polite
        for vuln in fetch_component_cves(comp, per_component):
            desc = _desc_of(vuln).lower()
            cve_id = vuln.get("cve", {}).get("id", "?")
            if not desc or not any(w in desc for w in interaction_words):
                continue
            # which OTHER components co-occur?
            others = [c for c in COMPONENTS if c != comp and c in desc]
            for other in others:
                if (comp, other) in known or (other, comp) in known:
                    continue
                snippet = desc[:180]
                proposals.append({
                    "pair": [comp, other],
                    "cve": cve_id,
                    "why": f"advisory co-occurrence: {snippet}",
                })
    # dedup by pair (keep first evidence)
    seen = {}
    for p in proposals:
        key = tuple(sorted(p["pair"]))
        if key not in seen:
            seen[key] = p
    return list(seen.values())


def print_proposals(proposals):
    if not proposals:
        print("[*] No new pair proposals from advisory mining "
              "(either all known or no co-occurrence hits).")
        return
    print(f"[*] {len(proposals)} candidate interaction pair(s) from advisory mining:\n")
    for p in proposals:
        a, b = p["pair"]
        print(f"  {a} + {b}")
        print(f"      evidence: {p['cve']} — {p['why'][:150]}")
    print("\n  Approve entries by adding to knowledge/interactions_local.json:")
    print('  [{"a": "%s", "b": "%s", "hypothesis": "...", "playbook": "..."}]' %
          (proposals[0]["pair"][0], proposals[0]["pair"][1]))
    print("  (stack_interactions loads that file ON TOP of its built-ins.)")


def show_local_table():
    if not LOCAL_TABLE.exists():
        print("[*] No local interaction entries yet (knowledge/interactions_local.json).")
        return
    entries = json.loads(LOCAL_TABLE.read_text())
    print(f"[*] {len(entries)} local interaction entr(ies):")
    for e in entries:
        pair = f"{e.get('a')} + {e.get('b')}" if e.get("b") else f"{e.get('a')} (any)"
        print(f"  {pair:<26} {e.get('hypothesis', '')[:80]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interaction-table growth (advisory mining)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mine", help="Mine CVE co-occurrences -> pair proposals")
    m.add_argument("--components", default="",
                   help="Comma-separated subset of components to mine (default: core proxies)")
    m.add_argument("--per-component", dest="per_component", type=int, default=10)
    sub.add_parser("local", help="Show operator-approved local table entries")
    args = parser.parse_args()
    if args.cmd == "mine":
        comps = [c.strip() for c in args.components.split(",") if c.strip()] or None
        print_proposals(mine_pairs(comps, args.per_component))
    else:
        show_local_table()
