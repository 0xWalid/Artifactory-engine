#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Stack Interaction Hypothesizer

Researchers attack WHERE COMPONENTS MEET, not endpoints in isolation:
proxy+app (request smuggling), cache+app (poisoning/deception),
parser+parser (differentials), CDN+origin (token replay)...

This module is deterministic: it reads the workspace fingerprint cache
(tech banners per host, recorded during recon), pairs components against a
built-in INTERACTION TABLE of known juicy combinations, and files a lead per
triggered hypothesis — each pointing at the matching playbook for the
orchestrator to run. Zero model tokens; the LLM's job stays judgment, not
recall.

  * `hypothesize` — fingerprint cache -> interaction leads (idempotent: no
    duplicate hypothesis for the same host+pair)
  * `pairs`       — list the built-in interaction table (inspect/extend it
                     in this file; it's plain data, no framework needed)
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402
from bootstrap import engine_root  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
FINGERPRINTS_FILE = BLACKBOARD_DIR / "fingerprints.json"

# Operator-growth sidecar: approved entries mined by interaction_growth.py
# load ON TOP of the built-ins (never silently; the file is a readable diff).
LOCAL_TABLE = engine_root() / "knowledge" / "interactions_local.json"


def _load_interactions() -> list:
    entries = list(INTERACTIONS)
    if LOCAL_TABLE.exists():
        try:
            for e in json.loads(LOCAL_TABLE.read_text()):
                entries.append((e.get("a", ""), e.get("b", ""),
                                e.get("hypothesis", ""), e.get("playbook", "")))
        except Exception:
            pass
    return entries

# The interaction table: (component A matcher, component B matcher, hypothesis,
# playbook reference). Matchers are lowercase substrings against the combined
# tech strings recorded for a host. Keep it curated — every entry should be a
# REAL researcher-grade check, not scanner noise.
INTERACTIONS = [
    # --- proxy + backend differentials (request smuggling family) ---
    ("nginx", "tomcat", "Nginx-fronted Tomcat: normalization differential (semicolon / path params)",
     "recon/methodology + PortSwigger HTTP request smuggling"),
    ("nginx", "jetty", "Nginx + Jetty: CL.TE / TE.CL smuggling candidates",
     "request smuggling methodology"),
    # 'apache/' matches httpd Server headers (Apache/2.4.x) but NOT the product
    # name "Apache Tomcat" — keeps product vs front-end distinct.
    ("apache/", "tomcat", "Apache httpd + Tomcat: path-normalization bypass (off-by-slash)",
     "orange-parser playbook family"),
    ("haproxy", "envoy", "HAProxy/Envoy chain: header parsing differential candidates",
     "request smuggling methodology"),
    ("envoy", "grpc", "Envoy + gRPC: content-type/length parsing differential",
     "request smuggling methodology"),
    # --- HTTP/2-era classes (h2c, rapid-reset, h2 differential) ---
    ("envoy", "h2", "Envoy + HTTP/2: h2 desync/rapid-reset style candidates", "edge-smuggling"),
    ("nginx", "h2", "Nginx + HTTP/2: h2 smuggling (content-length vs stream framing)",
     "edge-smuggling"),
    ("iis", "h2", "IIS + HTTP/2: h2 differential candidates", "edge-smuggling"),
    ("traefik", "h2", "Traefik + HTTP/2: upgrade/h2c smuggling candidates", "edge-smuggling"),
    ("grpc", "", "gRPC surface: grpc-reflection + message-framing abuse candidates",
     "grpc-attacks"),
    ("h2c", "", "h2c upgrade accepted: cleartext smuggling channel candidate (h2c smuggling)",
     "edge-smuggling"),
    # --- cache layers ---
    ("varnish", "app", "Varnish present: cache poisoning/deception candidate "
     "(unkeyed headers, web cache poisoning)", "web-cache-poisoning"),
    ("cloudflare", "cache", "Cloudflare cache: cache-deception candidate (path confusion)",
     "cache-deception"),
    ("akamai", "", "Akamai edge: request-smuggling + cache-key candidates",
     "edge-smuggling"),
    # --- CDN + origin ---
    ("cloudfront", "s3", "CloudFront + S3: origin token-replay / bucket takeover candidate",
     "domain-takeover"),
    ("fastly", "", "Fastly edge: request smuggling (HTTP/2) candidates", "edge-smuggling"),
    # --- parser differentials ---
    ("php", "nginx", "PHP + Nginx: path-info / %-encoded differential candidates",
     "parser-differential"),
    ("express", "node", "Express/Node: prototype-pollution candidates if any sink exists",
     "prototype-pollution"),
    # --- auth/session stacks ---
    ("keycloak", "", "Keycloak present: auth-flow flaws (account linking, redirect URIs)",
     "auth-flow"),
    ("oauth", "", "OAuth detected: redirect_uri validation + code-reuse checks",
     "oauth-flaws"),
    ("graphql", "", "GraphQL: introspection, depth-cost, field-suggestion checks",
     "graphql-attacks"),
]


def _host_tech_string(fp: dict, host: str) -> str:
    return " ".join(str(e.get("tech", "")) for e in fp.get(host, [])).lower()


def hypothesize():
    fp = load_json(FINGERPRINTS_FILE)
    if not fp:
        print("[*] Fingerprint cache empty — record banners first "
              "(sec_flow.py fingerprint --host <h> --tech '<banner>' --record).")
        return
    board = load_json(BOARD_FILE)
    existing = {str(l.get("value", "")) for l in (board or {}).get("leads", [])}

    leads = []
    for host, entries in fp.items():
        if not isinstance(entries, list):  # skip metadata keys like 'updated_at'
            continue
        tech = _host_tech_string(fp, host)
        if not tech:
            continue
        for a_match, b_match, hypothesis, playbook in _load_interactions():
            if a_match not in tech:
                continue
            if b_match and b_match not in tech:
                continue
            value = (f"stack interaction: {host} [{a_match}"
                     + (f" + {b_match}" if b_match else "") + "]")
            if value in existing:
                continue
            leads.append({
                "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                "type": "tech",
                "value": value,
                "signal": hypothesis,
                "confidence": 0.5,
                "suggested_next": f"run the {playbook} playbook against {host}; "
                                   f"interaction flaws live BETWEEN components",
                "must_verify": True,
                "preconditions": [],
                "source_pointer": "STACK_HYPO",
                "status": "new",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    if not leads:
        print("[*] No NEW interaction hypotheses (either no matches or all queued).")
        return
    with json_transaction("board.json") as b:
        if b is not None:
            b.setdefault("leads", []).extend(leads)
    print(f"[✔] {len(leads)} stack-interaction hypothesis lead(s) filed "
          f"(from {len(fp)} fingerprinted host(s)):")
    for l in leads[:8]:
        print(f"  {l['value']}\n      {l['signal']}")
    if len(leads) > 8:
        print(f"  ... {len(leads) - 8} more (sec_flow.py leads --type tech)")


def show_pairs():
    entries = _load_interactions()
    print(f"[*] Interaction table ({len(entries)} entries"
          + (f", incl. {len(entries) - len(INTERACTIONS)} local" if len(entries) > len(INTERACTIONS) else "")
          + "):\n")
    for a, b, hyp, pb in entries:
        pair = f"{a} + {b}" if b else f"{a} (any)"
        print(f"  {pair:<28} {hyp[:80]}")
    print("\n(Extend by editing INTERACTIONS in stack_interactions.py — plain data.)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stack-interaction hypothesizer")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hypothesize", help="Fingerprint cache -> interaction leads")
    sub.add_parser("pairs", help="List the built-in interaction table")
    args = parser.parse_args()
    if args.cmd == "hypothesize":
        hypothesize()
    else:
        show_pairs()
