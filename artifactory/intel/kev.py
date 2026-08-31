#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - CISA KEV (Known-Exploited-Vulnerabilities)

The practitioner's real prioritization: which CVEs are being exploited in the
wild RIGHT NOW. This module pulls the official CISA KEV catalog (one JSON
feed, no key), caches it locally (respects offline re-runs), and:

  * `mark`   — scans the board's cve leads; any lead whose value references a
               KEV CVE gets its confidence raised and a priority-1 suggested
               next step. Every KEV hit is also flagged on the finding trail.
  * `list`   — show the cached catalog (or filter by --product).

Why it matters for the 1-day engine: intel.py enumerates ALL candidates;
KEV tells you which three matter this week. Verify those first.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
KEV_FILE = BLACKBOARD_DIR / "kev_cache.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev(max_age_hours: int = 24, offline: bool = False) -> list:
    """Load (and cache) the KEV catalog. Cache-first: a fresh cache means zero
    network; --offline forces cache-only; a stale/missing cache refetches."""
    cached = None
    if KEV_FILE.exists():
        try:
            doc = json.loads(KEV_FILE.read_text())
            age_h = (datetime.now(timezone.utc) -
                     datetime.fromisoformat(doc.get("fetched_at"))).total_seconds() / 3600
            if offline or age_h < max_age_hours:
                return doc.get("vulns", [])
            cached = doc
        except Exception:
            cached = None

    if offline:
        print("[!] --offline with no usable cache; nothing to load.", file=sys.stderr)
        return []

    import urllib.request
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "artifactory-kev/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            doc = json.loads(r.read().decode())
    except Exception as e:
        print(f"[!] KEV fetch failed ({e})"
              + (" — using stale cache" if cached else ""), file=sys.stderr)
        return cached.get("vulns", []) if cached else []

    vulns = doc.get("vulnerabilities", [])
    KEV_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEV_FILE.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "vulns": vulns,
    }))
    return vulns


def kev_by_cve(vulns: list) -> dict:
    return {v.get("cveID", "").upper(): v for v in vulns if v.get("cveID")}


def _cve_refs(text: str) -> set:
    return set(re.findall(r"\bCVE-\d{4}-\d{4,8}\b", (text or "").upper()))


def mark_board(offline=False) -> int:
    vulns = fetch_kev(offline=offline)
    if not vulns:
        print("[*] No KEV entries available; nothing marked.")
        return 0
    by_cve = kev_by_cve(vulns)

    marked = 0
    with json_transaction("board.json") as board:
        if board is None:
            print("[!] board.json missing — run init_env.py first.", file=sys.stderr)
            sys.exit(1)
        for l in board.get("leads", []):
            if l.get("type") != "cve":
                continue
            refs = _cve_refs(l.get("value", "") + " " + (l.get("signal") or ""))
            hits = refs & set(by_cve)
            if not hits:
                continue
            kev = by_cve[next(iter(hits))]
            l["kev"] = True
            l["confidence"] = max(float(l.get("confidence", 0)), 0.85)
            l["suggested_next"] = (f"PRIORITY 1 — known exploited in the wild: "
                                   f"{kev.get('vendorProject','?')} {kev.get('product','?')} "
                                   f"({kev.get('dateAdded','?')}). Verify version condition "
                                   f"and PoC IMMEDIATELY.")
            l.setdefault("preconditions", [])
            marked += 1

    print(f"[✔] KEV catalog: {len(vulns)} known-exploited CVE(s); "
          f"{marked} board lead(s) marked priority-1.")
    if marked:
        print("    Work them first: sec_flow.py leads --type cve (sorted by confidence)")
    return marked


def list_kev(product: str = "", offline=False, limit: int = 20):
    vulns = fetch_kev(offline=offline)
    if not vulns:
        print("[*] No KEV entries available.")
        return
    if product:
        p = product.lower()
        vulns = [v for v in vulns if p in (v.get("product", "") + v.get("vendorProject", "")).lower()]
    print(f"[*] KEV: {len(vulns)} entr(ies)"
          + (f" matching '{product}'" if product else "") + ":\n")
    for v in vulns[:limit]:
        print(f"  {v.get('cveID')}  {v.get('vendorProject','?')} / {v.get('product','?')}")
        print(f"      added {v.get('dateAdded','?')} — {(v.get('shortDescription') or '')[:100]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CISA KEV prioritization")
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mark", help="Mark board cve leads that match the KEV catalog")
    m.add_argument("--offline", action="store_true", help="Use cache only")
    li = sub.add_parser("list", help="Show the KEV catalog (optionally filtered)")
    li.add_argument("--product", default="")
    li.add_argument("--offline", action="store_true")
    li.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    if args.cmd == "mark":
        mark_board(offline=args.offline)
    else:
        list_kev(args.product, args.offline, args.limit)
