#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - CWE Cross-Index

One lookup resolves everything the framework knows about a vulnerability
class: greenhouse recipes, playbooks, payload families, dead-end history,
playbook confirm-rates, source lineage, KEV context. The 'wordnet of vulns'.

  * `lookup <class>`   — everything known, one card
  * `map`             — every class x every knowledge store (the coverage map)
  * `gaps`            — classes with NO methodology/ground-truth/payloads
                        (the pre-engagement blind-spot list)

Deterministic joins over: greenhouse.BUG_RECIPES, prompts/*, payloads/index,
deadends.jsonl, playbook_confirm_rates.json, source_lineage.json.
"""

import argparse
import json
import re
import sys
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import blackboard_dir  # noqa: E402
from bootstrap import engine_root  # noqa: E402
import playbook_engine as pe  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
DEADENDS = Path.home() / ".artifactory" / "deadends.jsonl"
PB_RATES = Path.home() / ".artifactory" / "playbook_confirm_rates.json"
LINEAGE = Path.home() / ".artifactory" / "source_lineage.json"
PAYLOAD_INDEX = engine_root() / "payloads" / "index.json"

# class aliases -> canonical class token (the join key across stores)
CLASS_ALIASES = {
    "xss": ["xss", "cross-site scripting"],
    "sqli": ["sqli", "sql injection"],
    "traversal": ["traversal", "path traversal", "lfi", "file read"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "access-control": ["bac", "access control", "broken access control"],
    "idor": ["idor", "bola", "object reference"],
    "mass-assignment": ["mass assignment", "parameter tampering"],
    "race": ["race condition", "race"],
    "jwt": ["jwt", "alg confusion"],
    "token": ["session token", "entropy", "token weak"],
    "oauth": ["oauth", "redirect"],
    "ssti": ["ssti", "template injection"],
    "xxe": ["xxe", "xml external entity"],
    "deserialization": ["deser", "pickle", "unserialize"],
    "redirect": ["open redirect", "redirect"],
    "injection": ["command injection", "injection"],
}


def _canonical(query: str):
    q = (query or "").lower()
    for canon, aliases in CLASS_ALIASES.items():
        if any(a in q for a in aliases):
            return canon
    return q.strip() or None


def _read_jsonl(p: Path) -> list:
    out = []
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


def lookup(query: str):
    canon = _canonical(query)
    if not canon:
        print("[!] Which class? e.g. xss, sqli, traversal, ssrf, idor, race, jwt, ssti, xxe")
        return
    aliases = CLASS_ALIASES.get(canon, [canon])

    # 1) greenhouse ground truth
    import greenhouse as gh
    recipes = [c for c, r in gh.BUG_RECIPES.items()
               if any(a in c or any(a in r["family"] for a in [canon]) or
                      any(a in c for a in aliases)
                      for a in [canon])]
    recipes = [c for c in gh.BUG_RECIPES
               if any(a in c.replace("-", " ").replace("_", " ") for a in aliases)
               or canon in c.replace("-", " ")]

    # 2) playbooks (token overlap)
    pbs = [pb.name for pb in pe.PROMPTS_DIR.glob("*/*.md")
           if any(a.replace(" ", "_") in pb.stem or a.replace(" ", "-") in pb.stem
                  or a.replace(" ", "") in pb.stem for a in [canon] + aliases)]

    # 3) payload families
    families = []
    if PAYLOAD_INDEX.exists():
        idx = json.loads(PAYLOAD_INDEX.read_text())
        families = [c for c in idx
                    if any(a in c or any(a in idx[c].get("when", "").lower()
                                          for a in [canon]) for a in [canon])]
        families = [c for c in idx if any(a in c for a in [canon] + aliases)]

    # 4) dead-end history
    deads = [r for r in _read_jsonl(DEADENDS)
             if any(a in json.dumps(r) for a in [canon])]

    # 5) playbook confirm-rates
    rates = {}
    if PB_RATES.exists():
        rates = json.loads(PB_RATES.read_text()).get(canon, {})

    # 6) source lineage
    lineage = {}
    if LINEAGE.exists():
        led = json.loads(LINEAGE.read_text())
        for sid, classes in led.items():
            if canon in classes:
                lineage[sid] = classes[canon]

    print("=" * 62)
    print(f"CLASS CROSS-INDEX: {canon}  (query: '{query}')")
    print("=" * 62)
    print(f"\n  Greenhouse ground truth: ", end="")
    print(", ".join(recipes) if recipes else "NONE (grow one: greenhouse.py list)")
    print(f"  Playbooks:               ", end="")
    print(", ".join(pbs) if pbs else "NONE (synthesis protocol)")
    print(f"  Payload families:        ", end="")
    print(", ".join(families) if families else "NONE (payload_corpus.py)")
    print(f"  Playbook confirm-rate:   ", end="")
    print(json.dumps(rates) if rates else "unmeasured")
    print(f"  Source lineage:          ", end="")
    print(json.dumps(lineage) if lineage else "no synthesized-source outcomes")
    print(f"  Dead-end history:       ", end="")
    print(f"{len(deads)} record(s)" if deads else "none (never died here — or never tried)")
    if deads:
        for d in deads[-3:]:
            print(f"      {d.get('stack', '?')[:36]} | {d.get('signal_family', '')[:40]}")

    # coverage verdict
    have = [bool(recipes), bool(pbs), bool(families)]
    if all(have):
        print("\n  [OK] Full coverage: ground truth + methodology + payloads.")
    elif not recipes and not pbs:
        print("\n  [!!] NO COVERAGE: nothing exists for this class — cold-start")
        print("       path: greenhouse.py grow <recipe> or synthesis protocol")
    else:
        missing = []
        if not recipes:
            missing.append("ground truth (grow a recipe)")
        if not pbs:
            missing.append("methodology (synthesis)")
        if not families:
            missing.append("payloads (add a family)")
        print(f"\n  [~] Partial coverage — missing: {'; '.join(missing)}")


def coverage_map():
    """Every class x every store. The pre-engagement blind-spot list."""
    import greenhouse as gh
    pb_names = {pb.stem for pb in pe.PROMPTS_DIR.glob("*/*.md")}
    fam_names = set()
    if PAYLOAD_INDEX.exists():
        fam_names = set(json.loads(PAYLOAD_INDEX.read_text()).keys())

    print(f"[*] COVERAGE MAP (class x knowledge store)\n")
    print(f"  {'class':<16} {'ground truth':>12} {'methodology':>11} {'payloads':>8} {'rates':>6}")
    print("  " + "-" * 60)
    gaps = []
    for canon, aliases in CLASS_ALIASES.items():
        gh_ok = any(any(a in c.replace("-", " ") for a in aliases)
                    for c in gh.BUG_RECIPES)
        pb_ok = any(a.replace(" ", "_") in n or a.replace(" ", "") in n or
                    a.replace(" ", "-") in n
                    for a in [canon] + aliases for n in pb_names)
        pay_ok = any(a in f for a in [canon] + aliases for f in fam_names)
        rated = False
        if PB_RATES.exists():
            rated = canon in json.loads(PB_RATES.read_text())
        row = (canon, gh_ok, pb_ok, pay_ok, rated)
        print(f"  {canon:<16} {'YES' if gh_ok else '-':>12} "
              f"{'YES' if pb_ok else '-':>11} {'YES' if pay_ok else '-':>8} "
              f"{'YES' if rated else '-':>6}")
        if not pb_ok and not gh_ok:
            gaps.append(canon)
    print(f"\n  TOTAL BLIND SPOTS (no methodology AND no ground truth): "
          f"{len(gaps)}" + (f" -> {', '.join(gaps)}" if gaps else ""))


def gaps_only():
    """The blind-spot list alone (for doctor/status)."""
    import greenhouse as gh
    pb_names = {pb.stem for pb in pe.PROMPTS_DIR.glob("*/*.md")}
    out = []
    for canon, aliases in CLASS_ALIASES.items():
        gh_ok = any(any(a in c.replace("-", " ") for a in aliases)
                    for c in gh.BUG_RECIPES)
        pb_ok = any(a.replace(" ", "_") in n or a.replace(" ", "") in n or
                    a.replace(" ", "-") in n
                    for a in [canon] + aliases for n in pb_names)
        if not gh_ok and not pb_ok:
            out.append(canon)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CWE cross-index (one lookup per class)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    lk = sub.add_parser("lookup", help="Everything known about a class")
    lk.add_argument("query")
    sub.add_parser("map", help="Full class x store coverage map")
    sub.add_parser("gaps", help="Blind-spot list only")
    args = parser.parse_args()
    if args.cmd == "lookup":
        lookup(args.query)
    elif args.cmd == "map":
        coverage_map()
    else:
        gaps = gaps_only()
        print("\n".join(gaps) if gaps else "no blind spots")
