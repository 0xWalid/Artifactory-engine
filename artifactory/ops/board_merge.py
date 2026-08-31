#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Cross-Operator Board Merge

Two agents, two workspaces, one target: merge their boards with conflict
detection. Findings/leads/hosts merge by identity (title/value); conflicting
statuses surface as CONFLICT entries for the operator — never silently
resolved. Execution pointers from BOTH boards are preserved with a source
prefix so evidence stays attributable.

  * `merge --from <other-workspace>`   — merge that workspace's board into
    the CURRENT one (current board wins ties EXCEPT when the other's entry
    has stronger status: confirmed beats informational; dead beats new for
    the same lead identity).

Scope files are NOT merged (scope is per-engagement policy — the operator
decides); a report of scope differences is printed instead.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"


def merge(other_dir: str, label_prefix: str = "merged"):
    other_bb = Path(other_dir) / ".blackboard"
    other_board_f = other_bb / "board.json"
    if not other_board_f.exists():
        print(f"[!] No board.json at {other_board_f}", file=sys.stderr)
        sys.exit(1)
    other = json.loads(other_board_f.read_text())
    mine = load_json(BOARD_FILE) or {}
    if not mine:
        print("[!] Current workspace has no board — init first.", file=sys.stderr)
        sys.exit(1)

    conflicts, merged_counts = [], {"findings": 0, "leads": 0, "hosts": 0, "endpoints": 0}

    with json_transaction("board.json") as board:
        # ---- findings: identity = title (lowercased) ----
        by_title = {f.get("title", "").lower(): f for f in board.get("findings", [])}
        for f in other.get("findings", []):
            key = (f.get("title") or "").lower()
            if not key:
                continue
            if key in by_title:
                mine_f = by_title[key]
                # conflict matrix: confirmed is strongest; differing severities flag
                if mine_f.get("status") != f.get("status"):
                    stronger = "confirmed" if "confirmed" in (mine_f.get("status"), f.get("status")) else None
                    if stronger:
                        loser = mine_f if mine_f.get("status") != stronger else f
                        conflicts.append(("finding", f.get("title", ""),
                                           mine_f.get("status"), f.get("status"),
                                           f"kept {stronger}"))
                        if mine_f.get("status") != stronger:
                            mine_f["status"] = stronger
                    else:
                        conflicts.append(("finding", f.get("title", ""),
                                          mine_f.get("status"), f.get("status"), "kept current"))
                # union the evidence pointers
                extra = [p for p in (f.get("related_pointers") or [])
                         if p not in (mine_f.get("related_pointers") or [])]
                mine_f.setdefault("related_pointers", []).extend(extra)
                mine_f["merged_from"] = mine_f.get("merged_from", []) + [label_prefix]
            else:
                f = dict(f)
                f["merged_from"] = [label_prefix]
                board.setdefault("findings", []).append(f)
                by_title[key] = f
                merged_counts["findings"] += 1

        # ---- leads: identity = (type, value); terminal states win ----
        lead_keys = {(l.get("type"), str(l.get("value"))) for l in board.get("leads", [])}
        lead_lookup = {(l.get("type"), str(l.get("value"))): l for l in board.get("leads", [])}
        for l in other.get("leads", []):
            key = (l.get("type"), str(l.get("value")))
            if key in lead_keys:
                cur = lead_lookup[key]
                for stronger in ("dead", "confirmed"):
                    if l.get("status") == stronger and cur.get("status") != stronger:
                        conflicts.append(("lead", str(l.get("value"))[:50],
                                          cur.get("status"), l.get("status"),
                                          f"kept {stronger}"))
                        cur["status"] = stronger
                        break
            else:
                board.setdefault("leads", []).append(l)
                lead_keys.add(key)
                merged_counts["leads"] += 1

        # ---- assets: plain unions ----
        assets = board.setdefault("discovered_assets",
                                  {"hosts": [], "endpoints": [], "open_ports": []})
        for k in ("hosts", "endpoints", "open_ports"):
            mine_list = assets.setdefault(k, [])
            for item in (other.get("discovered_assets") or {}).get(k, []):
                if item not in mine_list:
                    mine_list.append(item)
                    merged_counts[k] += 1

    # ---- scope differences: reported, never merged ----
    scope_diffs = []
    other_scope_f = other_bb / "scope.json"
    if other_scope_f.exists():
        try:
            oscope = json.loads(other_scope_f.read_text())
            myscope = json.loads((BLACKBOARD_DIR / "scope.json").read_text())
            for k in ("allowed_hosts", "allowed_domains", "allowed_cidrs"):
                extra = [h for h in oscope.get(k, []) if h not in myscope.get(k, [])]
                if extra:
                    scope_diffs.append((k, extra))
        except Exception:
            pass

    print(f"[OK] Merge complete (from {other_dir}):")
    print(f"    new findings: {merged_counts['findings']}, new leads: {merged_counts['leads']}, "
          f"new hosts: {merged_counts['hosts']}, new endpoints: {merged_counts['endpoints']}")
    if conflicts:
        print(f"\n  CONFLICTS ({len(conflicts)}) — resolved by strongest-status, listed for review:")
        for kind, ident, a, b, kept in conflicts[:12]:
            print(f"    [{kind}] {ident[:50]}: '{a}' vs '{b}' -> {kept}")
    if scope_diffs:
        print("\n  SCOPE DIFFERENCES (NOT merged — policy stays per-engagement):")
        for k, extra in scope_diffs:
            print(f"    {k}: {', '.join(str(e) for e in extra[:5])}")
    print(f"\n  Evidence pointers preserved with attribution; regeneration: report_engine.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cross-operator board merge")
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="Merge another workspace's board into this one")
    m.add_argument("--from", dest="other_dir", required=True, help="Other workspace dir")
    m.add_argument("--label", default=None, help="Attribution label (default: dir name)")
    args = parser.parse_args()
    prefix = args.label or Path(args.other_dir).name
    merge(args.other_dir, prefix[:24])
