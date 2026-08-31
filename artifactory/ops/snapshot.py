#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Engagement Snapshots + Surface Diff

The retest heuristic every researcher uses: "what changed since we last
tested this place?" Close out an engagement with a snapshot; next engagement,
diff the new board against the snapshot and get precise, prioritized NEW
surface.

  * `snapshot`  — copy board.json to .blackboard/snapshots/<ts>-<label>.json
                  (endpoints, findings, fingerprints, sessions-metadata).
  * `diff`      — compare the CURRENT board against the LATEST (or --label)
                  snapshot: new endpoints, gone endpoints, new fingerprints
                  (stack changes!), unresolved-again findings. Every NEW item
                  becomes a priority lead — fresh surface gets tested first,
                  and the 'disappeared' surface is flagged too (an endpoint
                  that vanished may just have moved).
  * `list`      — show snapshots.

Deterministic. Zero model tokens. Pairs with debrief (auto-snapshot hook).
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

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SNAPSHOTS_DIR = BLACKBOARD_DIR / "snapshots"
FP_FILE = BLACKBOARD_DIR / "fingerprints.json"


def _snap_data() -> dict:
    board = load_json(BOARD_FILE) or {}
    return {
        "taken_at": datetime.now(timezone.utc).isoformat(),
        "endpoints": sorted((board.get("discovered_assets") or {}).get("endpoints", [])),
        "hosts": sorted((board.get("discovered_assets") or {}).get("hosts", [])),
        "findings": [
            {"id": f.get("id"), "title": f.get("title"), "status": f.get("status"),
             "severity": f.get("severity")}
            for f in board.get("findings", [])
        ],
        "fingerprints": load_json(FP_FILE) or {},
        "board_leads": len(board.get("leads", [])),
    }


def take_snapshot(label="close-out"):
    if not BOARD_FILE.exists():
        print("[!] No board.json — nothing to snapshot.", file=sys.stderr)
        sys.exit(1)
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    data = _snap_data()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = SNAPSHOTS_DIR / f"{ts}-{label}.json"
    path.write_text(json.dumps(data, indent=2))
    print(f"[✔] Snapshot saved: {path.name}")
    print(f"    {len(data['endpoints'])} endpoints, {len(data['findings'])} findings, "
          f"{len(data['fingerprints'])} fingerprinted host(s)")
    return path


def list_snapshots():
    if not SNAPSHOTS_DIR.exists():
        print("[*] No snapshots yet (take one at engagement close: snapshot.py snapshot).")
        return
    snaps = sorted(SNAPSHOTS_DIR.glob("*.json"))
    for p in snaps:
        d = json.loads(p.read_text())
        print(f"  {p.name}  ({len(d.get('endpoints', []))} ep, "
              f"{len(d.get('findings', []))} findings)")


def _load_snapshot(label=None):
    if not SNAPSHOTS_DIR.exists():
        return None
    snaps = sorted(SNAPSHOTS_DIR.glob("*.json"))
    if not snaps:
        return None
    if label:
        match = [p for p in snaps if label in p.name]
        if not match:
            print(f"[!] No snapshot matching '{label}'.", file=sys.stderr)
            sys.exit(1)
        return json.loads(match[-1].read_text())
    return json.loads(snaps[-1].read_text())


def surface_diff(label=None):
    snap = _load_snapshot(label)
    if not snap:
        print("[*] No snapshot to diff against — take one first "
              "(snapshot.py snapshot --label <name>).")
        return
    board = load_json(BOARD_FILE) or {}
    cur_eps = set((board.get("discovered_assets") or {}).get("endpoints", []))
    old_eps = set(snap.get("endpoints", []))

    new_eps = sorted(cur_eps - old_eps)
    gone_eps = sorted(old_eps - cur_eps)

    cur_fp = load_json(FP_FILE) or {}
    old_fp = snap.get("fingerprints", {})
    fp_changes = []
    for host in sorted(set(cur_fp) | set(old_fp)):
        c = {str(e.get("tech", "")) for e in cur_fp.get(host, []) if isinstance(e, dict)}
        o = {str(e.get("tech", "")) for e in old_fp.get(host, []) if isinstance(e, dict)}
        added, removed = c - o, o - c
        if added or removed:
            fp_changes.append((host, sorted(added), sorted(removed)))

    old_findings = {f.get("title") for f in snap.get("findings", [])}

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    for ep in new_eps:
        leads.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "endpoint",
            "value": f"NEW SURFACE: {ep}",
            "signal": "appeared since the last engagement snapshot",
            "confidence": 0.6,
            "suggested_next": "fresh surface is untested by definition — role-diff, "
                               "verb-matrix, and fuzz it first",
            "must_verify": False,
            "preconditions": [],
            "source_pointer": pointer_id,
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    for host, added, removed in fp_changes:
        leads.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "tech",
            "value": f"STACK CHANGE: {host} (+{','.join(added) or '-'} -{','.join(removed) or '-'})",
            "signal": "component versions changed since last engagement — re-run "
                      "intel/KEV/stack-interactions for the new stack",
            "confidence": 0.6,
            "suggested_next": "re-run fingerprint-driven intel + interaction hypotheses",
            "must_verify": True,
            "preconditions": [],
            "source_pointer": pointer_id,
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    (BLACKBOARD_DIR / "artifacts").mkdir(parents=True, exist_ok=True)
    lines = [f"snapshot: {snap.get('taken_at')}", f"new endpoints ({len(new_eps)}):"]
    lines += [f"  + {e}" for e in new_eps[:100]]
    lines += [f"gone endpoints ({len(gone_eps)}):"]
    lines += [f"  - {e}" for e in gone_eps[:100]]
    lines += [f"stack changes ({len(fp_changes)}):"] + \
             [f"  {h}: +{a} -{r}" for h, a, r in fp_changes]
    lines += [f"previously-found findings still absent now: "
              f"{sorted(set(f.get('title', '') for f in board.get('findings', [])) - old_findings)}"]
    (BLACKBOARD_DIR / "artifacts" / f"{pointer_id}.log").write_text(
        "--- COMMAND ---\nsnapshot.py diff\n\n--- STDOUT ---\n"
        + "\n".join(lines) + "\n\n--- STDERR ---\n")

    if leads:
        with json_transaction("board.json") as b:
            if b is not None:
                b.setdefault("leads", []).extend(leads)

    print(f"[*] SURFACE DIFF vs {snap.get('taken_at')}:\n")
    print(f"    new endpoints:      {len(new_eps)}")
    for e in new_eps[:8]:
        print(f"      + {e}")
    if len(new_eps) > 8:
        print(f"      ... {len(new_eps) - 8} more")
    print(f"    gone endpoints:     {len(gone_eps)}  (moved or removed — verify)")
    for e in gone_eps[:5]:
        print(f"      - {e}")
    print(f"    stack changes:      {len(fp_changes)}")
    for h, a, r in fp_changes[:5]:
        print(f"      {h}: +{a} -{r}")
    if leads:
        print(f"\n[✔] {len(leads)} priority lead(s) filed (fresh surface first). "
              f"Full diff: inspect --id {pointer_id}")
    else:
        print("\n[*] No new surface/stack deltas vs the snapshot.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Engagement snapshots + surface diff")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="Snapshot the current board at close-out")
    s.add_argument("--label", default="close-out")
    sub.add_parser("list", help="List snapshots")
    d = sub.add_parser("diff", help="Diff current board vs a snapshot")
    d.add_argument("--label", default=None, help="Snapshot label substring (default: latest)")
    args = parser.parse_args()
    if args.cmd == "snapshot":
        take_snapshot(args.label)
    elif args.cmd == "list":
        list_snapshots()
    else:
        surface_diff(args.label)
