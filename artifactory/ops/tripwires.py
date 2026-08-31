#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Production Tripwires

Planted high-value decoy secrets at likely leak paths INSIDE scope. If any
finding, artifact, or report output ever surfaces one, the ENTIRE detect ->
redact -> report chain is verified in production — not just in tests. If a
tripwire never fires where it should have, a coverage hole is exposed.

  * `plant`   — write N unique decoy secrets to likely-leak locations
                (.env-style files under authorized code paths, response
                headers already observed, board fields). Each decoy maps to a
                unique TRIPWIRE id.
  * `check`   — sweep the board (findings/leads/artifacts/reports) for decoy
                values. A HIT = full-chain verification (detection worked AND
                redaction must have held in every operator-facing surface).
                A MISS on a decoy placed somewhere a real leak would occur =
                coverage gap surfaced.

Decoys look like real credentials (AWS-style/JWT-ish) but carry an embedded
TRIPWIRE token that identifies the plant site. Values never appear in this
file's output unredacted: the checker prints TRIPWIRE ids, not secrets.
"""

import argparse
import json
import re
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
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
TRIPWIRE_FILE = BLACKBOARD_DIR / "tripwires.json"

# Where leaks really happen, in production order of likelihood.
PLANT_SITES = [
    ("env-file", "an .env-style file under an authorized code path"),
    ("config-json", "a config/settings json under an authorized code path"),
    ("http-response", "a response artifact captured during testing (planted via header)"),
    ("board-detail", "a finding/lead detail field operators write into"),
]


def _decoy_for(site: str, n: int) -> str:
    """Realistic-looking decoy carrying the TRIPWIRE token. Not printed raw."""
    tw = f"TRIPWIRE{uuid.uuid4().hex[:8].upper()}"
    if site in ("env-file", "config-json"):
        return f"AWS_SECRET_ACCESS_KEY=AKIA{tw[:16]}"
    if site == "http-response":
        return f"X-Internal-Token: Bearer eyJ{tw.lower()}.sig.sig"
    return f"internal-api-key: {tw}"


def plant(code_root: str = ""):
    """Plant decoys. Env/config sites need an authorized code path (from
    scope.json allowed_code_paths or --code-root); response/board sites plant
    into the next captured traffic naturally (the decoy value goes into a
    board artifact so any sweep sees it)."""
    tw_store = {}
    planted = []

    root = None
    if code_root:
        root = Path(code_root)
    else:
        scope = load_json(SCOPE_FILE) or {}
        paths = scope.get("allowed_code_paths", [])
        if paths:
            root = Path(paths[0])

    for site, desc in PLANT_SITES:
        decoy = _decoy_for(site, len(tw_store))
        tw_id = f"TW_{uuid.uuid4().hex[:6].upper()}"
        tw_store[tw_id] = {"site": site, "decoy": decoy, "planted_at":
                           datetime.now(timezone.utc).isoformat()}
        if site in ("env-file", "config-json") and root and root.exists():
            target = root / (".env.tripwire" if site == "env-file" else "config.tripwire.json")
            target.write_text(
                (f"# planted decoy\n{decoy}\n" if site == "env-file"
                 else json.dumps({"_tripwire": decoy}, indent=2)))
            planted.append((tw_id, site, str(target)))
        elif site == "board-detail":
            # plant into a low-notice board location: a lead detail
            with json_transaction("board.json") as board:
                if board is not None:
                    board.setdefault("leads", []).append({
                        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                        "type": "anomaly",
                        "value": "internal config observed during testing",
                        "signal": decoy,  # the plant: any sweep of signals sees it
                        "confidence": 0.1,
                        "suggested_next": "ignore unless surfaced by tripwire check",
                        "must_verify": False, "preconditions": [],
                        "source_pointer": "TRIPWIRE_PLANT",
                        "status": "new",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
            planted.append((tw_id, site, "board.json (lead signal)"))
        else:
            # http-response: place in a fresh artifact so the sweep path is real
            ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
            pid = f"MSG_TRIPWIRE{uuid.uuid4().hex[:4].upper()}"
            (ARTIFACTS_DIR / f"{pid}.log").write_text(
                f"--- COMMAND ---\ncaptured traffic (tripwire plant)\n\n"
                f"--- STDOUT ---\nX-Debug-Info: {decoy}\n\n--- STDERR ---\n")
            planted.append((tw_id, site, f"artifacts/{pid}.log"))

    TRIPWIRE_FILE.write_text(json.dumps(tw_store, indent=2))
    print(f"[OK] {len(planted)} tripwire(s) planted:")
    for tw_id, site, where in planted:
        print(f"    {tw_id} [{site}] -> {where}")
    print("    Check with: tripwires.py check   (a HIT = full-chain verification;")
    print("    a MISS everywhere = either clean or the sweep never looked)")


def check():
    """Sweep everything operator-facing for planted decoys. Prints TRIPWIRE ids
    (never raw decoys). Cross-references WHERE each hit surfaced."""
    if not TRIPWIRE_FILE.exists():
        print("[*] No tripwires planted (tripwires.py plant).")
        return
    tw_store = json.loads(TRIPWIRE_FILE.read_text())
    board = load_json(BOARD_FILE) or {}

    # gather all text surfaces: findings, leads, artifacts, reports
    surfaces = {}
    for f in board.get("findings", []):
        surfaces[f"finding {f.get('id')}"] = json.dumps(f)
    for l in board.get("leads", []):
        surfaces[f"lead {l.get('id')}"] = json.dumps(l)
    if ARTIFACTS_DIR.exists():
        for art in ARTIFACTS_DIR.glob("*.log"):
            surfaces[f"artifact {art.stem}"] = art.read_text(errors="replace")
    reports = Path.cwd() / "reports"
    if reports.exists():
        for r in reports.glob("**/*.md"):
            surfaces[f"report {r.name}"] = r.read_text(errors="replace")

    hits, misses = [], []
    for tw_id, meta in tw_store.items():
        decoy = meta["decoy"]
        found_in = [name for name, text in surfaces.items() if decoy in text]
        if found_in:
            hits.append((tw_id, meta["site"], found_in))
        else:
            misses.append((tw_id, meta["site"]))

    print("=" * 62)
    print("TRIPWIRE CHECK (production verification of the whole chain)")
    print("=" * 62)
    if hits:
        print(f"\n  HITS ({len(hits)}) — the decoy WAS carried into surfaces:")
        for tw_id, site, where in hits:
            print(f"    {tw_id} [{site}] surfaced in: {', '.join(where[:3])}")
        print("\n  VERDICT: detection chain reaches these surfaces. Verify each is a")
        print("  REDACTED surface (inspect output) — raw decoys in operator-facing text")
        print("  would be a redaction failure; raw decoys in artifacts are expected.")
    if misses:
        print(f"\n  MISSES ({len(misses)}) — planted but never surfaced:")
        for tw_id, site in misses:
            print(f"    {tw_id} [{site}]")
        print("\n  Verdict depends on WHERE: env-file/config misses mean the sweep")
        print("  (secrets.py scan) never covered that path; response misses may mean")
        print("  no capture looked. Each miss is a potential coverage hole to close.")
    if not hits and not misses:
        print("  [!] Tripwire store is empty.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Production tripwires (chain verification)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plant", help="Plant decoy secrets at likely leak paths")
    p.add_argument("--code-root", dest="code_root", default="",
                   help="Code root for env/config plants (default: first allowed_code_path)")
    sub.add_parser("check", help="Sweep surfaces for decoys; verdict per site")
    args = parser.parse_args()
    if args.cmd == "plant":
        plant(args.code_root)
    else:
        check()
