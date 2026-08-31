#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Wordlist Winnowing

Fuzz wordlists are 95% dead weight per target class. This tracks which entries
ever produced non-404s (from crawler/ffuf/gobuster artifacts on the board) and
auto-prunes the never-hit tail — the list compounds toward what actually
exists on YOUR kind of targets.

  * `record`  — harvest endpoint-discovery results from the board + artifacts
                into ~/.artifactory/wordlist_hits.json (global: wins travel
                across engagements)
  * `winnow`  — read a wordlist file, emit the hit-proven subset to --out
                (entries never observed anywhere go to a .pruned sidecar for
                review — nothing is silently destroyed)

Deterministic; zero tokens. Run `record` after each content-discovery pass,
`winnow` before the next one.
"""

import argparse
import json
import sys
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
HITS_FILE = Path.home() / ".artifactory" / "wordlist_hits.json"


def _load_hits() -> dict:
    if HITS_FILE.exists():
        try:
            return json.loads(HITS_FILE.read_text())
        except Exception:
            return {}
    return {}


def record_hits():
    """Harvest discovered paths (board endpoints + endpoint-type leads) into
    the global hit set. The words themselves are what we track — paths are
    normalized to their last segment so directory-name hits generalize."""
    board = load_json(BOARD_FILE) or {}
    endpoints = (board.get("discovered_assets") or {}).get("endpoints", [])
    lead_eps = [str(l.get("value", "")) for l in board.get("leads", [])
                if l.get("type") == "endpoint"]
    words = set()
    for ep in list(endpoints) + lead_eps:
        ep = (ep or "").strip()
        if not ep.startswith("/"):
            continue
        for seg in ep.strip("/").split("/"):
            if seg and not seg.isdigit() and not seg.startswith("{"):
                words.add(seg)
    if not words:
        print("[*] No discovered paths on the board to harvest.")
        return
    hits = _load_hits()
    added = 0
    for w in words:
        if w not in hits:
            hits[w] = 0
            added += 1
        hits[w] += 1
    HITS_FILE.parent.mkdir(parents=True, exist_ok=True)
    HITS_FILE.write_text(json.dumps(hits, indent=1))
    print(f"[✔] Wordlist hits: {added} new word(s), {len(hits)} tracked total "
          f"(global {HITS_FILE}).")


def winnow(wordlist: str, out: str):
    src = Path(wordlist)
    if not src.exists():
        print(f"[!] Wordlist '{wordlist}' not found.", file=sys.stderr)
        sys.exit(1)
    hits = _load_hits()
    lines = [l.strip() for l in src.read_text().splitlines() if l.strip()]
    keep, prune = [], []
    for w in lines:
        (keep if w in hits else prune).append(w)
    Path(out).write_text("\n".join(keep) + ("\n" if keep else ""))
    prune_path = Path(out + ".pruned")
    prune_path.write_text("\n".join(prune) + ("\n" if prune else ""))
    pct = (len(keep) / len(lines) * 100) if lines else 0
    print(f"[*] Winnowed {wordlist}: {len(keep)}/{len(lines)} entries proven-hit ({pct:.0f}%)")
    print(f"    kept   -> {out}")
    print(f"    pruned -> {prune_path} (kept for review; delete when satisfied)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wordlist winnowing (proven-hit tracking)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("record", help="Harvest board-discovered words into the global hit set")
    w = sub.add_parser("winnow", help="Split a wordlist into hit-proven vs unproven")
    w.add_argument("--wordlist", required=True)
    w.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.cmd == "record":
        record_hits()
    else:
        winnow(args.wordlist, args.out)
