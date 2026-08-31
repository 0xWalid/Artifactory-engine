#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Skeptic Second-Opinion Ledger

Track every skeptic verdict (survives/killed/inconclusive) and its eventual
ground truth (was the finding later confirmed by evidence, or did it die?).
Over engagements this makes THE SKEPTIC ITSELF evaluable: a skeptic that
kills findings that would have survived is too aggressive; one that passes
everything is decoration. Stats render on demand.

  * `record --finding <FID> --verdict <survives|killed|inconclusive>` — log a skeptic verdict
  * `resolve --finding <FID> --outcome <confirmed|dead>`             — ground truth arrives
  * `stats`                                                          — the skeptic's own scorecard
Ledger: ~/.artifactory/skeptic_ledger.jsonl (append-only)
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LEDGER = Path.home() / ".artifactory" / "skeptic_ledger.jsonl"


def _read():
    out = []
    if LEDGER.exists():
        for line in LEDGER.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


def record(finding, verdict, note=""):
    if verdict not in ("survives", "killed", "inconclusive"):
        print("[!] verdict: survives|killed|inconclusive", file=sys.stderr)
        sys.exit(1)
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with open(LEDGER, "a") as f:
        f.write(json.dumps({
            "finding": finding, "verdict": verdict, "note": note,
            "at": datetime.now(timezone.utc).isoformat(),
            "resolved": None,
        }) + "\n")
    print(f"[OK] Skeptic verdict logged: {finding} -> {verdict}")


def resolve(finding, outcome):
    if outcome not in ("confirmed", "dead"):
        print("[!] outcome: confirmed|dead", file=sys.stderr)
        sys.exit(1)
    rows = _read()
    hit = False
    for r in rows:
        if r["finding"] == finding and r["resolved"] is None:
            r["resolved"] = outcome
            hit = True
    if hit:
        LEDGER.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        print(f"[OK] Resolved {finding} -> {outcome}")
    else:
        print("[*] No unresolved verdict for that finding.")


def stats():
    rows = _read()
    resolved = [r for r in rows if r["resolved"]]
    if not resolved:
        print("[*] No resolved skeptic verdicts yet — the scorecard fills as "
              "engagements resolve findings.")
        return
    agree = sum(1 for r in resolved
                if (r["verdict"] == "survives" and r["resolved"] == "confirmed")
                or (r["verdict"] == "killed" and r["resolved"] == "dead"))
    overkill = [r for r in resolved if r["verdict"] == "killed" and r["resolved"] == "confirmed"]
    rubber = [r for r in resolved if r["verdict"] == "survives" and r["resolved"] == "dead"]
    n = len(resolved)
    print(f"[*] SKEPTIC SCORECARD ({n} resolved verdict(s)):\n")
    print(f"    agreement:     {agree}/{n} ({agree/n:.0%})")
    print(f"    over-kills:     {len(overkill)}  (killed findings that were real — TOO AGGRESSIVE)")
    print(f"    rubber stamps: {len(rubber)}  (passed findings that died — TOO LENIENT)")
    for r in overkill[:3]:
        print(f"      overkill: {r['finding']} — {r.get('note', '')[:60]}")
    for r in rubber[:3]:
        print(f"      rubber:   {r['finding']} — {r.get('note', '')[:60]}")
    if agree / n >= 0.8 and not overkill:
        print("\n    Verdict: healthy gate.")
    elif overkill:
        print("\n    Verdict: loosen the kill criteria (real findings are dying at review).")
    elif rubber:
        print("\n    Verdict: tighten the review (weak evidence is passing).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Skeptic second-opinion ledger")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record", help="Log a skeptic verdict on a finding")
    r.add_argument("--finding", required=True)
    r.add_argument("--verdict", required=True)
    r.add_argument("--note", default="")
    s = sub.add_parser("resolve", help="Record the eventual ground truth")
    s.add_argument("--finding", required=True)
    s.add_argument("--outcome", required=True)
    sub.add_parser("stats", help="The skeptic's own scorecard")
    args = parser.parse_args()
    if args.cmd == "record":
        record(args.finding, args.verdict, args.note)
    elif args.cmd == "resolve":
        resolve(args.finding, args.outcome)
    else:
        stats()
