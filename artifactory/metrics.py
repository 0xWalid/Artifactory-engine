#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Global Metrics Rollup

The cross-engagement dashboard: aggregates every workspace's evals/scores.jsonl
+ lessons into one trend view so "is the framework actually getting better?"
is answered with a curve, not a feeling.

  * `show`   — table of every recorded engagement (label, confirmed, precision,
               coverage, tokens, vulns/1M) + the TREND line (first-half vs
               last-half deltas).
  * `scan`   — discover workspaces under a root dir (default: ~/engagements)
               and register their scores into the global history.

History lives in ~/.artifactory/metrics_history.jsonl (append-only). Scores
already mirror there when run inside a workspace with GLOBUS=1... no — keep
it simple: `scan` pulls from workspaces, `show` renders. Cron-able via
maintenance.py.
"""

import argparse
import json
import sys
from pathlib import Path

HISTORY = Path.home() / ".artifactory" / "metrics_history.jsonl"


def _read_history() -> list:
    if not HISTORY.exists():
        return []
    out = []
    for line in HISTORY.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def scan_workspaces(root: str):
    """Pull evals/scores.jsonl from every workspace under root into history."""
    base = Path(root).expanduser()
    if not base.exists():
        print(f"[!] Root '{root}' does not exist.", file=sys.stderr)
        sys.exit(1)
    found = 0
    seen = {(r.get("label"), r.get("timestamp")) for r in _read_history()}
    for scores in base.glob("*/evals/scores.jsonl"):
        ws = scores.parent.parent
        for line in scores.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            key = (rec.get("label"), rec.get("timestamp"))
            if key in seen:
                continue
            rec["workspace"] = str(ws)
            seen.add(key)
            HISTORY.parent.mkdir(parents=True, exist_ok=True)
            with open(HISTORY, "a") as f:
                f.write(json.dumps(rec) + "\n")
            found += 1
    print(f"[✔] {found} new score record(s) registered from {base}")
    return found


def show():
    rows = sorted(_read_history(), key=lambda r: r.get("timestamp") or "")
    if not rows:
        print("[*] No history yet. Run engagements with `eval_engine.py score --label <x>`, "
              "then `metrics.py scan <your-workspaces-root>`.")
        return
    print(f"[*] GLOBAL METRICS — {len(rows)} recorded run(s)\n")
    print(f"  {'date':<10} {'label':<24} {'conf':>4} {'prec':>5} {'cov':>5} "
          f"{'tokens':>9} {'v/1M':>6}")
    print("  " + "-" * 66)
    for r in rows:
        date = (r.get("timestamp") or "")[:10]
        print(f"  {date:<10} {(r.get('label') or '?')[:24]:<24} "
              f"{r.get('confirmed_vulns', 0):>4} {r.get('precision', 0):>5} "
              f"{r.get('coverage', 0):>5} {r.get('tokens_spent', 0):>9.0f} "
              f"{r.get('vulns_per_1M_tokens', 0):>6}")

    # Trend: first half vs second half on the metrics that matter
    if len(rows) >= 4:
        mid = len(rows) // 2
        def avg(rs, k):
            vals = [r.get(k) or 0 for r in rs]
            return sum(vals) / len(vals) if vals else 0
        first, last = rows[:mid], rows[mid:]
        print("\n  TREND (first half -> recent half):")
        for k, name in [("vulns_per_1M_tokens", "vulns/1M-tokens"),
                        ("precision", "precision"),
                        ("coverage", "coverage"),
                        ("confirmed_vulns", "confirmed count")]:
            a, b = avg(first, k), avg(last, k)
            arrow = "↑" if b > a else ("↓" if b < a else "=")
            print(f"    {name:<18} {a:>7.2f} -> {b:>7.2f}  {arrow}")
        verdict = "IMPROVING" if avg(last, "vulns_per_1M_tokens") > avg(first, "vulns_per_1M_tokens") \
            else "FLAT/REGRESSING"
        print(f"\n  ★ CURVE: {verdict} on the north-star metric.")
    else:
        print("\n  (>=4 runs enables trend analysis)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Global metrics rollup")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Register scores from workspaces under a root")
    s.add_argument("--root", default="~/engagements")
    sub.add_parser("show", help="Cross-engagement dashboard + trend")
    args = parser.parse_args()
    if args.cmd == "scan":
        scan_workspaces(args.root)
    else:
        show()
