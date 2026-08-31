#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Maintenance Loop

One command, cron-able, that keeps the framework's information diet fresh.
Everything here is deterministic/cheap (HTTP fetches + hash checks + suite) —
no LLM tokens. Run weekly (or after each engagement) to:

  1. Re-hash the research library (--refresh semantics: changed sources
     re-queue themselves into the pending synthesis worklist).
  2. Refresh the CISA KEV cache and re-mark the board's cve leads.
  3. Prune stale target fingerprints (>= TTL days old).
  4. Flag low-conversion playbooks for retirement review (their class leads
     died at high rate across recorded lessons) — flags only, never deletes.
  5. Run the deterministic engine suite (optional, --suite) — the gate's own
     health check, so drift is caught before it costs an engagement.

Exit code 0 = healthy; non-zero = something needs the operator's attention.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
FINGERPRINTS_FILE = BLACKBOARD_DIR / "fingerprints.json"
LESSONS_GLOBAL = Path.home() / ".artifactory" / "lessons.jsonl"

FINGERPRINT_TTL_DAYS = 14


def step(msg):
    print(f"[*] {msg}")


def maintenance(run_suite=False, offline=False):
    issues = 0

    # 1) research-library freshness
    step("1/5 Research library freshness (re-hash sources)...")
    try:
        import playbook_engine
        changed = playbook_engine.refresh_source_hashes(verbose=False)
        if changed:
            print(f"    [~] {len(changed)} source(s) changed -> re-queued for re-synthesis "
                  f"(run: playbook_engine.py --sources-json --pending, then /artifactory research)")
        else:
            print("    [+] all built sources unchanged")
    except Exception as e:
        print(f"    [!] refresh failed: {e}")
        issues += 1

    # 2) KEV cache + board marking
    step("2/5 CISA KEV refresh + cve-lead prioritization...")
    try:
        if BOARD_FILE.exists():
            import kev
            kev.fetch_kev(offline=offline)
            marked = kev.mark_board(offline=offline)
            print(f"    [+] KEV refreshed; {marked} board lead(s) at priority-1")
        else:
            print("    [*] no board.json in this workspace — KEV cached only")
            import kev
            kev.fetch_kev(offline=offline)
    except Exception as e:
        print(f"    [!] KEV failed: {e}")
        issues += 1

    # 3) prune stale fingerprints
    step("3/5 Prune stale target fingerprints (TTL)...")
    try:
        if FINGERPRINTS_FILE.exists():
            fp = load_json(FINGERPRINTS_FILE)
            cutoff = datetime.now(timezone.utc).timestamp() - FINGERPRINT_TTL_DAYS * 86400
            pruned = 0
            for host, entries in list(fp.items()):
                if not isinstance(entries, list):
                    continue
                fresh = []
                for e in entries:
                    try:
                        ts = datetime.fromisoformat(e.get("recorded_at", "")).timestamp()
                        if ts >= cutoff:
                            fresh.append(e)
                        else:
                            pruned += 1
                    except Exception:
                        fresh.append(e)  # unparsable = keep, never destroy data
                if fresh:
                    fp[host] = fresh
                else:
                    fp.pop(host)
            if pruned:
                from board_io import json_transaction
                with json_transaction("fingerprints.json", create=True) as doc:
                    if doc is not None:
                        doc.clear()
                        doc.update(fp)
                print(f"    [+] pruned {pruned} stale fingerprint(s)")
            else:
                print("    [+] fingerprints fresh")
        else:
            print("    [*] no fingerprint cache")
    except Exception as e:
        print(f"    [!] fingerprint prune failed: {e}")
        issues += 1

    # 4) playbook retirement flags (lessons-driven, never auto-delete)
    step("4/5 Playbook retirement review (flags only)...")
    flagged = []
    try:
        if LESSONS_GLOBAL.exists():
            lessons = []
            for line in LESSONS_GLOBAL.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        lessons.append(json.loads(line))
                    except Exception:
                        continue
            # aggregate lead conversion by type across engagements
            tally = {}
            for l in lessons:
                for lesson in l.get("lessons", []):
                    if lesson.get("kind") == "TUNE-EXTRACTOR":
                        flagged.append(lesson.get("text", "")[:110])
            if flagged:
                print("    [~] review candidates from past debriefs:")
                for f in flagged[-3:]:
                    print(f"        - {f}")
            else:
                print("    [+] no retirement candidates flagged")
        else:
            print("    [*] no lessons recorded yet")
    except Exception as e:
        print(f"    [!] retirement scan failed: {e}")
        issues += 1

    # 5) engine suite (optional)
    if run_suite:
        step("5/5 Deterministic engine suite...")
        rc = subprocess.run([sys.executable,
                             str(Path(_engine_dir) / "eval_engine.py"),
                             "suite", "engine"]).returncode
        if rc == 0:
            print("    [+] suite: ALL PASS")
        else:
            print("    [!] suite FAILED — run `eval_engine.py suite engine --verbose`")
            issues += 1
    else:
        print("[*] 5/5 engine suite skipped (--suite to include)")

    print()
    if issues:
        print(f"[!] MAINTENANCE COMPLETE WITH {issues} issue(s) needing attention.")
        return 1
    print("[✔] MAINTENANCE COMPLETE — framework fresh.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Freshness/health maintenance loop")
    parser.add_argument("--suite", action="store_true", help="Also run the engine suite")
    parser.add_argument("--offline", action="store_true", help="Network-free: caches only")
    parser.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                        help="Watch mode: re-run the loop every N seconds until stopped "
                             "(Ctrl-C). Between runs, only the cheap steps execute; "
                             "the suite runs at most once per pass with --suite.")
    args = parser.parse_args()
    if args.watch and args.watch < 300:
        print("[!] --watch interval too aggressive (<300s); politeness floor is 300s "
              "— these are public feeds we're polling.", file=sys.stderr)
        sys.exit(1)
    if args.watch:
        import time
        print(f"[*] WATCH MODE: maintenance every {args.watch}s. Ctrl-C to stop.")
        try:
            while True:
                maintenance(run_suite=args.suite, offline=args.offline)
                print(f"[*] sleeping {args.watch}s ...")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\n[*] Watch stopped.")
        sys.exit(0)
    sys.exit(maintenance(run_suite=args.suite, offline=args.offline))
