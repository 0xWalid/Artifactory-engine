#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Source Lineage & Earned Reliability

Sources earn trust the way code earns it: by outcome. This module makes the
chain `source -> playbook -> leads -> confirms/deaths` walkable and computes
per-source x per-class reliability from data debrief already collects.

  * `chain <source-id>`    — walk one source's full lineage
  * `reliability`         — the earned-tier table: every source x class with
                             confirms/losses, ranked; demotions flagged for
                             review; promotions suggested (tier is EARNED)
  * `apply`               — operator-approved: writes earned tiers back into
                             sources.json (nothing mutates without this step)
  * `record`              — called by debrief: attach outcome tallies to the
                             global ledger (~/.artifactory/source_lineage.json)

Playbook lineage is recorded at synthesis time by playbook_engine (source id
embedded in the saved file's header), so the chain is deterministic.
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
from board_io import load_json, blackboard_dir  # noqa: E402
import playbook_engine as pe  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
LEDGER = Path.home() / ".artifactory" / "source_lineage.json"

TIER_ORDER = {"primary": 3, "advisory": 2, "report": 2, "guide": 1}


def _load_ledger() -> dict:
    if LEDGER.exists():
        try:
            return json.loads(LEDGER.read_text())
        except Exception:
            return {}
    return {}


def _save_ledger(led: dict):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(json.dumps(led, indent=1))


def playbook_source_id(pb_path: Path) -> str:
    """Extract the source id a playbook was synthesized from (the header
    records 'Practitioner / Methodology: <author>' and registry saves use the
    source id as name — resolve via sources.json by matching the name)."""
    name = pb_path.stem
    for s in pe.load_sources():
        if (s.get("id") or s.get("title")) == name:
            return s.get("id") or name
    return ""


def _class_playbooks(cls: str) -> list:
    """Playbooks plausibly covering a finding class: name-token overlap.
    'traversal' matches 'path_traversal'; 'access-control' matches
    'role_diff'-adjacent names via keyword pairs below."""
    if not cls:
        return []
    SYNONYMS = {
        "traversal": ["path", "traversal", "lfi"],
        "access-control": ["role", "bac", "access", "auth"],
        "idor": ["idor", "role_diff", "object"],
        "injection": ["sqli", "xss", "command", "ssti", "injection"],
        "ssrf": ["ssrf"],
        "leak": ["secret", "entropy"],
        "redirect": ["redirect"],
        "mass-assignment": ["role", "assignment", "mass"],
        "deserialization": ["deser", "pickle"],
        "auth-bypass": ["auth", "jwt", "role"],
    }
    kws = set(SYNONYMS.get(cls, [cls.replace("-", "_")]))
    hits = []
    for pb in pe.PROMPTS_DIR.glob("*/*.md"):
        toks = set(re.split(r"[-_]", pb.stem))
        if toks & kws:
            hits.append(pb)
    return hits


def record_outcomes(board: dict):
    """Debrief hook: attribute confirmed findings (and dead leads) to the
    playbooks covering their class, and up to the SOURCE when the playbook
    was synthesized from one (registry name match). Hand-authored playbooks
    accrue local class stats; source lineage fills only for synthesized ones.
    Ledger shape: {source_or_playbook: {class: {wins, losses}}}."""
    try:
        import sec_flow as _sf
    except Exception:
        return {}
    led = _load_ledger()
    findings = board.get("findings", [])
    sources = {s.get("id") or s.get("title"): s for s in pe.load_sources()}

    for f in findings:
        if f.get("status") != "confirmed":
            continue
        cls = _sf._finding_class(f.get("title", "") + " " + (f.get("details") or ""))
        if not cls:
            continue
        pbs = _class_playbooks(cls)
        if not pbs:
            continue  # no methodology owns this class: that's the coverage gap's job to show
        for pb in pbs[:1]:  # attribute to the first (deterministic) owner
            # source if the playbook came from one; else the playbook itself
            sid = playbook_source_id(pb) or pb.stem
            d = led.setdefault(sid, {}).setdefault(cls, {"wins": 0, "losses": 0})
            d["wins"] += 1

    # LOSS side: dead leads whose class maps to an owning playbook = the
    # playbook was RENDERED but produced nothing -> the loss ledger.
    for l in board.get("leads", []):
        if l.get("status") != "dead":
            continue
        cls = _sf._finding_class(str(l.get("value", "")) + " " + str(l.get("signal", "")))
        if not cls:
            continue
        pbs = _class_playbooks(cls)
        for pb in pbs[:1]:
            sid = playbook_source_id(pb) or pb.stem
            d = led.setdefault(sid, {}).setdefault(cls, {"wins": 0, "losses": 0})
            d["losses"] += 1
    _save_ledger(led)
    return led


def walk_chain(source_id: str):
    """Render one source's full lineage: playbooks synthesized from it, the
    classes they cover, and the outcome tallies from the ledger."""
    sources = {s.get("id") or s.get("title"): s for s in pe.load_sources()}
    src = sources.get(source_id)
    if not src:
        print(f"[!] No source '{source_id}' in the registry.", file=sys.stderr)
        sys.exit(1)
    led = _load_ledger()

    print(f"[*] LINEAGE: {source_id}")
    print(f"    url: {src.get('url', '')}")
    print(f"    tier (current): {pe.infer_tier(src)}")
    built = pe.source_is_built(src)
    print(f"    playbook: {'BUILT' if built else 'not built'} "
          f"({pe.playbook_path_for_source(src).relative_to(pe.PROMPTS_DIR.parent)})")
    outcomes = led.get(source_id, {})
    if outcomes:
        print(f"    field outcomes:")
        for cls, d in sorted(outcomes.items(), key=lambda kv: -(kv[1]['wins'] + kv[1]['losses'])):
            print(f"      {cls:<20} wins={d['wins']} losses={d['losses']}")
    else:
        print("    field outcomes: none recorded yet")
    if built and not outcomes:
        print("    [~] built but unmeasured — it has run without outcome attribution")
    return src, outcomes


def reliability():
    """The earned-tier table: sources ranked by field evidence, not metadata."""
    sources = pe.load_sources()
    led = _load_ledger()
    rows = []
    for s in sources:
        sid = s.get("id") or s.get("title")
        outcomes = led.get(sid, {})
        wins = sum(d["wins"] for d in outcomes.values())
        losses = sum(d["losses"] for d in outcomes.values())
        current = pe.infer_tier(s)
        # earned-tier proposal logic
        if wins >= 2 and losses == 0:
            earned = "primary"
        elif wins >= 1:
            earned = "advisory"
        elif losses >= 3 and wins == 0:
            earned = "demote-review"
        elif outcomes:
            earned = current  # mixed: keep, no promotion
        else:
            earned = "-"     # unmeasured
        rows.append((sid, current, earned, wins, losses, len(outcomes)))
    rows.sort(key=lambda r: (-r[3], r[1]))

    print(f"[*] SOURCE RELIABILITY (earned from field outcomes):\n")
    print(f"  {'source':<28} {'tier':>9} {'earned':>13} {'wins':>5} {'loss':>5} {'classes':>7}")
    print("  " + "-" * 72)
    demotions = []
    for sid, current, earned, wins, losses, ncls in rows:
        flag = ""
        if earned == "demote-review":
            flag = "  <-- DEMOTION CANDIDATE (losses, no wins)"
            demotions.append(sid)
        print(f"  {sid[:28]:<28} {current:>9} {earned:>13} {wins:>5} {losses:>5} {ncls:>7}{flag}")
    unmeasured = sum(1 for r in rows if r[2] == "-")
    print(f"\n  {unmeasured} unmeasured source(s) (built playbooks without outcome "
          f"attribution — run engagements + debrief to measure).")
    if demotions:
        print(f"\n  [!] Demotion candidates need operator review before any tier change:")
        for d in demotions:
            print(f"      - {d}")
    print("\n  Apply earned tiers (operator-approved) with: lineage.py apply")
    return demotions


def apply_earned():
    """Write earned tiers into sources.json — the only mutation path, and it
    requires this explicit operator command (never automatic)."""
    sources = pe.load_sources()
    led = _load_ledger()
    changed = 0
    for s in sources:
        sid = s.get("id") or s.get("title")
        outcomes = led.get(sid, {})
        if not outcomes:
            continue
        wins = sum(d["wins"] for d in outcomes.values())
        losses = sum(d["losses"] for d in outcomes.values())
        if wins >= 2 and losses == 0 and pe.infer_tier(s) != "primary":
            s["tier"] = "primary"
            s["tier_earned"] = f"{wins} confirm(s), 0 losses"
            changed += 1
        elif wins >= 1 and pe.infer_tier(s) not in ("primary", "advisory"):
            s["tier"] = "advisory"
            s["tier_earned"] = f"{wins} confirm(s)"
            changed += 1
        # demotions are flagged for review, never auto-applied
    if changed:
        pe.save_sources(sources)
        print(f"[OK] {changed} source tier(s) updated to earned values "
              f"(demotions remain review-only).")
    else:
        print("[*] No tier changes earned yet (or already applied).")


def divergence(playbook: str):
    """Step-level failure correlation: for a losing playbook (losses >= wins),
    correlate each dead lead's kill reason (rationale outcome / signal text)
    against the playbook's SECTION headings to pinpoint WHERE the methodology
    diverges from reality. Output = the divergence report card."""
    if "/" not in playbook:
        print("[!] Playbook must be <category>/<name>.", file=sys.stderr)
        sys.exit(1)
    category, name = playbook.split("/", 1)
    pb_path = pe.get_playbook_path(category, name)
    if not pb_path.exists():
        print(f"[!] Playbook '{playbook}' not found.", file=sys.stderr)
        sys.exit(1)
    led = _load_ledger()
    sid = playbook_source_id(pb_path) or pb_path.stem
    outcomes = led.get(sid, {})
    wins = sum(d["wins"] for d in outcomes.values())
    losses = sum(d["losses"] for d in outcomes.values())

    print("=" * 62)
    print(f"STEP-LEVEL DIVERGENCE: {playbook}  (wins={wins} losses={losses})")
    print("=" * 62)
    if losses == 0:
        print("  [*] No losses recorded — nothing to correlate (either healthy or unmeasured).")
        return

    # collect dead-lead reasons from the current board for this playbook's classes
    try:
        import sec_flow as _sf
    except Exception:
        return
    board = load_json(BOARD_FILE) or {}
    rationales = []
    rat_file = BLACKBOARD_DIR / "rationale.jsonl"
    if rat_file.exists():
        for line in rat_file.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    rationales.append(json.loads(line))
                except Exception:
                    pass

    sections = re.findall(r"^##\s+(.+)$", pb_path.read_text(), re.M)
    reasons = []
    for l in board.get("leads", []):
        if l.get("status") != "dead":
            continue
        cls = _sf._finding_class(str(l.get("value", "")) + " " + str(l.get("signal", "")))
        if not cls or not _class_playbooks(cls):
            continue
        if (pb_path.stem not in [p.stem for p in _class_playbooks(cls)]):
            continue
        reason = str(l.get("signal", ""))[:80]
        # enrich with rationale outcome if the lead id matches
        for r in rationales:
            if r.get("lead_id") == l.get("id") and r.get("outcome"):
                reason = f"{r.get('outcome')} | {reason}"
                break
        reasons.append(reason)

    if not reasons:
        print("  [*] Losses recorded in the ledger but no dead-lead reasons on THIS")
        print("      board (cross-engagement losses; replay the past workspace for detail).")
        return
    print(f"\n  Dead-lead reasons under this playbook's classes ({len(reasons)}):")
    for r in reasons[:12]:
        print(f"    - {r}")
    print(f"\n  Playbook sections (where the divergence likely lives):")
    for s in sections:
        print(f"    # {s}")
    print("\n  DIVERGENCE CARD: group the reasons above against the section whose step")
    print("  produced them; the section with the most kill-reasons is where the")
    print("  methodology diverges from reality. Patch THAT section (not the whole")
    print("  playbook), re-run acceptance, then re-gate.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Source lineage & earned reliability")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("chain", help="Walk one source's lineage (playbooks + outcomes)")
    c.add_argument("source_id")
    sub.add_parser("reliability", help="Earned-tier table (ranked, demotions flagged)")
    sub.add_parser("record", help="Record board outcomes into the ledger (debrief hook)")
    sub.add_parser("apply", help="Operator-approved: apply earned tier promotions")
    d = sub.add_parser("divergence", help="Step-level failure correlation for a losing playbook")
    d.add_argument("playbook", help="<category>/<name>")
    args = parser.parse_args()
    if args.cmd == "chain":
        walk_chain(args.source_id)
    elif args.cmd == "reliability":
        reliability()
    elif args.cmd == "record":
        board = load_json(BOARD_FILE) or {}
        led = record_outcomes(board)
        print(f"[OK] Outcomes recorded for {len(led)} source(s).")
    elif args.cmd == "divergence":
        divergence(args.playbook)
    else:
        apply_earned()

