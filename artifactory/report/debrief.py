#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Automated Debrief Engine

Post-engagement learning loop, deterministic-first: computes what ACTUALLY
happened (worked-lead ratios, kill-vs-confirm rates, chain utilization, token
efficiency per finding, lead types that converted vs dead-ended, coverage
gaps) from board.json + tokens.jsonl + rationale.jsonl — zero model tokens —
and proposes concrete playbook/agent improvements as a REVIEW CARD.

The card is the human gate: nothing is auto-applied. On approval the operator
routes items to the existing ingestion flow (ingest.py / playbook_engine)
so every learned change remains an approved git diff.

The episodic store (.blackboard/lessons.jsonl, mirrored to a global
~/.artifactory/lessons.jsonl so learnings survive across engagements) is
plain JSONL: inspectable, grep-able, cheap to retrieve from any agent.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
TOKENS_FILE = BLACKBOARD_DIR / "tokens.jsonl"
RATIONALE_FILE = BLACKBOARD_DIR / "rationale.jsonl"
LESSONS_FILE = BLACKBOARD_DIR / "lessons.jsonl"
GLOBAL_LESSONS = Path.home() / ".artifactory" / "lessons.jsonl"
DEADENDS_FILE = Path.home() / ".artifactory" / "deadends.jsonl"


WINS_FILE_PB = Path.home() / ".artifactory" / "playbook_confirm_rates.json"


def record_playbook_rates(confirmed: list, board: dict):
    """Playbook confirm-rate ledger (mirror of payload wins): which playbook
    families produced confirmed findings on which stack classes. `analyze`
    consults the ranking so methodology SELECTION is evidence-driven."""
    try:
        import sec_flow as _sf
        rates = {}
        if WINS_FILE_PB.exists():
            try:
                rates = json.loads(WINS_FILE_PB.read_text())
            except Exception:
                rates = {}
        fp = load_json(BLACKBOARD_DIR / "fingerprints.json") or {}
        stack_bits = []
        for host, entries in fp.items():
            if isinstance(entries, list):
                stack_bits += [str(e.get("tech", "")) for e in entries]
        stack = "|".join(sorted(set(t for t in stack_bits if t))[:6]) or "unknown"
        # Which playbook files were RENDERED during this engagement? We infer
        # from execution-log commands mentioning playbook_engine; fall back to
        # finding-class attribution.
        rendered = set()
        for p in board.get("execution_log_pointers", []):
            cmd = p.get("command") or ""
            if "playbook_engine" in cmd:
                rendered.add(cmd)
        for f in confirmed:
            cls = _sf._finding_class(f.get("title", "") + " " + (f.get("details") or ""))
            key = cls or "unclassified"
            d = rates.setdefault(key, {}).setdefault(stack, {"wins": 0})
            d["wins"] += 1
        WINS_FILE_PB.parent.mkdir(parents=True, exist_ok=True)
        WINS_FILE_PB.write_text(json.dumps(rates, indent=2))
        return rates
    except Exception:
        return {}


def show_playbook_ranking(search=""):
    """Evidence-ranked playbook families: wins per class across stacks. The
    operator/agent consults this when choosing which playbooks to run."""
    if not WINS_FILE_PB.exists():
        print("[*] No playbook confirm-rates recorded yet (they fill from debriefs).")
        return
    try:
        rates = json.loads(WINS_FILE_PB.read_text())
    except Exception:
        print("[!] Corrupt playbook rates file.", file=sys.stderr)
        return
    rows = []
    for cls, stacks in rates.items():
        if search and search.lower() not in cls.lower():
            continue
        wins = sum(s["wins"] for s in stacks.values())
        rows.append((cls, wins, len(stacks)))
    rows.sort(key=lambda r: -r[1])
    if not rows:
        print(f"[*] No playbook families match '{search}'.")
        return
    print(f"[*] Playbook confirm-rate ranking (evidence-based, cross-engagement):\n")
    for cls, wins, nstacks in rows:
        print(f"  {cls:<20} {wins} confirmed finding(s) across {nstacks} stack(s)")


def record_deadends():


    """Negative knowledge: hypotheses that were tested and DIED (status=dead
    leads with a rationale), grouped into a stack-keyed store so future
    engagements consult it BEFORE burning tokens on the same class. Pattern:
    'ssrf on nginx-fronted-node with no egress' shouldn't be re-attempted
    blindly next time. Global file (cross-engagement) + board hint."""
    board = load_json(BOARD_FILE)
    if not board:
        return []
    rationales = _read_jsonl(RATIONALE_FILE)
    dead_leads = [l for l in board.get("leads", []) if l.get("status") == "dead"]
    if not dead_leads:
        return []

    # Group dead leads by (type, signal-family) with their kill reasons.
    families = {}
    for l in dead_leads:
        key = (l.get("type", "?"), (l.get("signal") or "")[:40])
        families.setdefault(key, []).append(l)
    # The workspace fingerprint stack (if any) keys the dead-end record.
    fp = load_json(BLACKBOARD_DIR / "fingerprints.json") or {}
    stack = []
    for host, entries in fp.items():
        if isinstance(entries, list):
            stack += [str(e.get("tech", "")) for e in entries]
    stack_key = "|".join(sorted(set(stack))[:8]) or "unknown-stack"

    records = []
    for (ltype, sig), members in families.items():
        reasons = []
        for l in members:
            # pull matching rationale outcomes where possible
            for r in rationales:
                if r.get("lead_id") == l.get("id") and r.get("outcome"):
                    reasons.append(str(r.get("outcome"))[:80])
        records.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stack": stack_key,
            "lead_type": ltype,
            "signal_family": sig,
            "count": len(members),
            "kill_reasons": reasons[:3],
            "values_sample": [str(m.get("value", ""))[:60] for m in members[:3]],
        })
    DEADENDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DEADENDS_FILE, "a") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return records


def check_deadends(stack_tech: str = "") -> list:
    """Consult the dead-end store: has this technique class already died on
    this stack? Used by analyze before delegating — cheap 'don't re-burn'."""
    records = _read_jsonl(DEADENDS_FILE)
    if not records or not stack_tech:
        return []
    t = stack_tech.lower()
    hits = []
    for r in records:
        stack = (r.get("stack") or "").lower()
        # rough stack overlap: any shared tech token
        if any(tok in t for tok in stack.split("|") if len(tok) > 3):
            hits.append(r)
    return hits


def _read_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _token_totals() -> dict:
    by_role = {}
    total = 0
    for r in _read_jsonl(TOKENS_FILE):
        if r.get("unit") != "tokens":
            continue
        total += r.get("amount", 0)
        by_role[r.get("role", "other")] = by_role.get(r.get("role", "other"), 0) + r.get("amount", 0)
    return {"total": total, "by_role": by_role}


def debrief(label=""):
    board = load_json(BOARD_FILE)
    if not board:
        print("[!] No board.json — nothing to debrief.", file=sys.stderr)
        sys.exit(1)

    findings = board.get("findings", [])
    leads = board.get("leads", [])
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    chains = sum(len(f.get("chain_to", [])) for f in findings)
    tokens = _token_totals()
    rationales = _read_jsonl(RATIONALE_FILE)

    # Lead conversion by type: which discovery signals actually paid off?
    by_type = {}
    for l in leads:
        t = l.get("type", "?")
        d = by_type.setdefault(t, {"total": 0, "confirmed": 0, "dead": 0, "new": 0})
        d["total"] += 1
        st = l.get("status", "new")
        if st == "confirmed":
            d["confirmed"] += 1
        elif st == "dead":
            d["dead"] += 1
        else:
            d["new"] += 1

    untested = [l for l in leads if l.get("status") == "new"]
    per_finding_cost = (tokens["total"] / len(confirmed)) if confirmed else None

    # ------- deterministic lesson extraction (the review card) -------
    card = []

    # 1. High-conversion lead types -> reinforce (these signals are worth trusting)
    good_types = {t: d for t, d in by_type.items()
                  if d["confirmed"] >= 2 and d["confirmed"] / max(d["total"], 1) >= 0.3}
    if good_types:
        card.append(("REINFORCE",
                     f"Lead types that converted well: "
                     + ", ".join(f"{t} ({d['confirmed']}/{d['total']})" for t, d in good_types.items())
                     + " — prioritize these signals next engagement."))

    # 2. Zero-conversion types with volume -> the extractor may be noisy
    noisy_types = {t: d for t, d in by_type.items()
                   if d["total"] >= 5 and d["confirmed"] == 0 and d["dead"] / max(d["total"], 1) > 0.5}
    if noisy_types:
        card.append(("TUNE-EXTRACTOR",
                     f"Lead types that never converted and mostly died: "
                     + ", ".join(f"{t} ({d['dead']}/{d['total']} dead)" for t, d in noisy_types.items())
                     + " — consider tightening the triage extractor or lowering their default confidence."))

    # 3. Coverage honesty: untested leads at close-out
    if untested:
        types = {}
        for l in untested:
            types[l.get("type", "?")] = types.get(l.get("type", "?"), 0) + 1
        card.append(("COVERAGE-GAP",
                     f"{len(untested)} leads left untested at close-out "
                     f"({', '.join(f'{t}:{n}' for t, n in sorted(types.items()))}) — "
                     "carry into the report's coverage section; consider a lighter-weight "
                     "verification path for this class."))

    # 4. Token efficiency
    if per_finding_cost:
        card.append(("METRIC",
                     f"North-star: {len(confirmed)} confirmed / {tokens['total']:.0f} tokens = "
                     f"{len(confirmed)/(tokens['total']/1_000_000):.2f} vulns/1M-tokens; "
                     f"~{per_finding_cost:.0f} tokens per confirmed finding. "
                     + ("Good efficiency." if per_finding_cost < 100_000 else
                        "Expensive — check the token report for which purposes burned budget.")))
    # 4b. Purpose-level burn: the top purpose is where optimization pays first
    purposes = {}
    for r in _read_jsonl(TOKENS_FILE):
        if r.get("unit") != "tokens":
            continue
        p = (r.get("purpose") or "unspecified")[:40]
        purposes[p] = purposes.get(p, 0) + r.get("amount", 0)
    if purposes:
        top_purpose = max(purposes, key=purposes.get)
        share = purposes[top_purpose] / max(tokens["total"], 1)
        if share > 0.5 and tokens["total"] > 20_000:
            card.append(("TOKEN-HOTSPOT",
                         f"'{top_purpose}' consumed {share:.0%} of all tokens "
                         f"({purposes[top_purpose]:.0f}). If it didn't produce findings, "
                         "that step is the optimization target — background it, narrow its "
                         "inputs, or batch it next engagement."))

    # 4c. Command-shape mining: which command FAMILIES preceded confirms?
    # Uses related_pointers on confirmed findings -> execution_log_pointers'
    # command strings -> classified by leading tool/pattern. This is the
    # evidence base for improving technique selection.
    board_data = board
    exec_ptrs = {p.get("pointer_id"): (p.get("command") or "") for p in board_data.get("execution_log_pointers", [])}
    confirm_ptrs = set()
    for f in confirmed:
        confirm_ptrs.update(f.get("related_pointers") or [])
        if f.get("evidence_pointer"):
            confirm_ptrs.add(f["evidence_pointer"])
    shape_hits = {}
    for pid in confirm_ptrs:
        cmd = exec_ptrs.get(pid, "")
        if not cmd:
            continue
        first = cmd.split()[0] if cmd.split() else "?"
        # normalize the binary name only (curl, ffuf, grep via bash -c, ...)
        if first.endswith("bash") or first.endswith("sh"):
            parts = cmd.split()
            first = parts[2] if len(parts) > 2 else first
        shape_hits[first] = shape_hits.get(first, 0) + 1
    if shape_hits:
        ranked = sorted(shape_hits.items(), key=lambda kv: -kv[1])
        card.append(("COMMAND-SHAPES",
                     "Commands that led to confirms: "
                     + ", ".join(f"{t}x{n}" for t, n in ranked[:5])
                     + " — favor these tool families early next engagement; "
                       "never-confirmed families are candidates to background."))

    # 5. Chain utilization
    if confirmed and chains == 0:
        card.append(("CHAIN-LESSON",
                     f"{len(confirmed)} confirmed findings but ZERO chain edges — impact was "
                     "left on the table. Next engagement run `chains --mine` before close-out."))
    elif chains:
        card.append(("CHAIN-LESSON", f"{chains} chain edge(s) recorded — good composition discipline."))

    # 6. Rationale discipline
    if len(rationales) < len(confirmed):
        card.append(("PROCESS",
                     f"Decision journal thinner than findings ({len(rationales)} rationales vs "
                     f"{len(confirmed)} confirmed) — log add-rationale for every verdict so reports "
                     "carry 'How We Got Here'."))

    # 7. Precision
    informational = [f for f in findings if f.get("status") == "informational"]
    if informational and len(informational) > 2 * len(confirmed):
        card.append(("PRECISION",
                     f"{len(informational)} informational vs {len(confirmed)} confirmed — many "
                     "unproven observations. Either test the promising ones or stop filing them."))

    if not card:
        card.append(("NOTHING-TO-LEARN", "Clean engagement; no salient lessons extracted."))

    # ------- output -------
    print("=" * 62)
    print("ENGAGEMENT DEBRIEF (deterministic — zero model tokens)")
    print("=" * 62)
    print(f"  Findings: {len(confirmed)} confirmed / {len(informational)} informational")
    print(f"  Leads:    {len(leads)} total | {len(untested)} untested at close-out")
    print(f"  Chains:  {chains} edge(s)")
    print(f"  Tokens:  {tokens['total']:.0f} "
          f"({', '.join(f'{r}={v:.0f}' for r, v in sorted(tokens['by_role'].items())) or 'unlogged'})")
    print(f"  Rationales: {len(rationales)}\n")
    print("REVIEW CARD (approve items -> route via ingest/playbook flow):")
    for kind, text in card:
        print(f"  [{kind}] {text}")

    # ------- persist to episodic store (local + global mirror) -------
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "label": label or Path.cwd().name,
        "confirmed": len(confirmed),
        "informational": len(informational),
        "leads_total": len(leads),
        "untested": len(untested),
        "chain_edges": chains,
        "tokens_total": tokens["total"],
        "vulns_per_1M": round(len(confirmed) / (tokens["total"] / 1_000_000), 2)
                        if tokens["total"] else None,
        "lessons": [{"kind": k, "text": t} for k, t in card],
    }
    BLACKBOARD_DIR.mkdir(parents=True, exist_ok=True)
    with open(LESSONS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
    GLOBAL_LESSONS.parent.mkdir(parents=True, exist_ok=True)
    with open(GLOBAL_LESSONS, "a") as f:
        f.write(json.dumps(record) + "\n")

    # Negative knowledge: persist what DIED so future engagements consult it
    deadends = record_deadends()
    if deadends:
        print(f"\n[✔] {len(deadends)} dead-end pattern(s) persisted to the negative-knowledge "
              f"store ({DEADENDS_FILE.name}) — future runs consult before re-attempting.")

    # Playbook confirm-rates: technique selection becomes evidence-driven
    rates = record_playbook_rates(confirmed, board)
    if confirmed:
        print(f"[✔] Playbook confirm-rates updated ({WINS_FILE_PB.name}). "
              f"Ranking: debrief.py playbooks")

    # Engagement snapshot for surface-diff at the next engagement
    try:
        import snapshot as _snap
        sp = _snap.take_snapshot(label=f"debrief-{label or Path.cwd().name}"[:40])
        print(f"[✔] Engagement snapshot saved ({sp.name}) — next run: snapshot.py diff")
    except Exception:
        pass

    # Payload-corpus feedback: a confirmed finding means its payload family
    # WORKED on this stack — record the win so `list` ranks by proven results.
    try:
        import payload_corpus
        import sec_flow as _sf
        stack_bits = []
        fp = load_json(BLACKBOARD_DIR / "fingerprints.json") or {}
        for host, entries in fp.items():
            if isinstance(entries, list):
                stack_bits += [str(e.get("tech", "")) for e in entries]
        stack = "|".join(sorted(set(t for t in stack_bits if t))[:6]) or "unknown"
        fed = 0
        for f in confirmed:
            cls = _sf._finding_class(f.get("title", "") + " " + (f.get("details") or ""))
            if cls:
                payload_corpus.note_worked(cls, stack, True)
                fed += 1
        if fed:
            print(f"[✔] Payload corpus updated: {fed} family/stack win(s) recorded on '{stack}'.")
    except Exception:
        pass  # corpus feedback is opportunistic, never blocks the debrief

    print(f"\n[✔] Lesson persisted to {LESSONS_FILE.name} + global {GLOBAL_LESSONS}")
    print("    Retrieve anytime: debrief.py lessons [--search '<term>']")
    return record


def replay(snapshot_label=None):
    """Counterfactual audit: re-derive what TODAY's improved knowledge would
    have done on a PAST board. Loads a snapshot, re-runs the knowledge joins
    (coverage map on its endpoints, dead-end consultation on its findings,
    playbook rates at today's values) and prints the deltas: what we now know
    that would have changed decisions."""
    import snapshot as _snap
    from pathlib import Path as _P
    snap = _snap._load_snapshot(snapshot_label)
    if not snap:
        print("[*] No snapshot to replay (take one at engagement close-out).")
        return
    print("=" * 62)
    print(f"DEBRIEF REPLAY vs snapshot {snap.get('taken_at', '')[:19]}")
    print("=" * 62)

    # 1) would today's knowledge have covered more of that surface?
    try:
        import cross_index as _ci
        gaps = _ci.gaps_only()
        covered = [e for e in snap.get("endpoints", [])
                   if any(g in str(e) for g in gaps)]
        print(f"\n  Endpoints in that engagement: {len(snap.get('endpoints', []))}")
        print(f"  Blind-spot classes today: {len(gaps)}" +
              (f" ({', '.join(gaps)})" if gaps else ""))
    except Exception:
        pass

    # 2) dead-ends learned SINCE that snapshot: those classes would now be
    #    skipped/cheap-checked instead of fully burned
    deadends = _read_jsonl(DEADENDS_FILE)
    since = [d for d in deadends
             if (d.get("timestamp") or "") > (snap.get("taken_at") or "")]
    print(f"  Dead-end patterns learned since: {len(since)}")
    for d in since[:5]:
        print(f"    [{d.get('lead_type')}] on {str(d.get('stack', ''))[:30]}: "
              f"{str(d.get('signal_family', ''))[:50]}")

    # 3) playbook rates for that snapshot's confirmed classes, at TODAY's values
    try:
        rates = json.loads(WINS_FILE_PB.read_text()) if WINS_FILE_PB.exists() else {}
    except Exception:
        rates = {}
    their_classes = set()
    try:
        import sec_flow as _sf
        for f in snap.get("findings", []):
            c = _sf._finding_class((f.get("title") or "") + " " + (f.get("details") or ""))
            if c:
                their_classes.add(c)
    except Exception:
        pass
    print(f"  Classes confirmed back then: {', '.join(sorted(their_classes)) or 'none'}")
    for c in sorted(their_classes):
        if c in rates:
            stacks = rates[c]
            wins = sum(s["wins"] for s in stacks.values())
            print(f"    today's rate for {c}: {wins} win(s) across {len(stacks)} stack(s)")
        else:
            print(f"    today's rate for {c}: still unmeasured")

    # 4) the honest verdict
    if since:
        print("\n  VERDICT: current knowledge WOULD have changed that engagement")
        print(f"  ({len(since)} class(es) would now be auto-cheap-checked or skipped).")
    else:
        print("\n  VERDICT: no post-hoc knowledge deltas recorded for that window yet —")
        print("  this is the tool that proves (or disproves) learning changed behavior.")


def fresh_eyes():
    """On-stall novelty: propose technique permutations from the payload
    corpus x dead-end complement — things NOT yet tried on this stack."""
    import sec_flow as _sf
    board = load_json(BOARD_FILE) or {}
    fp = load_json(BLACKBOARD_DIR / "fingerprints.json") or {}
    stack_bits = []
    for host, entries in fp.items():
        if isinstance(entries, list):
            stack_bits += [str(e.get("tech", "")) for e in entries]
    stack = "|".join(sorted(set(t for t in stack_bits if t))[:6]) or "unknown"

    # dead classes for THIS stack (already tried, already died)
    dead = set()
    for d in _read_jsonl(DEADENDS_FILE):
        if any(tok in stack for tok in (d.get("stack") or "").split("|") if len(tok) > 3):
            dead.add(d.get("lead_type", ""))

    # payload families + their per-stack history
    try:
        import payload_corpus as _pc
        wins = _pc._load_wins()
        fams = []
        if _pc.INDEX_FILE.exists():
            fams = list(json.loads(_pc.INDEX_FILE.read_text()).keys())
    except Exception:
        fams, wins = [], {}

    proposals = []
    for fam in fams:
        if fam in dead:
            continue  # already died on this stack: do not re-burn
        hist = wins.get(fam, {})
        if hist.get(stack):
            continue  # already won here: not novel, just rerun
        proposals.append(fam)

    print("=" * 62)
    print(f"FRESH-EYES PROPOSALS for stack '{stack}'")
    print("=" * 62)
    if not proposals:
        print("\n  [*] No untried payload families for this stack — either exhaustively")
        print("      tested, or the corpus needs new families (payload_corpus.py).")
        return
    print(f"\n  Untried payload families on this stack ({len(proposals)}):")
    for fam in proposals:
        print(f"    - {fam}: payload_corpus.py list --search {fam}")
    print("\n  Also consider PERMUTATIONS of tried-but-unwon families (encoding,")
    print("  context wrappers: JSON vs form vs header placement) — the corpus")
    print("  holds base payloads; permutation is the exploit agent's leverage.")
    print("  Dead families are deliberately excluded (they cost tokens already).")


def show_lessons(search="", limit=10):



    lessons = _read_jsonl(GLOBAL_LESSONS) or _read_jsonl(LESSONS_FILE)
    if search:
        lessons = [l for l in lessons if search.lower() in json.dumps(l).lower()]
    if not lessons:
        print("[*] No lessons recorded yet. Run a debrief after your next engagement.")
        return
    print(f"[*] {len(lessons)} engagement debrief(s)"
          + (f" matching '{search}'" if search else "") + ":\n")
    for l in lessons[-limit:]:
        date = (l.get("timestamp") or "")[:10]
        print(f"  {date} {l.get('label')}: {l.get('confirmed')} confirmed, "
              f"{l.get('untested')} untested, {l.get('chain_edges')} chain edges, "
              f"{l.get('vulns_per_1M')} vulns/1M-tokens")
        for lesson in l.get("lessons", []):
            print(f"      [{lesson.get('kind')}] {lesson.get('text')[:110]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Debrief + Episodic Lessons")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    d = subparsers.add_parser("debrief", help="Compute + persist the engagement debrief")
    d.add_argument("--label", default="")
    subparsers.add_parser("lessons", help="Browse past engagement lessons") \
        .add_argument("--search", default="")
    de = subparsers.add_parser("deadends", help="Browse the negative-knowledge store")
    de.add_argument("--stack", default="", help="Filter by stack tech token")
    pb = subparsers.add_parser("playbooks", help="Evidence-ranked playbook families")
    pb.add_argument("--search", default="")
    rp = subparsers.add_parser("replay", help="Counterfactual: what would today's knowledge have done then?")
    rp.add_argument("--label", default=None)
    subparsers.add_parser("fresh-eyes", help="Untried technique families for this stack (stall-breaker)")
    args = parser.parse_args()
    if args.subcommand == "debrief":
        debrief(args.label)
    elif args.subcommand == "deadends":
        recs = _read_jsonl(DEADENDS_FILE)
        if args.stack:
            recs = [r for r in recs if args.stack.lower() in (r.get("stack") or "").lower()]
        if not recs:
            print("[*] No dead-ends recorded yet (they accumulate as leads get killed).")
        for r in recs[-15:]:
            print(f"  {r.get('stack', '?')[:40]} | {r.get('lead_type')} x{r.get('count')} "
                  f"— {r.get('signal_family', '')[:60]}")
            for reason in r.get("kill_reasons", [])[:2]:
                print(f"      {reason}")
    elif args.subcommand == "playbooks":
        show_playbook_ranking(args.search)
    elif args.subcommand == "replay":
        replay(args.label)
    elif args.subcommand == "fresh-eyes":
        fresh_eyes()
    else:
        show_lessons(args.search)
