#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - PoC Delta Miner

When a PoC WORKS but the playbook's steps didn't produce it, mechanically diff
the working evidence-chain (the commands that actually ran for the confirmed
finding) against the playbook's diagnostic step set, and propose the MISSING
steps as a playbook-patch card — routed through the existing ingest approval
flow, never auto-applied.

  * `mine --finding <FINDING_ID> --playbook <category>/<name>`
      finding's related_pointers + evidence_pointer -> the actual command set
      playbook text -> the declared command set (curl/httpx/ffuf lines)
      delta = actually-ran commands with no playbook counterpart
      -> PATCH CARD (missing steps + why they mattered + save instructions)

Deterministic diffing; zero model tokens. The LLM operator reviews the card.
"""

import argparse
import json
import re
import sys
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import load_json, blackboard_dir  # noqa: E402
import playbook_engine as pe  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"


def _cmd_signature(cmd: str) -> tuple:
    """Normalize a command to a comparable signature: (tool, url-path,
    key-flags). Exact flags/whitespace differences shouldn't hide a match."""
    if not cmd:
        return ("", "", "")
    parts = cmd.split()
    tool = parts[0].split("/")[-1]
    # unwrap bash -c 'pipeline'
    if tool in ("bash", "sh") and len(parts) > 2:
        parts = parts[2:]
        tool = parts[0].split("/")[-1] if parts else "bash"
    url = ""
    for p in parts:
        if p.startswith(("http://", "https://")):
            url = re.sub(r"https?://[^/\s]+", "", p)  # strip scheme+host
            break
    flags = tuple(sorted({p for p in parts if p.startswith("-")}))
    return (tool, url.split("?")[0], flags)


def _playbook_commands(pb_text: str) -> list:
    """Extract runnable diagnostic commands from playbook markdown."""
    cmds = []
    in_code = False
    for line in pb_text.splitlines():
        s = line.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if not in_code:
            continue
        # command lines in code blocks
        if re.match(r"^(curl|httpx|ffuf|nmap|python3|grep)\b", s) or \
           s.startswith("python3 " + "~/artifactory"):
            cmds.append(s)
    return cmds


def mine(finding_id: str, playbook: str):
    board = load_json(BOARD_FILE) or {}
    finding = next((f for f in board.get("findings", [])
                    if f.get("id") == finding_id), None)
    if not finding:
        print(f"[!] Finding '{finding_id}' not found on the board.", file=sys.stderr)
        sys.exit(1)
    if "/" not in playbook:
        print("[!] --playbook must be <category>/<name>.", file=sys.stderr)
        sys.exit(1)
    category, name = playbook.split("/", 1)
    pb_path = pe.get_playbook_path(category, name)
    if not pb_path.exists():
        print(f"[!] Playbook '{playbook}' not found ({pb_path}).", file=sys.stderr)
        sys.exit(1)
    pb_text = pb_path.read_text()

    # 1) what actually ran for this finding
    exec_ptrs = {p.get("pointer_id"): p.get("command") or ""
                 for p in board.get("execution_log_pointers", [])}
    actual_cmds = []
    seen_pids = set()
    for pid in (finding.get("related_pointers") or []):
        c = exec_ptrs.get(pid)
        if c and pid not in seen_pids:
            seen_pids.add(pid)
            actual_cmds.append((pid, c))
    if finding.get("evidence_pointer") and finding["evidence_pointer"] not in seen_pids:
        c = exec_ptrs.get(finding["evidence_pointer"])
        if c:
            actual_cmds.append((finding["evidence_pointer"], c))

    # 2) what the playbook declares
    declared = _playbook_commands(pb_text)
    declared_sigs = {_cmd_signature(c) for c in declared}

    # 3) the delta: actual commands with no declared counterpart
    missing = []
    for pid, cmd in actual_cmds:
        sig = _cmd_signature(cmd)
        if sig in declared_sigs:
            continue
        # fuzzy: same tool+url even if flags differ = covered
        covered = any(d[0] == sig[0] and d[1] == sig[1] for d in declared_sigs)
        if not covered and sig[0] not in ("",):
            missing.append((pid, cmd))

    print("=" * 64)
    print("POC DELTA MINER — methodology patch card")
    print("=" * 64)
    print(f"  Finding:   {finding.get('title', '')[:70]}")
    print(f"  Playbook:  {playbook}")
    print(f"  Actually ran: {len(actual_cmds)} command(s); playbook declares "
          f"{len(declared)}; delta: {len(missing)}\n")

    if not missing:
        print("  [*] No delta — the working evidence chain is already covered by")
        print("      the playbook's steps. (Either the playbook is accurate, or the")
        print("      finding came from a lead the playbook doesn't own.)")
        return

    print("  MISSING STEPS (ran in reality, absent from the methodology):")
    for pid, cmd in missing:
        print(f"    [{pid}] {cmd[:110]}")
    print()
    print("  WHY IT MATTERS: these commands produced the evidence behind a CONFIRMED")
    print("  finding; a reader following only the playbook would not run them and")
    print("  would MISS this bug class instance.")
    print()
    print("  PROPOSED PATCH (review, then save via the ingest flow — never auto-applied):")
    print("    1. Add the missing steps to the playbook's '## Diagnostic Checks' section.")
    print("    2. Note the discovery context (what lead/role-diff row produced them).")
    print("    3. Re-run: eval_engine.py acceptance --category " + category +
          " --name " + name)
    print("    4. On ACCEPTED, save via: playbook_engine.py --category " + category +
          " --name " + name + " --author '<you>' --save-content '<updated markdown>'")
    print()
    print("  The card ends here — the operator decides. (Human gate, as always.)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC delta miner (playbook patch cards)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mine", help="Diff a confirmed finding's evidence chain vs its playbook")
    m.add_argument("--finding", required=True, help="FINDING_ id")
    m.add_argument("--playbook", required=True, help="<category>/<name>")
    args = parser.parse_args()
    mine(args.finding, args.playbook)
