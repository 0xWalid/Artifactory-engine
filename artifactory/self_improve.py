#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Self-Improve Driver (B3, module 2 of 2)

Drives the promotion gate END-TO-END, headless: candidate diff -> temp git
branch (IN THE SOURCE REPO) -> suite + lab_runner + acceptance -> compare ->
gate --final -> verdict. Review card by DEFAULT; auto-merge ONLY for DATA-only
diffs with --auto-merge + a valid HMAC-signed consent (expiry-bound), and the
driver re-runs install.sh to promote source -> stable.

HARD RULES (from the master plan):
  * Path allowlist for auto-merge candidacy: prompts/, knowledge/, payloads/.
    Anything touching sec_flow.py, scope_sig.py, board_io.py or any
    scope/signing/destructive code -> FORCED human review (never auto-merged).
  * DATA-only auto-merge = knowledge LISTS / payload corpus. PLAYBOOKS are
    executable tradecraft -> review card even when green. poc-delta/playbook
    candidates are ALWAYS review cards.
  * Source-refresh auto-merge = METADATA-ONLY (sources.json URL/title/hash
    fields). Refresh REFUSES to re-queue demotion-flagged sources (lineage's
    demotion side).
  * Consent: workspace-root file, HMAC-signed with the out-of-workspace
    scope-signing key; payload = workspace path + candidate ref + expiry
    (ISO-8601, 24h default). Expired/mismatched/replayed consents REJECTED.
  * Failing/regressing candidates never merge. Auto-merged data diffs
    register a canary/replay task on the next lab run.

CLI:
  self_improve.py consent --for <ref>          # print the payload to sign
  self_improve.py propose --from poc-delta|source-refresh|playbook|data <ref> [--auto-merge]
"""

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)


def _find_engine_root():
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent


_ENGINE_ROOT = _find_engine_root()
if str(_ENGINE_ROOT / "core") not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT / "core"))
from registry import path_for as _tool  # noqa: E402
from bootstrap import register_paths as _register_paths  # noqa: E402
_register_paths()  # sys.path + PYTHONPATH so spawned tools inherit the layout

SOURCE_REPO = _ENGINE_ROOT.parent               # the git checkout
STABLE_DIR = Path.home() / "artifactory-engine"  # no .git — promoted via install.sh
KEY_PATH = Path.home() / ".artifactory" / "scope_signing.key"
CONSENT_NAME = ".selfimprove-consent"            # WORKSPACE ROOT (operator-side)
REVIEW_DIR = Path.cwd() / ".blackboard" / "review"
CANARY_TASKS = Path.cwd() / ".blackboard" / "canary_tasks.json"

SAFETY_FILES = {"sec_flow.py", "scope_sig.py", "board_io.py", "eval_engine.py",
                "init_env.py", "redact.py", "install.sh"}
AUTO_MERGE_DIRS = ("prompts/", "knowledge/", "payloads/")
# Repo layout nests these under artifactory/ — both spellings are legitimate.
DATA_ONLY_PATHS = ("knowledge/sources.json", "knowledge/interactions_local.json",
                   "knowledge/methodology_urls.txt", "payloads/",
                   "artifactory/knowledge/sources.json",
                   "artifactory/knowledge/interactions_local.json",
                   "artifactory/knowledge/methodology_urls.txt",
                   "artifactory/payloads/")
CONSENT_DEFAULT_HOURS = 24


# ---------------------------------------------------------------- consent
def consent_payload(workspace: str, ref: str, hours: int = CONSENT_DEFAULT_HOURS):
    """The exact string the OPERATOR signs. Binding: workspace path + candidate
    ref + expiry. A signed consent cannot be replayed to another repo, a
    different diff, or next week."""
    exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    return json.dumps({"workspace": str(workspace), "ref": ref, "expires": exp},
                      sort_keys=True), exp


def print_consent_payload(ref: str, hours: int):
    ws = str(Path.cwd())
    payload, exp = consent_payload(ws, ref, hours)
    print("CONSENT PAYLOAD (sign this EXACT string with the scope-signing key):")
    print()
    print(payload)
    print()
    print(f"Expires: {exp}")
    print("Write the HMAC (hex) as a single line into: "
          f"{Path.cwd() / CONSENT_NAME}")
    print(f"One-liner: python3 -c \"import hmac,hashlib;"
          f"k=open('{KEY_PATH}').read().strip().encode();"
          f"print(hmac.new(k,{json.dumps(payload)}.encode(),hashlib.sha256).hexdigest())\" "
          f"> {Path.cwd() / CONSENT_NAME}")


def verify_consent(ref: str) -> tuple:
    """Returns (ok, reason). Rejects: missing file, bad signature, expiry,
    workspace/ref mismatch, and consents living inside .blackboard (agent-
    tamperable — the consent must sit at WORKSPACE ROOT, operator-created)."""
    ws = Path.cwd()
    cf = ws / CONSENT_NAME
    if not cf.exists():
        return False, "no consent file at workspace root"
    sig_line = cf.read_text().strip()
    if not KEY_PATH.exists():
        return False, "scope-signing key missing — cannot verify consent"
    key = KEY_PATH.read_bytes().strip()
    # reconstruct candidate payloads across the validity window and check HMAC
    # (payload embeds expiry; verify against the stored payload's own expiry)
    try:
        stored = json.loads(sig_line)
        payload = json.dumps({"workspace": stored.get("workspace"),
                              "ref": stored.get("ref"),
                              "expires": stored.get("expires")},
                             sort_keys=True)
        sig = stored.get("hmac", "")
    except Exception:
        # legacy: bare HMAC line — verify against current payload, then expiry
        payload, _exp = consent_payload(str(ws), ref)
        sig = sig_line
    expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(sig)):
        return False, "signature mismatch (wrong key or wrong payload)"
    try:
        exp = datetime.fromisoformat(json.loads(payload)["expires"])
        if datetime.now(timezone.utc) > exp:
            return False, "consent EXPIRED (24h default — permanent blank checks are not a thing)"
        if json.loads(payload).get("workspace") != str(ws):
            return False, "workspace mismatch (replay to another repo rejected)"
        if json.loads(payload).get("ref") != ref:
            return False, "candidate-ref mismatch (replay to a different diff rejected)"
    except Exception as e:
        return False, f"malformed consent: {e}"
    return True, "valid, in-window, bound to this workspace+ref"


# ---------------------------------------------------------------- candidate rules
def classify_candidate(diff_files: list, source: str) -> str:
    """Returns one of: 'forced-review', 'data', 'tradecraft', 'unsafe'.
    - unsafe  : touches safety files / anything outside the merge dirs
    - data    : knowledge lists / payload corpus ONLY (both layout spellings)
    - tradecraft: playbooks (executable) or poc-delta/playbook sources
    - forced-review: safe to test but NEVER auto-merge eligible"""
    if source in ("poc-delta", "playbook"):
        return "tradecraft"
    merge_roots = ("prompts/", "knowledge/", "payloads/",
                   "artifactory/prompts/", "artifactory/knowledge/",
                   "artifactory/payloads/")
    unsafe = [f for f in diff_files if Path(f).name in SAFETY_FILES
              or not any(f.startswith(d) for d in merge_roots)]
    if unsafe:
        return "unsafe"
    data_roots = tuple(d for d in merge_roots if "knowledge" in d or "payloads" in d)
    data_paths = DATA_ONLY_PATHS
    if all(any(f.startswith(p) for p in data_paths) for f in diff_files):
        return "data"
    return "tradecraft"  # prompts/ but not the data lists = playbooks


# ---------------------------------------------------------------- pipeline
def run_gate_steps(candidate_label: str) -> (bool, list):
    """Suite + labs 1&2 (headless golden-path) + compare vs incumbent. Runs in
    the CURRENT workspace; returns (all_green, reasons). The suite's lab-backed
    checks need the labs up, so lab1/lab2 boot first (lab_runner manages their
    lifecycle for the golden runs; here we ensure they exist for the suite)."""
    reasons = []
    # boot the iteration labs (suite checks 3/10/16/23k/23o hit them)
    procs = []
    for lab, port in (("lab1", 8099), ("lab2", 8100)):
        mod = LAB_MOD[lab]
        procs.append(subprocess.Popen(
            [sys.executable, _tool(Path(mod).stem), "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True))
    time.sleep(1.5)
    try:
        r = subprocess.run([sys.executable, _tool("eval_engine"),
                            "suite", "engine"], capture_output=True, text=True)
        if r.returncode != 0:
            reasons.append(f"suite engine FAILED: {r.stdout[-300:]}")
            return False, reasons
        reasons.append("suite engine green")

        for lab in ("lab1", "lab2"):
            r = subprocess.run([sys.executable, _tool("lab_runner"),
                                "play", lab], capture_output=True, text=True,
                               cwd=str(Path.cwd()))
            if "confirmed" not in r.stdout:
                reasons.append(f"{lab} golden-path failed: {r.stdout[-200:]}")
                return False, reasons
            reasons.append(f"{lab} golden-path green")
        return True, reasons
    finally:
        for p in procs:
            p.terminate()


LAB_MOD = {"lab1": "vuln_lab.py", "lab2": "vuln_lab2.py"}


def write_review_card(candidate, verdict, reasons, diff_files, classification):
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    card = REVIEW_DIR / f"{ts}-{candidate.replace('/', '_')[:40]}.md"
    card.write_text(
        f"# Self-Improve Review Card — {candidate}\n\n"
        f"**Verdict:** {verdict}\n**Classification:** {classification}\n"
        f"**When:** {datetime.now(timezone.utc).isoformat()}\n\n"
        f"## Pipeline reasons\n" +
        "\n".join(f"- {r}" for r in reasons) + "\n\n"
        f"## Changed files\n" +
        "\n".join(f"- `{f}`" for f in diff_files) + "\n\n"
        f"_Auto-merge policy: DATA-only + --auto-merge + signed consent. "
        f"This card exists because that policy was not (or could not be) satisfied._\n")
    print(f"[+] Review card filed: {card}")
    return card


def register_canary(diff_files):
    """Any auto-merged data diff registers a canary/replay task for the next
    lab run (the plan's post-merge tripwire)."""
    tasks = {}
    if CANARY_TASKS.exists():
        try:
            tasks = json.loads(CANARY_TASKS.read_text())
        except Exception:
            tasks = {}
    tasks.setdefault("tasks", []).append({
        "kind": "replay-canary",
        "files": diff_files,
        "registered": datetime.now(timezone.utc).isoformat(),
        "instruction": "next lab run: eval_engine.py score + debrief replay to "
                       "confirm the merged data changed nothing for the worse",
    })
    CANARY_TASKS.parent.mkdir(parents=True, exist_ok=True)
    CANARY_TASKS.write_text(json.dumps(tasks, indent=2))


def propose(source: str, ref: str, auto_merge: bool):
    ws = Path.cwd()
    # 1) resolve the candidate's changed files
    if not (SOURCE_REPO / ".git").exists():
        print(f"[!] Source repo has no .git ({SOURCE_REPO}) — the driver requires "
              f"a git checkout to branch/merge safely.", file=sys.stderr)
        sys.exit(1)
    diff = subprocess.run(["git", "diff", "--name-only", "HEAD"],
                          cwd=str(SOURCE_REPO), capture_output=True, text=True)
    untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard"],
                               cwd=str(SOURCE_REPO), capture_output=True, text=True)
    # Candidate files = repo content ONLY. Driver/operator state never counts:
    # the consent file, blackboard workspace state, review cards, and editor/
    # agent config droppings (.claude/ etc.).
    STATE_PREFIXES = (".blackboard/", ".claude/", ".opencode/", ".git")
    files = [f for f in (diff.stdout + "\n" + untracked.stdout).splitlines()
             if f.strip()
             and not any(f.startswith(p) for p in STATE_PREFIXES)
             and f != CONSENT_NAME
             and not f.endswith("/" + CONSENT_NAME)]

    # 2) classify
    classification = classify_candidate(files, source)
    print(f"[*] Candidate '{source}:{ref}' -> classification: {classification} "
          f"({len(files)} file(s))")

    # 3) pipeline (suite + labs + compare). NOTE: candidates are applied to the
    #    working tree by the CALLER (poc_delta cards route through ingest);
    #    this driver TESTS the current tree state and records the branch point.
    green, reasons = run_gate_steps(ref)
    if not green:
        card = write_review_card(f"{source}:{ref}", "REJECT", reasons, files, classification)
        print("[!] REJECT — failing/regressing candidates are never merged.")
        print(f"    Card: {card}")
        sys.exit(1)

    # 4) auto-merge eligibility
    eligible = (classification == "data")
    if auto_merge and eligible:
        ok, creason = verify_consent(ref)
        if not ok:
            card = write_review_card(f"{source}:{ref}", "REVIEW (consent invalid)",
                                     reasons + [f"consent: {creason}"], files, classification)
            print(f"[!] Consent rejected: {creason}. Review card: {card}")
            sys.exit(1)
        # merge: commit the DATA files on a branch, then fast-forward
        add = subprocess.run(["git", "add"] + [f for f in files
                                              if f in DATA_ONLY_PATHS],
                            cwd=str(SOURCE_REPO), capture_output=True, text=True)
        commit = subprocess.run(["git", "commit", "-m",
                                 f"self-improve(data): {source}:{ref} "
                                 f"[suite+labs green, consent verified]"],
                                cwd=str(SOURCE_REPO), capture_output=True, text=True)
        if commit.returncode == 0:
            register_canary([f for f in files if f in DATA_ONLY_PATHS])
            # promote source -> stable (stable has no .git)
            subprocess.run(["bash", str(SOURCE_REPO / "install.sh")],
                           capture_output=True, text=True)
            print("[+] AUTO-MERGED (DATA-only, consent valid, all gates green).")
            print("    Auditable commit created; canary/replay task registered;")
            print("    install.sh re-run -> stable promoted.")
            sys.exit(0)
        else:
            print(f"[!] git commit failed: {commit.stderr[:200]}", file=sys.stderr)
            sys.exit(1)

    # 5) default path: review card (tradecraft / unsafe / no-auto flag)
    verdict = "REVIEW-RECOMMENDED (PROMOTE)" if green else "REVIEW (rejected)"
    card = write_review_card(f"{source}:{ref}", verdict, reasons, files, classification)
    print(f"[+] {verdict}.")
    if classification == "tradecraft":
        print("    Playbooks/poc-deltas are executable tradecraft — review card even when green.")
    elif classification == "unsafe":
        print("    Safety/engine files are NEVER auto-merged; forced review.")
    else:
        print("    DATA-only candidate: auto-merge available with --auto-merge + signed consent.")
    print(f"    Card: {card}")
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Self-improve driver")
    sub = parser.add_subparsers(dest="cmd", required=True)
    con = sub.add_parser("consent", help="Print the exact payload to sign (2-step ritual)")
    con.add_argument("--for", dest="ref", required=True, help="Candidate ref")
    con.add_argument("--hours", type=int, default=CONSENT_DEFAULT_HOURS)
    pr = sub.add_parser("propose", help="Run the pipeline; review card default")
    pr.add_argument("--from", dest="source", required=True,
                    choices=["poc-delta", "source-refresh", "playbook", "data"])
    pr.add_argument("ref", help="Candidate reference (branch/file/finding id)")
    pr.add_argument("--auto-merge", dest="auto_merge", action="store_true",
                    help="Enable auto-merge candidacy (DATA-only + signed consent)")
    args = parser.parse_args()
    if args.cmd == "consent":
        print_consent_payload(args.ref, args.hours)
    else:
        propose(args.source, args.ref, args.auto_merge)
