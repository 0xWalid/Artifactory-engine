#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Security Flow Execution Engine
Handles safe non-shell execution, CIDR scope validation, artifact logging,
JSON-aware inspection, and state asset recording.
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Shared, lock-serialised blackboard I/O (prevents parallel-agent write races).
_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction  # noqa: E402

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
HISTORY_FILE = BLACKBOARD_DIR / "history.log"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
CANARY_FILE = BLACKBOARD_DIR / "canaries.json"
RATIONALE_FILE = BLACKBOARD_DIR / "rationale.jsonl"

# Finding severity/status vocabularies (WS1: verification gate).
SEVERITIES = ["info", "low", "medium", "high", "critical"]
FINDING_STATUSES = ["informational", "confirmed"]

# Wall-clock ceiling for any single diagnostic command so a hung tool cannot
# stall the engine indefinitely.
COMMAND_TIMEOUT = 300


def ensure_blackboard_dirs():
    BLACKBOARD_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    if not HISTORY_FILE.exists():
        HISTORY_FILE.touch()


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def is_target_in_scope(target: str, scope: dict) -> bool:
    # Fail-closed: an empty/missing scope grants nothing. Callers must ensure a
    # populated scope.json (via init_env.py) before any command is permitted.
    if not scope:
        return False

    allowed_hosts = scope.get("allowed_hosts", [])
    allowed_domains = scope.get("allowed_domains", [])
    allowed_cidrs = scope.get("allowed_cidrs", [])

    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Host & Domain checks
    if clean_target in allowed_hosts:
        return True

    for domain in allowed_domains:
        domain_clean = domain.replace("*.", "")
        if clean_target == domain_clean or clean_target.endswith("." + domain_clean):
            return True

    # IP & CIDR Subnet checks
    try:
        resolved_ip_str = socket.gethostbyname(clean_target)
        if resolved_ip_str in allowed_hosts:
            return True

        resolved_ip = ipaddress.ip_address(resolved_ip_str)
        for cidr in allowed_cidrs:
            if resolved_ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except (socket.gaierror, ValueError):
        pass

    return False


def clean_host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def matches_authorized_domain(host: str, scope: dict) -> bool:
    """True if host falls under an authorized apex/wildcard in allowed_domains."""
    for domain in scope.get("allowed_domains", []):
        domain_clean = domain.replace("*.", "")
        if host == domain_clean or host.endswith("." + domain_clean):
            return True
    return False


def classify_and_expand_scope(host: str) -> str:
    """WS2: decide how a newly-discovered host enters scope.

    - Already in scope (host/cidr/domain) or under an authorized wildcard ->
      materialise it in `allowed_hosts` and mark 'authorized'.
    - Otherwise -> queue in `pending_scope` for explicit operator approval.
    Never silently authorises a host that is not under an approved domain.
    Returns one of: 'authorized' | 'pending' | 'noop'.
    """
    host = clean_host(host)
    if not host:
        return "noop"

    outcome = "noop"
    with json_transaction("scope.json", create=True) as scope:
        allowed_hosts = scope.setdefault("allowed_hosts", [])
        pending = scope.setdefault("pending_scope", [])

        if matches_authorized_domain(host, scope):
            if host not in allowed_hosts:
                allowed_hosts.append(host)
            if host in pending:
                pending.remove(host)
            outcome = "authorized"
        elif host in allowed_hosts:
            outcome = "authorized"
        else:
            if host not in pending:
                pending.append(host)
            outcome = "pending"
    return outcome


def manage_scope(add_host=None, add_domain=None, add_cidr=None, approve=None, do_list=False):
    """WS2: operator-facing scope editing + per-project visibility."""
    if not SCOPE_FILE.exists():
        print(f"[!] Error: {SCOPE_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    if do_list and not any([add_host, add_domain, add_cidr, approve]):
        scope = load_json(SCOPE_FILE)
        print("[*] Current scope:")
        print(f"    allowed_hosts:   {scope.get('allowed_hosts', [])}")
        print(f"    allowed_domains: {scope.get('allowed_domains', [])}")
        print(f"    allowed_cidrs:   {scope.get('allowed_cidrs', [])}")
        print(f"    pending_scope:   {scope.get('pending_scope', [])}  (awaiting --approve)")
        return

    with json_transaction("scope.json", create=True) as scope:
        allowed_hosts = scope.setdefault("allowed_hosts", [])
        allowed_domains = scope.setdefault("allowed_domains", [])
        allowed_cidrs = scope.setdefault("allowed_cidrs", [])
        pending = scope.setdefault("pending_scope", [])

        if add_host and add_host not in allowed_hosts:
            allowed_hosts.append(add_host)
            print(f"[✔] Added host to scope: {add_host}")
        if add_domain and add_domain not in allowed_domains:
            allowed_domains.append(add_domain)
            print(f"[✔] Added domain to scope: {add_domain}")
        if add_cidr and add_cidr not in allowed_cidrs:
            allowed_cidrs.append(add_cidr)
            print(f"[✔] Added CIDR to scope: {add_cidr}")
        if approve:
            host = clean_host(approve)
            if host in pending:
                pending.remove(host)
            if host not in allowed_hosts:
                allowed_hosts.append(host)
            print(f"[✔] Approved into scope: {host}")


def update_board_state(pointer_id: str, cmd: str, returncode: int, summary: str = ""):
    if not BOARD_FILE.exists():
        return

    try:
        with json_transaction("board.json") as board_data:
            if board_data is None:
                return
            pointer_entry = {
                "pointer_id": pointer_id,
                "command": cmd,
                "return_code": returncode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
            }
            board_data.setdefault("execution_log_pointers", []).append(pointer_entry)
    except Exception as e:
        print(f"[!] Warning: Could not update board.json: {e}", file=sys.stderr)


def trigger_report_generation():
    """Invokes the local report engine to (re)build per-finding advisories.

    Imported lazily from the engine directory so recording assets never hard-
    depends on the reporter being importable; failures degrade gracefully.
    """
    try:
        engine_dir = str(Path(__file__).resolve().parent)
        if engine_dir not in sys.path:
            sys.path.insert(0, engine_dir)
        import report_engine
        report_engine.generate_individual_reports()
    except Exception as e:
        print(f"[!] Warning: auto-report generation failed: {e}", file=sys.stderr)


def trigger_triage(pointer_id: str):
    """Runs the background triage/Scout pass on a completed artifact.

    Extracts ranked leads into board.json so the operator consumes a short
    lead list instead of raw output. Lazily imported; failures degrade quietly.
    """
    try:
        engine_dir = str(Path(__file__).resolve().parent)
        if engine_dir not in sys.path:
            sys.path.insert(0, engine_dir)
        import triage
        triage.triage_pointer(pointer_id)
    except Exception as e:
        print(f"[!] Warning: triage pass failed: {e}", file=sys.stderr)


def _resolve_evidence(poc: str, evidence_from):
    """Returns (evidence_text, evidence_pointer, has_evidence)."""
    evidence_text = poc or ""
    evidence_pointer = None
    if evidence_from:
        art = ARTIFACTS_DIR / f"{evidence_from}.log"
        if art.exists():
            evidence_pointer = evidence_from
        else:
            print(f"[!] Warning: evidence pointer '{evidence_from}' has no artifact "
                  f"log; ignoring it.", file=sys.stderr)
    has_evidence = bool(evidence_text) or bool(evidence_pointer)
    return evidence_text, evidence_pointer, has_evidence


def add_asset_to_board(host: str = None, endpoint: str = None, port: str = None,
                       finding: str = None, details: str = "", severity: str = "info",
                       status: str = "informational", poc: str = "", evidence_from=None):
    if not BOARD_FILE.exists():
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    # Verification gate (WS1): a finding may only be 'confirmed' when it carries
    # evidence (an inline PoC or a real execution-pointer artifact). Otherwise it
    # is downgraded to 'informational' so unverified observations never masquerade
    # as confirmed vulnerabilities.
    evidence_text, evidence_pointer, has_evidence = ("", None, False)
    if finding:
        if severity not in SEVERITIES:
            severity = "info"
        if status not in FINDING_STATUSES:
            status = "informational"
        evidence_text, evidence_pointer, has_evidence = _resolve_evidence(poc, evidence_from)
        if status == "confirmed" and not has_evidence:
            status = "informational"
            print("[!] VERIFICATION GATE: no PoC/evidence supplied — filed as "
                  "'informational', NOT 'confirmed'. Run the proving command, then "
                  "log with --poc \"<payload/request+response>\" or "
                  "--evidence-from <POINTER_ID>.", file=sys.stderr)

    try:
        added = []
        with json_transaction("board.json") as board_data:
            if board_data is None:
                print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
                sys.exit(1)

            assets = board_data.setdefault("discovered_assets", {"hosts": [], "endpoints": [], "open_ports": []})
            findings_list = board_data.setdefault("findings", [])

            if host and host not in assets.setdefault("hosts", []):
                assets["hosts"].append(host)
                added.append(f"Host: {host}")

            if endpoint and endpoint not in assets.setdefault("endpoints", []):
                assets["endpoints"].append(endpoint)
                added.append(f"Endpoint: {endpoint}")

            if port and port not in assets.setdefault("open_ports", []):
                assets["open_ports"].append(port)
                added.append(f"Port: {port}")

            if finding:
                # Attach the most recent execution pointers so the report engine can
                # correlate THIS finding to the commands that produced it. Ensure the
                # explicit evidence pointer is included.
                recent_pointers = [
                    p.get("pointer_id")
                    for p in board_data.get("execution_log_pointers", [])[-3:]
                    if p.get("pointer_id")
                ]
                if evidence_pointer and evidence_pointer not in recent_pointers:
                    recent_pointers.append(evidence_pointer)
                entry = {
                    "id": f"FINDING_{uuid.uuid4().hex[:6].upper()}",
                    "title": finding,
                    "details": details,
                    "severity": severity,
                    "status": status,
                    "evidence": evidence_text,
                    "evidence_pointer": evidence_pointer,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "related_pointers": recent_pointers,
                }
                findings_list.append(entry)
                added.append(f"Finding[{status}/{severity}]: {finding}")

        print(f"[✔] Blackboard updated: {', '.join(added) if added else 'No new entries'}")

        # WS2: a discovered host is classified against scope (auto-authorise under
        # an approved wildcard, else queue as pending).
        if host:
            outcome = classify_and_expand_scope(host)
            if outcome == "authorized":
                print(f"[✔] Scope: '{clean_host(host)}' is under an approved domain — added to allowed_hosts.")
            elif outcome == "pending":
                print(f"[!] Scope: '{clean_host(host)}' is NOT under an approved domain — "
                      f"queued in pending_scope. Approve with: "
                      f"sec_flow.py scope --approve {clean_host(host)}")

        # Auto-trigger the report engine when a finding is recorded so advisories
        # and evidence logs stay in sync (as documented in the /artifactory command).
        if finding:
            trigger_report_generation()

    except SystemExit:
        raise
    except Exception as e:
        print(f"[!] Error updating assets in board.json: {e}", file=sys.stderr)
        sys.exit(1)


def add_rationale(lead=None, hypothesis="", why="", action="", expected="",
                  pointer=None, outcome=""):
    """WS7: append one decision-journal record explaining *why* an action was
    taken and *what* resulted. Feeds the report's 'How we got here' section."""
    ensure_blackboard_dirs()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "lead_id": lead,
        "hypothesis": hypothesis,
        "why_chosen": why,
        "action": action,
        "expected_signal": expected,
        "pointer_id": pointer,
        "outcome": outcome,
    }
    with open(RATIONALE_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[✔] Rationale logged{f' for {lead}' if lead else ''}.")


def load_canary_token() -> str:
    """Returns the workspace canary token, or '' if none is registered."""
    return load_json(CANARY_FILE).get("canary_token", "")


# Binaries that are catastrophic and never legitimate for diagnostic testing.
DESTRUCTIVE_BINARIES = {
    "mkfs", "mke2fs", "dd", "shred", "wipefs", "fdisk", "parted", "mkswap",
    "shutdown", "reboot", "halt", "poweroff", "fastboot",
}


def is_destructive_command(cmd: str) -> tuple[bool, str]:
    """
    Detects clearly destructive operations (data/host destruction) that must be
    refused regardless of scope. This intentionally does NOT flag data-retrieval
    or offensive testing — only irreversible destruction of the host/filesystem.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    basenames = [tok.split("/")[-1] for tok in tokens]

    # rm with a recursive or force flag (e.g. rm -rf, rm -r, rm -f)
    for i, base in enumerate(basenames):
        if base == "rm":
            flags = " ".join(tokens[i + 1:])
            if re.search(r'-\w*[rf]', flags):
                return True, "recursive/forced file deletion (rm -r/-f)"

    # Outright destructive system binaries (incl. mkfs.* filesystem variants)
    for base in basenames:
        if base in DESTRUCTIVE_BINARIES or base.startswith("mkfs"):
            return True, f"destructive system command ({base})"

    # Dangerous full-string constructs
    if re.search(r'>\s*/dev/[sh]d[a-z]', cmd):
        return True, "write to raw disk device"
    if re.search(r':\s*\(\s*\)\s*\{.*\}\s*;?\s*:', cmd):
        return True, "fork bomb"
    if re.search(r'\b(chmod|chown)\s+-R\b\s+.*\s+/(?:\s|$)', cmd):
        return True, "recursive permission/ownership change on root"
    if re.search(r'\binit\s+[06]\b', cmd):
        return True, "system runlevel change"

    return False, ""


def preflight_checks(cmd: str, target: str) -> str:
    """Runs every hard gate before a command may execute. Exits the process on
    any violation. Returns the resolved canary token (for the post-exec scan)."""
    scope = load_json(SCOPE_FILE)

    # Fail-closed scope gate: refuse to execute unless a populated scope exists
    # and an in-scope target has been explicitly declared for this command.
    if not scope:
        print(
            "[!] SCOPE ERROR: .blackboard/scope.json is missing or empty. "
            "Run 'python3 ~/artifactory/init_env.py --target .' and define the "
            "engagement scope before executing any command.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not target:
        print(
            "[!] SCOPE ERROR: a --target is required. Every command must be "
            "validated against scope.json before execution.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not is_target_in_scope(target, scope):
        print(f"[!] SCOPE ERROR: Target '{target}' is not permitted by .blackboard/scope.json", file=sys.stderr)
        sys.exit(1)

    # Canary pre-check: the canary token marks do-not-touch data. A command that
    # explicitly references it is trying to reach protected material — refuse.
    canary = load_canary_token()
    if canary and canary in cmd:
        print(
            f"[!] CANARY TRIPWIRE: command references the protected canary token "
            f"and was blocked before execution.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Destructive-action guard: only irreversible host/filesystem destruction is
    # blocked (enabled by 'DESTRUCTIVE_WRITE' in scope.json disallowed_actions).
    # Offensive testing and proof-of-concept data retrieval are NOT gated here.
    if "DESTRUCTIVE_WRITE" in scope.get("disallowed_actions", []):
        destructive, reason = is_destructive_command(cmd)
        if destructive:
            print(
                f"[!] DESTRUCTIVE-ACTION BLOCK: refused {reason}. "
                f"This is disallowed by scope.json; edit 'disallowed_actions' to override.",
                file=sys.stderr,
            )
            sys.exit(1)

    return canary


def execute_and_log(cmd: str, pointer_id: str, canary: str, quiet: bool = False):
    """Runs a pre-validated command, logs the artifact, updates the board, and
    performs the canary post-check. Assumes preflight_checks already passed."""
    timestamp = datetime.now(timezone.utc).isoformat()

    if not quiet:
        print(f"[*] Executing [{pointer_id}]: {cmd}")

    try:
        cmd_args = shlex.split(cmd)
        result = subprocess.run(
            cmd_args, shell=False, capture_output=True, text=True, timeout=COMMAND_TIMEOUT
        )
        stdout, stderr = result.stdout, result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = f"[!] Command timed out after {COMMAND_TIMEOUT}s and was terminated."
        returncode = 124
    except Exception as e:
        stdout, stderr = "", str(e)
        returncode = 1

    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"
    artifact_content = f"--- COMMAND ---\n{cmd}\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n"
    artifact_path.write_text(artifact_content)

    with open(HISTORY_FILE, "a") as f:
        f.write(f"[{timestamp}] [{pointer_id}] RETURN:{returncode} CMD: {cmd}\n")

    # Canary post-check: if the token surfaced in output, the command reached
    # protected do-not-touch data — flag it loudly and record the tripwire.
    if canary and (canary in stdout or canary in stderr):
        print(
            f"\n[!!!] CANARY TRIPWIRE HIT [{pointer_id}]: the protected canary token "
            f"appeared in command output. This command reached do-not-touch data — "
            f"halt and review scope before continuing.",
            file=sys.stderr,
        )
        with open(HISTORY_FILE, "a") as f:
            f.write(f"[{timestamp}] [{pointer_id}] CANARY_TRIPWIRE cmd touched protected data\n")

    lines = stdout.strip().split("\n") if stdout else []
    summary = lines[0] if lines else ("Error" if stderr else "Empty Output")
    update_board_state(pointer_id, cmd, returncode, summary[:120])

    if not quiet:
        if len(lines) > 100:
            print(f"[+] Output truncated (>100 lines). Full log: .blackboard/artifacts/{pointer_id}.log")
            print("\n".join(lines[:20]))
            print(f"\n... [{len(lines) - 40} lines omitted] ...\n")
            print("\n".join(lines[-20:]))
        else:
            if stdout:
                print(stdout)
        if stderr:
            print(stderr, file=sys.stderr)


def launch_background(cmd: str, target: str, pointer_id: str):
    """Spawns a detached child that runs the (already-validated) command, logs
    it, and triages the result into leads — without blocking the operator."""
    child = [
        sys.executable, str(Path(__file__).resolve()),
        "_bg-exec", "--cmd", cmd, "--target", target, "--pointer", pointer_id,
    ]
    with open(os.devnull, "wb") as devnull:
        subprocess.Popen(
            child, cwd=str(Path.cwd()), stdout=devnull, stderr=devnull,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )


def repeat_command_notice(cmd: str) -> str:
    """Loop guard (harness observability): surface — never block — when this
    exact command has already been executed in this workspace.

    Re-running an identical command is the canonical agent-loop pathology ("calls
    the same tool eleven times, confidently returning a result it never
    re-validated"). A pentester may legitimately re-run, so this only warns and
    points at the cached artifact so the operator can `inspect` it instead of
    burning a turn. Returns a notice string, or "" if this is a first run.
    """
    board = load_json(BOARD_FILE)
    if not board:
        return ""
    prior = [
        p for p in board.get("execution_log_pointers", [])
        if p.get("command") == cmd and p.get("pointer_id")
    ]
    if not prior:
        return ""
    last = prior[-1]
    return (
        f"[~] LOOP NOTICE: this exact command has already run {len(prior)} time(s). "
        f"Last was {last.get('pointer_id')} (rc={last.get('return_code')}, "
        f"\"{(last.get('summary') or '').strip()}\"). If nothing changed, reuse it: "
        f"sec_flow.py inspect --id {last.get('pointer_id')} — don't re-run in a loop."
    )


def run_command(cmd: str, target: str = None, background: bool = False):
    ensure_blackboard_dirs()
    canary = preflight_checks(cmd, target)

    notice = repeat_command_notice(cmd)
    if notice:
        print(notice, file=sys.stderr)

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"

    if background:
        launch_background(cmd, target, pointer_id)
        print(
            f"[*] Backgrounded [{pointer_id}]: {cmd}\n"
            f"    Results + leads will land on board.json when it finishes. "
            f"Pull them with: sec_flow.py leads"
        )
        return

    execute_and_log(cmd, pointer_id, canary)
    trigger_triage(pointer_id)


def bg_exec(cmd: str, target: str, pointer_id: str):
    """Internal entrypoint for the detached background child. Re-runs preflight
    (defense in depth) then executes + triages quietly."""
    ensure_blackboard_dirs()
    canary = preflight_checks(cmd, target)
    execute_and_log(cmd, pointer_id, canary, quiet=True)
    trigger_triage(pointer_id)


def show_leads(status: str = None, ltype: str = None, limit: int = 20,
               lead_id: str = None, set_status: str = None):
    """Operator-facing: the short ranked lead list (not raw logs), or update one."""
    board = load_json(BOARD_FILE)
    if not board:
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)
    leads = board.get("leads", [])

    # Mutation mode: update a single lead's status.
    if lead_id and set_status:
        with json_transaction("board.json") as board:
            if board is None:
                print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
                sys.exit(1)
            found = False
            for l in board.get("leads", []):
                if l.get("id") == lead_id:
                    l["status"] = set_status
                    found = True
                    break
            if not found:
                print(f"[!] Lead '{lead_id}' not found.", file=sys.stderr)
                sys.exit(1)
        print(f"[✔] Lead {lead_id} -> status '{set_status}'")
        return

    view = [
        l for l in leads
        if (not status or l.get("status") == status)
        and (not ltype or l.get("type") == ltype)
    ]
    view.sort(key=lambda l: l.get("confidence", 0), reverse=True)
    if not view:
        print("[*] No leads match (run some recon via 'run' first).")
        return

    print(f"[*] Leads ({len(view)} shown, ranked by confidence):\n")
    for l in view[:limit]:
        print(f"  [{l.get('confidence')}] {l.get('id')} ({l.get('type')}/{l.get('status')}) "
              f"{l.get('value')}")
        if l.get("suggested_next"):
            print(f"        ↳ next: {l['suggested_next']}  (src {l.get('source_pointer')})")


def inspect_artifact(pointer_id: str, grep_pattern: str = None, json_key: str = None, max_lines: int = 50):
    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"

    if not artifact_path.exists():
        print(f"[!] Error: Artifact '{pointer_id}' not found in {ARTIFACTS_DIR}", file=sys.stderr)
        sys.exit(1)

    raw_text = artifact_path.read_text()

    # Extract STDOUT section only
    stdout_match = re.search(r"--- STDOUT ---\n(.*?)(?=\n--- STDERR ---|\Z)", raw_text, re.DOTALL)
    stdout_content = stdout_match.group(1).strip() if stdout_match else raw_text

    # Mode 1: JSON Key Extractor
    if json_key:
        print(f"[*] Extracting JSON key '{json_key}' from {pointer_id}:")
        found = False
        for line in stdout_content.splitlines():
            try:
                data = json.loads(line)
                if isinstance(data, dict) and json_key in data:
                    print(json.dumps(data[json_key], indent=2))
                    found = True
            except json.JSONDecodeError:
                continue
        if not found:
            print(f"[!] Key '{json_key}' not found or output is not line-delimited JSON.")
        return

    # Mode 2: Regex Grep
    lines = stdout_content.splitlines()
    if grep_pattern:
        regex = re.compile(grep_pattern, re.IGNORECASE)
        matched_lines = [line for line in lines if regex.search(line)]
        print(f"[*] Showing matches for '{grep_pattern}' in {pointer_id} (Limit: {max_lines}):\n")
        for line in matched_lines[:max_lines]:
            print(line)
        if len(matched_lines) > max_lines:
            print(f"\n... [{len(matched_lines) - max_lines} matching lines omitted] ...")
        return

    # Mode 3: Head slice
    print(f"[*] Showing head of {pointer_id} (Limit: {max_lines}):\n")
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        print(f"\n... [{len(lines) - max_lines} lines omitted] ...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Flow Execution Engine")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # run
    run_parser = subparsers.add_parser("run", help="Run command and log artifacts")
    run_parser.add_argument("--cmd", required=True, help="Command to execute")
    run_parser.add_argument("--target", help="Target domain/host to validate against scope")
    run_parser.add_argument(
        "--background", "--bg", action="store_true", dest="background",
        help="Run detached: return immediately, log + triage results to board.json when done",
    )

    # _bg-exec (internal: the detached child entrypoint for --background)
    bg_parser = subparsers.add_parser("_bg-exec", help=argparse.SUPPRESS)
    bg_parser.add_argument("--cmd", required=True)
    bg_parser.add_argument("--target", required=True)
    bg_parser.add_argument("--pointer", required=True)

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect and query artifact logs")
    inspect_parser.add_argument("--id", required=True, help="Pointer ID (e.g., MSG_A1B2C3D4)")
    inspect_parser.add_argument("--grep", help="Regex pattern to filter log lines")
    inspect_parser.add_argument("--json-key", help="JSON field/key to extract from output lines")
    inspect_parser.add_argument("--lines", type=int, default=50, help="Max lines to return (default: 50)")

    # add-asset
    asset_parser = subparsers.add_parser("add-asset", help="Record discovered asset to board.json")
    asset_parser.add_argument("--host", help="Discovered hostname or IP")
    asset_parser.add_argument("--endpoint", help="Discovered URL path or route")
    asset_parser.add_argument("--port", help="Discovered open port (e.g., 8080/tcp)")
    asset_parser.add_argument("--finding", help="Vulnerability or observation title")
    asset_parser.add_argument("--details", default="", help="Short description of the finding")
    asset_parser.add_argument("--severity", default="info", choices=SEVERITIES,
                              help="Finding severity (default: info)")
    asset_parser.add_argument("--status", default="informational", choices=FINDING_STATUSES,
                              help="informational (default) or confirmed (requires evidence)")
    asset_parser.add_argument("--poc", default="",
                              help="Inline proof: the payload / request+response that proves impact")
    asset_parser.add_argument("--evidence-from", dest="evidence_from",
                              help="Pointer ID whose artifact log is the evidence for this finding")

    # scope (WS2: per-project scope + subdomain approval)
    scope_parser = subparsers.add_parser("scope", help="View or edit engagement scope")
    scope_parser.add_argument("--list", dest="do_list", action="store_true", help="Show current scope + pending")
    scope_parser.add_argument("--add-host", dest="add_host", help="Authorise a host/IP")
    scope_parser.add_argument("--add-domain", dest="add_domain", help="Authorise a domain/wildcard (e.g. *.example.com)")
    scope_parser.add_argument("--add-cidr", dest="add_cidr", help="Authorise a CIDR range")
    scope_parser.add_argument("--approve", help="Promote a pending host into allowed_hosts")

    # add-rationale (WS7: decision journal -> 'How we got here')
    rat_parser = subparsers.add_parser("add-rationale", help="Log why an action was taken and its outcome")
    rat_parser.add_argument("--lead", help="Lead ID this decision relates to")
    rat_parser.add_argument("--hypothesis", default="", help="The attack theory being tested")
    rat_parser.add_argument("--why", default="", help="Why this action was chosen")
    rat_parser.add_argument("--action", default="", help="What was done")
    rat_parser.add_argument("--expected", default="", help="Signal that would confirm the hypothesis")
    rat_parser.add_argument("--pointer", help="Related execution pointer ID")
    rat_parser.add_argument("--outcome", default="", help="What actually happened (confirmed|dead|inconclusive + note)")

    # leads (operator-facing: consume ranked leads instead of raw logs)
    leads_parser = subparsers.add_parser("leads", help="Show/triage ranked leads on the board")
    leads_parser.add_argument("--status", help="Filter by status (new|testing|confirmed|dead)")
    leads_parser.add_argument("--type", dest="ltype", help="Filter by type (endpoint|port|subdomain|tech|anomaly)")
    leads_parser.add_argument("--limit", type=int, default=20, help="Max leads to show (default: 20)")
    leads_parser.add_argument("--id", dest="lead_id", help="Lead ID to update")
    leads_parser.add_argument("--set-status", dest="set_status", help="New status for --id")

    args = parser.parse_args()

    if args.subcommand == "run":
        run_command(args.cmd, args.target, args.background)
    elif args.subcommand == "_bg-exec":
        bg_exec(args.cmd, args.target, args.pointer)
    elif args.subcommand == "inspect":
        inspect_artifact(args.id, args.grep, args.json_key, args.lines)
    elif args.subcommand == "add-asset":
        add_asset_to_board(args.host, args.endpoint, args.port, args.finding, args.details,
                           args.severity, args.status, args.poc, args.evidence_from)
    elif args.subcommand == "scope":
        manage_scope(args.add_host, args.add_domain, args.add_cidr, args.approve, args.do_list)
    elif args.subcommand == "add-rationale":
        add_rationale(args.lead, args.hypothesis, args.why, args.action, args.expected,
                      args.pointer, args.outcome)
    elif args.subcommand == "leads":
        show_leads(args.status, args.ltype, args.limit, args.lead_id, args.set_status)