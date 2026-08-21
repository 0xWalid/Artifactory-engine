#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Security Flow Execution Engine
Handles safe non-shell execution, CIDR scope validation, artifact logging,
JSON-aware inspection, and state asset recording.
"""

import argparse
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
HISTORY_FILE = BLACKBOARD_DIR / "history.log"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
CANARY_FILE = BLACKBOARD_DIR / "canaries.json"

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


def update_board_state(pointer_id: str, cmd: str, returncode: int, summary: str = ""):
    if not BOARD_FILE.exists():
        return

    try:
        board_data = load_json(BOARD_FILE)
        board_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        pointer_entry = {
            "pointer_id": pointer_id,
            "command": cmd,
            "return_code": returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary
        }
        
        board_data.setdefault("execution_log_pointers", []).append(pointer_entry)
        BOARD_FILE.write_text(json.dumps(board_data, indent=2))
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


def add_asset_to_board(host: str = None, endpoint: str = None, port: str = None, finding: str = None, details: str = ""):
    if not BOARD_FILE.exists():
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    try:
        board_data = load_json(BOARD_FILE)
        board_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        assets = board_data.setdefault("discovered_assets", {"hosts": [], "endpoints": [], "open_ports": []})
        findings_list = board_data.setdefault("findings", [])

        added = []
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
            # correlate THIS finding to the commands that actually produced it,
            # rather than dumping every command into every advisory.
            recent_pointers = [
                p.get("pointer_id")
                for p in board_data.get("execution_log_pointers", [])[-3:]
                if p.get("pointer_id")
            ]
            entry = {
                "id": f"FINDING_{uuid.uuid4().hex[:6].upper()}",
                "title": finding,
                "details": details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "related_pointers": recent_pointers,
            }
            findings_list.append(entry)
            added.append(f"Finding: {finding}")

        BOARD_FILE.write_text(json.dumps(board_data, indent=2))
        print(f"[✔] Blackboard updated: {', '.join(added) if added else 'No new entries'}")

        # Auto-trigger the report engine when a finding is recorded so advisories
        # and evidence logs stay in sync (as documented in the /artifactory command).
        if finding:
            trigger_report_generation()

    except Exception as e:
        print(f"[!] Error updating assets in board.json: {e}", file=sys.stderr)
        sys.exit(1)


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


def run_command(cmd: str, target: str = None):
    ensure_blackboard_dirs()
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

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

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

    args = parser.parse_args()

    if args.subcommand == "run":
        run_command(args.cmd, args.target)
    elif args.subcommand == "inspect":
        inspect_artifact(args.id, args.grep, args.json_key, args.lines)
    elif args.subcommand == "add-asset":
        add_asset_to_board(args.host, args.endpoint, args.port, args.finding, args.details)