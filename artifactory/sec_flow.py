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
    if not scope:
        return True

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
            entry = {
                "id": f"FINDING_{uuid.uuid4().hex[:6].upper()}",
                "title": finding,
                "details": details,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            findings_list.append(entry)
            added.append(f"Finding: {finding}")

        BOARD_FILE.write_text(json.dumps(board_data, indent=2))
        print(f"[✔] Blackboard updated: {', '.join(added) if added else 'No new entries'}")

    except Exception as e:
        print(f"[!] Error updating assets in board.json: {e}", file=sys.stderr)
        sys.exit(1)


def run_command(cmd: str, target: str = None):
    ensure_blackboard_dirs()
    scope = load_json(SCOPE_FILE)

    if target and not is_target_in_scope(target, scope):
        print(f"[!] SCOPE ERROR: Target '{target}' is not permitted by .blackboard/scope.json", file=sys.stderr)
        sys.exit(1)

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    print(f"[*] Executing [{pointer_id}]: {cmd}")

    try:
        cmd_args = shlex.split(cmd)
        result = subprocess.run(cmd_args, shell=False, capture_output=True, text=True)
        stdout, stderr = result.stdout, result.stderr
        returncode = result.returncode
    except Exception as e:
        stdout, stderr = "", str(e)
        returncode = 1

    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"
    artifact_content = f"--- COMMAND ---\n{cmd}\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n"
    artifact_path.write_text(artifact_content)

    with open(HISTORY_FILE, "a") as f:
        f.write(f"[{timestamp}] [{pointer_id}] RETURN:{returncode} CMD: {cmd}\n")

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