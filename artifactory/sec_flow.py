#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Execution Wrapper & Guardrails (Phase 4)
Handles deterministic tool execution, scope tripwires, SAST pre-filtering, 
and artifact pointer management.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
BOARD_FILE = BLACKBOARD_DIR / "board.json"

# Ensure runtime directories exist
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def load_scope():
    """Loads scope constraints from .blackboard/scope.json"""
    if not SCOPE_FILE.exists():
        print("[!] Warning: No scope.json found. Creating default empty scope.")
        default_scope = {"allowed_domains": [], "allowed_ips": [], "canary_tokens": ["CANARY_TRIPWIRE_TOKEN"]}
        SCOPE_FILE.write_text(json.dumps(default_scope, indent=2))
        return default_scope
    try:
        return json.loads(SCOPE_FILE.read_text())
    except Exception as e:
        print(f"[!] Error parsing scope.json: {e}")
        sys.exit(1)


def check_scope_and_canaries(target: str) -> bool:
    """Tripwire check: Verify target matches scope and doesn't hit a canary token."""
    scope = load_scope()
    
    # Check Canary Tokens
    for token in scope.get("canary_tokens", []):
        if token in target:
            print(f"[TRIPWIRE TRIGGERED] Target string contains Canary token '{token}'. Aborting execution immediately.")
            return False

    allowed_domains = scope.get("allowed_domains", [])
    allowed_ips = scope.get("allowed_ips", [])

    # If no restrictions are set, log a warning
    if not allowed_domains and not allowed_ips:
        print("[!] Notice: Allowed scope lists are empty. Proceeding with caution.")
        return True

    # Simple domain matching
    domain_match = any(domain in target for domain in allowed_domains)
    ip_match = any(ip in target for ip in allowed_ips)

    if not (domain_match or ip_match):
        print(f"[SCOPE DENIED] Target '{target}' does not match allowed domains/IPs in scope.json.")
        return False

    return True


def run_sast_prefilter(target_path: str, rule_config: str = "auto") -> dict:
    """Runs deterministic SAST (Semgrep) pre-filtering on a target code directory or file."""
    print(f"[*] Running SAST pre-filter on: {target_path}")
    if not os.path.exists(target_path):
        return {"status": "error", "message": f"Path {target_path} does not exist"}

    cmd = ["semgrep", "--config", rule_config, "--json", target_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode in (0, 1): # 0 = no findings, 1 = findings
            try:
                data = json.loads(res.stdout)
                return {"status": "success", "results": data.get("results", [])}
            except json.JSONDecodeError:
                return {"status": "error", "message": "Failed to parse Semgrep output JSON"}
        return {"status": "error", "message": res.stderr}
    except FileNotFoundError:
        print("[!] Semgrep is not installed or not in PATH. Skipping SAST pre-filtering.")
        return {"status": "skipped", "message": "Semgrep binary missing"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "SAST pre-filter timed out after 120s"}


def execute_tool(cmd_str: str, target_ref: str) -> str:
    """Executes a command safely, enforcing tripwires and saving output as a pointer artifact."""
    if not check_scope_and_canaries(target_ref):
        sys.exit(1)

    artifact_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    output_file = ARTIFACTS_DIR / f"{artifact_id}.log"

    print(f"[*] Executing Tool Command: {cmd_str}")
    print(f"[*] Artifact Pointer ID: {artifact_id}")

    try:
        res = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=300)
        full_output = f"=== STDOUT ===\n{res.stdout}\n\n=== STDERR ===\n{res.stderr}"
        output_file.write_text(full_output)

        # Truncated context output
        stdout_lines = res.stdout.splitlines()
        preview = "\n".join(stdout_lines[:15]) if len(stdout_lines) > 15 else res.stdout
        
        summary = (
            f"Command Executed: {cmd_str}\n"
            f"Exit Code: {res.returncode}\n"
            f"Artifact Saved: {output_file}\n"
            f"Pointer ID: [{artifact_id}]\n"
            f"--- Output Preview (First 15 lines) ---\n"
            f"{preview}\n"
            f"--- End Preview (Use artifact {artifact_id} for full raw data) ---"
        )
        return summary
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out: {cmd_str}"
        output_file.write_text(error_msg)
        return f"[!] Error: Execution timed out. Artifact saved to [{artifact_id}]."
    except Exception as e:
        error_msg = f"Execution failed: {str(e)}"
        output_file.write_text(error_msg)
        return f"[!] Error executing command: {str(e)}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sovereign Blackboard Tool Execution Wrapper")
    subparsers = parser.add_subparsers(dest="action", help="Action to perform")

    # Run tool sub-command
    run_parser = subparsers.add_parser("run", help="Run a security tool command")
    run_parser.add_argument("--cmd", required=True, help="Command string to execute")
    run_parser.add_argument("--target", required=True, help="Target domain/IP/path to validate scope")

    # SAST sub-command
    sast_parser = subparsers.add_parser("sast", help="Run SAST pre-filtering on source code")
    sast_parser.add_argument("--path", required=True, help="Path to source directory or file")
    sast_parser.add_argument("--rules", default="auto", help="Semgrep rulesets or config")

    args = parser.parse_args()

    if args.action == "run":
        result = execute_tool(args.cmd, args.target)
        print(result)
    elif args.action == "sast":
        result = run_sast_prefilter(args.path, args.rules)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
