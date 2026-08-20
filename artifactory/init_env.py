#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture (SBA) - Target Workspace Initializer
Creates isolated .blackboard workspaces with structured schemas.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def init_target_workspace(target_dir: Path):
    """Initializes a local, isolated .blackboard workspace with formal state schemas."""
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    blackboard_dir = target_dir / ".blackboard"
    artifacts_dir = blackboard_dir / "artifacts"
    board_file = blackboard_dir / "board.json"
    scope_file = blackboard_dir / "scope.json"
    canary_file = blackboard_dir / "canaries.json"

    blackboard_dir.mkdir(exist_ok=True)
    artifacts_dir.mkdir(exist_ok=True)

    print(f"[+] Target Workspace: {target_dir}")
    print(f"[+] Blackboard Store: {blackboard_dir}")
    print(f"[+] Artifacts Folder: {artifacts_dir}")

    if not board_file.exists():
        initial_board = {
            "version": "1.1.0",
            "target_path": str(target_dir),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "discovered_assets": {
                "hosts": [],
                "endpoints": [],
                "open_ports": []
            },
            "findings": [],
            "execution_log_pointers": []
        }
        board_file.write_text(json.dumps(initial_board, indent=2))
        print(f"[+] Created: {board_file.name}")
    else:
        print(f"[*] Exists (Skipped): {board_file.name}")

    if not scope_file.exists():
        initial_scope = {
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "allowed_domains": ["*.local.target"],
            "allowed_cidrs": ["127.0.0.0/8"],
            "disallowed_actions": ["DOS", "DESTRUCTIVE_WRITE", "EXFILTRATE_PII"]
        }
        scope_file.write_text(json.dumps(initial_scope, indent=2))
        print(f"[+] Created: {scope_file.name}")
    else:
        print(f"[*] Exists (Skipped): {scope_file.name}")

    if not canary_file.exists():
        initial_canary = {
            "canary_token": f"sba_canary_{target_dir.name}_do_not_touch",
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        canary_file.write_text(json.dumps(initial_canary, indent=2))
        print(f"[+] Created: {canary_file.name}")
    else:
        print(f"[*] Exists (Skipped): {canary_file.name}")

    print("[✔] Workspace setup complete.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SBA Target Workspace Initializer")
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        default=".",
        help="Path to target project directory (default: current directory)"
    )
    args = parser.parse_args()

    init_target_workspace(Path(args.target))