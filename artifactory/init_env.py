#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture (SBA) - Target Workspace Initializer
Creates isolated .blackboard workspaces with structured schemas.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def init_target_workspace(target_dir: Path, scope_from: Path = None):
    """Initializes a local, isolated .blackboard workspace with formal state schemas."""
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    blackboard_dir = target_dir / ".blackboard"
    artifacts_dir = blackboard_dir / "artifacts"
    board_file = blackboard_dir / "board.json"
    scope_file = blackboard_dir / "scope.json"
    canary_file = blackboard_dir / "canaries.json"
    scout_file = blackboard_dir / "scout.json"

    blackboard_dir.mkdir(exist_ok=True)
    artifacts_dir.mkdir(exist_ok=True)

    print(f"[+] Target Workspace: {target_dir}")
    print(f"[+] Blackboard Store: {blackboard_dir}")
    print(f"[+] Artifacts Folder: {artifacts_dir}")

    if not board_file.exists():
        initial_board = {
            "version": "2.0.0",
            "target_path": str(target_dir),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "discovered_assets": {
                "hosts": [],
                "endpoints": [],
                "open_ports": []
            },
            "findings": [],
            "leads": [],
            "execution_log_pointers": []
        }
        board_file.write_text(json.dumps(initial_board, indent=2))
        print(f"[+] Created: {board_file.name}")
    else:
        print(f"[*] Exists (Skipped): {board_file.name}")

    if not scope_file.exists():
        # Per-project scope. Seed from a saved template (--scope-from) so a new
        # engagement can inherit an approved scope instead of the localhost default.
        if scope_from and Path(scope_from).exists():
            try:
                initial_scope = json.loads(Path(scope_from).read_text())
                initial_scope.setdefault("pending_scope", [])
                print(f"[+] Seeded scope from template: {scope_from}")
            except Exception as e:
                print(f"[!] Could not read --scope-from ({e}); using localhost default.")
                initial_scope = None
        else:
            initial_scope = None

        if initial_scope is None:
            initial_scope = {
                "allowed_hosts": ["127.0.0.1", "localhost"],
                "allowed_domains": ["*.local.target"],
                "allowed_cidrs": ["127.0.0.0/8"],
                "pending_scope": [],
                # White-box SAST gate (separate from the network host/CIDR gate):
                # semgrep may only scan code under a directory listed here. Empty
                # by default => fail-closed, no local source is scanned until the
                # operator authorises an engagement code path.
                "allowed_code_paths": [],
                "disallowed_actions": ["DESTRUCTIVE_WRITE", "DOS"]
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

    if not scout_file.exists():
        # Background "Scout" brain config. Provider-agnostic and OpenAI-compatible:
        # the Scout digests raw tool output into ranked leads so the expensive
        # operator model never has to read the firehose. Disabled by default;
        # triage still works deterministically (no model calls) until enabled.
        initial_scout = {
            "enabled": True,
            "base_url": "https://api.groq.com/openai/v1",
            "model": "llama-3.3-70b-versatile",
            "api_key_env": "GROQ_API_KEY",
            "fallbacks": [
                {
                    "base_url": "https://openrouter.ai/api/v1",
                    "model": "meta-llama/llama-3.3-70b-instruct:free",
                    "api_key_env": "OPENROUTER_API_KEY"
                }
            ],
            "max_leads_per_triage": 8,
            "request_timeout": 20,
            "_note": (
                "The Groq -> OpenRouter failover chain also lives in the engine "
                "code (triage.KNOWN_PROVIDERS), so ranking works even if this file "
                "is deleted or incomplete: just export GROQ_API_KEY and/or "
                "OPENROUTER_API_KEY. A provider is only used if its api_key_env is "
                "set; with no keys, deterministic triage runs alone. This file lets "
                "you override models/order or add providers (Cerebras, Gemini's "
                "OpenAI endpoint, ...). Set enabled=false to hard-disable the model."
            ),
        }
        scout_file.write_text(json.dumps(initial_scout, indent=2))
        print(f"[+] Created: {scout_file.name}")
    else:
        print(f"[*] Exists (Skipped): {scout_file.name}")

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
    parser.add_argument(
        "--scope-from",
        type=str,
        default=None,
        help="Path to a saved scope.json template to seed this workspace's scope"
    )
    args = parser.parse_args()

    init_target_workspace(Path(args.target), args.scope_from)