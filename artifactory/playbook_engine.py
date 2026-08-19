#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - On-Demand Playbook Engine
Checks for existing micro-playbooks or generates practitioner templates.
"""

import argparse
import sys
from pathlib import Path

PROMPTS_DIR = Path(__file__).parent / "prompts"


def get_playbook_path(category: str, name: str) -> Path:
    slug = name.lower().replace(" ", "_").replace("-", "_")
    if not slug.endswith(".md"):
        slug += ".md"
    return PROMPTS_DIR / category / slug


def check_or_create_playbook(category: str, name: str, author: str = "Practitioner"):
    target_path = get_playbook_path(category, name)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if target_path.exists():
        print(f"[FOUND] Playbook exists at: {target_path}")
        return target_path, target_path.read_text(), False

    # Template structure if missing
    template = f"""# Micro-Playbook: {name}
**Practitioner / Methodology:** {author}
**Category:** {category}

## 1. Objective
Describe the target vulnerability or tradecraft scenario.

## 2. Methodology & Step-by-Step Tradecraft
1. **Initial Vector:** Identify relevant endpoints and headers.
2. **Probing & Payload Testing:** Describe non-destructive test cases.
3. **Verification:** Confirm impact without causing system disruption.

## 3. Agent Operational Constraints
- Store raw tool outputs / HTTP dumps in `.blackboard/artifacts/` via `sec_flow.py`.
- Never output logs >100 lines into context; reference via pointer IDs (`[MSG_XXX]`).
"""
    return target_path, template, True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="On-Demand Playbook Engine")
    parser.add_argument("--category", "-c", required=True, choices=["recon", "web", "auth", "infra", "logic", "chaining"])
    parser.add_argument("--name", "-n", required=True, help="Playbook name (e.g., http_smuggling)")
    parser.add_argument("--author", "-a", default="Industry Specialist", help="Author/Practitioner reference (e.g., James Kettle)")
    
    args = parser.parse_args()
    path, content, is_new = check_or_create_playbook(args.category, args.name, args.author)

    if is_new:
        print(f"[MISSING] No playbook found. Creating initial template at: {path}")
        path.write_text(content)
        print("\n--- TEMPLATE GENERATED ---")
        print(content)
    else:
        print("\n--- EXISTING PLAYBOOK LOADED ---")
        print(content)
