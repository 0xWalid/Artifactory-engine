#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - On-Demand Playbook Engine
Checks, generates, renders, and persists practitioner playbooks with target parameter substitution.
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


def render_playbook(content: str, target: str = "", auth_token: str = "") -> str:
    """Substitutes template variables with active engagement targets."""
    if not target:
        return content

    target_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    target_url = target if target.startswith("http") else f"https://{target}"

    rendered = content.replace("{{TARGET_HOST}}", target_host)
    rendered = rendered.replace("{{TARGET_URL}}", target_url)

    if auth_token:
        rendered = rendered.replace("{{AUTH_TOKEN}}", auth_token)

    return rendered


def save_researched_playbook(category: str, name: str, content: str, author: str = "Synthesized Tradecraft") -> Path:
    """Saves newly researched tradecraft into the local playbook repository."""
    target_path = get_playbook_path(category, name)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    header = f"# Micro-Playbook: {name.replace('_', ' ').title()}\n"
    header += f"**Practitioner / Methodology:** {author}\n"
    header += f"**Category:** {category}\n\n"

    target_path.write_text(header + content.strip())
    return target_path


def check_or_fetch_playbook(category: str, name: str, target: str = "", auth_token: str = "") -> tuple[Path, str, bool]:
    """
    Checks if a playbook exists.
    Returns (path, content, is_found).
    """
    target_path = get_playbook_path(category, name)

    if target_path.exists():
        raw_content = target_path.read_text()
        rendered_content = render_playbook(raw_content, target, auth_token)
        return target_path, rendered_content, True

    # Signal to OpenCode that tradecraft must be synthesized/researched
    research_prompt = f"""[STATUS: MISSING_NEEDS_RESEARCH]
Playbook not found at: {target_path}
Category: {category}
Vulnerability/Vector: {name}

ACTION REQUIRED:
1. Search industry sources (OWASP WSTG, PortSwigger Web Security, CVE advisories) for '{name}' targeting '{category}'.
2. Extract concrete, non-destructive diagnostic CLI commands (curl, httpx, ffuf) and response indicators.
3. Save the tradecraft via:
   python3 ~/artifactory/playbook_engine.py --category {category} --name {name} --save-content "<content>"
4. Re-execute the test.
"""
    return target_path, research_prompt, False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="On-Demand Playbook Engine")
    parser.add_argument("--category", "-c", required=True, choices=["recon", "web", "auth", "infra", "logic", "chaining"])
    parser.add_argument("--name", "-n", required=True, help="Playbook name (e.g., graphql_idor, s3_bucket_leak)")
    parser.add_argument("--author", "-a", default="Industry Specialist", help="Author/Practitioner reference")
    parser.add_argument("--target", "-t", default="", help="Target URL/Host for dynamic parameter substitution")
    parser.add_argument("--auth-token", default="", help="Optional Bearer token for variable substitution")
    parser.add_argument("--save-content", help="Directly save newly synthesized playbook content")

    args = parser.parse_args()

    if args.save_content:
        saved_path = save_researched_playbook(args.category, args.name, args.save_content, args.author)
        print(f"[✔] Successfully saved synthesized playbook to: {saved_path}")
        sys.exit(0)

    path, content, found = check_or_fetch_playbook(
        category=args.category,
        name=args.name,
        target=args.target,
        auth_token=args.auth_token
    )

    if found:
        print(f"[STATUS: FOUND] Loaded playbook: {path}\n")
    print(content)