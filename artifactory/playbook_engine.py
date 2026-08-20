#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - On-Demand Playbook Engine
Checks, generates, and renders practitioner playbooks with target parameter substitution.
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


def check_or_create_playbook(category: str, name: str, author: str = "Practitioner", target: str = "", auth_token: str = ""):
    target_path = get_playbook_path(category, name)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if target_path.exists():
        raw_content = target_path.read_text()
        rendered_content = render_playbook(raw_content, target, auth_token)
        return target_path, rendered_content, False

    # Standard starter template
    template = f"""# Micro-Playbook: {name.replace('_', ' ').title()}
**Practitioner / Methodology:** {author}
**Category:** {category}

## 1. Objective
Describe the target scenario or vector.

## 2. Methodology & Step-by-Step Tradecraft
1. **Initial Vector:** Identify relevant endpoints and headers on `{{{{TARGET_URL}}}}`.
2. **Probing & Diagnostic Testing:** Non-destructive test commands.
3. **Verification:** Confirm status without disrupting operations.

## 3. Operational Constraints
- Execute all commands via `sec_flow.py run --cmd "<command>" --target "{{{{TARGET_HOST}}}}"`.
- Query large outputs via `sec_flow.py inspect --id <POINTER_ID>`.
"""
    target_path.write_text(template)
    rendered_template = render_playbook(template, target, auth_token)
    return target_path, rendered_template, True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="On-Demand Playbook Engine")
    parser.add_argument("--category", "-c", required=True, choices=["recon", "web", "auth", "infra", "logic", "chaining"])
    parser.add_argument("--name", "-n", required=True, help="Playbook name (e.g., graphql_idor)")
    parser.add_argument("--author", "-a", default="Practitioner", help="Author/Practitioner reference")
    parser.add_argument("--target", "-t", default="", help="Target URL/Host for dynamic variable substitution")
    parser.add_argument("--auth-token", default="", help="Optional Bearer token for variable substitution")

    args = parser.parse_args()
    path, content, is_new = check_or_create_playbook(
        category=args.category,
        name=args.name,
        author=args.author,
        target=args.target,
        auth_token=args.auth_token
    )

    if is_new:
        print(f"[MISSING] Created initial template at: {path}\n")
    else:
        print(f"[FOUND] Loaded playbook: {path}\n")

    print(content)