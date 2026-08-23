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

    # Signal to the agent that tradecraft must be synthesized into a real
    # testing methodology (not just a raw command list) before proceeding.
    research_prompt = f"""[STATUS: MISSING_NEEDS_RESEARCH]
No playbook found at: {target_path}
Category: {category}
Vulnerability / Vector: {name}

You must now SYNTHESIZE A TESTING METHODOLOGY for this vector before any command
runs. Do not emit ad-hoc commands. Follow this protocol in order:

1. IDENTIFY THE AUTHORITY FOR THIS BUG CLASS.
   Name the practitioner(s) / research most associated with '{name}' and pull
   from their primary material. Map the class to the right source, e.g.:
     - web / request smuggling / cache / SSRF ...... James Kettle, PortSwigger Research
     - recon / attack surface / methodology ......... Jason Haddix, TBHM
     - logic / SSRF / cloud / OAuth ................. Orange Tsai, Frans Rosen
     - infra / cloud .................................. relevant CVE + vendor advisories
   Always cross-check against OWASP WSTG and any relevant CVE advisories.
   Retain the source link(s) — they are recorded with the playbook.

2. REQUEST MORE INPUT FROM THE OPERATOR (do this explicitly, then WAIT):
   ❓ Provide any of the following to sharpen the methodology:
      - Additional writeup / advisory URLs to fold in
      - Local files (writeups, prior reports, Burp/HTTP logs) to ingest
      - Custom payloads, headers, or auth material specific to the target
      - Scope notes or constraints (rate limits, approved aggressive techniques)
   If the operator has nothing to add, they should say "proceed".

3. SYNTHESIZE A STRUCTURED METHODOLOGY (parameterized, non-destructive):
   Compose the playbook body with these sections, using the template variables
   {{{{TARGET_URL}}}}, {{{{TARGET_HOST}}}}, {{{{AUTH_TOKEN}}}} instead of live values:
      ## Preconditions & Indicators   (when this vuln is plausible)
      ## Enumeration                  (how to confirm the surface exists)
      ## Diagnostic Checks            (concrete curl/httpx/ffuf commands, safe/non-destructive)
      ## Verification & Impact        (response signatures that confirm the finding)
      ## Escalation & Chaining        (how this links into a larger attack path)

4. CONFIRMATION GATE (MANDATORY PAUSE):
   Present the summary card (name, practitioner, source links, category, key
   steps) and PAUSE for operator approval before writing anything.

5. SAVE & EXECUTE (only after approval):
   python3 ~/artifactory/playbook_engine.py --category {category} --name {name} \\
     --author "<Practitioner / Source>" --save-content "<synthesized_markdown>"
   Then re-run the test against the target via sec_flow.py run.
"""
    return target_path, research_prompt, False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="On-Demand Playbook Engine")
    parser.add_argument("--category", "-c", required=True, choices=["recon", "web", "auth", "infra", "logic", "chaining", "sast"])
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