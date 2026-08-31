#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Tradecraft Ingestion & Parameterization Pipeline
Converts raw writeups, CTF solutions, and blog posts into generic, parameterized playbooks.
"""

import argparse
import os
import re
import sys
from pathlib import Path


def _find_engine_root():
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent


PROMPTS_DIR = _find_engine_root() / "prompts"


def strip_and_parameterize(raw_text: str, custom_target: str = None) -> str:
    """
    Strips specific domains, IPs, and hardcoded values from raw writeups,
    replacing them with SBA template variables.

    Ordering is deliberate to avoid double-substitution:
      1. explicit target  2. bearer tokens  3. full URLs (scheme + domain/IP,
      preserving the path)  4. standalone IPv4  5. bare domains.
    URLs are handled before bare IPs/domains so a scheme'd host is not first
    mangled into a host placeholder and then left as a broken URL.
    """
    text = raw_text

    if custom_target:
        text = text.replace(custom_target, "{{TARGET_HOST}}")

    # Authorization bearer tokens (JWT-style or opaque) -> template variable.
    text = re.sub(
        r'Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
        'Bearer {{AUTH_TOKEN}}',
        text,
    )

    # Full URLs: scheme + (IPv4 | dotted domain) + optional port. The trailing
    # path/query is intentionally preserved so endpoints survive in the playbook.
    text = re.sub(
        r'https?://(?:\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?',
        '{{TARGET_URL}}',
        text,
    )

    # Standalone IPv4 addresses (any that were not part of a URL above).
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '{{TARGET_HOST}}', text)

    # Standalone bare domains (incl. subdomains) ending in a known TLD. A curated
    # list (rather than a generic \.[a-z]{2,} match) is deliberate so code tokens
    # like app.js / config.json / response.body are NOT mangled into placeholders.
    text = re.sub(
        r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|dev|app|co|edu|gov|mil|local|'
        r'internal|corp|lan|xyz|me|info|biz|cloud|tech|site|online|store|network|'
        r'uk|de|fr|es|it|nl|ru|cn|jp|kr|in|br|au|ca|us|eu|sh|gg|ly|to|id|ai)\b',
        '{{TARGET_HOST}}',
        text,
    )

    return text


def quality_gate_check(content: str) -> tuple[bool, str]:
    """
    Evaluates whether a writeup has enough actionable technical detail
    to serve as a functional playbook.
    """
    has_cli = bool(re.search(r'(curl|ffuf|nmap|sqlmap|httpx|gobuster|nikto|semgrep|wfuzz)', content, re.I))
    has_http_methods = bool(re.search(r'(GET|POST|PUT|DELETE|PATCH)\s+/', content))
    has_parameters = bool(re.search(r'(\?|\&)[a-zA-Z0-9_]+=', content))

    score = sum([has_cli, has_http_methods, has_parameters])

    if score >= 1:
        return True, f"Passed Quality Gate (Score: {score}/3 - Actionable technical mechanics identified)."
    else:
        return False, "Failed Quality Gate: Content lacks concrete CLI commands, HTTP methods, or parameter targets."


def save_or_merge_playbook(category: str, name: str, content: str, source_ref: str = "") -> Path:
    """Saves a new playbook or appends elevated strategy to an existing one."""
    slug = name.lower().replace(" ", "_").replace("-", "_")
    if not slug.endswith(".md"):
        slug += ".md"

    category_dir = PROMPTS_DIR / category
    category_dir.mkdir(parents=True, exist_ok=True)
    file_path = category_dir / slug

    header = f"# Ingested Tradecraft: {name.replace('_', ' ').title()}\n"
    if source_ref:
        header += f"**Source Reference:** {source_ref}\n"
    header += f"**Category:** {category}\n\n"

    if file_path.exists():
        print(f"[*] Updating existing playbook at: {file_path}")
        with open(file_path, "a") as f:
            f.write("\n\n---\n\n## 🔄 Elevated Strategy / Additional Vector\n")
            if source_ref:
                f.write(f"**Source:** {source_ref}\n\n")
            f.write(content)
    else:
        print(f"[+] Creating new playbook at: {file_path}")
        with open(file_path, "w") as f:
            f.write(header + content)

    return file_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tradecraft Ingestion Engine")
    parser.add_argument("--file", "-f", help="Path to raw writeup text file")
    parser.add_argument("--content", help="Raw text content to ingest directly (can also be read from stdin)")
    parser.add_argument("--category", "-c", required=True, choices=["recon", "web", "auth", "infra", "logic", "chaining", "sast"])
    parser.add_argument("--name", "-n", required=True, help="Playbook target name (e.g., graphql_idor)")
    parser.add_argument("--source", "-s", default="", help="Source reference URL or Article title")
    parser.add_argument("--target-domain", "-t", default="", help="Specific target domain to strip out if known")
    parser.add_argument("--force", action="store_true", help="Bypass quality gate check if needed")

    args = parser.parse_args()

    raw_text = ""
    if args.content:
        raw_text = args.content
    elif args.file and os.path.exists(args.file):
        with open(args.file, "r") as f:
            raw_text = f.read()
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()

    if not raw_text.strip():
        print("[!] Error: Input content required via --file, --content, or stdin.", file=sys.stderr)
        sys.exit(1)

    if not args.force:
        passed, reason = quality_gate_check(raw_text)
        print(f"[*] Quality Check: {reason}")
        if not passed:
            print("[!] Ingestion aborted. Input material is missing actionable execution steps.")
            sys.exit(1)

    parameterized_text = strip_and_parameterize(raw_text, args.target_domain)
    saved_path = save_or_merge_playbook(args.category, args.name, parameterized_text, args.source)
    print(f"[✔] Ingestion complete: {saved_path}")