#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - On-Demand Playbook Engine
Checks, generates, renders, and persists practitioner playbooks with target parameter substitution.
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

METHODOLOGY_URLS_FILE = Path(__file__).parent / "knowledge" / "methodology_urls.txt"

PROMPTS_DIR = Path(__file__).parent / "prompts"
SOURCES_FILE = Path(__file__).parent / "knowledge" / "sources.json"


def get_playbook_path(category: str, name: str) -> Path:
    slug = name.lower().replace(" ", "_").replace("-", "_")
    if not slug.endswith(".md"):
        slug += ".md"
    return PROMPTS_DIR / category / slug


def playbook_path_for_source(s: dict) -> Path:
    """Deterministic playbook location for a registry source, so the engine —
    not the LLM — decides whether it's already been built. Save convention:
    category = first category, name = source id (falls back to title)."""
    cats = s.get("category") or ["misc"]
    name = s.get("id") or s.get("title") or "source"
    return get_playbook_path(cats[0], name)


def source_is_built(s: dict) -> bool:
    """True if a playbook already exists on disk for this source."""
    return playbook_path_for_source(s).exists()


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


def load_sources() -> list:
    """Load the curated research library (knowledge/sources.json)."""
    try:
        return json.loads(SOURCES_FILE.read_text()).get("sources", [])
    except Exception:
        return []


def suggest_sources(category: str, name: str, limit: int = 8) -> str:
    """Rank library entries against the requested category + vector name and
    render a markdown suggestion block. Keeps synthesis anchored to primary
    material instead of model memory (self-learning loop, item 2)."""
    sources = load_sources()
    if not sources:
        return ""
    tokens = {t for t in name.lower().replace("-", "_").split("_") if len(t) > 2}
    scored = []
    for s in sources:
        cats = s.get("category", [])
        score = 0
        if category in cats:
            score += 10
        tags = {t.lower() for t in s.get("tags", [])}
        score += 4 * len(tokens & tags)
        blob = f"{s.get('title', '')} {s.get('note', '')}".lower()
        score += sum(1 for t in tokens if t in blob)
        if score > 0:
            scored.append((score, s))
    scored.sort(key=lambda pair: pair[0], reverse=True)

    top = [s for _, s in scored[:limit]]
    if not top:
        # Always show at least the universal anchors for the category.
        top = [s for s in sources if category in s.get("category", [])][:limit]
    if not top:
        return ""

    lines = [
        "",
        "## 📚 Built-in Research Library (consult these FIRST — primary material)",
        "",
    ]
    for s in top:
        authors = ", ".join(s.get("authors", [])) or "community"
        lines.append(f"- **{s['title']}** — {authors} · <{s['url']}>")
        if s.get("note"):
            lines.append(f"  - {s['note']}")
    lines.append("")
    lines.append(
        "Fold these into the methodology below; retain every source link you use. "
        "If these are insufficient, request more URLs from the operator (step 2)."
    )
    return "\n".join(lines)


def save_researched_playbook(category: str, name: str, content: str, author: str = "Synthesized Tradecraft") -> Path:
    """Saves newly researched tradecraft into the local playbook repository."""
    target_path = get_playbook_path(category, name)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    header = f"# Micro-Playbook: {name.replace('_', ' ').title()}\n"
    header += f"**Practitioner / Methodology:** {author}\n"
    header += f"**Category:** {category}\n\n"

    target_path.write_text(header + content.strip())
    return target_path


def _normalize_url(url: str) -> str:
    """Canonical key for dedup: lowercase scheme+host, no trailing slash/fragment."""
    u = (url or "").strip()
    u = u.split("#", 1)[0]
    u = u.rstrip("/")
    return u.lower()


def export_urls(category: str = "", pending_only: bool = False) -> Path:
    """(Re)generate knowledge/methodology_urls.txt deterministically from the
    curated registry, so the flat feed list never drifts from sources.json.
    Grouped by first category, one URL per line, `#` title/section comments.
    When pending_only, sources that already have a playbook on disk are omitted
    (a shrinking to-do feed)."""
    from collections import OrderedDict

    sources = load_sources()
    groups = OrderedDict()
    for s in sources:
        cats = s.get("category") or ["misc"]
        if category and category not in cats:
            continue
        if pending_only and source_is_built(s):
            continue
        groups.setdefault(cats[0], []).append(s)

    total = sum(len(v) for v in groups.values())
    lines = [
        "# Artifactory methodology source URLs",
        "# ------------------------------------",
        "# One authoritative source per line. Feed this list to the framework",
        "# from OpenCode with `/artifactory research` to turn each into a",
        "# parameterized .md playbook (fetch -> quality-gate -> approval -> save).",
        "# Lines starting with # are comments and are skipped on ingest.",
        "# Regenerate with: playbook_engine.py --export-urls [--category <cat>]",
        f"# Generated from knowledge/sources.json ({total} sources).",
        "",
    ]
    for cat, items in groups.items():
        lines.append(f"# --- {cat} ---")
        for s in items:
            url = (s.get("url") or "").strip()
            title = (s.get("title") or "").strip()
            if url:
                if title:
                    lines.append(f"# {title}")
                lines.append(url)
        lines.append("")

    METHODOLOGY_URLS_FILE.parent.mkdir(parents=True, exist_ok=True)
    METHODOLOGY_URLS_FILE.write_text("\n".join(lines).rstrip() + "\n")
    return METHODOLOGY_URLS_FILE


def add_source(url: str, title: str, category: str, authors=None, tags=None,
               note: str = "", stype: str = "writeup", force: bool = False) -> tuple[bool, str]:
    """Append one source to sources.json with URL-based dedup. Returns
    (changed, message). Pure local write — no network."""
    if not (url and title and category):
        return False, "url, title and category are all required"
    try:
        doc = json.loads(SOURCES_FILE.read_text())
    except Exception as e:
        return False, f"cannot read {SOURCES_FILE}: {e}"

    sources = doc.setdefault("sources", [])
    key = _normalize_url(url)
    for s in sources:
        if _normalize_url(s.get("url", "")) == key:
            if not force:
                return False, f"duplicate URL already in registry (id={s.get('id')}); use --force to overwrite"
            s.update({
                "title": title,
                "url": url.strip(),
                "authors": authors or s.get("authors", []),
                "category": [category] if isinstance(category, str) else category,
                "tags": tags or s.get("tags", []),
                "note": note or s.get("note", ""),
                "type": stype or s.get("type", "writeup"),
            })
            doc["updated"] = date.today().isoformat()
            SOURCES_FILE.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
            return True, f"overwrote existing source id={s.get('id')}"

    # New entry. Derive a stable id from the title.
    base_id = title.lower().replace(" ", "-")
    base_id = "".join(c for c in base_id if c.isalnum() or c == "-").strip("-")[:48] or "source"
    existing_ids = {s.get("id") for s in sources}
    new_id, n = base_id, 2
    while new_id in existing_ids:
        new_id = f"{base_id}-{n}"
        n += 1

    sources.append({
        "id": new_id,
        "title": title.strip(),
        "url": url.strip(),
        "authors": authors or [],
        "category": [category] if isinstance(category, str) else category,
        "tags": tags or [],
        "note": note,
        "type": stype or "writeup",
    })
    doc["updated"] = date.today().isoformat()
    SOURCES_FILE.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    return True, f"added source id={new_id}"


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
    sources_block = suggest_sources(category, name)
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
{sources_block}
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
    parser.add_argument("--category", "-c", required=False, default=None,
                        help="Playbook/library category (playbooks: recon|web|auth|infra|logic|chaining|sast; library also has intel|learning)")
    parser.add_argument("--name", "-n", required=False, default=None,
                        help="Playbook name (e.g., graphql_idor, s3_bucket_leak)")
    parser.add_argument("--author", "-a", default="Industry Specialist", help="Author/Practitioner reference")
    parser.add_argument("--target", "-t", default="", help="Target URL/Host for dynamic parameter substitution")
    parser.add_argument("--auth-token", default="", help="Optional Bearer token for variable substitution")
    parser.add_argument("--save-content", help="Directly save newly synthesized playbook content")
    parser.add_argument("--list-sources", action="store_true", dest="list_sources",
                        help="Print the built-in research library (optionally filtered by --category)")
    parser.add_argument("--sources-json", action="store_true", dest="sources_json",
                        help="Print the research library as compact JSON (for /artifactory research)")
    parser.add_argument("--export-urls", action="store_true", dest="export_urls",
                        help="(Re)generate knowledge/methodology_urls.txt from sources.json")
    parser.add_argument("--pending", action="store_true",
                        help="With --sources-json/--export-urls: emit ONLY sources whose playbook does not yet exist on disk (token-efficient worklist)")
    parser.add_argument("--add-source", dest="add_source_url", default=None,
                        help="Add a source URL to the registry (requires --title + --category)")
    parser.add_argument("--title", default=None, help="Title for --add-source")
    parser.add_argument("--authors", default="", help="Comma-separated authors for --add-source")
    parser.add_argument("--tags", default="", help="Comma-separated tags for --add-source")
    parser.add_argument("--note", default="", help="Short note for --add-source")
    parser.add_argument("--source-type", default="writeup", help="Source type for --add-source")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing source URL on --add-source")

    args = parser.parse_args()

    if args.sources_json:
        sources = load_sources()
        out = []
        for s in sources:
            if args.category and args.category not in s.get("category", []):
                continue
            built = source_is_built(s)
            if args.pending and built:
                continue
            cats = s.get("category") or ["misc"]
            out.append(
                {"id": s.get("id"), "title": s.get("title"), "url": s.get("url"),
                 "category": s.get("category", []), "authors": s.get("authors", []),
                 "tags": s.get("tags", []),
                 "save_category": cats[0], "save_name": s.get("id") or s.get("title"),
                 "playbook": str(playbook_path_for_source(s).relative_to(PROMPTS_DIR.parent)),
                 "built": built}
            )
        print(json.dumps(out, ensure_ascii=False))
        sys.exit(0)

    if args.add_source_url:
        if not args.title or not args.category:
            parser.error("--add-source requires --title and --category")
        authors = [a.strip() for a in args.authors.split(",") if a.strip()]
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
        changed, msg = add_source(
            args.add_source_url, args.title, args.category,
            authors=authors, tags=tags, note=args.note,
            stype=args.source_type, force=args.force,
        )
        print(f"[{'✔' if changed else '!'}] {msg}")
        if changed:
            path = export_urls()
            print(f"[✔] Reflowed URL list: {path}")
        sys.exit(0 if changed else 1)

    if args.export_urls:
        path = export_urls(args.category or "", pending_only=args.pending)
        print(f"[✔] Wrote {path}")
        sys.exit(0)

    if args.list_sources:
        sources = load_sources()
        for s in sources:
            if args.category and args.category not in s.get("category", []):
                continue
            authors = ", ".join(s.get("authors", [])) or "community"
            print(f"- [{','.join(s.get('category', []))}] {s['title']} — {authors}\n  {s['url']}")
        print(f"\n({len(sources)} entries in {SOURCES_FILE})")
        sys.exit(0)

    if not args.category or not args.name:
        parser.error("--category and --name are required unless --list-sources is used")

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