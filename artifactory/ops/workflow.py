#!/usr/bin/env python3
"""
Artifactory workflow loader — the docs-side dispatcher.

`/artifactory <name> [args]` (one OpenCode command) routes here: the agent runs
`art.py workflow <name>` and this prints the matching workflows/<name>.md body,
with the {{ART}} placeholder resolved to the absolute dispatcher path. Only the
requested workflow is loaded — the token win that replaced the ~30KB monolith.
Unknown/empty name prints the capability index (catalog) plus usage.
"""

import sys
from pathlib import Path


def _find_engine_root():
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent.parent


_ENGINE_ROOT = _find_engine_root()
WORKFLOWS_DIR = _ENGINE_ROOT / "workflows"
ART = f"python3 {_ENGINE_ROOT / 'art.py'}"


def _render(md_path: Path) -> str:
    return md_path.read_text(encoding="utf-8").replace("{{ART}}", ART)


def _names():
    if not WORKFLOWS_DIR.is_dir():
        return []
    return sorted(p.stem for p in WORKFLOWS_DIR.glob("*.md"))


def main(argv):
    name = argv[1].strip().lower() if len(argv) > 1 and argv[1].strip() else ""
    target = WORKFLOWS_DIR / f"{name}.md" if name else None

    if target and target.is_file():
        sys.stdout.write(_render(target))
        return 0

    # Unknown/empty: usage + index (catalog body if present).
    names = _names()
    if name:
        print(f"[!] Unknown workflow: '{name}'. Available: {', '.join(names) or '(none)'}\n")
    print("Usage: /artifactory <workflow> [args]")
    print(f"Workflows: {', '.join(names) or '(none found)'}\n")
    catalog = WORKFLOWS_DIR / "catalog.md"
    if catalog.is_file():
        sys.stdout.write(_render(catalog))
    return 0 if names else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
