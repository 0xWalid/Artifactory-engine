#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Patch-Diff 1-Day Variant Engine

The plan's 1-day loop, deterministic part: given a security-fix COMMIT DIFF
(or advisory text) for an upstream project, extract WHAT the bug class was
(sink patterns, vulnerable-call shapes) and emit concrete VARIANT-HUNT
commands that sweep your in-scope target for the same bug family
("same bug, different sink").

Zero model tokens: sink extraction is regex/heuristic over the diff text.
The LLM (exploit agent) only reads the short hunt list this produces.

Inputs: --diff <file with a git diff / patch>  OR --text "<advisory text>"
        --project <name>  (for labeling leads)
Outputs: variant-hunt leads on the board + printed hunt commands
"""

import argparse
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()

# Bug-class signatures: (class name, regexes that indicate it in diff/advisory
# text, hunt command template with {SINK}/{PROJECT}).
BUG_CLASSES = [
    ("path-traversal",
     [r"\.\./", r"resolvePath", r"normalize.*path", r"sanitize.*path", r"path\.join",
      r"realpath", r"traversal"],
     "grep -rn --include='*.{SINK_EXT}' -E '{SINK}' <code-path> | head -40"),
    ("ssrf",
     [r"urlopen", r"requests\.get", r"fetch\(", r"http\.client", r"URL\s*=.*input",
      r"curl_exec", r"HttpGet"],
     "grep -rn --include='*.{SINK_EXT}' -E '{SINK}' <code-path> | head -40"),
    ("sql-injection",
     [r"SELECT .*\+", r"query\(.*\+", r"execute\(.*\+", r"concat.*query", r"LIKE.*\+"],
     "grep -rn --include='*.{SINK_EXT}' -E '{SINK}' <code-path> | head -40"),
    ("command-injection",
     [r"os\.system", r"subprocess", r"exec\(", r"popen", r"Runtime\.getRuntime",
      r"shell_exec"],
     "grep -rn --include='*.{SINK_EXT}' -E '{SINK}' <code-path> | head -40"),
    ("xss",
     [r"innerHTML", r"document\.write", r"\bv-html\b", r"dangerouslySetInnerHTML",
      r"\|safe\b"],
     "grep -rn --include='*.{SINK_EXT}' -E '{SINK}' <code-path> | head -40"),
    ("deserialization",
     [r"pickle\.loads", r"unserialize", r"ObjectInputStream", r"yaml\.load",
      r"readObject"],
     "grep -rn --include='*.{SINK_EXT}' -E '{SINK}' <code-path> | head -40"),
]

# File extensions considered per project language guess (from the diff paths).
LANG_EXTS = {
    "py": ["py"], "js": ["js", "jsx", "ts", "tsx"], "java": ["java"],
    "php": ["php"], "go": ["go"], "rb": ["rb"], "cs": ["cs"],
}


def _guess_ext(diff_text: str) -> str:
    exts = re.findall(r"^diff --git a/.+?\.(py|js|jsx|ts|tsx|java|php|go|rb|cs)b/", diff_text, re.M)
    if not exts:
        exts = re.findall(r"^\+\+\+ b/.+?\.(py|js|jsx|ts|tsx|java|php|go|rb|cs)$", diff_text, re.M)
    if not exts:
        return "py|js|php|java"
    # single most common
    counts = {}
    for e in exts:
        counts[e] = counts.get(e, 0) + 1
    top = max(counts, key=counts.get)
    return "|".join(LANG_EXTS.get(top, [top]))


def extract_sinks(text: str, project: str):
    """Map diff/advisory text -> bug classes + the exact sink strings that
    fired. Deterministic; returns [(class, [sink regexes])] in priority order."""
    hits = []
    for cls, pats, _ in BUG_CLASSES:
        matched = [p for p in pats if re.search(p, text)]
        if matched:
            hits.append((cls, matched))
    return hits


def run_patch_diff(diff_file=None, text="", project="project"):
    src = ""
    if diff_file:
        p = Path(diff_file)
        if not p.exists():
            print(f"[!] Diff file '{diff_file}' not found.", file=sys.stderr)
            sys.exit(1)
        src = p.read_text()
    if text:
        src += "\n" + text
    if not src.strip():
        print("[!] Provide --diff <file> and/or --text '<advisory>'.", file=sys.stderr)
        sys.exit(1)

    ext = _guess_ext(src)
    hits = extract_sinks(src, project)
    if not hits:
        print("[*] No known bug-class signatures in this diff — nothing to hunt. "
              "(Deterministic pass only; route complex cases to synthesis.)")
        return

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    print(f"[*] Patch-diff analysis for '{project}' — {len(hits)} bug-class signal(s):\n")
    for cls, sinks in hits:
        sink_alt = "|".join(re.escape(s) for s in sinks[:3])
        cmd = (f"grep -rn --include='*.({ext})' -E '{sink_alt}' <code-path> | head -40")
        # the actual variant hunt: same class, EVERYWHERE in the codebase
        leads.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "cve",
            "value": f"variant hunt: {cls} family from {project} patch",
            "signal": f"sinks: {', '.join(sinks[:3])}",
            "confidence": 0.5,
            "suggested_next": cmd,
            "must_verify": True,
            "preconditions": [],
            "source_pointer": pointer_id,
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        print(f"  [{cls}] sinks: {', '.join(sinks[:3])}")
        print(f"      hunt: {cmd}\n")

    (BLACKBOARD_DIR / "artifacts").mkdir(parents=True, exist_ok=True)
    (BLACKBOARD_DIR / "artifacts" / f"{pointer_id}.log").write_text(
        f"--- COMMAND ---\npatch_diff.py --project {project}\n\n"
        f"--- STDOUT ---\nclasses: {', '.join(c for c, _ in hits)}\n\n--- STDERR ---\n")
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
    print(f"[✔] {len(leads)} variant-hunt lead(s) on the board (pointer {pointer_id}).")
    print("    The exploit agent runs the hunt commands; the verifier proves survivors.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patch-Diff 1-Day Variant Engine")
    parser.add_argument("--diff", dest="diff_file", default=None,
                        help="File containing the upstream security-fix diff")
    parser.add_argument("--text", default="", help="Advisory text (second signal)")
    parser.add_argument("--project", default="project", help="Upstream project name")
    args = parser.parse_args()
    run_patch_diff(args.diff_file, args.text, args.project)
