#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Artifact Secret Scanner

Deterministic trufflehog-style sweep over .blackboard/artifacts/: the raw
evidence you already collected gets re-mined for credentials/keys/tokens you
may have captured incidentally. A response that happened to contain a
cloud key, a JWT, or a connection string is a FINDING-SEED, not noise.

  * `scan`  — regex secret families over every artifact; hits become
               must_verify `anomaly` leads with pointer+line attribution.
               Deduped per secret VALUE across the whole history (the same
               leaked token in 40 artifacts is one lead, not forty).
  * Report-safe: this scanner does NOT exfiltrate anything — it files leads;
               the operator pulls the exact artifact via inspect (redacted).

Zero model tokens. Designed to run at engagement close (debrief) and
mid-engagement after heavy collection passes.
"""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"

# (family, regex) — ordered, most-specific first. Values must be long/structured
# enough to avoid routine false positives.
SECRET_FAMILIES = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("connection-string", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(\+srv)?|redis|mssql|amqp)://[^\s\"'<>]{10,}\b")),
    ("bearer-credential", re.compile(
        r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9\-._~+/=]{16,}")),
    ("basic-auth", re.compile(
        r"(?i)\bauthorization:\s*basic\s+[A-Za-z0-9+/=]{12,}")),
    ("env-secret", re.compile(
        r"(?i)\b(DB_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET_ACCESS_KEY|SMTP_PASS)\s*[=:]\s*['\"]?[^\s'\"]{8,}")),
]


def scan_artifacts(limit_per_family=5):
    if not ARTIFACTS_DIR.exists():
        print("[*] No artifacts yet — run some commands first.")
        return
    board = load_json(BOARD_FILE)
    existing = {str(l.get("value", "")) for l in (board or {}).get("leads", [])}
    existing_values = {str(l.get("value", "")) for l in (board or {}).get("leads", [])}

    seen_values = set()  # dedup by SECRET VALUE across all artifacts
    hits = []  # (family, value, pointer, line_no)
    for art in sorted(ARTIFACTS_DIR.glob("*.log")):
        text = art.read_text(errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            for family, rx in SECRET_FAMILIES:
                m = rx.search(line)
                if not m:
                    continue
                value = m.group(0)
                key = (family, value)
                if key in seen_values:
                    continue
                seen_values.add(key)
                hits.append((family, value, art.stem, i))
                break

    if not hits:
        print("[*] No secret-shaped material found in artifacts.")
        return

    leads = []
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    counts = {}
    for family, value, art, line in hits:
        counts[family] = counts.get(family, 0) + 1
        lead_value = f"artifact secret: {family}"
        if lead_value in existing_values:
            continue  # one lead per family keeps the board clean
        leads.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "anomaly",
            "value": lead_value,
            "signal": f"{value[:60]}... in {art}:{line}",
            "confidence": 0.75,
            "suggested_next": f"verify in context: inspect --id {art} — is this a REAL "
                              f"credential (test validity, provenance) or lab/sample data?",
            "must_verify": True,
            "preconditions": [],
            "source_pointer": art,
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)

    # Master log artifact (the pointer everyone inspects)
    (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
        "--- COMMAND ---\nsecrets.py scan (deterministic)\n\n--- STDOUT ---\n"
        + "\n".join(f"{fam}: {val[:80]} ({art}:{line})" for fam, val, art, line in hits)
        + "\n\n--- STDERR ---\n")

    print(f"[✔] {len(hits)} secret-shaped hit(s) across {len(counts)} famil(ies):")
    for fam, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {fam}: {n}")
    if leads:
        print(f"    {len(leads)} new anomaly lead(s) filed (one per family; "
              f"master log: {pointer_id}).")
    else:
        print("    (families already had leads on the board)")
    print("    Values are redacted from context; pull exact lines with: "
          f"sec_flow.py inspect --id {pointer_id} --grep '<family>'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Artifact secret scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="Sweep artifacts for secret-shaped material -> anomaly leads")
    args = parser.parse_args()
    scan_artifacts()
