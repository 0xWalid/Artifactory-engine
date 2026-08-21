#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Background Triage & Scout Brain

Digests raw command artifacts into ranked *leads* on board.json so the
expensive operator model never has to read the firehose of tool output.

Two layers, in order:
  1. Deterministic extractors (free, instant, no model): parse endpoints,
     ports, subdomains, tech banners and high-signal anomalies out of the log.
  2. Optional "Scout" model (cheap/free, OpenAI-compatible, provider-agnostic):
     ranks/annotates the extracted candidates. Controlled by .blackboard/scout.json.
     If disabled or unreachable, deterministic leads are still saved.

Nothing here blocks the operator: it runs inline for sync commands and inside
the detached child for backgrounded ones.
"""

import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SCOUT_FILE = BLACKBOARD_DIR / "scout.json"

# High-signal substrings that turn a line into an "anomaly" lead outright.
ANOMALY_SIGNALS = [
    ("traceback (most recent call last)", "python stack trace leaked"),
    ("exception in thread", "java exception leaked"),
    ("sql syntax", "SQL error - possible SQLi"),
    ("you have an error in your sql", "SQL error - possible SQLi"),
    ("root:x:0:0", "/etc/passwd contents - possible LFI/traversal"),
    ("begin rsa private key", "private key material exposed"),
    ("begin openssh private key", "private key material exposed"),
    ("aws_secret_access_key", "AWS secret leaked"),
    ("authorization: bearer", "bearer token in output"),
    ("set-cookie", "session cookie observed"),
    ("index of /", "directory listing enabled"),
    ("debug = true", "debug mode enabled"),
]


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def read_artifact(pointer_id: str):
    """Returns (command, stdout, stderr) for a pointer, or (None, None, None)."""
    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"
    if not artifact_path.exists():
        return None, None, None
    raw = artifact_path.read_text()

    def _section(tag, nxt):
        pat = rf"--- {tag} ---\n(.*?)(?=\n--- {nxt} ---|\Z)" if nxt else rf"--- {tag} ---\n(.*)"
        m = re.search(pat, raw, re.DOTALL)
        return m.group(1).strip() if m else ""

    cmd = _section("COMMAND", "STDOUT")
    stdout = _section("STDOUT", "STDERR")
    stderr = _section("STDERR", None)
    return cmd, stdout, stderr


def _mklead(ltype, value, signal, pointer_id, confidence=0.4, suggested_next=""):
    return {
        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
        "type": ltype,
        "value": value,
        "signal": signal,
        "confidence": confidence,
        "suggested_next": suggested_next,
        "source_pointer": pointer_id,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def deterministic_extract(cmd: str, stdout: str, stderr: str, pointer_id: str) -> list:
    """Parse structured/known tool output into leads without any model call."""
    leads = []
    combined = f"{stdout}\n{stderr}"
    lines = stdout.splitlines()

    # --- nmap open ports:  "80/tcp   open  http" ---
    for m in re.finditer(r"(?m)^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", stdout):
        port, proto, svc = m.group(1), m.group(2), m.group(3)
        leads.append(_mklead(
            "port", f"{port}/{proto} ({svc})",
            f"open {svc} service", pointer_id, 0.5,
            f"probe the {svc} service on port {port}",
        ))

    # --- ffuf / gobuster / feroxbuster / httpx JSON-ish endpoint discovery ---
    for line in lines:
        s = line.strip()
        # JSON object lines with a url/input/path key
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
            except Exception:
                obj = None
            if isinstance(obj, dict):
                url = obj.get("url") or obj.get("input") or obj.get("path")
                status = obj.get("status") or obj.get("status_code")
                if url:
                    leads.append(_mklead(
                        "endpoint", str(url),
                        f"discovered path (status {status})" if status else "discovered path",
                        pointer_id, 0.45, "fuzz params / test this endpoint",
                    ))
                    continue
        # gobuster-style "/admin  (Status: 200)"
        gm = re.match(r"^(/\S*)\s+\(Status:\s*(\d{3})\)", s)
        if gm:
            leads.append(_mklead(
                "endpoint", gm.group(1),
                f"discovered path (status {gm.group(2)})",
                pointer_id, 0.45, "fuzz params / test this endpoint",
            ))

    # --- subdomains (subfinder/amass): bare host-only lines ---
    for line in lines:
        s = line.strip()
        if re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+\.[a-z]{2,}", s, re.I):
            leads.append(_mklead(
                "subdomain", s, "resolved subdomain", pointer_id, 0.4,
                "resolve + probe this host for its own surface",
            ))

    # --- tech / version banners ---
    for m in re.finditer(r"(?im)^(?:Server|X-Powered-By):\s*(.+)$", combined):
        leads.append(_mklead(
            "tech", m.group(1).strip(), "server/framework banner", pointer_id, 0.35,
            "map known CVEs / default paths for this stack",
        ))

    # --- high-signal anomalies (case-insensitive substring hits) ---
    low = combined.lower()
    for needle, meaning in ANOMALY_SIGNALS:
        if needle in low:
            leads.append(_mklead(
                "anomaly", meaning, needle, pointer_id, 0.8,
                "confirm + escalate this signal into a finding",
            ))

    return leads


def scout_rank(candidates: list, scout_cfg: dict) -> dict:
    """
    Optional cheap-model pass. Sends ONLY the compact candidate list (never the
    raw log) and asks for a ranking. Returns {value: {confidence, suggested_next}}.
    Fails silent -> deterministic leads stand on their own.
    """
    import os
    import urllib.request

    if not scout_cfg.get("enabled"):
        return {}

    api_key = os.environ.get(scout_cfg.get("api_key_env", ""), "")
    base_url = (scout_cfg.get("base_url") or "").rstrip("/")
    model = scout_cfg.get("model")
    if not (api_key and base_url and model):
        return {}

    # Compact payload: type + value + signal only. Keeps request tiny.
    compact = [
        {"value": c["value"], "type": c["type"], "signal": c["signal"]}
        for c in candidates[: scout_cfg.get("max_leads_per_triage", 8)]
    ]
    system = (
        "You are a penetration-testing triage scout. Given discovered items from a "
        "scan, return ONLY a compact JSON array. Each element: "
        '{"value": <the item value verbatim>, "confidence": <0.0-1.0 how likely '
        'this leads to a real vuln>, "suggested_next": <one concrete next test, '
        "terse>}. No prose, no markdown fences."
    )
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(compact)},
        ],
        "temperature": 0.2,
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        timeout = scout_cfg.get("request_timeout", 20)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        content = data["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?|```$", "", content, flags=re.M).strip()
        ranked = json.loads(content)
        out = {}
        for r in ranked:
            if isinstance(r, dict) and "value" in r:
                out[str(r["value"])] = {
                    "confidence": r.get("confidence"),
                    "suggested_next": r.get("suggested_next"),
                }
        return out
    except Exception as e:
        print(f"[!] Scout model skipped ({e}); using deterministic leads only.",
              file=sys.stderr)
        return {}


def triage_pointer(pointer_id: str):
    if not BOARD_FILE.exists():
        print(f"[!] Triage: {BOARD_FILE} not found; run init_env.py first.", file=sys.stderr)
        return

    cmd, stdout, stderr = read_artifact(pointer_id)
    if cmd is None:
        print(f"[!] Triage: artifact {pointer_id} not found.", file=sys.stderr)
        return

    candidates = deterministic_extract(cmd, stdout or "", stderr or "", pointer_id)
    if not candidates:
        return

    # Optional cheap-model ranking pass (fails silent).
    ranked = scout_rank(candidates, load_json(SCOUT_FILE))
    for lead in candidates:
        hit = ranked.get(lead["value"])
        if hit:
            if isinstance(hit.get("confidence"), (int, float)):
                lead["confidence"] = round(float(hit["confidence"]), 2)
            if hit.get("suggested_next"):
                lead["suggested_next"] = hit["suggested_next"]

    board = load_json(BOARD_FILE)
    existing = board.setdefault("leads", [])
    seen = {(l.get("type"), l.get("value")) for l in existing}
    added = 0
    for lead in candidates:
        key = (lead["type"], lead["value"])
        if key in seen:
            continue
        seen.add(key)
        existing.append(lead)
        added += 1

    if added:
        existing.sort(key=lambda l: l.get("confidence", 0), reverse=True)
        board["updated_at"] = datetime.now(timezone.utc).isoformat()
        BOARD_FILE.write_text(json.dumps(board, indent=2))
        top = existing[0]
        print(f"[+] Triage [{pointer_id}]: +{added} lead(s). "
              f"Top: [{top['type']}] {top['value']} (conf {top.get('confidence')})")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SBA Background Triage / Scout")
    parser.add_argument("--pointer", "-p", required=True, help="Artifact pointer ID to triage")
    args = parser.parse_args()
    triage_pointer(args.pointer)



