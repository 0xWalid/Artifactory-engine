#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Burp Suite Bridge

For Burp-first operators: your manual Burp work becomes engine-readable state
at zero token cost, and (when Burp Pro's REST API is enabled) the engine can
drive scans directly. Works with ANY Burp edition for the export flows.

Three entry points:

  1. ingest-history  --file <proxy-history-export.xml>
     Burp: Proxy -> HTTP history -> select items -> right-click -> "Save items".
     The XML is parsed into: endpoint leads (unique paths), raw request/
     response artifacts (MSG_ pointers — verifiable evidence for later), and an
     endpoints.txt inventory ready for role-diff. Out-of-scope hosts in the
     history are FLAGGED, never silently dropped.
     Workflow: browse the app as the BASELINE (highest-privilege) role through
     Burp, export, ingest — role-diff then replays your captured surface
     across every other role.

  2. ingest-issues   --file <scanner-issues-export.xml>
     Burp Pro: export Scanner issues as XML. Each issue becomes a must_verify
     lead (scanner candidates are never findings — the verification gate
     applies).

  3. scan             --target <url> [--api-host 127.0.0.1 --api-port 1337]
     Requires Burp Pro with the REST API enabled. Launches a scan, polls to
     completion, files issues as must_verify leads. API unreachable -> a
     coverage-gap lead is filed instead of silent skipping.
"""

import argparse
import base64
import json
import re
import shlex
import subprocess
import sys
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402
from scope_sig import verify_scope, tamper_notice  # noqa: E402
from sec_flow import is_target_in_scope, ensure_blackboard_dirs  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"

SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low",
                "information": "info", "informational": "info"}


def _mklead(ltype, value, signal, pointer_id, confidence=0.4, suggested_next="",
            must_verify=False):
    return {
        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
        "type": ltype,
        "value": value,
        "signal": signal,
        "confidence": confidence,
        "suggested_next": suggested_next,
        "must_verify": must_verify,
        "preconditions": [],
        "source_pointer": pointer_id,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _maybe_b64(data: str) -> str:
    """Burp 'Save items' base64-encodes request/response by default; the
    operator may also have chosen raw. Detect and decode."""
    s = (data or "").strip()
    if not s:
        return s
    try:
        decoded = base64.b64decode(s, validate=True).decode("utf-8", "replace")
        # A Burp request/response starts with a method line / HTTP status line
        if re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP/)", decoded):
            return decoded
    except Exception:
        pass
    return s


def _write_artifact(pointer_id: str, content: str):
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(content)


def _record_pointer(board, pointer_id: str, summary: str, command: str):
    board.setdefault("execution_log_pointers", []).append({
        "pointer_id": pointer_id,
        "command": command,
        "return_code": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
    })


def _parse_history_items(xml_text: str):
    """Yield dicts from Burp's Save-items XML. Tolerant parsing: <item> blocks,
    optional base64 request/response."""
    items = []
    for block in re.findall(r"<item>(.*?)</item>", xml_text, re.DOTALL):

        def field(name):
            m = re.search(rf"<{name}>(.*?)</{name}>", block, re.DOTALL)
            return m.group(1).strip() if m else ""

        items.append({
            "host": field("host"),
            "port": field("port"),
            "protocol": field("protocol"),
            "method": field("method"),
            "url": field("url"),
            "request": _maybe_b64(field("request")),
            "response": _maybe_b64(field("response")),
            "status": field("status"),
        })
    return items


def ingest_history(file: str, out_file: str = "endpoints.txt", role: str = "baseline"):
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    p = Path(file)
    if not p.exists():
        print(f"[!] Export file '{file}' not found.", file=sys.stderr)
        sys.exit(1)
    items = _parse_history_items(p.read_text(errors="replace"))
    if not items:
        print("[!] No <item> entries found — is this a Burp 'Save items' export?",
              file=sys.stderr)
        sys.exit(1)

    scope = load_json(SCOPE_FILE)
    endpoints, leads, skipped = [], [], []
    seen_paths = set()
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"

    for it in items:
        host, url = it["host"], it["url"]
        if host and not is_target_in_scope(f"{it['protocol']}://{host}:{it['port']}"
                                           if it["port"] not in ("80", "443") else host, scope):
            skipped.append(f"{it['method']} {url}")
            continue
        # unique path per host
        m = re.match(r"https?://[^/]+(/[^?#]*)", url or "")
        path = m.group(1) if m else (url or "")
        key = f"{host}{path}"
        if key in seen_paths:
            continue
        seen_paths.add(key)
        endpoints.append((host, path, it["method"], it["status"]))

    # One artifact holds the full captured traffic (evidence for the verifier).
    traffic = []
    for it in items[:500]:
        traffic.append(f"=== {it['method']} {it['url']} [status {it['status']}] ===")
        if it["request"]:
            traffic.append("--- request ---\n" + it["request"][:4000])
        if it["response"]:
            traffic.append("--- response ---\n" + it["response"][:4000])
    _write_artifact(pointer_id,
                    f"--- COMMAND ---\nburp_bridge ingest-history {file}\n\n"
                    f"--- STDOUT ---\n" + "\n".join(traffic) + "\n\n--- STDERR ---\n")

    for host, path, method, status in endpoints:
        leads.append(_mklead(
            "endpoint", path,
            f"burp history: {method} -> {status} on {host}",
            pointer_id, 0.5, "include in role-diff inventory; fuzz params",
        ))
    if skipped:
        leads.append(_mklead(
            "anomaly", f"{len(skipped)} out-of-scope host entries in Burp history",
            "history contains hosts NOT authorized in scope.json — skipped, listed in signal",
            pointer_id, 0.2, "confirm whether these hosts should be in scope (do not approve blindly)",
        ))

    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            _record_pointer(board, pointer_id,
                            f"burp history ingest: {len(endpoints)} endpoint(s), "
                            f"{len(skipped)} out-of-scope skip(s)", f"burp_bridge ingest-history {file}")

    out = Path(out_file)
    out.write_text("\n".join(path for _, path, _, _ in endpoints) + "\n")

    print(f"[✔] Ingested {len(items)} Burp history item(s):")
    print(f"    {len(endpoints)} unique endpoint(s) -> endpoint leads (pointer {pointer_id})")
    print(f"    {len(skipped)} out-of-scope item(s) flagged (never silently dropped)")
    print(f"    Inventory written: {out} — feed to role-diff as the BASELINE surface.")
    print(f"    Raw traffic stored as verifiable evidence: inspect --id {pointer_id}")
    if skipped:
        print("    Out-of-scope (skipped):")
        for s in skipped[:5]:
            print(f"      {s}")


def ingest_issues(file: str):
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    p = Path(file)
    if not p.exists():
        print(f"[!] Export file '{file}' not found.", file=sys.stderr)
        sys.exit(1)
    xml = p.read_text(errors="replace")
    issues = []
    for block in re.findall(r"<issue>(.*?)</issue>", xml, re.DOTALL):

        def field(name):
            m = re.search(rf"<{name}><!\[CDATA\[(.*?)\]\]></{name}>|<{name}>(.*?)</{name}>",
                          block, re.DOTALL)
            return (m.group(1) or m.group(2) or "").strip() if m else ""

        issues.append({
            "name": field("name"),
            "severity": field("severity").lower(),
            "url": field("url") or field("host"),
            "detail": field("issue_detail") or field("detail"),
        })
    if not issues:
        print("[!] No <issue> entries found — export Scanner issues as XML.", file=sys.stderr)
        sys.exit(1)

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    sev_counts = {}
    leads = []
    for iss in issues:
        sev = SEVERITY_MAP.get(iss["severity"], "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        leads.append(_mklead(
            "cve", f"burp scanner: {iss['name'][:100]}",
            f"scanner issue ({sev}) on {iss['url'][:80]}",
            pointer_id, 0.5 if sev in ("high", "medium") else 0.3,
            "verify manually — scanner candidates are never findings (verification gate applies)",
            must_verify=True,
        ))
    _write_artifact(pointer_id,
                    f"--- COMMAND ---\nburp_bridge ingest-issues {file}\n\n"
                    f"--- STDOUT ---\n" + "\n".join(
                        f"[{i['severity']}] {i['name']} @ {i['url']}\n{i['detail'][:2000]}"
                        for i in issues) + "\n\n--- STDERR ---\n")
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            _record_pointer(board, pointer_id, f"burp issues ingest: {len(issues)} issue(s)",
                            f"burp_bridge ingest-issues {file}")

    print(f"[✔] Ingested {len(issues)} Burp scanner issue(s) as must_verify leads "
          f"({', '.join(f'{k}={v}' for k, v in sorted(sev_counts.items()))}).")
    print(f"    Evidence artifact: inspect --id {pointer_id}")
    print("    Work them: sec_flow.py leads --type cve")


def _api_call(base: str, path: str, method="GET", body=None, timeout=15):
    url = f"{base}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def api_scan(target: str, api_host: str = "127.0.0.1", api_port: int = 1337):
    """Burp Pro REST API path (v0.1). Scan the target, poll, pull issues as
    must_verify leads. API off/unreachable -> coverage-gap lead (no silent drop)."""
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    if not is_target_in_scope(target, load_json(SCOPE_FILE)):
        print(f"[!] SCOPE ERROR: '{target}' not in scope.json.", file=sys.stderr)
        sys.exit(1)

    base = f"http://{api_host}:{api_port}/v0.1"
    try:
        scan = _api_call(base, "/scan", method="POST", body={
            "scan_type": "pulse",
            "scope": {"include": [{"rule": re.escape(target) + ".*"}]},
        }, timeout=10)
    except Exception as e:
        pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
        _write_artifact(pointer_id,
                        f"--- COMMAND ---\nburp_bridge scan {target}\n\n--- STDOUT ---\n"
                        f"Burp REST API unreachable at {base} ({e})\n\n--- STDERR ---\n")
        with json_transaction("board.json", create=True) as board:
            if board is not None:
                board.setdefault("leads", []).append(_mklead(
                    "cve", "Burp REST scan (COVERAGE GAP)",
                    f"API unreachable at {base} — enable it in Burp Pro: Settings -> Misc -> API",
                    pointer_id, 0.0, "start Burp Pro with the REST API enabled to close the gap"))
        print(f"[!] Burp REST API unreachable at {base} — filed a coverage-gap lead. "
              f"(In Burp Pro: Settings -> Misc -> REST API, then re-run.)", file=sys.stderr)
        sys.exit(1)

    scan_id = scan.get("scan_id") or scan.get("id")
    if not scan_id:
        print(f"[!] Unexpected scan response: {json.dumps(scan)[:300]}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Scan launched (id {scan_id}). Polling...")

    import time
    while True:
        time.sleep(10)
        status = _api_call(base, f"/scan/{scan_id}")
        state = status.get("scan_status") or status.get("status") or ""
        print(f"    state: {state}")
        if state in ("succeeded", "completed", "aborted", "failed"):
            break

    details = _api_call(base, f"/scan/{scan_id}/details")
    raw_issues = details.get("issue_events") or details.get("issues") or []
    leads = []
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    for ev in raw_issues:
        iss = ev.get("issue", ev)  # handle both shapes
        name = iss.get("name", "?")
        sev = str(iss.get("severity", "info")).lower()
        url = iss.get("url") or iss.get("origin") or target
        leads.append(_mklead(
            "cve", f"burp scan: {name[:100]}",
            f"scanner issue ({sev}) on {str(url)[:80]}",
            pointer_id, 0.5 if sev in ("high", "medium") else 0.3,
            "verify manually before any confirmation", must_verify=True))
    _write_artifact(pointer_id,
                    f"--- COMMAND ---\nburp_bridge scan {target}\n\n--- STDOUT ---\n"
                    + json.dumps(details, indent=2)[:20000] + "\n\n--- STDERR ---\n")
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            _record_pointer(board, pointer_id, f"burp scan: {len(leads)} issue lead(s)",
                            f"burp_bridge scan {target}")
    print(f"[✔] {len(leads)} issue lead(s) filed from the Burp scan (pointer {pointer_id}).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Burp Suite bridge (any edition)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("ingest-history", help="Ingest a Burp 'Save items' proxy-history export")
    h.add_argument("--file", required=True, help="Path to the exported XML")
    h.add_argument("--out", default="endpoints.txt", help="Inventory output (role-diff baseline)")
    h.add_argument("--role", default="baseline", help="Label for the captured role")

    i = sub.add_parser("ingest-issues", help="Ingest a Burp Scanner issues XML export")
    i.add_argument("--file", required=True)

    s = sub.add_parser("scan", help="Drive a scan via Burp Pro's REST API (Pro only)")
    s.add_argument("--target", required=True)
    s.add_argument("--api-host", default="127.0.0.1")
    s.add_argument("--api-port", type=int, default=1337)

    args = parser.parse_args()
    ensure_blackboard_dirs()
    if args.cmd == "ingest-history":
        ingest_history(args.file, args.out, args.role)
    elif args.cmd == "ingest-issues":
        ingest_issues(args.file)
    elif args.cmd == "scan":
        api_scan(args.target, args.api_host, args.api_port)
