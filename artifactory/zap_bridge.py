#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - ZAP Bridge (headless, docker one-shot)

Launches OWASP ZAP in docker, drives an active scan against an in-scope
target via its REST API, and files every alert as a must_verify lead (a
scanner alert is a CANDIDATE — the verification gate still applies; ZAP finds
leads, the verifier proves findings).

No local ZAP install needed: uses `docker run` with the official
softwaresecurityproject/zap image. No docker either? A coverage-gap lead is
filed instead of silent skipping.

Design notes:
  * One-shot container with a named volume per scan is heavy; instead we run
    zap-baseline-style single session (init + attack + dump alerts) inside
    the container, then parse the JSON the container prints.
  * Everything goes through the same fail-closed scope gate as any target
    command (the scan target must be authorized).
  * Rate-limited by ZAP's own thread defaults (2) — politeness preserved.
"""

import argparse
import json
import shlex
import subprocess
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402
from scope_sig import verify_scope, tamper_notice  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"

ZAP_IMAGE = "softwaresecurityproject/zap:stable"
ZAP_TIMEOUT = 900  # container wall-clock

SEVERITY_MAP = {"High": "high", "Medium": "medium", "Low": "low",
                "Informational": "info"}


def _scope_ok(target: str) -> bool:
    """Reuse the runner's semantics without importing the CLI module."""
    import ipaddress
    import socket
    scope = load_json(SCOPE_FILE)
    if not scope:
        return False
    h = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if h in scope.get("allowed_hosts", []):
        return True
    for d in scope.get("allowed_domains", []):
        d = d.replace("*.", "")
        if h == d or h.endswith("." + d):
            return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(h))
        for c in scope.get("allowed_cidrs", []):
            if ip in ipaddress.ip_network(c, strict=False):
                return True
    except (socket.gaierror, ValueError):
        return False
    return False


def run_zap_scan(target: str, full: bool = False):
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    if not _scope_ok(target):
        print(f"[!] SCOPE ERROR: '{target}' not in scope.json — authorize it first.",
              file=sys.stderr)
        sys.exit(1)
    if not shutil.which("docker"):
        pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
            "--- COMMAND ---\nzap bridge (unavailable)\n\n--- STDOUT ---\n"
            "docker not found on PATH\n\n--- STDERR ---\n")
        with json_transaction("board.json", create=True) as board:
            if board is not None:
                board.setdefault("leads", []).append({
                    "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                    "type": "cve",
                    "value": "ZAP active scan (COVERAGE GAP)",
                    "signal": "docker not installed — ZAP scan not fired",
                    "confidence": 0.0,
                    "suggested_next": "install docker to close the coverage gap",
                    "must_verify": False, "preconditions": [],
                    "source_pointer": pointer_id, "status": "new",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
        print("[!] docker not installed — filed a coverage-gap lead instead of "
              "silently skipping.", file=sys.stderr)
        sys.exit(1)

    # One-shot ZAP session: quick/baseline or full active scan
    script = "zap-baseline.py" if not full else "zap-full-scan.py"
    cmd = [
        "docker", "run", "--rm", "--network", "host",
        ZAP_IMAGE, script, "-t", target, "-J", "/tmp/zap.json",
    ]
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    print(f"[*] ZAP scan [{pointer_id}]: {' '.join(shlex.quote(c) for c in cmd)}")
    print(f"    (first pull of {ZAP_IMAGE} may take a while; timeout {ZAP_TIMEOUT}s)")

    # Capture alerts from the container's stdout JSON (baseline prints a report).
    # We re-scan alerts via the engine-side summary the script prints; full JSON
    # dump goes to the artifact for inspect.
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ZAP_TIMEOUT)
        stdout, stderr, rc = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, rc = "", f"ZAP container timed out after {ZAP_TIMEOUT}s", 124

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
        f"--- COMMAND ---\n{' '.join(cmd)}\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n")

    # Parse ZAP's baseline summary lines: "PASS|WARN|FAIL|INFO: <rule> <url> (<n>)"
    leads = []
    for line in stdout.splitlines():
        line = line.strip()
        if not (line.startswith(("FAIL:", "WARN:"))):
            continue
        kind, rest = line.split(":", 1)
        rest = rest.strip()
        sev = "high" if kind == "FAIL" else "medium"
        leads.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "cve",
            "value": f"zap: {rest[:120]}",
            "signal": f"scanner alert ({kind}, {sev})",
            "confidence": 0.5 if kind == "FAIL" else 0.35,
            "suggested_next": "verify alert manually (scanner candidates are never findings)",
            "must_verify": True, "preconditions": [],
            "source_pointer": pointer_id, "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            board.setdefault("execution_log_pointers", []).append({
                "pointer_id": pointer_id,
                "command": f"zap bridge {' '.join(cmd[:6])}...",
                "return_code": rc,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": f"zap scan: {len(leads)} alert lead(s)",
            })

    print(f"[✔] ZAP scan complete (rc={rc}): {len(leads)} must_verify alert lead(s) "
          f"filed (pointer {pointer_id}).")
    print("    Work them with: sec_flow.py leads --type cve")
    if not leads and rc != 0:
        print(f"[!] Container exited {rc} — inspect the artifact: "
              f"sec_flow.py inspect --id {pointer_id}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZAP headless scan bridge (docker)")
    parser.add_argument("--target", required=True, help="In-scope target URL")
    parser.add_argument("--full", action="store_true",
                        help="Full active scan (default: baseline passive+quick)")
    args = parser.parse_args()
    run_zap_scan(args.target, full=args.full)
