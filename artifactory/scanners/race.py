#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Race Condition Probe

Basic last-byte-style race probing, stdlib threads:

  * Send N identical requests in a tight burst (threads + barrier so release
    is as simultaneous as Python allows), then measure how many "took effect".
  * Single-execution semantics violated (e.g. coupon used once but 2+ succeed,
    balance decremented once for 5 requests) = the race is REAL.
  * This is the approximation tier (no raw-socket single-packet). It still
    catches the large class of naive races; the playbook points at Kettle's
    single-packet technique for the hard ones.

Operator defines the EFFECT CHECK as a shell command that runs AFTER the
burst (`--check "curl -s ... | grep -c ..."`): its stdout number is compared
against the number of successful bursts. Zero model tokens.
"""

import argparse
import json
import shlex
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import ipaddress
import socket
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
SESSIONS_DIR = BLACKBOARD_DIR / "sessions"


def _scope_ok(target: str) -> bool:
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


def run_race_probe(url, method="POST", body="", headers=None, session_id=None,
                   threads=20, check_cmd="", timeout=15):
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    if not _scope_ok(url):
        print(f"[!] SCOPE ERROR: '{url}' not in scope.json.", file=sys.stderr)
        sys.exit(1)

    hdrs = dict(headers or {})
    if session_id:
        sp = SESSIONS_DIR / f"{session_id}.json"
        if sp.exists():
            sess = json.loads(sp.read_text())
            if sess.get("auth_type") == "cookie":
                hdrs["Cookie"] = sess.get("credential", "")
            elif sess.get("auth_type") == "bearer":
                hdrs["Authorization"] = f"Bearer {sess.get('credential', '')}"

    def fire():
        data = body.encode() if body else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in hdrs.items():
            req.add_header(k, v)
        req.add_header("User-Agent", "artifactory-race/1.0")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0

    # Warm the connection pool first (DNS/TLS setup out of the timed window)
    warm = fire()
    print(f"[*] Race probe: {threads} simultaneous {method}s (warmup status {warm})")

    statuses = [None] * threads
    barrier = threading.Barrier(threads)

    def worker(i):
        barrier.wait()  # release as simultaneously as Python allows
        statuses[i] = fire()

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    burst_time = time.time() - t0

    ok = sum(1 for s in statuses if s and 200 <= s < 300)
    codes = {}
    for s in statuses:
        codes[s] = codes.get(s, 0) + 1
    print(f"    burst: {ok}/{threads} x 2xx in {burst_time:.2f}s — codes {codes}")

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    log = [f"burst {threads}x {method} {url}", f"codes: {codes}",
           f"warmup: {warm}"]

    leads = []
    if check_cmd:
        r = subprocess.run(shlex.split(check_cmd), capture_output=True, text=True, timeout=60)
        observed = (r.stdout.strip() or "0").splitlines()[-1]
        log.append(f"effect-check `{check_cmd}` -> {observed!r} (rc={r.returncode})")
        try:
            effect = int(float(observed))
        except ValueError:
            effect = None
        if effect is not None and ok > 0 and effect < ok:
            leads.append({
                "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                "type": "anomaly",
                "value": f"race condition: {ok} successes but {effect} effect(s)",
                "signal": f"single-execution semantics violated on {method} {url} "
                          f"(effect measured by the operator's check command)",
                "confidence": 0.75,
                "suggested_next": "narrow the window: retry with more threads; then "
                                   "escalate via the single-packet technique (race "
                                   "playbook) for the definitive PoC",
                "must_verify": True, "preconditions": [],
                "source_pointer": pointer_id, "status": "new",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    (BLACKBOARD_DIR / "artifacts").mkdir(parents=True, exist_ok=True)
    (BLACKBOARD_DIR / "artifacts" / f"{pointer_id}.log").write_text(
        "--- COMMAND ---\nrace.py probe (burst)\n\n--- STDOUT ---\n"
        + "\n".join(log) + "\n\n--- STDERR ---\n")
    if leads:
        with json_transaction("board.json") as board:
            if board is not None:
                board.setdefault("leads", []).extend(leads)
    print(f"[✔] Probe complete (artifact {pointer_id}).")
    if leads:
        print(f"    {len(leads)} RACE lead(s) filed — effect count contradicts successes.")
    else:
        print("    No effect contradiction measured (either safe, or supply --check "
              "with a command that counts the real effect).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Race condition probe (burst + effect check)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe", help="Burst N identical requests, then measure the effect")
    p.add_argument("--url", required=True)
    p.add_argument("--method", default="POST")
    p.add_argument("--body", default="", help="Request body (raw)")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--session", default=None, help="SESS_ id to fire as")
    p.add_argument("--check", default="",
                   help="Shell command run after the burst; its stdout number = observed effect count")
    p.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    run_race_probe(args.url, args.method, args.body, None, args.session,
                   args.threads, args.check, args.timeout)
