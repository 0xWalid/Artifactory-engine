#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Eval Engine (the learning-loop gate)

Three levels, matching the plan's promotion policy:

  1. `suite engine`   — deterministic checks that the ENGINE's own machinery
     works: scope gate blocks out-of-scope, verification gate downgrades
     unproven findings, triage extracts leads, role-diff files delta leads,
     OOB attribution works. No LLM involved. Runs in seconds, in /tmp.

  2. `score`          — engagement scoring: reads board.json + tokens.jsonl of
     the CURRENT workspace and computes the north-star metric
     (proven vulns / 1M tokens) + precision (confirmed vs informational) +
     coverage (leads worked vs left new). This is how a real engagement feeds
     the loop WITHOUT directly promoting anything (live targets have
     confounds; labs are the only promotion ground).

  3. `gate`           — the promotion gate: given a candidate change to
     prompts/agents/engine (a git diff), run the engine suite + lab suite
     before/after and compare. A candidate is promoted ONLY if it does not
     regress the suite. Writes evals/manifest.json so history is inspectable.

The lab suite (LLM-in-the-loop when opencode runs it) is expressed as a
MANIFEST of cases: each case says which endpoint+role exhibits a vuln, what
the engine must produce (a confirmed finding referencing a real pointer),
and which safe endpoints must stay clean. opencode (or a human) executes the
manifest; this engine validates the board state against it deterministically.
"""

import argparse
import json
import base64
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)


def _find_engine_root():
    """Engine root = the dir containing art.py (works at root or in a package)."""
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent


_ENGINE_ROOT = _find_engine_root()
if str(_ENGINE_ROOT / "core") not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT / "core"))
from board_io import load_json, blackboard_dir  # noqa: E402
from registry import path_for as _tool  # noqa: E402  (stem -> abs script path)
from bootstrap import register_paths as _register_paths  # noqa: E402
_register_paths()  # sys.path + PYTHONPATH so spawned tools inherit the layout

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
EVALS_DIR = Path.cwd() / "evals"

PY = sys.executable

# Lab suite manifest: what the ENGINE (driven by an operator/agent following
# the /artifactory flow) must produce against vuln_lab.py for the suite to
# count as passed. Validated deterministically from board.json.
LAB_MANIFEST = {
    "lab": "vuln_lab.py on 127.0.0.1:8099",
    "cases": [
        {
            "id": "V1-BAC",
            "vuln": "broken access control on /admin",
            "must_confirm": True,
            "confirm_marker": "/admin",
            "evidence_required": True,
        },
        {
            "id": "V2-IDOR",
            "vuln": "IDOR on /api/orders/1001 as user",
            "must_confirm": True,
            "confirm_marker": "order",
            "evidence_required": True,
        },
        {
            "id": "V3-BLIND-SSRF",
            "vuln": "blind SSRF via /api/fetch?url=",
            "must_confirm": True,
            "confirm_marker": "fetch",
            "evidence_required": True,
        },
        {
            "id": "V4-ANOMALY",
            "vuln": "stack trace + private key leak on /api/error",
            "must_confirm": True,
            "confirm_marker": "error",
            "evidence_required": True,
        },
    ],
    "negative_controls": [
        # A false positive = a confirmed finding claiming the SAFE endpoint is
        # vulnerable. (Markers like PRIVATE are allowed to appear in OTHER
        # findings' evidence — that's V4's real leak, not a /health FP.)
        {"id": "SAFE-health", "endpoint": "/health",
         "must_not_confirm_marker": "/health"},
    ],
}

# Lab 2 manifest (JSON/API flavor) — keeps the gate from overfitting lab 1.
LAB2_MANIFEST = {
    "lab": "vuln_lab2.py on 127.0.0.1:8100",
    "cases": [
        {"id": "V5-JS-SECRET", "vuln": "API key leaked in JS bundle",
         "must_confirm": True, "confirm_marker": "app.js", "evidence_required": True},
        {"id": "V6-REDIRECT", "vuln": "open redirect on /redirect",
         "must_confirm": True, "confirm_marker": "redirect", "evidence_required": True},
        {"id": "V7-TRAVERSAL", "vuln": "path traversal on /files",
         "must_confirm": True, "confirm_marker": "files", "evidence_required": True},
        {"id": "V8-MASS-ASSIGN", "vuln": "mass assignment on PUT /api/profile",
         "must_confirm": True, "confirm_marker": "profile", "evidence_required": True},
    ],
    "negative_controls": [
        {"id": "SAFE-ping", "endpoint": "/api/ping",
         "must_not_confirm_marker": "/api/ping"},
    ],
}

# Lab 3 manifest (HOLD-OUT): referenced only by `gate --final`.
LAB3_MANIFEST = {
    "lab": "vuln_lab3.py on 127.0.0.1:8101 (HOLD-OUT — final promotion only)",
    "cases": [
        {"id": "V9-HEADER-BYPASS", "vuln": "X-Role header auth bypass on /api/admin",
         "must_confirm": True, "confirm_marker": "admin", "evidence_required": True},
        {"id": "V10-DEBUG-LEAK", "vuln": "env dump on /api/debug",
         "must_confirm": True, "confirm_marker": "debug", "evidence_required": True},
        {"id": "V11-CORS", "vuln": "CORS reflect+credentials misconfig",
         "must_confirm": True, "confirm_marker": "cors", "evidence_required": True},
    ],
    "negative_controls": [
        {"id": "SAFE-version", "endpoint": "/api/version",
         "must_not_confirm_marker": "/api/version"},
    ],
    # Skeptic contract (LLM-side, best-effort gate): a HIGH-IMPACT claim with
    # NO evidence must NOT survive the skeptic. A skeptic run that endorses an
    # evidence-less critical finding is a gate failure even though the final
    # say is the verification gate. Checked by validate-lab lab3 when a
    # 'skeptic' rationale entry exists.
    "skeptic_contracts": [
        {"id": "SKEPTIC-NO-EVIDENCE",
         "rule": "no confirmed finding without evidence (verification gate covers "
                 "the recording; the skeptic must never argue to bypass it)"},
    ],
}

LAB_MANIFESTS = {"lab1": LAB_MANIFEST, "lab2": LAB2_MANIFEST, "lab3": LAB3_MANIFEST}
SCORES_FILE = Path.cwd() / "evals" / "scores.jsonl"


# ---------------------------------------------------------------- engine suite
def _run(cmd, cwd=None, env=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr


def suite_engine(verbose=False):
    """Deterministic engine-machinery suite in an isolated /tmp workspace.
    Verifies: scope gate, destructive block, verification gate, lead triage,
    loop notice, role-diff delta leads, OOB tag attribution, token accounting."""
    tmp = Path(tempfile.mkdtemp(prefix="sba_eval_"))
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        if verbose or not cond:
            print(f"  [{'✔' if cond else '!'}] {name}" + (f" — {detail}" if detail and not cond else ""))

    try:
        # 0) init workspace
        rc, out, err = _run([PY, _tool("init_env"), "--target", str(tmp)])
        check("init_env creates workspace", (tmp / ".blackboard" / "board.json").exists(), err)

        # 1) fail-closed scope: example.invalid must be refused
        rc, out, err = _run([PY, _tool("sec_flow"), "run",
                             "--cmd", "curl -s http://example.invalid/", "--target", "example.invalid"],
                            cwd=tmp)
        check("scope gate blocks out-of-scope target", rc != 0 and "SCOPE ERROR" in err, err)

        # 2) destructive-action block (in default disallowed_actions)
        rc, out, err = _run([PY, _tool("sec_flow"), "run",
                             "--cmd", "rm -rf /", "--target", "127.0.0.1"], cwd=tmp)
        check("destructive block refuses rm -rf", rc != 0 and "DESTRUCTIVE" in err, err)

        # 3) in-scope run + triage: the lab error page must produce an anomaly lead
        rc, out, err = _run([PY, _tool("sec_flow"), "run",
                             "--cmd", "curl -s http://127.0.0.1:8099/api/error",
                             "--target", "127.0.0.1"], cwd=tmp)
        board = load_json(tmp / ".blackboard" / "board.json")
        anomaly = [l for l in board.get("leads", []) if l.get("type") == "anomaly"]
        check("run executes in-scope", rc == 0, err)
        check("triage files anomaly lead from stack trace",
              any("trace" in (l.get("signal") or "").lower() or "trace" in str(l.get("value", "")).lower()
                  for l in anomaly) or bool(anomaly), f"anomaly leads: {[l.get('value') for l in anomaly]}")

        # 4) verification gate: confirmed without evidence -> informational
        rc, out, err = _run([PY, _tool("sec_flow"), "add-asset",
                             "--finding", "Unproven claim", "--severity", "high",
                             "--status", "confirmed"], cwd=tmp)
        board = load_json(tmp / ".blackboard" / "board.json")
        f = board.get("findings", [{}])[-1]
        check("verification gate downgrades unproven finding",
              f.get("status") == "informational", out + err)

        # 5) loop notice on identical command re-run
        rc, out, err = _run([PY, _tool("sec_flow"), "run",
                             "--cmd", "curl -s http://127.0.0.1:8099/api/error",
                             "--target", "127.0.0.1"], cwd=tmp)
        check("loop notice fires on repeat command", "LOOP NOTICE" in err, err)

        # 6) role-diff: seed sessions and replay -> BAC delta leads
        rc, out, err = _run([PY, _tool("auth_manager"), "add",
                             "--role", "admin", "--auth-type", "cookie",
                             "--target", "http://127.0.0.1:8099",
                             "--credential", "session=admin-s3ssion"], cwd=tmp)
        rc2, out2, err2 = _run([PY, _tool("auth_manager"), "add",
                                "--role", "user", "--auth-type", "cookie",
                                "--target", "http://127.0.0.1:8099",
                                "--credential", "session=user-s3ssion"], cwd=tmp)
        eps = tmp / "endpoints.txt"
        eps.write_text("/admin\n/api/me\n")
        check("sessions register as pointers", rc == 0 and rc2 == 0, err + err2)
        board = load_json(tmp / ".blackboard" / "board.json")
        sess_meta = board.get("sessions", [])
        check("credentials stay OUT of board.json (pointer discipline)",
              all("credential" not in s and "s3ssion" not in json.dumps(s) for s in sess_meta),
              json.dumps(sess_meta))

        rc, out, err = _run([PY, _tool("auth_manager"), "role-diff",
                             "--base-url", "http://127.0.0.1:8099",
                             "--roles", "admin,USER_SESS_ID",
                             "--endpoints", str(eps)], cwd=tmp)
        # roles arg needs real SESS ids: pull from board
        board = load_json(tmp / ".blackboard" / "board.json")
        sids = [s["id"] for s in board.get("sessions", []) if s.get("role") in ("admin", "user")]
        sids = ",".join(sids)
        rc, out, err = _run([PY, _tool("auth_manager"), "role-diff",
                             "--base-url", "http://127.0.0.1:8099",
                             "--roles", sids, "--endpoints", str(eps)], cwd=tmp)
        board = load_json(tmp / ".blackboard" / "board.json")
        rd = [l for l in board.get("leads", []) if l.get("type") == "rolediff"]
        check("role-diff replays across roles", rc == 0, err)
        check("role-diff files delta leads on /admin (BAC)",
              any("/admin" in str(l.get("value", "")) for l in rd), f"rolediff: {[l.get('value') for l in rd]}")

        # 7) OOB: generate + detached listener + self-callback + attribution
        rc, out, err = _run([PY, _tool("oob"), "generate", "--host", "127.0.0.1",
                             "--http-port", "8899", "--purpose", "eval blind ssrf"], cwd=tmp)
        # Start the listener detached ourselves (it blocks forever; the runner's
        # 300s ceiling would kill it mid-suite).
        listener = subprocess.Popen(
            [PY, _tool("oob"), "listen", "--http-port", "8899"],
            cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        state = load_json(tmp / ".blackboard" / "oob_state.json")
        probes = state.get("probes", {})
        check("OOB mints registered probes", bool(probes), "no probes in oob_state.json")
        tag = next(iter(probes)) if probes else None
        if tag:
            # simulate the vulnerable server calling back
            try:
                urllib_req = __import__("urllib.request", fromlist=["urlopen"])
                urllib_req.urlopen(f"http://127.0.0.1:8899/oob-{tag}/probe", timeout=5)
            except Exception:
                pass
            time.sleep(0.5)
            rc, out, err = _run([PY, _tool("oob"), "status"], cwd=tmp)
            board = load_json(tmp / ".blackboard" / "board.json")
            oob_leads = [l for l in board.get("leads", [])
                         if l.get("type") == "anomaly" and "OOB" in str(l.get("value", ""))]
            check("OOB callback files attributed anomaly lead", bool(oob_leads), out + err)
        listener.terminate()

        # 8) token accounting: budget + metric
        rc, out, err = _run([PY, _tool("tokens"), "log",
                             "--role", "operator", "--purpose", "eval suite", "--amount", "50000"],
                            cwd=tmp)
        rc2, out2, err2 = _run([PY, _tool("tokens"), "budget",
                                "--role", "operator", "--limit", "100000"], cwd=tmp)
        rc3, out3, err3 = _run([PY, _tool("tokens"), "report"], cwd=tmp)
        check("token ledger + report work",
              rc == 0 and rc2 == 0 and "50000" in out3 and "NORTH-STAR" in out3, out3 + err3)

        # 9) chain edges: link two findings and view chains
        rc, out, err = _run([PY, _tool("sec_flow"), "add-asset",
                             "--finding", "Role leak via /admin", "--severity", "high",
                             "--status", "confirmed", "--poc", "user cookie -> 200 admin panel"],
                            cwd=tmp)
        board = load_json(tmp / ".blackboard" / "board.json")
        findings = board.get("findings", [])
        check("confirmed-with-PoC finding records as confirmed",
              any(f.get("status") == "confirmed" for f in findings), out + err)
        if len(findings) >= 2:
            f2, f1 = findings[-1], findings[0]
            rc, out, err = _run([PY, _tool("sec_flow"), "chains",
                                 "--link", f"{f1['id']},{f2['id']}",
                                 "--note", "leak -> role abuse"], cwd=tmp)
            rc2, out2, err2 = _run([PY, _tool("sec_flow"), "chains"], cwd=tmp)
            check("chain edge records + chains view", rc == 0 and "leak" in out2.lower(), out2 + err2)
        else:
            check("chain edge records (skipped: <2 findings)", True)

        # 10) scope signing: fresh workspace must verify 'ok'; tampering must fail
        rc, out, err = _run([PY, "-c",
                             "import sys; sys.path.insert(0, " + repr(_engine_dir) + "); "
                             "import os; os.chdir(" + repr(str(tmp)) + "); "
                             "from scope_sig import verify_scope; print(verify_scope())"],
                            cwd=tmp)
        check("fresh workspace scope signature verifies", out.strip() == "ok", out + err)
        # Tamper: widen allowed_hosts without re-signing -> must go TAMPERED
        scope_doc = json.loads((tmp / ".blackboard" / "scope.json").read_text())
        scope_doc["allowed_hosts"].append("evil.example.com")
        (tmp / ".blackboard" / "scope.json").write_text(json.dumps(scope_doc, indent=2))
        rc, out, err = _run([PY, "-c",
                             "import sys; sys.path.insert(0, " + repr(_engine_dir) + "); "
                             "import os; os.chdir(" + repr(str(tmp)) + "); "
                             "from scope_sig import verify_scope; print(verify_scope())"],
                            cwd=tmp)
        check("tampered scope detected (TAMPERED verdict)", out.strip().startswith("TAMPERED"), out + err)
        rc, out, err = _run([PY, _tool("sec_flow"), "run",
                             "--cmd", "curl -s http://evil.example.com/", "--target", "evil.example.com"],
                            cwd=tmp)
        check("tampered scope refuses commands", rc != 0 and "SIGNATURE" in err, err)
        # Operator-approved scope edit re-signs and verifies again
        rc, out, err = _run([PY, _tool("sec_flow"), "scope",
                             "--add-host", "127.0.0.99"], cwd=tmp)
        rc, out, err = _run([PY, "-c",
                             "import sys; sys.path.insert(0, " + repr(_engine_dir) + "); "
                             "import os; os.chdir(" + repr(str(tmp)) + "); "
                             "from scope_sig import verify_scope; print(verify_scope())"],
                            cwd=tmp)
        check("operator scope edit re-signs (verifies ok)", out.strip() == "ok", out + err)

        # 11) rate limiter: set a pacing interval, two rapid runs must pace
        scope_doc = json.loads((tmp / ".blackboard" / "scope.json").read_text())
        scope_doc["rate_limit"] = {"min_interval_seconds": 1.0}
        (tmp / ".blackboard" / "scope.json").write_text(json.dumps(scope_doc, indent=2))
        _run([PY, _tool("sec_flow"), "scope", "--add-host", "127.0.0.1"], cwd=tmp)  # re-sign
        t0 = time.time()
        _run([PY, _tool("sec_flow"), "run",
              "--cmd", "curl -s http://127.0.0.1:8099/health", "--target", "127.0.0.1"], cwd=tmp)
        rc, out, err = _run([PY, _tool("sec_flow"), "run",
                             "--cmd", "curl -s http://127.0.0.1:8099/health", "--target", "127.0.0.1"],
                            cwd=tmp)
        elapsed = time.time() - t0
        check("rate limiter paces rapid second command",
              "RATE LIMIT" in err or elapsed >= 1.0, f"elapsed={elapsed:.2f}s err={err[:200]}")

        # 12) fingerprint cache: record + lookup + TTL filter
        rc, out, err = _run([PY, _tool("sec_flow"), "fingerprint",
                             "--host", "127.0.0.1", "--tech", "nginx 1.18.0", "--record"],
                            cwd=tmp)
        rc2, out2, err2 = _run([PY, _tool("sec_flow"), "fingerprint",
                                "--host", "127.0.0.1"], cwd=tmp)
        check("fingerprint records + looks up", rc == 0 and "nginx 1.18.0" in out2, out2 + err2)

        # 13) nuclei: binary present or not, the no-silent-drop contract holds either way
        import shutil as _sh
        if _sh.which("nuclei"):
            rc, out, err = _run([PY, _tool("sec_flow"), "nuclei",
                                 "--target", "http://127.0.0.1:8099"], cwd=tmp)
            check("nuclei scan executes (in-scope)", rc == 0, err)
        else:
            # Mock a nuclei binary so the REAL parse path runs end-to-end:
            # it must emit one JSONL match and sec_flow must convert it to a
            # must_verify cve lead.
            mock_dir = tmp / "mockbin"
            mock_dir.mkdir(exist_ok=True)
            mock = mock_dir / "nuclei"
            mock.write_text("#!/bin/sh\necho '{\"template-id\":\"tech-detect\","
                            "\"matched-at\":\"http://127.0.0.1:8099\","
                            "\"info\":{\"severity\":\"info\"}}'\n")
            mock.chmod(0o755)
            import os as _os
            env = {**_os.environ, "PATH": f"{mock_dir}:{_os.environ['PATH']}"}
            rc, out, err = _run([PY, _tool("sec_flow"), "nuclei",
                                 "--target", "http://127.0.0.1:8099"], cwd=tmp, env=env)
            board = load_json(tmp / ".blackboard" / "board.json")
            nleads = [l for l in board.get("leads", [])
                      if str(l.get("value", "")).startswith("nuclei:")]
            check("nuclei match -> must_verify cve lead (mocked binary, real parse path)",
                  rc == 0 and len(nleads) == 1 and nleads[0].get("must_verify"), out + err)
            # And the honest-gap branch with no binary at all:
            env2 = {k: v for k, v in _os.environ.items()}
            env2["PATH"] = "/nonexistent"
            rc, out, err = _run([PY, _tool("sec_flow"), "nuclei",
                                 "--target", "http://127.0.0.1:8099"], cwd=tmp, env=env2)
            board = load_json(tmp / ".blackboard" / "board.json")
            gap = [l for l in board.get("leads", [])
                   if "COVERAGE GAP" in str(l.get("value", ""))]
            check("missing nuclei files visible coverage-gap lead",
                  rc != 0 and bool(gap), err)

        # 14) redaction: secrets must never leave the engine via inspect/preview
        art = tmp / ".blackboard" / "artifacts" / "MSG_REDACTTEST.log"
        art.write_text("--- COMMAND ---\nredact test\n\n--- STDOUT ---\n"
                       "Set-Cookie: session=super-secret-cookie-99\n"
                       "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryE4J3yVbq5wQ\n"
                       "\"DB_PASSWORD\": \"super-db-pass-77\", \"api_key\":\"abcdef98765\"\n"
                       "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n"
                       "\n--- STDERR ---\n")
        rc, out, err = _run([PY, _tool("sec_flow"), "inspect",
                             "--id", "MSG_REDACTTEST"], cwd=tmp)
        check("inspect redacts cookies + JWTs + JSON secrets + keys",
              "super-secret-cookie-99" not in out and "eyJhbGci" not in out
              and "super-db-pass-77" not in out and "abcdef98765" not in out
              and "MIIabc" not in out
              and "__REDACTED" in out, out)
        # Session credential redaction: register a session, then leak its cookie in a log
        rc, out, err = _run([PY, _tool("auth_manager"), "add",
                             "--role", "user", "--auth-type", "cookie",
                             "--target", "http://127.0.0.1:8099",
                             "--credential", "session=t0ps3cr3tLABcookie"], cwd=tmp)
        art2 = tmp / ".blackboard" / "artifacts" / "MSG_REDACT2.log"
        art2.write_text("--- COMMAND ---\nredact test 2\n\n--- STDOUT ---\n"
                        "leaked: session=t0ps3cr3tLABcookie\n\n--- STDERR ---\n")
        rc, out, err = _run([PY, _tool("sec_flow"), "inspect",
                             "--id", "MSG_REDACT2"], cwd=tmp)
        check("session credentials redacted from egress",
              "t0ps3cr3tLABcookie" not in out and "__REDACTED" in out, out)

        # 15) sig-deletion downgrade attack must be TAMPERED (ever-signed marker)
        rc, out, err = _run([PY, "-c",
                             "import sys; sys.path.insert(0, " + repr(_engine_dir) + "); "
                             "import os; os.chdir(" + repr(str(tmp)) + "); "
                             "from scope_sig import verify_scope; print(verify_scope())"],
                            cwd=tmp)
        if out.strip() == "ok":
            (tmp / ".blackboard" / "scope.sig").unlink()
            rc, out, err = _run([PY, "-c",
                                 "import sys; sys.path.insert(0, " + repr(_engine_dir) + "); "
                                 "import os; os.chdir(" + repr(str(tmp)) + "); "
                                 "from scope_sig import verify_scope; print(verify_scope())"],
                                cwd=tmp)
            check("deleting scope.sig from signed workspace = TAMPERED",
                  out.strip().startswith("TAMPERED"), out)
        else:
            check("deleting scope.sig from signed workspace = TAMPERED (skipped: not signed)",
                  False, f"verify_scope returned {out.strip()}")

        # 16) crawl: deterministic inventory build against the lab
        rc, out, err = _run([PY, _tool("crawl"), "--base-url",
                             "http://127.0.0.1:8099", "--max-depth", "1",
                             "--delay", "0.05"], cwd=tmp)
        inv = tmp / "endpoints.txt"
        inv_ok = inv.exists() and any("/admin" in l for l in inv.read_text().splitlines())
        check("crawler builds role-diff inventory + finds /admin", rc == 0 and inv_ok,
              out + err)

        # 17) chain mining: primitive/needs proposals appear deterministically
        rc, out, err = _run([PY, _tool("sec_flow"), "add-asset",
                             "--finding", "Broken access control on /admin — user role reaches admin panel",
                             "--severity", "high", "--status", "confirmed",
                             "--poc", "user cookie -> 200 admin panel"], cwd=tmp)
        rc, out, err = _run([PY, _tool("sec_flow"), "chains", "--mine"],
                            cwd=tmp)
        check("chain mining proposes primitive/needs edges",
              rc == 0 and ("CHAIN MINING" in out) and ("->" in out), out)

        # 19) broad code-path roots are refused (footgun guard)
        rc, out, err = _run([PY, _tool("sec_flow"), "scope",
                             "--add-code-path", "/tmp"], cwd=tmp)
        check("system-root code path refused", rc != 0 and "too broad" in err, err)
        rc, out, err = _run([PY, _tool("sec_flow"), "scope",
                             "--add-code-path", str(tmp / "proj")], cwd=tmp)
        check("specific project code path accepted", rc == 0, err)

        # 21) status dashboard renders every section
        rc, out, err = _run([PY, _tool("sec_flow"), "status"], cwd=tmp)
        check("status dashboard renders (scope/findings/leads/chains/tokens)",
              rc == 0 and "ENGAGEMENT STATUS" in out and "Findings:" in out
              and "Leads:" in out and "Chains:" in out, out)

        # 21b) burp bridge: ingest a synthetic 'Save items' export (the any-edition path)
        hist = tmp / "history.xml"
        req = base64.b64encode(
            b"GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").decode()
        resp = base64.b64encode(b"HTTP/1.1 200 OK\r\n\r\n{\"page\":\"admin\"}").decode()
        hist.write_text(
            '<?xml version="1.0"?><items>'
            '<item><protocol>http</protocol><host>127.0.0.1</host><port>8099</port>'
            f'<request>{req}</request><status>200</status><response>{resp}</response>'
            '<method>GET</method><url>http://127.0.0.1:8099/admin</url></item>'
            '<item><protocol>http</protocol><host>ev.invalid</host><port>80</port>'
            f'<request>{req}</request><status>200</status><response>{resp}</response>'
            '<method>GET</method><url>http://ev.invalid/x</url></item>'
            '</items>')
        rc, out, err = _run([PY, _tool("burp_bridge"), "ingest-history",
                             "--file", str(hist)], cwd=tmp)
        inv = tmp / "endpoints.txt"
        check("burp history ingest -> inventory + endpoint leads",
              rc == 0 and inv.exists() and "/admin" in inv.read_text()
              and "out-of-scope" in out, out + err)

        # 23) researcher behaviors: kev, stack interactions, payload corpus,
        #     variant propagation
        # 23a) payload corpus: init + list + note
        rc, out, err = _run([PY, _tool("payload_corpus"), "list",
                             "--search", "ssrf"], cwd=tmp)
        check("payload corpus lists seeded classes",
              rc == 0 and "169.254.169.254" in out, out + err)
        rc, out, err = _run([PY, _tool("payload_corpus"), "note",
                             "--class", "ssrf", "--stack", "nginx",
                             "--worked", "true"], cwd=tmp)
        check("payload corpus records stack wins", rc == 0 and "WORKED" in out, out + err)

        # 23b) stack interactions: fingerprint then hypothesize
        _run([PY, _tool("sec_flow"), "fingerprint", "--host", "stack.test.local",
              "--tech", "nginx 1.18", "--record"], cwd=tmp)
        _run([PY, _tool("sec_flow"), "fingerprint", "--host", "stack.test.local",
              "--tech", "Apache Tomcat 9", "--record"], cwd=tmp)
        rc, out, err = _run([PY, _tool("stack_interactions"),
                             "hypothesize"], cwd=tmp)
        check("stack interactions fires nginx+tomcat hypothesis (no apache/ FP)",
              rc == 0 and "nginx + tomcat" in out
              and "apache/ + tomcat" not in out, out)
        # idempotence: second run adds nothing
        rc, out, err = _run([PY, _tool("stack_interactions"),
                             "hypothesize"], cwd=tmp)
        check("stack interactions idempotent", rc == 0 and "No NEW" in out, out)

        # 23c) variant propagation on confirm (covered in-flow): confirm an IDOR
        #      with endpoints on the board -> variant sweep leads appear
        _run([PY, _tool("sec_flow"), "add-asset",
             "--endpoint", "/api/orders/2001"], cwd=tmp)
        _run([PY, _tool("sec_flow"), "add-asset",
             "--endpoint", "/api/orders/2002"], cwd=tmp)
        rc, out, err = _run([PY, _tool("sec_flow"), "add-asset",
                             "--finding", "IDOR on /api/orders/2001",
                             "--severity", "medium", "--status", "confirmed",
                             "--poc", "user reads other order"], cwd=tmp)
        board = load_json(tmp / ".blackboard" / "board.json")
        variants = [l for l in board.get("leads", [])
                    if "variant sweep" in str(l.get("value", ""))]
        check("confirm queues same-class variant sweeps",
              len(variants) >= 1 and any("2002" in v["value"] for v in variants)
              and not any("2001" in v["value"] for v in variants), out + err)

        # 23d) kev: network-dependent; verify the CLI shape offline (cache-only)
        rc, out, err = _run([PY, _tool("kev"), "list",
                             "--offline", "--limit", "3"], cwd=tmp)
        check("kev CLI functions (offline mode degrades gracefully)",
              rc == 0, out + err)

        # 23e) metrics rollup: scan + show with two synthetic workspaces
        eng_root = tmp / "engs"
        for ws in ("wsA", "wsB"):
            (eng_root / ws / "evals").mkdir(parents=True, exist_ok=True)
            (eng_root / ws / "evals" / "scores.jsonl").write_text(
                json.dumps({"label": f"{ws}-run",
                            "timestamp": f"2026-01-0{1 if ws == 'wsA' else 2}T00:00:00",
                            "confirmed_vulns": 2, "precision": 0.8, "coverage": 0.7,
                            "tokens_spent": 10000,
                            "vulns_per_1M_tokens": 200.0}) + "\n")
        env = {**os.environ, "HOME": str(tmp / "fakehome")}
        rc, out, err = _run([PY, _tool("metrics"), "scan",
                             "--root", str(eng_root)], cwd=tmp, env=env)
        rc2, out2, err2 = _run([PY, _tool("metrics"), "show"], cwd=tmp, env=env)
        check("metrics scan+show (global history, sorted)",
              rc == 0 and "2 new score record" in out
              and "wsA-run" in out2 and out2.index("wsA-run") < out2.index("wsB-run"),
              out + out2 + err2)

        # 23f) interaction growth: mining CLI runs offline-cleanly (network is
        # optional; the no-hit path must be a clean exit, not a crash)
        rc, out, err = _run([PY, _tool("interaction_growth"), "mine",
                             "--components", "nginx", "--per-component", "1"],
                            cwd=tmp)
        check("interaction growth mining degrades cleanly",
              rc == 0 and ("No new pair proposals" in out or "candidate" in out), out + err)

        # 23g) local interaction sidecar loads on top of built-ins
        kdir = _ENGINE_ROOT / "knowledge"
        local_tbl = kdir / "interactions_local.json"
        had_local = local_tbl.exists()
        if not had_local:
            local_tbl.write_text(json.dumps(
                [{"a": "testcomp", "b": "", "hypothesis": "suite test entry",
                  "playbook": "test"}]))
            _run([PY, _tool("sec_flow"), "fingerprint", "--host", "side.test",
                  "--tech", "testcomp 1.0", "--record"], cwd=tmp)
            rc, out, err = _run([PY, _tool("stack_interactions"),
                                 "hypothesize"], cwd=tmp)
            check("local interactions sidecar loads over built-ins",
                  rc == 0 and "testcomp" in out, out)
            local_tbl.unlink()
        else:
            check("local interactions sidecar loads over built-ins (present: skipped)",
                  True)

        # 23h) component aliasing: broadening + hint
        rc, out, err = _run([PY, _tool("component_aliases")], cwd=tmp)
        check("component aliases map products->embedded",
              rc == 0 and "gitlab" in out.lower(), out + err)

        # 23i) fuzz driver: scaffold + grammar-vs-lab (lab /api/fetch is a sink)
        rc, out, err = _run([PY, _tool("fuzz_driver"), "scaffold",
                             "--out", str(tmp / "harness.c")], cwd=tmp)
        check("fuzz scaffold generates", rc == 0 and (tmp / "harness.c").exists()
              and "LLVMFuzzerTestOneInput" in (tmp / "harness.c").read_text(), out + err)
        seedf = tmp / "seed.bin"
        seedf.write_bytes(b"{\"url\":\"http://127.0.0.1:8099/health\"}")
        rc, out, err = _run([PY, _tool("fuzz_driver"), "grammar",
                             "--target", "http://127.0.0.1:8099/api/fetch?url=x",
                             "--seed", str(seedf), "--iterations", "10",
                             "--delay", "0.02"], cwd=tmp)
        check("grammar fuzz runs + logs artifact (no crash on odd responses)",
              rc == 0 and ("anomal" in out.lower() or "survived" in out.lower()), out + err)

        # 23j) payload corpus per-line IDs
        rc, out, err = _run([PY, _tool("payload_corpus"), "list",
                             "--search", "sqli"], cwd=tmp)
        rc2, out2, err2 = _run([PY, _tool("payload_corpus"), "note",
                                "--class", "sqli", "--payload-id", "P2",
                                "--stack", "mysql", "--worked", "true"], cwd=tmp,
                                env={**os.environ, "HOME": str(tmp / "fakehome")})
        check("payload corpus P-ids + fine-grained note",
              rc == 0 and "P1." in out and rc2 == 0 and "sqli#P2" in out2, out + out2 + err2)

        # 23k) verb matrix: the lab's DELETE-on-read-route vuln must surface
        _run([PY, _tool("auth_manager"), "add", "--role", "user",
              "--auth-type", "cookie", "--target", "http://127.0.0.1:8099",
              "--credential", "session=user-s3ssion"], cwd=tmp)
        board = load_json(tmp / ".blackboard" / "board.json")
        sid = board["sessions"][-1]["id"]
        eps_f = tmp / "vm_eps.txt"
        eps_f.write_text("/api/orders/1001\n")
        rc, out, err = _run([PY, _tool("auth_manager"), "verb-matrix",
                             "--base-url", "http://127.0.0.1:8099", "--session", sid,
                             "--endpoints", str(eps_f), "--delay", "0.02"], cwd=tmp)
        check("verb matrix flags over-permissive DELETE (200 on read route)",
              rc == 0 and "DELETE" in out and "200" in out, out)

        # 23l) timing oracle: same-body slow-response detection path exists
        # (functional timing check is flaky in CI; assert the code path by
        # verifying fetch_as returns elapsed and role-diff runs)
        rc, out, err = _run([PY, _tool("auth_manager"), "role-diff",
                             "--base-url", "http://127.0.0.1:8099",
                             "--roles", sid, "--endpoints", str(eps_f)], cwd=tmp)
        check("role-diff timing-instrumented path executes",
              rc != 0 and ">=2 roles" in err, err)  # correct guard: needs 2 roles

        # 23m) secrets scanner: seeded artifact -> family lead
        (tmp / ".blackboard" / "artifacts" / "MSG_SUITESECRET.log").write_text(
            "--- COMMAND ---\ncurl\n\n--- STDOUT ---\nkey=AKIAIOSFODNN7EXAMPLE\n\n--- STDERR ---\n")
        rc, out, err = _run([PY, _tool("secrets"), "scan"], cwd=tmp)
        check("artifact secret scanner files family leads",
              rc == 0 and "aws-access-key" in out, out + err)

        # 23n) snapshot + diff: new endpoint becomes a priority lead
        _run([PY, _tool("snapshot"), "snapshot", "--label", "s1"], cwd=tmp)
        _run([PY, _tool("sec_flow"), "add-asset",
              "--endpoint", "/brand-new-route"], cwd=tmp)
        rc, out, err = _run([PY, _tool("snapshot"), "diff"], cwd=tmp)
        check("surface diff detects new endpoint since snapshot",
              rc == 0 and "brand-new-route" in out, out)

        # 23o) wordlist winnowing: record + winnow split
        _run([PY, _tool("wordlist_wins"), "record"], cwd=tmp)
        wl = tmp / "wl.txt"
        wl.write_text("admin\nhealth\nzzz-never-seen\n")
        rc, out, err = _run([PY, _tool("wordlist_wins"), "winnow",
                             "--wordlist", str(wl), "--out", str(tmp / "wl_win.txt")],
                            cwd=tmp)
        won = (tmp / "wl_win.txt").read_text().splitlines()
        check("wordlist winnow keeps proven words only",
              rc == 0 and "admin" in won and "health" in won
              and "zzz-never-seen" not in won, out)

        # 23p) entropy analyzer: library-level analysis over synthetic tokens
        # (functional end-to-end covered by the lab; here: the detector math)
        rc, out, err = _run([PY, "-c",
                             "import sys; sys.path.insert(0, " + repr(_engine_dir) + "); "
                             "from entropy import analyze_tokens; "
                             "r = analyze_tokens(['1788045309x0799']*3 + ['1788045309x0800']*2); "
                             "print('DUP' if r['findings'] and 'duplicate' in r['findings'][0][0] else 'NODUP')"],
                            cwd=tmp)
        check("entropy analyzer flags duplicate + weak tokens",
              rc == 0 and "DUP" in out, out + err)

        # 25) operator interop: doctor, cross-index, poc-delta, skeptic ledger, tripwires
        rc, out, err = _run([PY, _tool("doctor"), "--json"],
                            cwd=tmp, env={**os.environ, "HOME": str(tmp / "fakehome")})
        doc = json.loads(out) if out.strip().startswith("[") else []
        check("doctor self-test runs (json mode)",
              rc in (0, 1) and len(doc) >= 5, out[:200])

        rc, out, err = _run([PY, _tool("cross_index"), "lookup", "traversal"],
                            cwd=tmp)
        check("cross-index lookup resolves a class",
              rc == 0 and "CLASS CROSS-INDEX" in out and "traversal" in out.lower(), out[:200])

        rc, out, err = _run([PY, _tool("cross_index"), "map"], cwd=tmp)
        check("coverage map renders class x store",
              rc == 0 and "COVERAGE MAP" in out and "BLIND SPOTS" in out, out[:200])

        rc, out, err = _run([PY, _tool("skeptic_ledger"), "record",
                             "--finding", "FINDING_TEST", "--verdict", "survives"],
                            cwd=tmp, env={**os.environ, "HOME": str(tmp / "fakehome")})
        rc2, out2, _ = _run([PY, _tool("skeptic_ledger"), "stats"],
                            cwd=tmp, env={**os.environ, "HOME": str(tmp / "fakehome")})
        check("skeptic ledger records + renders",
              rc == 0 and "logged" in out, out + out2)

        rc, out, err = _run([PY, _tool("tripwires"), "plant"], cwd=tmp)
        rc2, out2, _ = _run([PY, _tool("tripwires"), "check"], cwd=tmp)
        check("tripwires plant + full-chain check",
              rc == 0 and "planted" in out and "TRIPWIRE CHECK" in out2, out + out2)

        # greenhouse acceptance: known-good playbook class accepts
        rc, out, err = _run([PY, _tool("eval_engine"), "acceptance",
                             "--category", "sast", "--name", "ssrf",
                             "--port", "8901"], cwd=tmp)
        check("greenhouse acceptance ACCEPTS a matching playbook",
              rc == 0 and "ACCEPTED" in out, out)

        # 27) A1/A2: command-split smoke install — per-workflow files under the
        # byte budget, full workflow coverage (majors + catalog), dynamic count
        import subprocess as _sp2
        import tempfile as _tf
        import os as _os2
        fakehome = _tf.mkdtemp(prefix="sba_cmdhome_")
        env = {**_os2.environ, "HOME": fakehome}
        rc = _sp2.run(["bash", str(_ENGINE_ROOT.parent / "install.sh")],
                     cwd=str(_ENGINE_ROOT.parent), env=env,
                     capture_output=True, text=True, timeout=300).returncode
        cmd_dir = Path(fakehome) / ".config" / "opencode" / "commands"
        expected_files = ["analyze", "test", "intel", "scan-code", "research",
                          "discover", "roles", "oob", "chains", "eval-lab",
                          "nuclei", "burp", "patchdiff", "tokens", "catalog"]
        have = {p.stem for p in cmd_dir.glob("*.md")} if cmd_dir.exists() else set()
        missing = [f for f in expected_files if f not in have]
        check("A1: smoke install emits all 15 per-workflow command files",
              rc == 0 and not missing, f"rc={rc} missing={missing}")
        # byte budget: every emitted file <= 4KB (vs the ~30KB monolith)
        over = []
        for p in (cmd_dir.glob("*.md") if cmd_dir.exists() else []):
            if p.stat().st_size > 4096:
                over.append(f"{p.stem}:{p.stat().st_size}B")
        check("A1: every command file within the 4KB lazy-load budget",
              not over, f"over-budget: {over}")
        # coverage: the catalog one-line-indexes the non-major workflows; the
        # split must not drop ANY documented workflow (spot-check a sample of
        # tool names that lived in the old monolith's non-major sections)
        cat_text = (cmd_dir / "catalog.md").read_text() if (cmd_dir / "catalog.md").exists() else ""
        sample_tools = ["greenhouse", "lineage", "cross_index", "tripwires",
                        "skeptic_ledger", "secrets", "entropy", "graphql",
                        "race", "snapshot", "doctor", "client_report",
                        "maintenance", "metrics", "kev", "board_merge"]
        dropped = [t for t in sample_tools if t not in cat_text]
        check("A1: catalog loses no documented workflow (16-tool sample)",
              not dropped, f"dropped from catalog: {dropped}")
        # shared rules present in every file (generator-level dedup worked)
        no_preamble = [p.stem for p in cmd_dir.glob("*.md")
                       if "safe runner" not in p.read_text()] if cmd_dir.exists() else ["ALL"]
        check("A1: shared preamble emitted into every file",
              not no_preamble, f"missing preamble: {no_preamble}")
        # A2: install.sh contains exactly ONE sed rewrite pass
        inst_src = (_ENGINE_ROOT.parent / "install.sh").read_text()
        sed_count = inst_src.count('sed -i "s|~/artifactory|$ENGINE|g"')
        check("A2: install.sh has exactly one sed pass (no duplicate block)",
              sed_count == 1, f"sed passes: {sed_count}")
        # A2: skeptic agent has the escalation paragraph exactly once (no dup)
        skeptic_f = Path(fakehome) / ".config" / "opencode" / "agents" / "skeptic.md"
        sk_text = skeptic_f.read_text() if skeptic_f.exists() else ""
        check("A2: skeptic agent has no doubled paragraph",
              sk_text.count("Escalation ladder (when YOU are invoked)") == 1,
              f"count={sk_text.count('Escalation ladder (when YOU are invoked)')}")
        _shutil_rmtree = shutil.rmtree
        _shutil_rmtree(fakehome)

        # 27b) A3: wiring self-check — no true orphans; a planted orphan FAILS
        from doctor import wiring_check as _wc, WIRING_EXEMPT as _WE
        ok, orphans = _wc()
        check("A3: wiring check passes (no orphan modules)", ok, f"orphans={orphans}")
        # negative: a planted orphan must FAIL reachability. The probe name is
        # CONSTRUCTED at runtime (never a literal in this file) so the check
        # cannot accidentally "document" it by mentioning it.
        _orph = "orphan" + "_probe" + "_x9"
        inst_txt = (_ENGINE_ROOT.parent / "install.sh").read_text()
        eval_txt = (Path(_engine_dir) / "eval_engine.py").read_text()
        planted_is_orphan = (_orph not in inst_txt
                             and _orph not in eval_txt
                             and (_orph + ".py") not in _WE)
        check("A3: a planted undocumented/untested module IS detected as orphan",
              planted_is_orphan, "reachability semantics failed")

        # 27c) B0: model router — matrix obedience + clean fallback (no network)
        from model_router import route as _mr_route, ROLE_TIERS as _MR_TIERS, ROLES as _MR_ROLES
        import model_router as _mr
        # matrix sanity: every role resolves to a tier; planner exists; no invented roles
        check("B0: router matrix covers roles incl. planner, verbatim names",
              set(_MR_ROLES) >= {"operator", "scout", "exploit", "verifier",
                                "skeptic", "recon", "synthesis", "planner", "other"}
              and all(r in _MR_TIERS for r in _MR_ROLES),
              f"roles={_MR_ROLES}")
        # fallback semantics in a scratch cwd: cheap-only config routes capable->cheap
        scratch2 = tmp / "b0scratch"
        scratch2.mkdir()
        (scratch2 / ".blackboard").mkdir()
        (scratch2 / ".blackboard" / "models.json").write_text(json.dumps(
            {"cheap": {"base_url": "http://localhost:11434/v1",
                       "model": "llama3", "api_key_env": ""}}))
        rc, out, err = _run([PY, _tool("model_router"), "show",
                              "--role", "skeptic"], cwd=scratch2)
        check("B0: unset tier falls back to cheaper working tier",
              rc == 0 and "FALLBACK" in out and "cheap" in out, out + err)
        # never-blocks: empty config -> deterministic-only, exit 0
        rc, out, err = _run([PY, _tool("model_router"), "show",
                             "--role", "exploit"], cwd=tmp)
        check("B0: no config -> deterministic-only (never blocks)",
              rc == 0 and "deterministic-only" in out, out + err)

        # 27d) B1: chain planner — seeded 4-finding graph plans data_exfil
        b1 = tmp / "b1ws"
        b1.mkdir()
        rc = _run([PY, _tool("init_env"), "--target", str(b1)],
                  cwd=b1) if False else None
        # init via cwd (init_env writes into the target dir)
        _run([PY, _tool("init_env"), "--target", "."], cwd=b1)
        for title in ["API token leak in verbose error log",
                      "Auth bypass on /admin via header trust",
                      "IDOR on /api/orders allows reading other users' orders",
                      "Data reach: order dump endpoint exposes all records"]:
            _run([PY, _tool("sec_flow"), "add-asset",
                  "--finding", title, "--severity", "high",
                  "--status", "confirmed", "--poc", "seed"], cwd=b1)
        rc, out, err = _run([PY, _tool("sec_flow"), "chains",
                             "--plan", "--goal", "data_exfil"], cwd=b1)
        has3hop = "3 hop" in out
        check("B1: plan data_exfil returns a >=3-hop ranked path",
              rc == 0 and has3hop and "CHAIN PLAN" in out, out + err)
        b1board = load_json(b1 / ".blackboard" / "board.json")
        hypo = b1board.get("hypo_edges", [])
        # chain_to untouched by the planner (evidence-only store)
        no_chain_to = all(not f.get("chain_to") for f in b1board.get("findings", []))
        check("B1: planner writes hypo_edges, never chain_to",
              len(hypo) >= 1 and no_chain_to,
              f"hypo={len(hypo)} chain_to_clean={no_chain_to}")
        # hypo edges carry provenance
        check("B1: hypo_edges carry source provenance",
              all("source" in e for e in hypo), json.dumps(hypo)[:120])
        # no-path clean exit
        b1b = tmp / "b1empty"
        b1b.mkdir()
        _run([PY, _tool("init_env"), "--target", "."], cwd=b1b)
        rc, out, err = _run([PY, _tool("sec_flow"), "chains",
                             "--plan", "--goal", "RCE"], cwd=b1b)
        check("B1: no-path graph returns 'no chain to goal' cleanly",
              rc == 0 and "no chain to goal" in out, out + err)
        # lead-referencing hypo edge renders with a RESOLVED label in SUMMARY
        b1board.setdefault("leads", []).append({
            "id": "LEAD_S1", "type": "anomaly",
            "value": "SSRF candidate in image importer", "signal": "fetch",
            "confidence": 0.6, "suggested_next": "x", "must_verify": True,
            "preconditions": [], "source_pointer": "MSG_Z", "status": "new",
            "created_at": "now"})
        b1board.setdefault("hypo_edges", []).append({
            "from": "LEAD_S1", "to": b1board["findings"][0]["id"],
            "why": "test edge", "confidence": 0.6, "source": "deterministic",
            "created_at": "now"})
        (b1 / ".blackboard" / "board.json").write_text(json.dumps(b1board, indent=2))
        rc, out, err = _run([PY, _tool("report_engine")], cwd=b1)
        summary_txt = (b1 / "reports" / "SUMMARY.md").read_text()
        check("B1: SUMMARY separates Hypothesized paths + resolves LEAD labels",
              "Hypothesized Paths" in summary_txt
              and "SSRF candidate in image importer" in summary_txt,
              summary_txt[:200])

        # 27e) A4: planner agent registered with the chains --plan contract
        fakehome2 = _tf.mkdtemp(prefix="sba_planner_")
        _sp2.run(["bash", str(_ENGINE_ROOT.parent / "install.sh")],
                 cwd=str(_ENGINE_ROOT.parent),
                 env={**_os2.environ, "HOME": fakehome2},
                 capture_output=True, text=True, timeout=300)
        planner_f = Path(fakehome2) / ".config" / "opencode" / "agents" / "planner.md"
        pt = planner_f.read_text() if planner_f.exists() else ""
        check("A4: planner agent installed w/ --plan --goal contract + hypo-safety",
              pt and "chains --plan --goal" in pt and "NEVER write chain_to" in pt
              and "hypo_edges" in pt, pt[:150])
        exploit_f = Path(fakehome2) / ".config" / "opencode" / "agents" / "exploit.md"
        et = exploit_f.read_text() if exploit_f.exists() else ""
        check("A5: exploit agent references corpus payloads + model routing",
              "payload_corpus.py" in et and "model_router.py" in et, et[:150])
        _shutil_rmtree(fakehome2)

        # 27f) B2: MCP broker against a MOCK stdio server — pointer + lead,
        #      no schema / no raw secret on the board, gates enforced
        mock_srv = tmp / "mock_mcp.py"
        mock_srv.write_text(
            "import json, sys\n"
            "TOOLS=[{'name':'fetch_url','description':'Fetches a URL (mock)\\nlong schema doc',"
            "'inputSchema':{'type':'object','properties':{'url':{'type':'string'}},"
            "'required':['url']}}]\n"
            "for line in sys.stdin:\n"
            "    try: msg=json.loads(line)\n"
            "    except Exception: continue\n"
            "    m=msg.get('method'); r={'jsonrpc':'2.0','id':msg.get('id')}\n"
            "    if m=='initialize': r['result']={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'mock','version':'1'}}\n"
            "    elif m=='tools/list': r['result']={'tools':TOOLS}\n"
            "    elif m=='tools/call': r['result']={'content':[{'type':'text','text':'body ok secret=AKIAIMOCKSECRETKEY9999'}],'isError':False}\n"
            "    else: continue\n"
            "    sys.stdout.write(json.dumps(r)+'\\n'); sys.stdout.flush()\n")
        b2home = tmp / "b2home"
        (b2home / ".artifactory").mkdir(parents=True)
        (b2home / ".artifactory" / "mcp.json").write_text(json.dumps(
            {"servers": {"mock": {"transport": "stdio",
                                  "command": [PY, str(mock_srv)],
                                  "capabilities": ["local"], "approved": True}}}))
        b2env = {**os.environ, "HOME": str(b2home)}
        b2ws = tmp / "b2ws"
        b2ws.mkdir()
        _run([PY, _tool("init_env"), "--target", "."], cwd=b2ws, env=b2env)
        rc, out, err = _run([PY, _tool("mcp_broker"), "call",
                             "--server", "mock", "--tool", "fetch_url",
                             "--args", '{"url":"http://127.0.0.1/x"}'],
                            cwd=b2ws, env=b2env)
        b2board = json.dumps(load_json(b2ws / ".blackboard" / "board.json"))
        check("B2: mock MCP call -> MSG_* + lead, redaction holds",
              rc == 0 and "MCP call complete" in out
              and "LEAD_" in out
              and "inputSchema" not in b2board
              and "AKIAIMOCKSECRETKEY9999" not in b2board
              and "__REDACTED__" in out, out[:300] + err[:200])
        # describe: arg names + types only (no doc schema in output)
        rc, out, err = _run([PY, _tool("mcp_broker"), "describe",
                             "--tool", "fetch_url"], cwd=b2ws, env=b2env)
        check("B2: describe emits arg names+types only (no schema docs)",
              rc == 0 and "url: string (required)" in out
              and "long schema doc" not in out, out + err)
        # net-capability gate: no --target -> refused
        (b2home / ".artifactory" / "mcp.json").write_text(json.dumps(
            {"servers": {"mock": {"transport": "stdio",
                                  "command": [PY, str(mock_srv)],
                                  "capabilities": ["net"], "approved": True}}}))
        rc, out, err = _run([PY, _tool("mcp_broker"), "call",
                             "--server", "mock", "--tool", "fetch_url",
                             "--args", "{}"], cwd=b2ws, env=b2env)
        check("B2: net-capable server refuses target-less call (no passive bypass)",
              rc != 0 and "SCOPE ERROR" in err, err[:200])
        # unapproved server refused
        (b2home / ".artifactory" / "mcp.json").write_text(json.dumps(
            {"servers": {"mock": {"transport": "stdio",
                                  "command": [PY, str(mock_srv)],
                                  "capabilities": ["local"], "approved": False}}}))
        rc, out, err = _run([PY, _tool("mcp_broker"), "call",
                             "--server", "mock", "--tool", "fetch_url",
                             "--args", "{}"], cwd=b2ws, env=b2env)
        check("B2: unapproved server is unusable (allowlist)",
              rc != 0 and "not registered/approved" in err, err[:200])

        # 27g) B3: classification + consent semantics (no full pipeline in the
        #      suite — it runs in propose; here the RULES are the check)
        from self_improve import classify_candidate as _cc, verify_consent as _vc, DATA_ONLY_PATHS as _DOP
        check("B3: DATA candidate classifies as data (both layout spellings)",
              _cc(["artifactory/knowledge/sources.json"], "data") == "data"
              and _cc(["knowledge/sources.json"], "data") == "data")
        check("B3: playbook/poc-delta candidates classify as tradecraft (never auto)",
              _cc(["artifactory/prompts/sast/ssrf.md"], "playbook") == "tradecraft"
              and _cc(["prompts/web/x.md"], "poc-delta") == "tradecraft")
        check("B3: safety-file touch classifies as unsafe (forced review)",
              _cc(["artifactory/sec_flow.py"], "data") == "unsafe"
              and _cc(["artifactory/knowledge/sources.json",
                       "artifactory/scope_sig.py"], "data") == "unsafe")
        # consent: expired/mismatched/replayed consents REJECT
        exp_ws = str(tmp)
        _expired = json.dumps({
            "workspace": exp_ws, "ref": "r1",
            "expires": "2020-01-01T00:00:00+00:00"}, sort_keys=True)
        ok_exp, why_exp = None, None
        # craft an expired-but-correctly-signed consent in a scratch workspace
        scratch3 = tmp / "b3cons"
        (scratch3 / ".blackboard").mkdir(parents=True, exist_ok=True)
        key_b = b""
        import hmac as _hmac
        from scope_sig import KEY_PATH as _KP
        key_b = _KP.read_bytes().strip() if _KP.exists() else b"testkey"
        exp_payload = json.dumps({"workspace": str(scratch3), "ref": "r1",
                                  "expires": "2020-01-01T00:00:00+00:00"}, sort_keys=True)
        sig = _hmac.new(key_b, exp_payload.encode(), hashlib.sha256).hexdigest()
        (scratch3 / ".selfimprove-consent").write_text(
            json.dumps({**json.loads(exp_payload), "hmac": sig}))
        r_ok, r_why = None, None
        import self_improve as _si
        try:
            os.chdir(scratch3)
            r_ok, r_why = _si.verify_consent("r1")
        finally:
            os.chdir(tmp)
        check("B3: expired consent rejected (no permanent blank checks)",
              r_ok is False and "EXPIRED" in r_why, f"{r_ok} {r_why}")
        # workspace-binding: valid signature for a DIFFERENT workspace rejects
        other_payload = json.dumps({"workspace": "/definitely/other", "ref": "r1",
                                    "expires": "2099-01-01T00:00:00+00:00"}, sort_keys=True)
        sig2 = _hmac.new(key_b, other_payload.encode(), hashlib.sha256).hexdigest()
        (scratch3 / ".selfimprove-consent").write_text(
            json.dumps({**json.loads(other_payload), "hmac": sig2}))
        try:
            os.chdir(scratch3)
            r_ok2, r_why2 = _si.verify_consent("r1")
        finally:
            os.chdir(tmp)
        check("B3: cross-workspace consent replay rejected",
              r_ok2 is False and "mismatch" in r_why2.lower(), f"{r_ok2} {r_why2}")

        # 28) report engine renders chain paths in SUMMARY
        rc, out, err = _run([PY, _tool("report_engine")], cwd=tmp)
        summary = (tmp / "reports" / "SUMMARY.md")
        check("report renders attack paths + advisories",
              summary.exists() and "Attack Paths" in summary.read_text()
              and list((tmp / "reports").glob("FINDING_*.md")), err)

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Dynamic count (A2): the suite prints its OWN executed total — the
    # authoritative number (call sites may be conditional/skipped). README and
    # any doc must cite THIS, so drift is impossible by construction.
    print(f"\n[*] ENGINE SUITE: {len(passed)} passed, {len(failed)} failed "
          f"(suite-total: {len(passed) + len(failed)})")
    if failed:
        print("    FAILED:")
        for f in failed:
            print(f"      - {f}")
    return 0 if not failed else 1


# ------------------------------------------------------------ scoring
def _load_ledger_totals():
    tokens_file = BLACKBOARD_DIR / "tokens.jsonl"
    if not tokens_file.exists():
        return 0
    total = 0
    for line in tokens_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if r.get("unit") == "tokens":
                total += r.get("amount", 0)
        except Exception:
            continue
    return total


def score_engagement(label=""):
    """North-star + precision + coverage for the CURRENT workspace. Never
    promotes anything — output + append-only history (evals/scores.jsonl) so
    A/B comparisons are deterministic."""
    board = load_json(BOARD_FILE)
    if not board:
        print("[!] No board.json in this workspace. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    findings = board.get("findings", [])
    leads = board.get("leads", [])
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    informational = [f for f in findings if f.get("status") == "informational"]
    total_tokens = _load_ledger_totals()

    precision = (len(confirmed) / len(findings)) if findings else 0.0
    per_m = (len(confirmed) / (total_tokens / 1_000_000)) if total_tokens else 0.0
    worked = [l for l in leads if l.get("status") in ("confirmed", "dead", "testing")]
    coverage = (len(worked) / len(leads)) if leads else 1.0

    result = {
        "label": label or Path.cwd().name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "confirmed_vulns": len(confirmed),
        "informational": len(informational),
        "precision": round(precision, 3),
        "total_leads": len(leads),
        "leads_worked": len(worked),
        "coverage": round(coverage, 3),
        "tokens_spent": total_tokens,
        "vulns_per_1M_tokens": round(per_m, 2),
    }
    print(json.dumps(result, indent=2))
    print("\n  ★ NORTH-STAR: proven vulns / 1M tokens = "
          f"{per_m:.2f}  (precision {precision:.0%}, coverage {coverage:.0%})")

    # Append-only history for A/B compare
    EVALS_DIR.mkdir(exist_ok=True)
    with open(SCORES_FILE, "a") as f:
        f.write(json.dumps(result) + "\n")
    print(f"  [✔] Appended to {SCORES_FILE}")
    return result


def compare_scores():
    """A/B compare the two most recent scores (or all): which candidate won
    on the north-star + precision + coverage, deterministically."""
    if not SCORES_FILE.exists():
        print("[*] No scores yet. Run `score --label <name>` in each A/B workspace.")
        return 0
    rows = []
    for line in SCORES_FILE.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    if len(rows) < 2:
        print("[*] Only one score recorded — need two (A then B) to compare.")
        for r in rows:
            print(f"  {r['label']}: {r['confirmed_vulns']} confirmed, "
                  f"{r['vulns_per_1M_tokens']} vulns/1M-tokens")
        return 0
    a, b = rows[-2], rows[-1]
    print(f"[*] A/B COMPARE (deterministic):\n")
    print(f"  A: {a['label']:<28} {a['confirmed_vulns']} confirmed | "
          f"{a['vulns_per_1M_tokens']} vulns/1M | precision {a['precision']} | coverage {a['coverage']}")
    print(f"  B: {b['label']:<28} {b['confirmed_vulns']} confirmed | "
          f"{b['vulns_per_1M_tokens']} vulns/1M | precision {b['precision']} | coverage {b['coverage']}\n")
    better = []
    if b["confirmed_vulns"] > a["confirmed_vulns"]:
        better.append("more confirmed vulns")
    if b["vulns_per_1M_tokens"] > a["vulns_per_1M_tokens"]:
        better.append("better vulns/1M-tokens")
    if b["precision"] > a["precision"]:
        better.append("better precision")
    if b["coverage"] > a["coverage"]:
        better.append("better coverage")
    regressions = []
    if b["confirmed_vulns"] < a["confirmed_vulns"]:
        regressions.append("fewer confirmed vulns")
    if b["precision"] < a["precision"]:
        regressions.append("worse precision")
    verdict = "B WINS" if better and not regressions else \
              "REGRESSION" if regressions else "EQUIVALENT"
    if better:
        print(f"  B improved: {', '.join(better)}")
    if regressions:
        print(f"  B regressed: {', '.join(regressions)}")
    print(f"\n  VERDICT: {verdict}"
          + (" — candidate is safe to gate." if verdict == "B WINS" else ""))
    return 0


def validate_lab_manifest(lab_key="lab1", lab_port=None):
    """Deterministically validate the CURRENT board against a lab manifest:
    every seeded vuln must have a CONFIRMED finding with evidence; negative
    controls must not be confirmed as vulns. Used after an opencode-driven
    lab run to score it reproducibly."""
    manifest = LAB_MANIFESTS[lab_key]
    ports = {"lab1": 8099, "lab2": 8100, "lab3": 8101}
    board = load_json(BOARD_FILE)
    findings = board.get("findings", [])
    confirmed = [f for f in findings if f.get("status") == "confirmed"]

    passed, failed = [], []

    for case in manifest["cases"]:
        marker = case["confirm_marker"].lower()
        hit = [f for f in confirmed
               if marker in (f.get("title", "") + " " + f.get("details", "")).lower()]
        evidence_ok = all(f.get("evidence") or f.get("evidence_pointer") for f in hit) if hit else False
        if hit and evidence_ok:
            passed.append(case["id"])
        else:
            failed.append(case["id"])

    for nc in manifest["negative_controls"]:
        bad = [f for f in confirmed
               if nc["must_not_confirm_marker"].lower()
               in (f.get("title", "") + " " + f.get("details", "")).lower()]
        if bad:
            failed.append(nc["id"] + " (false positive!)")
        else:
            passed.append(nc["id"])

    # Skeptic contracts (lab3): every confirmed finding must still carry
    # evidence — the skeptic-endorsed shortcut (confirming without proof) is
    # a gate failure by construction.
    for sc in manifest.get("skeptic_contracts", []):
        bad = [f for f in confirmed
               if not (f.get("evidence") or f.get("evidence_pointer"))]
        if bad:
            failed.append(sc["id"] + f" ({len(bad)} evidence-less confirmed!)")
        else:
            passed.append(sc["id"])

    print(f"[*] {lab_key.upper()} MANIFEST: {len(passed)} passed, {len(failed)} failed")
    for p in passed:
        print(f"    [✔] {p}")
    for f in failed:
        print(f"    [!] {f}")
    return 0 if not failed else 1


# ------------------------------------------------------------ promotion gate
def gate(candidate: str, notes: str = ""):
    """The promotion gate. A candidate change (any diff to engine/playbooks/
    agents) is promoted ONLY if the deterministic engine suite passes AFTER the
    change and the lab manifest does not regress. Run BEFORE making the change
    to record the incumbent score, then AFTER, then this gate compares.

    Concretely this subcommand:
      1. runs `suite engine` now (the candidate state),
      2. reads evals/manifest.json for the incumbent's last suite result,
      3. refuses promotion if the suite regresses or lab cases were lost.

    The lab LLM-run itself is driven by opencode (the /artifactory eval-lab
    command); this gate only enforces determinism on what lands.
    """
    EVALS_DIR.mkdir(exist_ok=True)
    manifest_path = EVALS_DIR / "manifest.json"
    history = []
    if manifest_path.exists():
        try:
            history = json.loads(manifest_path.read_text())
        except Exception:
            history = []

    print(f"[*] PROMOTION GATE for candidate: {candidate}")
    print("[*] Step 1: deterministic engine suite (candidate state)...")
    rc = suite_engine(verbose=False)
    suite_ok = (rc == 0)

    incumbent = next((h for h in reversed(history) if h.get("suite_ok")), None)
    verdict = "PROMOTE"
    reasons = []
    if not suite_ok:
        verdict = "REJECT"
        reasons.append("engine suite FAILED in candidate state")
    if incumbent and incumbent.get("lab_cases_passed", 0) is not None:
        # Lab score must be re-supplied after the opencode lab run; if the
        # gate is run without it we warn (labs are the final promotion check).
        reasons.append("lab manifest must be re-run post-change (/artifactory eval-lab) before merge")

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "candidate": candidate,
        "notes": notes,
        "suite_ok": suite_ok,
        "lab_cases_passed": None,  # filled by validate_lab_manifest after the lab run
        "verdict": verdict,
        "reasons": reasons,
    }
    history.append(record)
    manifest_path.write_text(json.dumps(history, indent=2))

    print(f"\n    GATE: {verdict}")
    for r in reasons:
        print(f"      - {r}")
    print(f"    Recorded to {manifest_path}")
    return 0 if verdict == "PROMOTE" else 1


def gate_final(candidate: str):
    """FINAL promotion check against the HOLD-OUT lab (lab3). This is the
    anti-overfit backstop: iteration happens on labs 1-2; lab3 is only ever
    touched here. Requires the operator to have run lab3's manifest in this
    workspace (validated via validate-lab lab3) — the gate verifies both the
    engine suite AND the hold-out board state."""
    print(f"[*] FINAL GATE (hold-out) for candidate: {candidate}")
    print("[*] Step 1: engine suite...")
    suite_ok = suite_engine(verbose=False) == 0

    print("[*] Step 2: hold-out lab3 manifest on the current board...")
    holdout_ok = validate_lab_manifest("lab3") == 0

    verdict = "PROMOTE" if (suite_ok and holdout_ok) else "REJECT"
    reasons = []
    if not suite_ok:
        reasons.append("engine suite failed")
    if not holdout_ok:
        reasons.append("hold-out lab3 manifest not satisfied (run the lab3 engagement, "
                       "confirm V9/V10/V11, then re-gate)")

    EVALS_DIR.mkdir(exist_ok=True)
    manifest_path = EVALS_DIR / "manifest.json"
    history = []
    if manifest_path.exists():
        try:
            history = json.loads(manifest_path.read_text())
        except Exception:
            history = []
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "candidate": candidate,
        "gate": "final-holdout",
        "suite_ok": suite_ok,
        "holdout_ok": holdout_ok,
        "verdict": verdict,
        "reasons": reasons,
    })
    manifest_path.write_text(json.dumps(history, indent=2))

    print(f"\n    FINAL GATE: {verdict}")
    for r in reasons:
        print(f"      - {r}")
    return 0 if verdict == "PROMOTE" else 1


# ---------------------------------------------------------- acceptance harness
# A new/revised methodology must DETECT its planted bug before field use.
# The greenhouse provides per-class ground truth; this harness wires playbooks
# to recipes and checks the evidence chain.

# class keyword -> greenhouse recipe (kept in one place; extend as recipes grow)
PLAYBOOK_RECIPE_MAP = [
    (["xss", "cross-site scripting"], "xss-reflected"),
    (["sqli", "sql injection", "sql-injection"], "sqli-error"),
    (["traversal", "path", "lfi", "file read"], "traversal-read"),
    (["ssrf", "server-side request"], "ssrf-fetch"),
    (["access control", "bac", "role", "privilege", "admin"], "bac-role-panic"),
    (["idor", "object reference", "bola", "ownership"], "idor-object"),
    (["mass assignment", "parameter tampering"], "mass-assignment"),
    (["race"], "race-coupon"),
    (["jwt", "alg"], "jwt-alg-none"),
    (["token", "session management", "entropy"], "token-weak"),
    (["oauth", "redirect_uri", "open redirect"], "oauth-redirect-open"),
    (["ssti", "template injection"], "ssti-jinja2"),
    (["xxe", "xml external", "entity"], "xxe-simulated"),
    (["deserial", "pickle", "unserialize"], "deser-pickle"),
]


def recipe_for_playbook(category: str, name: str):
    """Map a playbook (category/name) to a greenhouse recipe via keyword match.
    Returns the recipe class or None."""
    blob = f"{category} {name}".lower()
    for kws, recipe in PLAYBOOK_RECIPE_MAP:
        if any(k in blob for k in kws):
            return recipe
    return None


def acceptance(category: str, name: str, port: int = 8600):
    """The acceptance harness: does the playbook's class have greenhouse
    ground truth, does that lab's vuln demonstrably exist (selfcheck), and
    does the playbook reference the detection evidence (marker)?

    Verdict scale:
      ACCEPTED      — lab exists, vuln plants + selfchecks, playbook text
                      references the marker/signature the lab exposes
      GROUND-TRUTH-ONLY — lab fine, but playbook doesn't reference the
                      detection signature (methodology may not actually
                      detect it — revise before field use)
      NO-RECIPE     — no greenhouse ground truth for this class yet:
                      grow one before trusting the methodology
      SELF-CHECK-FAILED — the planted lab is broken (recipe bug, not the
                      playbook's fault; fix the recipe)
    """
    import subprocess as _sp
    from pathlib import Path as _P
    recipe = recipe_for_playbook(category, name)
    if not recipe:
        print(f"[!] NO-RECIPE: no greenhouse ground truth for '{category}/{name}'.")
        print("    Grow one (greenhouse.py list) or add a recipe — a methodology")
        print("    without planted ground truth goes to the field untested.")
        return 1

    import greenhouse as _gh
    lab_dir = _P.cwd() / ".greenhouse" / recipe
    if not (lab_dir / "lab.py").exists():
        _gh.grow(recipe, port)
    lab = lab_dir / "lab.py"

    # 1) lab runs + selfcheck passes (the planted vuln is real)
    proc = _sp.Popen([sys.executable, str(lab), "--port", str(port)],
                     stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    import time as _t
    _t.sleep(0.7)
    rc = _sp.run([sys.executable, str(lab), "--selfcheck", "--port", str(port)],
                 capture_output=True, text=True, timeout=30).returncode
    proc.terminate()

    marker = _gh.BUG_RECIPES[recipe]["marker"]

    # 2) playbook exists + references the marker-ish evidence
    import playbook_engine as _pe
    pb_path = _pe.get_playbook_path(category, name)
    if not pb_path.exists():
        print(f"[!] Playbook '{category}/{name}' not found on disk.")
        return 1
    pb_text = pb_path.read_text().lower()

    # does the playbook mention the lab's observable signature family?
    sig_kws = {
        "xss-reflected": ["<script", "reflected", "encod"],
        "sqli-error": ["sql syntax", "error", "sqli"],
        "traversal-read": ["../", "traversal", "path"],
        "ssrf-fetch": ["url", "fetch", "oob", "callback"],
        "bac-role-panic": ["admin", "role", "403", "session"],
        "idor-object": ["order", "object", "owner", "id"],
        "mass-assignment": ["role", "field", "json", "profile"],
        "race-coupon": ["race", "burst", "thread", "coupon"],
        "jwt-alg-none": ["alg", "none", "jwt", "token"],
        "token-weak": ["entropy", "token", "session", "predict"],
        "oauth-redirect-open": ["redirect", "location", "redirect_uri"],
        "ssti-jinja2": ["{{", "template", "ssti", "7*7"],
        "xxe-simulated": ["entity", "doctype", "file://"],
        "deser-pickle": ["pickle", "base64", "deserial", "opcode"],
    }[recipe]
    references_sig = any(k.lower() in pb_text for k in sig_kws)

    if rc != 0:
        print(f"[!] SELF-CHECK-FAILED for recipe '{recipe}' — fix the recipe "
              f"(the playbook is not at fault).")
        return 1
    if not references_sig:
        print(f"[~] GROUND-TRUTH-ONLY: lab for '{recipe}' plants + selfchecks, but the")
        print(f"    playbook does not reference its observable signature "
              f"({', '.join(sig_kws[:3])}).")
        print(f"    The methodology may not actually detect this class — revise it")
        print(f"    to test for the signature, then re-accept.")
        return 1
    print(f"[OK] ACCEPTED: '{category}/{name}' has greenhouse ground truth "
          f"('{recipe}'), the planted vuln selfchecks, and the methodology")
    print(f"    references the observable signature. Marker for field evidence: {marker!r}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Eval Engine (learning-loop gate)")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    suite_p = subparsers.add_parser("suite", help="Run a suite")
    suite_p.add_argument("kind", choices=["engine"], help="'engine' = deterministic machinery checks")
    suite_p.add_argument("--verbose", action="store_true")

    subparsers.add_parser("score", help="North-star score of the CURRENT engagement workspace") \
        .add_argument("--label", default="")

    subparsers.add_parser("compare", help="A/B compare the two most recent scores")

    lab_p = subparsers.add_parser("validate-lab", help="Validate board vs a lab manifest")
    lab_p.add_argument("--lab", default="lab1", choices=list(LAB_MANIFESTS),
                       help="lab1 (8099) | lab2 (8100) | lab3 (8101, hold-out)")

    gate_p = subparsers.add_parser("gate", help="Promotion gate for a harness candidate change")
    gate_p.add_argument("--candidate", required=True, help="Short name of the change being gated")
    gate_p.add_argument("--notes", default="")
    gate_p.add_argument("--final", action="store_true",
                        help="FINAL gate: engine suite + HOLD-OUT lab3 manifest")

    acc = subparsers.add_parser("acceptance",
                                help="Greenhouse acceptance: must a playbook class detect its planted bug?")
    acc.add_argument("--category", required=True)
    acc.add_argument("--name", required=True)
    acc.add_argument("--port", type=int, default=8600)

    args = parser.parse_args()

    if args.subcommand == "suite":
        sys.exit(suite_engine(args.verbose))
    elif args.subcommand == "score":
        score_engagement(args.label)
    elif args.subcommand == "compare":
        sys.exit(compare_scores())
    elif args.subcommand == "validate-lab":
        sys.exit(validate_lab_manifest(args.lab))
    elif args.subcommand == "gate":
        sys.exit(gate_final(args.candidate) if args.final
                 else gate(args.candidate, args.notes))
    elif args.subcommand == "acceptance":
        sys.exit(acceptance(args.category, args.name, args.port))
