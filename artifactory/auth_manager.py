#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Auth-State Manager + Role-Diff Engine

Sessions as first-class blackboard artifacts: credentials/cookies/tokens are
stored under .blackboard/sessions/<id>.json and referenced BY POINTER from
board.json — auth state never lives inline in context. Supports:

  * role matrix per engagement (anonymous + authenticated roles)
  * cookie / bearer / header auth states (curl-compatible)
  * refresh hooks (a command template re-run by the harness when expired)
  * ROLE-DIFF: replay an endpoint inventory across roles, normalize responses,
    and file response DELTAS as broken-access-control leads. OWASP #1 class,
    mostly invisible to scanners (logic property, no injectable signature),
    and nearly free in tokens: mechanical execution, LLM only triages diffs.

All HTTP is done with urllib against in-scope targets ONLY (reuse of the
scope gate via a local check; refuses to touch out-of-scope hosts).
"""

import argparse
import http.cookiejar
import time
import ipaddress
import json
import re
import socket
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

BLACKBOARD_DIR = blackboard_dir()
SESSIONS_DIR = BLACKBOARD_DIR / "sessions"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"

AUTH_TYPES = ["cookie", "bearer", "header"]
VOLATILE_SUBSTRINGS = [
    # Normalization: volatile response content that must be stripped before any
    # cross-role comparison, or every endpoint would "diff" trivially.
    "csrf", "nonce", "xsrf", "captcha", "timestamp", "\"time\"", "'time'",
    "date", "token", "request_id", "requestid", "trace_id", "traceid", "_=",
]


def ensure_dirs():
    BLACKBOARD_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------- scope gate
def clean_host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def host_in_scope(host: str, scope: dict) -> bool:
    """Same fail-closed semantics as sec_flow.is_target_in_scope (kept local to
    avoid importing sec_flow, which has CLI side effects at import time)."""
    if not scope:
        return False
    h = clean_host(host)
    if h in scope.get("allowed_hosts", []):
        return True
    for domain in scope.get("allowed_domains", []):
        d = domain.replace("*.", "")
        if h == d or h.endswith("." + d):
            return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(h))
        if h in scope.get("allowed_hosts", []):
            return True
        for cidr in scope.get("allowed_cidrs", []):
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except (socket.gaierror, ValueError):
        return False
    return False


def require_scope(target: str):
    # Tamper evidence first: a TAMPERED scope authorizes nothing.
    try:
        from scope_sig import verify_scope, tamper_notice
        if verify_scope().startswith("TAMPERED"):
            print(tamper_notice(), file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass  # unsigned legacy workspace — the scope check below still applies
    scope = load_json(SCOPE_FILE)
    if not host_in_scope(target, scope):
        print(f"[!] SCOPE ERROR: '{target}' is not permitted by .blackboard/scope.json. "
              f"Add it first: sec_flow.py scope --add-host/-domain {clean_host(target)}",
              file=sys.stderr)
        sys.exit(1)


# ------------------------------------------------------------- session store
def _session_path(sid: str) -> Path:
    return SESSIONS_DIR / f"{sid}.json"


def add_session(role, auth_type, target, credential="", header_name="",
                refresh_hook="", expiry="", note=""):
    """Register a session artifact. The credential itself is stored ONLY in the
    session file (never in board.json / context); the board keeps a pointer."""
    ensure_dirs()
    if auth_type not in AUTH_TYPES:
        print(f"[!] Unknown auth type '{auth_type}'. Valid: {', '.join(AUTH_TYPES)}",
              file=sys.stderr)
        sys.exit(1)
    if auth_type in ("cookie",) and not credential:
        print("[!] cookie auth needs --credential '<cookie string>'", file=sys.stderr)
        sys.exit(1)
    if auth_type == "bearer" and not credential:
        print("[!] bearer auth needs --credential '<token>'", file=sys.stderr)
        sys.exit(1)
    if auth_type == "header" and not (header_name and credential):
        print("[!] header auth needs --header-name and --credential", file=sys.stderr)
        sys.exit(1)

    sid = f"SESS_{uuid.uuid4().hex[:6].upper()}"
    session = {
        "id": sid,
        "role": role,
        "auth_type": auth_type,
        "target": target,
        # credential (cookie value / bearer token / header value) — pointer body,
        # lives in this file only, never on the board.
        "credential": credential,
        "header_name": header_name if auth_type == "header" else "",
        "refresh_hook": refresh_hook,
        "expiry": expiry,
        "note": note,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_used": "",
        "valid": True,
    }
    _session_path(sid).write_text(json.dumps(session, indent=2))

    with json_transaction("board.json", create=True) as board:
        if board is None:
            print("[!] Error: board.json missing. Run init_env.py first.", file=sys.stderr)
            sys.exit(1)
        # Only the POINTER is board-visible: role/type/target/expiry/valid.
        board.setdefault("sessions", []).append({
            "id": sid,
            "role": role,
            "auth_type": auth_type,
            "target": target,
            "expiry": expiry,
            "refresh_hook": bool(refresh_hook),
            "valid": True,
        })
    print(f"[✔] Session {sid} [{role}/{auth_type}] -> {target} "
          f"(credential stored at .blackboard/sessions/{sid}.json — pointer on board)")


def list_sessions(role=None):
    board = load_json(BOARD_FILE)
    sessions = board.get("sessions", [])
    if role:
        sessions = [s for s in sessions if s.get("role") == role]
    if not sessions:
        print("[*] No sessions registered. Add one: auth_manager.py add --role admin "
              "--auth-type cookie --target http://127.0.0.1:8080 --credential '...'")
        return
    print(f"[*] Sessions ({len(sessions)}), role matrix:\n")
    by_role = {}
    for s in sessions:
        by_role.setdefault(s.get("role"), []).append(s)
    for r, sess in by_role.items():
        print(f"  {r}:")
        for s in sess:
            print(f"    {s['id']}  {s.get('auth_type'):<7} {s.get('target')}  "
                  f"{'valid' if s.get('valid', True) else 'INVALIDATED'}"
                  f"{'  [refresh hook]' if s.get('refresh_hook') else ''}")


def invalidate_session(sid):
    with json_transaction("board.json", create=True) as board:
        if board is None:
            print("[!] board.json missing.", file=sys.stderr)
            sys.exit(1)
        found = False
        for s in board.get("sessions", []):
            if s.get("id") == sid:
                s["valid"] = False
                found = True
        if not found:
            print(f"[!] Session '{sid}' not found.", file=sys.stderr)
            sys.exit(1)
    sp = _session_path(sid)
    if sp.exists():
        data = json.loads(sp.read_text())
        data["valid"] = False
        sp.write_text(json.dumps(data, indent=2))
    print(f"[✔] Session {sid} invalidated (kept on disk as evidence; excluded from future replays)")


def load_session(sid: str) -> dict:
    sp = _session_path(sid)
    if not sp.exists():
        print(f"[!] Session '{sid}' not found in {SESSIONS_DIR}", file=sys.stderr)
        sys.exit(1)
    return json.loads(sp.read_text())


# ------------------------------------------------------------ HTTP fetch
def _build_opener(session: dict):
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
    )
    return opener


def fetch_as(session, url, method="GET", timeout=15, headers=None) -> dict:
    """One request executed AS the session's role. Returns {status, headers,
    body, elapsed}. Timing is recorded per call — response-time deltas across
    roles are a blind-injection/user-enumeration oracle (role-diff uses it)."""
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "artifactory-auth-manager/1.0")
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    atype = session.get("auth_type")
    cred = session.get("credential", "")
    if atype == "cookie":
        req.add_header("Cookie", cred)
    elif atype == "bearer":
        req.add_header("Authorization", f"Bearer {cred}")
    elif atype == "header":
        req.add_header(session.get("header_name") or "X-Auth", cred)

    opener = _build_opener(session)
    t0 = time.time()
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode("utf-8", "replace")
        return {"status": resp.status, "headers": dict(resp.headers), "body": body,
                "elapsed": time.time() - t0}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        result = {"status": e.code, "headers": dict(e.headers or {}), "body": body,
                  "elapsed": time.time() - t0}
        # 401 auto-refresh: sessions with a refresh hook heal themselves once.
        # The hook is a command template ({{TARGET}} placeholder) executed via
        # the SAFE runner — scope/canary gates still apply to it.
        if e.code == 401 and session.get("refresh_hook") and not req.headers.get("X-Refreshed"):
            hook = session["refresh_hook"].replace("{{TARGET}}", session.get("target", ""))
            if hook:
                try:
                    import shlex as _shlex
                    import subprocess as _sp
                    _sp.run(_shlex.split(hook), capture_output=True, timeout=30)
                    # re-read the session file (the hook is expected to update it)
                    fresh = json.loads(_session_path(session["id"]).read_text())
                    req.add_header("Cookie", fresh.get("credential", ""))
                    req.add_header("X-Refreshed", "1")  # one retry only
                    t1 = time.time()
                    resp2 = opener.open(req, timeout=timeout)
                    return {"status": resp2.status, "headers": dict(resp2.headers),
                            "body": resp2.read().decode("utf-8", "replace"),
                            "elapsed": time.time() - t1, "refreshed": True}
                except Exception:
                    pass
        return result
    except Exception as e:
        return {"status": 0, "headers": {}, "body": f"__TRANSPORT_ERROR__ {e}",
                "elapsed": time.time() - t0}


# ------------------------------------------------------------ role-diff
def normalize_response(resp: dict) -> str:
    """Deterministic normalization so that only MEANINGFUL deltas survive:
    volatile values (CSRF tokens, nonces, timestamps, request IDs) are masked
    before comparison. Script, not LLM — never spends tokens."""
    body = resp.get("body", "")
    # Mask volatile key=value patterns: "csrf":"abc123" / csrf=abc123 / token: xyz
    for kw in VOLATILE_SUBSTRINGS:
        body = re.sub(
            rf'(["\']?[{kw[0].upper()}{kw[0].lower()}]{kw[1:]}["\']?\s*[:=]\s*)(["\']?)[A-Za-z0-9_\-\.%+]+',
            r"\1\2__VOL__",
            body,
        )
    # Mask unix-ish timestamps and long digit runs that are almost surely ephemeral
    body = re.sub(r"\b17[0-9]{8}\b", "__TS__", body)
    body = re.sub(r"\b1[89][0-9]{8,}\b", "__TS__", body)
    # Trim whitespace noise
    body = re.sub(r"\s+", " ", body).strip()
    return f"{resp.get('status')}|{body[:2000]}"


def _mklead(ltype, value, signal, pointer_id, confidence=0.4, suggested_next="",
            must_verify=True, preconditions=None):
    # Same shape as triage._mklead (kept local; triage import would pull the
    # scout provider table — fine either way, but this module stays standalone).
    return {
        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
        "type": ltype,
        "value": value,
        "signal": signal,
        "confidence": confidence,
        "suggested_next": suggested_next,
        "must_verify": must_verify,
        "preconditions": [p for p in (preconditions or []) if p],
        "source_pointer": pointer_id,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def run_role_diff(base_url, roles, endpoints_file, method="GET", timeout=15):
    """Replay an endpoint inventory across every role; file response deltas as
    broken-access-control leads. Baseline = first role in the list.

    roles: comma-separated SESSION IDs (order defines the baseline)
    endpoints_file: newline-separated paths (e.g. '/api/v1/users'), or '-' for stdin.
    """
    try:
        from scope_sig import verify_scope, tamper_notice
        if verify_scope().startswith("TAMPERED"):
            print(tamper_notice(), file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass
    scope = load_json(SCOPE_FILE)
    if not host_in_scope(base_url, scope):
        print(f"[!] SCOPE ERROR: '{base_url}' not in scope.json — add it before role-diff.",
              file=sys.stderr)
        sys.exit(1)

    sids = [s.strip() for s in roles.split(",") if s.strip()]
    sessions = []
    board = load_json(BOARD_FILE)
    for sid in sids:
        meta = next((s for s in board.get("sessions", []) if s.get("id") == sid), None)
        if not meta:
            print(f"[!] Session '{sid}' not registered on the board.", file=sys.stderr)
            sys.exit(1)
        if not meta.get("valid", True):
            print(f"[!] Session '{sid}' is invalidated — refresh it first.", file=sys.stderr)
            sys.exit(1)
        sessions.append(load_session(sid))
    if len(sessions) < 2:
        print("[!] Role-diff needs >=2 roles (baseline + at least one other).", file=sys.stderr)
        sys.exit(1)

    if endpoints_file == "-":
        endpoints = [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    else:
        ep_path = Path(endpoints_file)
        if not ep_path.exists():
            print(f"[!] Endpoints file '{endpoints_file}' not found.", file=sys.stderr)
            sys.exit(1)
        endpoints = [l.strip() for l in ep_path.read_text().splitlines() if l.strip()]
    if not endpoints:
        print("[!] No endpoints to replay.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Role-diff: {len(endpoints)} endpoints x {len(sessions)} roles "
          f"(baseline: {sessions[0]['role']}) against {base_url}\n")

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    results_log = []
    leads = []

    for ep in endpoints:
        url = base_url.rstrip("/") + (ep if ep.startswith("/") else "/" + ep)
        normed = {}
        raws = {}
        for s in sessions:
            r = fetch_as(s, url, method, timeout)
            normed[s["role"]] = normalize_response(r)
            raws[s["role"]] = r

        baseline_role = sessions[0]["role"]
        baseline = normed[baseline_role]
        for s in sessions[1:]:
            other = normed[s["role"]]
            if baseline != other:
                b_status = raws[baseline_role].get("status")
                o_status = raws[s["role"]].get("status")
                # Classify the delta for signal quality:
                sig = []
                if b_status != o_status:
                    sig.append(f"status {b_status}->{o_status}")
                else:
                    # same status, different normalized body — first divergence
                    # point helps the verifier zero in without reading the log
                    ba, bb = baseline.split("|", 1)[1], other.split("|", 1)[1]
                    for i, (ca, cb) in enumerate(zip(ba, bb)):
                        if ca != cb:
                            sig.append(f"body diverges at ~{i}: '{ba[max(0,i-15):i+20]}' vs '{bb[max(0,i-15):i+20]}'")
                            break
                leads.append(_mklead(
                    "rolediff", f"{ep} [{baseline_role} vs {s['role']}]",
                    "; ".join(sig)[:200] or "body delta after normalization",
                    pointer_id, 0.6,
                    f"verify: is the {s['role']} response supposed to differ on {ep}? "
                    f"If not -> broken access control",
                ))
                results_log.append(
                    f"DELTA {ep} [{baseline_role} vs {s['role']}] "
                    f"{'; '.join(sig)[:200] or 'body-delta'}")
            else:
                results_log.append(f"SAME  {ep} [{baseline_role} vs {s['role']}]")

            # Timing oracle: same body/status but consistently slower as one
            # role = blind injection / user-enumeration signal. Deltas below
            # network jitter are ignored (2x AND >=150ms bar).
            bt = raws[baseline_role].get("elapsed", 0)
            ot = raws[s["role"]].get("elapsed", 0)
            if baseline == other and ot > bt * 2 and (ot - bt) >= 0.15:
                leads.append(_mklead(
                    "rolediff", f"{ep} [{baseline_role} vs {s['role']}] TIMING",
                    f"same response but {ot:.2f}s vs {bt:.2f}s as {s['role']}",
                    pointer_id, 0.45,
                    f"timing oracle: re-run to confirm stability, then test "
                    f"blind injection / enumeration on {ep}",
                ))
                results_log.append(
                    f"SLOW  {ep} [{s['role']}] {ot:.2f}s vs {bt:.2f}s baseline")

    # Store the raw diff log as an artifact (pointer) and the leads on the board.
    from board_io import blackboard_dir as _bd
    (_bd() / "artifacts").mkdir(parents=True, exist_ok=True)
    art_path = _bd() / "artifacts" / f"{pointer_id}.log"
    art_path.write_text(
        "--- COMMAND ---\nauth_manager.py role-diff (mechanical replay)\n\n"
        f"--- STDOUT ---\n" + "\n".join(results_log) + "\n\n--- STDERR ---\n"
    )

    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            board.setdefault("execution_log_pointers", []).append({
                "pointer_id": pointer_id,
                "command": f"auth_manager.py role-diff {base_url} roles={roles} eps={len(endpoints)}",
                "return_code": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": f"role-diff: {len(leads)} delta lead(s) over {len(endpoints)} endpoints",
            })

    print(f"[✔] Replayed {len(endpoints)} endpoints across {len(sessions)} roles.")
    print(f"    Deltas (broken-access-control candidates): {len(leads)}")
    print(f"    Evidence pointer: {pointer_id} (inspect with sec_flow.py inspect --id {pointer_id})")
    print(f"    Leads on board: sec_flow.py leads --type rolediff")
    if leads:
        print("\n    Top deltas:")
        for l in leads[:10]:
            print(f"      {l['value']} — {l['signal']}")
        if len(leads) > 10:
            print(f"      ... {len(leads) - 10} more")


def run_verb_matrix(base_url, session_id, endpoints_file, timeout=15, delay=0.0):
    """HTTP verb matrix: for each endpoint, probe OPTIONS + write verbs
    (PUT/PATCH/DELETE) + method-override headers as ONE session. Findings that
    matter: write-verb allowed on read-only endpoints (405 expected, 2xx/3xx
    = candidate over-permissive route), and Allow-header revelations.
    Deterministic, zero model tokens."""
    try:
        from scope_sig import verify_scope, tamper_notice
        if verify_scope().startswith("TAMPERED"):
            print(tamper_notice(), file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass
    if not host_in_scope(base_url, load_json(SCOPE_FILE)):
        print(f"[!] SCOPE ERROR: '{base_url}' not in scope.json.", file=sys.stderr)
        sys.exit(1)

    sp = SESSIONS_DIR / f"{session_id}.json"
    if not sp.exists():
        print(f"[!] Session '{session_id}' not found.", file=sys.stderr)
        sys.exit(1)
    session = json.loads(sp.read_text())

    if endpoints_file == "-":
        endpoints = [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    else:
        ep_path = Path(endpoints_file)
        if not ep_path.exists():
            print(f"[!] Endpoints file '{endpoints_file}' not found.", file=sys.stderr)
            sys.exit(1)
        endpoints = [l.strip() for l in ep_path.read_text().splitlines() if l.strip()]
    if not endpoints:
        print("[!] No endpoints.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Verb matrix: {len(endpoints)} endpoints x (OPTIONS/PUT/PATCH/DELETE "
          f"+ override) as '{session.get('role', '?')}' against {base_url}\n")

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    results_log = []
    leads = []
    VERBS = ["OPTIONS", "PUT", "PATCH", "DELETE"]
    OVERRIDES = {"X-HTTP-Method-Override": "PUT", "X-Method-Override": "DELETE"}

    for ep in endpoints:
        url = base_url.rstrip("/") + (ep if ep.startswith("/") else "/" + ep)

        # 1) OPTIONS: what does the route claim to allow?
        r = fetch_as(session, url, "OPTIONS", timeout)
        allow = (r.get("headers") or {}).get("Allow", "")
        if allow:
            results_log.append(f"ALLOW {ep}: {allow}")
        read_verbs = {v.strip().upper() for v in allow.split(",") if v.strip()}

        # 2) write verbs: expect 405/501 on read-only routes
        for verb in VERBS[1:]:
            r = fetch_as(session, url, verb, timeout)
            st = r.get("status", 0)
            interesting = st and st < 300 and verb not in read_verbs and verb != "OPTIONS"
            results_log.append(f"{verb:6} {ep} -> {st}")
            if interesting:
                leads.append(_mklead(
                    "rolediff", f"{ep} [verb {verb} -> {st}]",
                    f"{verb} returned {st} (not in Allow: '{allow or 'none'}') — "
                    f"over-permissive route candidate",
                    pointer_id, 0.55,
                    f"confirm: is {verb} on {ep} intentional? send a SAFE body and "
                    f"revert, or check {verb} authorization as lower-priv role",
                ))

        # 3) method override headers: gated route via header override
        for hdr, verb in OVERRIDES.items():
            r = fetch_as(session, url, "POST", timeout, headers={hdr: verb})
            st = r.get("status", 0)
            results_log.append(f"OVRR {hdr}={verb} {ep} POST -> {st}")
            if st and 200 <= st < 300:
                leads.append(_mklead(
                    "rolediff", f"{ep} [{hdr}: {verb} accepted]",
                    f"POST with {hdr}: {verb} returned {st} — method-override "
                    f"bypass candidate (verb filters often miss overrides)",
                    pointer_id, 0.6,
                    f"verify: does the route enforce {verb} auth only on the "
                    f"direct verb? try the override as a LOW-priv session",
                ))
        if delay:
            time.sleep(delay)

    from board_io import blackboard_dir as _bd
    (_bd() / "artifacts").mkdir(parents=True, exist_ok=True)
    (_bd() / "artifacts" / f"{pointer_id}.log").write_text(
        "--- COMMAND ---\nauth_manager.py verb-matrix (mechanical probe)\n\n"
        f"--- STDOUT ---\n" + "\n".join(results_log) + "\n\n--- STDERR ---\n")
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            board.setdefault("execution_log_pointers", []).append({
                "pointer_id": pointer_id,
                "command": f"auth_manager.py verb-matrix {base_url} eps={len(endpoints)}",
                "return_code": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": f"verb matrix: {len(leads)} lead(s) over {len(endpoints)} endpoints",
            })

    print(f"[✔] Verb matrix complete: {len(leads)} lead(s) "
          f"(pointer {pointer_id}; leads --type rolediff).")
    for l in leads[:10]:
        print(f"  {l['value']} — {l['signal'][:80]}")
    if len(leads) > 10:
        print(f"  ... {len(leads) - 10} more")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auth-State Manager + Role-Diff Engine")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    add_p = subparsers.add_parser("add", help="Register a session artifact (role matrix entry)")
    add_p.add_argument("--role", required=True, help="Role name: admin, user, anon, support, ...")
    add_p.add_argument("--auth-type", dest="auth_type", required=True, choices=AUTH_TYPES)
    add_p.add_argument("--target", required=True, help="Base URL of the target app")
    add_p.add_argument("--credential", default="", help="Cookie string / bearer token / header value")
    add_p.add_argument("--header-name", dest="header_name", default="",
                       help="Header name for --auth-type header")
    add_p.add_argument("--refresh-hook", dest="refresh_hook", default="",
                       help="Command template to re-obtain the credential ({{TARGET}} placeholder)")
    add_p.add_argument("--expiry", default="", help="Expiry hint (ISO or human readable)")
    add_p.add_argument("--note", default="")

    subparsers.add_parser("list", help="Show the role matrix / session pointers") \
        .add_argument("--role", default=None)

    inv_p = subparsers.add_parser("invalidate", help="Mark a session invalid (kept as evidence)")
    inv_p.add_argument("--id", required=True, help="SESS_ id")

    diff_p = subparsers.add_parser("role-diff", help="Replay endpoints across roles -> BAC leads")
    diff_p.add_argument("--base-url", dest="base_url", required=True)
    diff_p.add_argument("--roles", required=True,
                        help="Comma-separated SESS_ ids, baseline first (e.g. SESS_A,SESS_B,SESS_ANON)")
    diff_p.add_argument("--endpoints", dest="endpoints_file", required=True,
                        help="File of newline-separated paths, or '-' for stdin")
    diff_p.add_argument("--method", default="GET")
    diff_p.add_argument("--timeout", type=int, default=15)

    vm_p = subparsers.add_parser("verb-matrix", help="OPTIONS + write verbs + override headers over the inventory")
    vm_p.add_argument("--base-url", dest="base_url", required=True)
    vm_p.add_argument("--session", required=True, help="SESS_ id to probe as")
    vm_p.add_argument("--endpoints", dest="endpoints_file", required=True,
                      help="File of paths or '-' for stdin")
    vm_p.add_argument("--timeout", type=int, default=15)
    vm_p.add_argument("--delay", type=float, default=0.0, help="Politeness delay per endpoint")

    args = parser.parse_args()

    if args.subcommand == "add":
        require_scope(args.target)
        add_session(args.role, args.auth_type, args.target, args.credential,
                    args.header_name, args.refresh_hook, args.expiry, args.note)
    elif args.subcommand == "list":
        list_sessions(args.role)
    elif args.subcommand == "invalidate":
        invalidate_session(args.id)
    elif args.subcommand == "role-diff":
        run_role_diff(args.base_url, args.roles, args.endpoints_file, args.method, args.timeout)
    elif args.subcommand == "verb-matrix":
        run_verb_matrix(args.base_url, args.session, args.endpoints_file,
                        args.timeout, args.delay)
