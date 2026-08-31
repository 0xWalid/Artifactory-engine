#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - GraphQL Attack Surface Helper

GraphQL endpoints have a specific attack surface that generic HTTP flows
miss. Deterministic checks, zero model tokens:

  * introspection      — is it enabled? dump the schema (types/fields/mutations)
  * field-suggestions  — typo'd field names; a "Did you mean X?" response
                         leaks the schema even when introspection is off
  * batching/aliasing   — depth-cost & query-burst (DoS-class candidates),
                         duplicate-field smuggling for access control
  * authz probe        — __typename/operation-name vs role-diff contract

Each finding-seed becomes a must_verify lead with the raw response in an
artifact (redacted at egress like everything else).
"""

import argparse
import json
import sys
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


def _gql(url, query, variables=None, session=None, timeout=15):
    body = {"query": query}
    if variables:
        body["variables"] = variables
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "artifactory-graphql/1.0")
    if session and session.get("auth_type") == "cookie":
        req.add_header("Cookie", session.get("credential", ""))
    elif session and session.get("auth_type") == "bearer":
        req.add_header("Authorization", f"Bearer {session.get('credential', '')}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}"), None
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}"), None
        except Exception:
            return e.code, {}, str(e)
    except Exception as e:
        return 0, {}, str(e)


def _mklead(ltype, value, signal, pointer_id, confidence, suggested_next,
            must_verify=True):
    return {
        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
        "type": ltype, "value": value, "signal": signal,
        "confidence": confidence, "suggested_next": suggested_next,
        "must_verify": must_verify, "preconditions": [],
        "source_pointer": pointer_id, "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def run_gql_checks(url, session_id=None):
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    if not _scope_ok(url):
        print(f"[!] SCOPE ERROR: '{url}' not in scope.json.", file=sys.stderr)
        sys.exit(1)
    session = None
    if session_id:
        sp = SESSIONS_DIR / f"{session_id}.json"
        if sp.exists():
            session = json.loads(sp.read_text())

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    log = []

    # 1) Introspection
    q = "query IntrospectionQuery { __schema { types { name kind } } }"
    status, data, err = _gql(url, q, session=session)
    types = ((data.get("data") or {}).get("__schema") or {}).get("types") or []
    log.append(f"introspection: status={status} types={len(types)} err={err}")
    if types:
        interesting = [t["name"] for t in types
                       if not t["name"].startswith("__")
                       and t.get("kind") in ("OBJECT", "MUTATION")]
        # full field dump for the artifact
        q2 = "query { __schema { queryType { name } mutationType { name } } }"
        _, d2, _ = _gql(url, q2, session=session)
        leads.append(_mklead(
            "anomaly", "GraphQL introspection ENABLED",
            f"schema leaked: {len(types)} types incl. {interesting[:5]}",
            pointer_id, 0.8,
            "dump full schema (types+fields), map mutations/queries to role-diff inventory"))
        log.append(f"non-internal types sample: {interesting[:20]}")
    elif status == 200 and (data.get("errors")):
        log.append(f"introspection blocked: {str(data.get('errors'))[:120]}")

    # 2) Field suggestions (schema leak despite disabled introspection)
    status, data, err = _gql(url, "query { userr }", session=session)
    blob = json.dumps(data)
    log.append(f"suggestion probe: {blob[:160]}")
    if "Did you mean" in blob or "did you mean" in blob:
        leads.append(_mklead(
            "anomaly", "GraphQL field suggestions leak schema",
            "typo probe returned 'Did you mean' — enumeration of names possible",
            pointer_id, 0.7,
            "script typo-probes to enumerate query/mutation names field by field"))

    # 3) Batching / aliasing (cost-abuse candidates)
    batch = [{"query": "query { __typename }"},
             {"query": "query { __typename }"},
             {"query": "query { __typename }"}]
    data_enc = json.dumps(batch).encode()
    req = urllib.request.Request(url, data=data_enc, method="POST")
    req.add_header("Content-Type", "application/json")
    if session and session.get("auth_type") == "cookie":
        req.add_header("Cookie", session.get("credential", ""))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode()[:200]
            log.append(f"batch probe: {r.status} {body[:100]}")
            if r.status == 200:
                leads.append(_mklead(
                    "anomaly", "GraphQL array-query batching accepted",
                    "3 queries in one request processed — depth/cost abuse candidate "
                    "(DoS-class: discover + minimally prove, never flood)",
                    pointer_id, 0.5,
                    "measure response latency vs 3 separate queries; check any "
                    "depth/complexity limits server-side"))
    except Exception as e:
        log.append(f"batch probe rejected: {e}")

    # 4) __typename-based hidden-operation probe via operationName
    status, data, err = _gql(url, "query X { __typename }", session=session)
    log.append(f"operation probe: status={status}")

    (BLACKBOARD_DIR / "artifacts").mkdir(parents=True, exist_ok=True)
    (BLACKBOARD_DIR / "artifacts" / f"{pointer_id}.log").write_text(
        "--- COMMAND ---\ngraphql.py checks (deterministic)\n\n--- STDOUT ---\n"
        + "\n".join(log) + "\n\n--- STDERR ---\n")
    if leads:
        with json_transaction("board.json") as board:
            if board is not None:
                board.setdefault("leads", []).extend(leads)
                board.setdefault("execution_log_pointers", []).append({
                    "pointer_id": pointer_id,
                    "command": f"graphql.py checks {url}",
                    "return_code": 0,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "summary": f"graphql checks: {len(leads)} lead(s)",
                })
    print(f"[*] GraphQL checks complete: {len(leads)} lead(s) (artifact {pointer_id}).")
    for l in leads:
        print(f"  [{l['confidence']}] {l['value']} — {l['signal'][:80]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraphQL attack-surface checks")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("checks", help="Introspection, suggestions, batching, authz probes")
    c.add_argument("--url", required=True, help="GraphQL endpoint (in-scope)")
    c.add_argument("--session", default=None, help="SESS_ id to probe as")
    args = parser.parse_args()
    run_gql_checks(args.url, args.session)
