#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Security Flow Execution Engine
Handles safe non-shell execution, CIDR scope validation, artifact logging,
JSON-aware inspection, and state asset recording.
"""

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Shared, lock-serialised blackboard I/O (prevents parallel-agent write races).
_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction  # noqa: E402
from scope_sig import verify_scope, tamper_notice, sign_scope  # noqa: E402
from redact import redact  # noqa: E402

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
HISTORY_FILE = BLACKBOARD_DIR / "history.log"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
CANARY_FILE = BLACKBOARD_DIR / "canaries.json"
RATIONALE_FILE = BLACKBOARD_DIR / "rationale.jsonl"
FINGERPRINTS_FILE = BLACKBOARD_DIR / "fingerprints.json"

# Finding severity/status vocabularies (WS1: verification gate).
SEVERITIES = ["info", "low", "medium", "high", "critical"]
FINDING_STATUSES = ["informational", "confirmed"]

# Wall-clock ceiling for any single diagnostic command so a hung tool cannot
# stall the engine indefinitely.
COMMAND_TIMEOUT = 300


def ensure_blackboard_dirs():
    BLACKBOARD_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    if not HISTORY_FILE.exists():
        HISTORY_FILE.touch()


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def is_target_in_scope(target: str, scope: dict) -> bool:
    # Fail-closed: an empty/missing scope grants nothing. Callers must ensure a
    # populated scope.json (via init_env.py) before any command is permitted.
    if not scope:
        return False

    allowed_hosts = scope.get("allowed_hosts", [])
    allowed_domains = scope.get("allowed_domains", [])
    allowed_cidrs = scope.get("allowed_cidrs", [])

    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Host & Domain checks
    if clean_target in allowed_hosts:
        return True

    for domain in allowed_domains:
        domain_clean = domain.replace("*.", "")
        if clean_target == domain_clean or clean_target.endswith("." + domain_clean):
            return True

    # IP & CIDR Subnet checks
    try:
        resolved_ip_str = socket.gethostbyname(clean_target)
        if resolved_ip_str in allowed_hosts:
            return True

        resolved_ip = ipaddress.ip_address(resolved_ip_str)
        for cidr in allowed_cidrs:
            if resolved_ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except (socket.gaierror, ValueError):
        pass

    return False


# ---------------------------------------------------------------- rate limiter
# Per-host pacing enforced IN CODE (not policy text): the plan's "rate limits
# enforced by the harness" gap. Defaults live in scope.json `rate_limit` and
# apply to every `run` command targeting a host (not passive-intel allowlist
# lookups, which never touch targets).
DEFAULT_RATE_LIMIT = {"min_interval_seconds": 0.0}
RATE_STATE_FILE = BLACKBOARD_DIR / "rate_state.json"


def _rate_limit_for(scope: dict) -> dict:
    rl = scope.get("rate_limit") or {}
    return {**DEFAULT_RATE_LIMIT, **rl}


def enforce_rate_limit(target: str, scope: dict):
    """Pace consecutive commands against the same host. Blocking sleep is
    bounded (< a few seconds) because min_interval is an operator-set ceiling,
    not an attacker-controlled value. Fails open if state is unreadable — the
    scope/canary/destructive gates carry the security load, pacing is safety
    polish (and is skipped entirely with min_interval_seconds <= 0)."""
    rl = _rate_limit_for(scope)
    interval = float(rl.get("min_interval_seconds") or 0)
    if interval <= 0:
        return
    host = clean_host(target)
    try:
        state = load_json(RATE_STATE_FILE)
        last = state.get(host)
        if last:
            elapsed = datetime.now(timezone.utc).timestamp() - float(last)
            if elapsed < interval:
                wait = interval - elapsed
                print(f"[~] RATE LIMIT: pacing {host} ({wait:.1f}s until next command "
                      f"is allowed; scope rate_limit.min_interval_seconds={interval:.1f}s)")
                time.sleep(min(wait, 30))
        # Always stamp the host's last-use time (first use included) so the
        # NEXT command against this host paces correctly. Lock-serialised so
        # parallel agents don't race on the pacing file.
        state[host] = datetime.now(timezone.utc).timestamp()
        try:
            with json_transaction("rate_state.json", create=True) as rs:
                if rs is not None:
                    rs.clear()
                    rs.update(state)
        except Exception:
            pass
    except Exception:
        pass  # pacing is advisory; never block the engagement on its own state


# ------------------------------------------------------ target fingerprint cache
# "Cache by target fingerprint — never re-learn a framework version twice."
# Records tech banners per host with a TTL; recon commands can consult the
# cache before re-probing, and intel.py can key CVE enumeration off it.
FINGERPRINT_TTL_DAYS = 14


def record_fingerprint(host: str, tech: str, source: str = "banner"):
    """Store a tech/version observation for a host (deduped, timestamped)."""
    host = clean_host(host)
    try:
        with json_transaction("fingerprints.json", create=True) as fp:
            if fp is None:
                return
            entries = fp.setdefault(host, [])
            if not any(e.get("tech") == tech for e in entries):
                entries.append({
                    "tech": tech,
                    "source": source,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                })
    except Exception:
        pass


def lookup_fingerprints(host: str, fresh_only: bool = True) -> list:
    """Return tech observations for a host (optionally TTL-filtered)."""
    host = clean_host(host)
    fp = load_json(FINGERPRINTS_FILE)
    entries = fp.get(host, []) if fp else []
    if not fresh_only:
        return entries
    cutoff = datetime.now(timezone.utc).timestamp() - FINGERPRINT_TTL_DAYS * 86400
    fresh = []
    for e in entries:
        try:
            ts = datetime.fromisoformat(e.get("recorded_at", "")).timestamp()
        except Exception:
            continue
        if ts >= cutoff:
            fresh.append(e)
    return fresh


def clean_host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def matches_authorized_domain(host: str, scope: dict) -> bool:
    """True if host falls under an authorized apex/wildcard in allowed_domains."""
    for domain in scope.get("allowed_domains", []):
        domain_clean = domain.replace("*.", "")
        if host == domain_clean or host.endswith("." + domain_clean):
            return True
    return False


def classify_and_expand_scope(host: str) -> str:
    """WS2: decide how a newly-discovered host enters scope.

    - Already in scope (host/cidr/domain) or under an authorized wildcard ->
      materialise it in `allowed_hosts` and mark 'authorized'.
    - Otherwise -> queue in `pending_scope` for explicit operator approval.
    Never silently authorises a host that is not under an approved domain.
    Returns one of: 'authorized' | 'pending' | 'noop'.
    """
    host = clean_host(host)
    if not host:
        return "noop"

    outcome = "noop"
    with json_transaction("scope.json", create=True) as scope:
        allowed_hosts = scope.setdefault("allowed_hosts", [])
        pending = scope.setdefault("pending_scope", [])

        if matches_authorized_domain(host, scope):
            if host not in allowed_hosts:
                allowed_hosts.append(host)
            if host in pending:
                pending.remove(host)
            outcome = "authorized"
        elif host in allowed_hosts:
            outcome = "authorized"
        else:
            if host not in pending:
                pending.append(host)
            outcome = "pending"
    # Outside the transaction: re-sign so the (authorized-field) change keeps
    # verifying. pending_scope is unsigned by design, so this stays valid.
    try:
        sign_scope()
    except Exception:
        pass
    return outcome


# Filesystem roots too broad to ever authorize for SAST/SCA source scanning.
# An operator can still edit scope.json directly (then re-sign) if they truly
# mean it — the CLI just refuses to be the footgun.
FORBIDDEN_CODE_ROOTS = {"/", "/tmp", "/var", "/etc", "/usr", "/opt", "/home", "/root", "/srv"}


def _is_forbidden_code_path(resolved: str) -> bool:
    p = Path(resolved)
    return str(p) in FORBIDDEN_CODE_ROOTS or p.parent == p  # "/" resolves to itself


def manage_scope(add_host=None, add_domain=None, add_cidr=None, add_code_path=None,
                 approve=None, do_list=False):
    """WS2: operator-facing scope editing + per-project visibility."""
    if not SCOPE_FILE.exists():
        print(f"[!] Error: {SCOPE_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    if do_list and not any([add_host, add_domain, add_cidr, add_code_path, approve]):
        scope = load_json(SCOPE_FILE)
        print("[*] Current scope:")
        print(f"    allowed_hosts:      {scope.get('allowed_hosts', [])}")
        print(f"    allowed_domains:    {scope.get('allowed_domains', [])}")
        print(f"    allowed_cidrs:      {scope.get('allowed_cidrs', [])}")
        print(f"    allowed_code_paths: {scope.get('allowed_code_paths', [])}")
        print(f"    pending_scope:      {scope.get('pending_scope', [])}  (awaiting --approve)")
        return

    with json_transaction("scope.json", create=True) as scope:
        allowed_hosts = scope.setdefault("allowed_hosts", [])
        allowed_domains = scope.setdefault("allowed_domains", [])
        allowed_cidrs = scope.setdefault("allowed_cidrs", [])
        allowed_code_paths = scope.setdefault("allowed_code_paths", [])
        pending = scope.setdefault("pending_scope", [])

        if add_host and add_host not in allowed_hosts:
            allowed_hosts.append(add_host)
            print(f"[✔] Added host to scope: {add_host}")
        if add_domain and add_domain not in allowed_domains:
            allowed_domains.append(add_domain)
            print(f"[✔] Added domain to scope: {add_domain}")
        if add_cidr and add_cidr not in allowed_cidrs:
            allowed_cidrs.append(add_cidr)
            print(f"[✔] Added CIDR to scope: {add_cidr}")
    if add_code_path:
        resolved = str(Path(add_code_path).resolve())
        if _is_forbidden_code_path(resolved):
            print(f"[!] SCOPE ERROR: '{resolved}' is a system-level root — too broad to "
                  f"authorize for code scanning. Authorize the specific project directory "
                  f"instead (edit scope.json directly + re-run init_env.py to re-sign "
                  f"if you genuinely need this).", file=sys.stderr)
            sys.exit(1)
        if resolved not in allowed_code_paths:
            allowed_code_paths.append(resolved)
            print(f"[✔] Authorized code path for SAST/SCA: {resolved}")
        else:
            print(f"[*] Code path already authorized: {resolved}")
        if approve:
            host = clean_host(approve)
            if host in pending:
                pending.remove(host)
            if host not in allowed_hosts:
                allowed_hosts.append(host)
            print(f"[✔] Approved into scope: {host}")

    # Any operator-driven scope edit re-signs the authorization fields.
    try:
        sign_scope()
    except Exception:
        pass


def update_board_state(pointer_id: str, cmd: str, returncode: int, summary: str = ""):
    if not BOARD_FILE.exists():
        return

    try:
        with json_transaction("board.json") as board_data:
            if board_data is None:
                return
            pointer_entry = {
                "pointer_id": pointer_id,
                "command": cmd,
                "return_code": returncode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
            }
            board_data.setdefault("execution_log_pointers", []).append(pointer_entry)
    except Exception as e:
        print(f"[!] Warning: Could not update board.json: {e}", file=sys.stderr)


def trigger_report_generation():
    """Invokes the local report engine to (re)build per-finding advisories.

    Imported lazily from the engine directory so recording assets never hard-
    depends on the reporter being importable; failures degrade gracefully.
    """
    try:
        engine_dir = str(Path(__file__).resolve().parent)
        if engine_dir not in sys.path:
            sys.path.insert(0, engine_dir)
        import report_engine
        report_engine.generate_individual_reports()
    except Exception as e:
        print(f"[!] Warning: auto-report generation failed: {e}", file=sys.stderr)


def trigger_triage(pointer_id: str):
    """Runs the background triage/Scout pass on a completed artifact.

    Extracts ranked leads into board.json so the operator consumes a short
    lead list instead of raw output. Lazily imported; failures degrade quietly.
    """
    try:
        engine_dir = str(Path(__file__).resolve().parent)
        if engine_dir not in sys.path:
            sys.path.insert(0, engine_dir)
        import triage
        triage.triage_pointer(pointer_id)
    except Exception as e:
        print(f"[!] Warning: triage pass failed: {e}", file=sys.stderr)


def _resolve_evidence(poc: str, evidence_from):
    """Returns (evidence_text, evidence_pointer, has_evidence)."""
    evidence_text = poc or ""
    evidence_pointer = None
    if evidence_from:
        art = ARTIFACTS_DIR / f"{evidence_from}.log"
        if art.exists():
            evidence_pointer = evidence_from
        else:
            print(f"[!] Warning: evidence pointer '{evidence_from}' has no artifact "
                  f"log; ignoring it.", file=sys.stderr)
    has_evidence = bool(evidence_text) or bool(evidence_pointer)
    return evidence_text, evidence_pointer, has_evidence


# Variant propagation: confirmed bug-class -> keyword family. When IDOR is
# proven on one endpoint, every other object-bearing endpoint becomes a
# same-family candidate until tested. Table mirrors researcher instinct.
FINDING_CLASS_FAMILIES = [
    ("idor", ["idor", "object reference", "bola", "ownership"]),
    ("access-control", ["access control", "bac", "privilege", "auth bypass", "role",
                        "unauthorized access", "admin"]),
    ("traversal", ["traversal", "path", "lfi", "file read"]),
    ("ssrf", ["ssrf", "server-side request"]),
    ("injection", ["sqli", "sql injection", "command injection", "ssti", "xss", "injection"]),
    ("leak", ["leak", "disclosure", "exposed", "verbose", "debug"]),
    ("redirect", ["redirect", "open redirect"]),
    ("mass-assignment", ["mass assignment", "role field", "parameter tampering"]),
]


def _finding_class(text: str) -> str:
    t = (text or "").lower()
    for cls, kws in FINDING_CLASS_FAMILIES:
        if any(k in t for k in kws):
            return cls
    return ""


def _propagate_variants(entry: dict, board: dict) -> list:
    """On confirm, queue same-class sweeps across the untested inventory.
    Deterministic: keywords + endpoints already on the board. Never overwrites
    existing leads (dedup by value prefix)."""
    cls = _finding_class(entry.get("title", "") + " " + (entry.get("details") or ""))
    if not cls:
        return []
    assets = (board.get("discovered_assets") or {}).get("endpoints", [])
    if not assets:
        return []

    existing = {str(l.get("value", "")) for l in board.get("leads", [])}
    out = []
    for ep in assets:
        ep = str(ep)
        if not ep.startswith("/"):
            continue
        # skip the endpoint(s) this finding already covers
        if ep in entry.get("title", "") + (entry.get("details") or ""):
            continue
        value = f"variant sweep [{cls}]: {ep}"
        if value in existing:
            continue
        out.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "endpoint",
            "value": value,
            "signal": f"same bug family as confirmed '{entry.get('title', '')[:60]}' — "
                      f"test this endpoint for the same class",
            "confidence": 0.55,
            "suggested_next": f"run the same {cls} technique against {ep}; "
                               f"kill with --set-status dead if it doesn't reproduce",
            "must_verify": True,
            "preconditions": [],
            "source_pointer": entry.get("evidence_pointer") or "VARIANT_SWEEP",
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return out[:40]  # cap: sweeps stay useful, not spammy



def add_asset_to_board(host: str = None, endpoint: str = None, port: str = None,
                       finding: str = None, details: str = "", severity: str = "info",
                       status: str = "informational", poc: str = "", evidence_from=None,
                       chain_to=None):
    if not BOARD_FILE.exists():
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    # Verification gate (WS1): a finding may only be 'confirmed' when it carries
    # evidence (an inline PoC or a real execution-pointer artifact). Otherwise it
    # is downgraded to 'informational' so unverified observations never masquerade
    # as confirmed vulnerabilities.
    evidence_text, evidence_pointer, has_evidence = ("", None, False)
    if finding:
        if severity not in SEVERITIES:
            severity = "info"
        if status not in FINDING_STATUSES:
            status = "informational"
        evidence_text, evidence_pointer, has_evidence = _resolve_evidence(poc, evidence_from)
        if status == "confirmed" and not has_evidence:
            status = "informational"
            print("[!] VERIFICATION GATE: no PoC/evidence supplied — filed as "
                  "'informational', NOT 'confirmed'. Run the proving command, then "
                  "log with --poc \"<payload/request+response>\" or "
                  "--evidence-from <POINTER_ID>.", file=sys.stderr)

    try:
        added = []
        with json_transaction("board.json") as board_data:
            if board_data is None:
                print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
                sys.exit(1)

            assets = board_data.setdefault("discovered_assets", {"hosts": [], "endpoints": [], "open_ports": []})
            findings_list = board_data.setdefault("findings", [])

            if host and host not in assets.setdefault("hosts", []):
                assets["hosts"].append(host)
                added.append(f"Host: {host}")

            if endpoint and endpoint not in assets.setdefault("endpoints", []):
                assets["endpoints"].append(endpoint)
                added.append(f"Endpoint: {endpoint}")

            if port and port not in assets.setdefault("open_ports", []):
                assets["open_ports"].append(port)
                added.append(f"Port: {port}")

            if finding:
                # Attach the most recent execution pointers so the report engine can
                # correlate THIS finding to the commands that produced it. Ensure the
                # explicit evidence pointer is included.
                recent_pointers = [
                    p.get("pointer_id")
                    for p in board_data.get("execution_log_pointers", [])[-3:]
                    if p.get("pointer_id")
                ]
                if evidence_pointer and evidence_pointer not in recent_pointers:
                    recent_pointers.append(evidence_pointer)
                entry = {
                    "id": f"FINDING_{uuid.uuid4().hex[:6].upper()}",
                    "title": finding,
                    "details": details,
                    "severity": severity,
                    "status": status,
                    "evidence": evidence_text,
                    "evidence_pointer": evidence_pointer,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "related_pointers": recent_pointers,
                }
                # Chain edges: link this finding to prior finding IDs (the
                # chain-mining graph — a leaked token -> auth bypass -> IDOR
                # becomes an explicit, walkable attack path on the board).
                if chain_to:
                    for cid in chain_to.split(","):
                        cid = cid.strip()
                        if cid and cid != entry["id"] and any(
                                f.get("id") == cid for f in findings_list):
                            entry.setdefault("chain_to", []).append(cid)
                findings_list.append(entry)
                added.append(f"Finding[{status}/{severity}]: {finding}")

                # Variant propagation (researcher habit): a CONFIRMED bug of a
                # class rarely exists at exactly one sink. When a finding is
                # confirmed, deterministically queue same-class leads over the
                # rest of the endpoint inventory so the sweep happens instead of
                # being "noted". Only on confirm — informational stays quiet.
                if status == "confirmed":
                    try:
                        variant_leads = _propagate_variants(entry, board_data)
                        if variant_leads:
                            board_data.setdefault("leads", []).extend(variant_leads)
                            added.append(f"{len(variant_leads)} variant-sweep lead(s) queued")
                    except Exception:
                        pass  # propagation is opportunistic, never blocks a finding

        print(f"[✔] Blackboard updated: {', '.join(added) if added else 'No new entries'}")

        # WS2: a discovered host is classified against scope (auto-authorise under
        # an approved wildcard, else queue as pending).
        if host:
            outcome = classify_and_expand_scope(host)
            if outcome == "authorized":
                print(f"[✔] Scope: '{clean_host(host)}' is under an approved domain — added to allowed_hosts.")
            elif outcome == "pending":
                print(f"[!] Scope: '{clean_host(host)}' is NOT under an approved domain — "
                      f"queued in pending_scope. Approve with: "
                      f"sec_flow.py scope --approve {clean_host(host)}")

        # Auto-trigger the report engine when a finding is recorded so advisories
        # and evidence logs stay in sync (as documented in the /artifactory command).
        if finding:
            trigger_report_generation()

    except SystemExit:
        raise
    except Exception as e:
        print(f"[!] Error updating assets in board.json: {e}", file=sys.stderr)
        sys.exit(1)


def add_rationale(lead=None, hypothesis="", why="", action="", expected="",
                  pointer=None, outcome=""):
    """WS7: append one decision-journal record explaining *why* an action was
    taken and *what* resulted. Feeds the report's 'How we got here' section."""
    ensure_blackboard_dirs()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "lead_id": lead,
        "hypothesis": hypothesis,
        "why_chosen": why,
        "action": action,
        "expected_signal": expected,
        "pointer_id": pointer,
        "outcome": outcome,
    }
    with open(RATIONALE_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[✔] Rationale logged{f' for {lead}' if lead else ''}.")


def manage_chains(link=None, unlink=None, note=""):
    """WS-CHAIN: view and edit the finding chain graph on the board.

    Chains are how discrete findings compose into demonstrated end-to-end
    impact (leaked token -> auth bypass -> IDOR -> data reach). The graph is
    walked here deterministically; chain COMPOSITION (which findings join)
    is the frontier model's job — this view makes the result inspectable.

    link: "FINDING_A,FINDING_B" (directed edge A -> B)
    unlink: "FINDING_A,FINDING_B" (remove that edge)
    note: optional annotation stored on the edge (A -> B)
    """
    ensure_blackboard_dirs()
    changed = False
    with json_transaction("board.json") as board:
        if board is None:
            print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
            sys.exit(1)
        findings = {f.get("id"): f for f in board.get("findings", [])}

        def _pair(arg):
            if not arg or "," not in arg:
                print("[!] Use --link/--unlink FINDING_A,FINDING_B (comma-separated pair).",
                      file=sys.stderr)
                sys.exit(1)
            a, b = [x.strip() for x in arg.split(",", 1)]
            return a, b

        if link:
            a, b = _pair(link)
            if a not in findings or b not in findings:
                print(f"[!] Both findings must exist on the board. Known: "
                      f"{', '.join(findings) or 'none'}", file=sys.stderr)
                sys.exit(1)
            edges = findings[a].setdefault("chain_to", [])
            if b not in edges:
                edges.append(b)
                changed = True
            if note:
                findings[a].setdefault("chain_notes", {})[b] = note
                changed = True
        if unlink:
            a, b = _pair(unlink)
            f = findings.get(a)
            if f and b in f.get("chain_to", []):
                f["chain_to"].remove(b)
                f.get("chain_notes", {}).pop(b, None)
                changed = True

    if changed:
        print("[✔] Chain graph updated.")

    # --- view: every edge in the graph + longest paths (attack paths) ---
    board = load_json(BOARD_FILE)
    findings = board.get("findings", [])
    by_id = {f.get("id"): f for f in findings}
    edges = []
    for f in findings:
        for b in f.get("chain_to", []):
            note_txt = f.get("chain_notes", {}).get(b, "")
            edges.append((f.get("id"), b, note_txt))

    if not edges:
        print("[*] No chain edges yet. Link findings with: chains --link FINDING_A,FINDING_B --note 'why'")
        print("    (e.g. token-leak finding -> auth-bypass finding -> IDOR finding)")
        return

    # simple reachability for path rendering
    graph = {}
    for a, b, _ in edges:
        graph.setdefault(a, []).append(b)

    def walk(start, path=None):
        path = path or [start]
        best = [path]
        for nxt in graph.get(start, []):
            if nxt in path:
                continue
            best.append(walk(nxt, path + [nxt]))
        return max(best, key=len)

    print(f"[*] Chain graph ({len(edges)} edge(s), {len(findings)} findings):\n")
    for a, b, note_txt in edges:
        t1 = (by_id.get(a, {}).get("title") or "?")[:60]
        t2 = (by_id.get(b, {}).get("title") or "?")[:60]
        print(f"  {a} -> {b}")
        print(f"      '{t1}'  =>  '{t2}'")
        if note_txt:
            print(f"      note: {note_txt}")

    # highlight the longest attack path
    longest = []
    for fid in by_id:
        p = walk(fid)
        if len(p) > len(longest):
            longest = p
    if len(longest) > 1:
        print(f"\n  ★ LONGEST DEMONSTRATED ATTACK PATH ({len(longest)} steps):")
        for i, fid in enumerate(longest, 1):
            t = (by_id.get(fid, {}).get("title") or "?")[:70]
            print(f"     {i}. {fid} — {t}")


# ---------------------------------------------------------- chain mining
# Deterministic primitive/needs matching: when does finding A's capability
# satisfy finding B's requirement? Keywords are cheap and explicit; the table
# mirrors prompts/chaining/chain_methodology.md. This PROPOSES edges — the
# operator/agent accepts with `chains --link`.
PRIMITIVE_NEEDS = [
    # (primitive keywords in A's title/details, needs keywords in B, why)
    (["leak", "secret", "key", "token", "credential", "password"],
     ["auth", "bypass", "session", "csrf", "api", "admin", "login", "jwt"],
     "A's leaked credential material can satisfy B's authentication requirement"),
    (["ssrf", "fetch", "internal", "network", "request"],
     ["internal", "metadata", "admin", "localhost", "cloud", "169.254"],
     "A's network reach can access B's internal-only surface"),
    (["xss", "script", "dom"],
     ["cookie", "csrf", "victim", "session", "same-site", "samesite", "action"],
     "A's script execution in the victim origin can drive B's authenticated action"),
    (["idor", "object", "read", "data", "access control", "bac"],
     ["admin", "panel", "function", "action", "sensitive", "order", "user", "account",
      "write", "update", "delete", "modify", "mass"],
     "A's broken object/access control likely extends to B's surface (same flaw family)"),
    (["file read", "traversal", "lfi", "disclosure", "path"],
     ["config", "env", "secret", "key", "credential", "source"],
     "A's file-read primitive can disclose B's sensitive configuration"),
    (["privilege", "role", "admin", "mass assignment", "escalation", "access control"],
     ["admin", "function", "panel", "action", "sensitive", "order"],
     "A's elevated/unchecked role unlocks B's privileged functionality"),
    # B1: the data_exfil goal's needs entry (goal-reachable per plan done-when)
    (["data reach", "data exposure", "exfiltration", "dump", "idor", "object"],
     ["data_reach", "object_access", "network"],
     "A's object/data access satisfies B's data-reach requirement"),
]


def plan_chains(goal: str, top: int = 3, auto_link: bool = False):
    """B1: multi-hop capability-graph planning toward a named goal (RCE /
    data_exfil / auth_bypass / priv_esc). Uses confirmed findings AND
    unconfirmed primitives; returns most-probable paths (Dijkstra, -log conf).
    Writes ONLY hypo_edges (board-level); never chain_to without evidence.
    --auto-link additionally links evidence-backed ADJACENT hops of a
    confirmed-only path into chain_to (the guarded store stays proof-only)."""
    import chain_planner
    board = load_json(BOARD_FILE)
    if not board:
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)
    if goal not in chain_planner.GOALS:
        print(f"[!] Unknown goal '{goal}'. Known: {', '.join(chain_planner.GOALS)}",
              file=sys.stderr)
        sys.exit(1)

    paths = chain_planner.plan_paths(board, goal, top=top)
    if not paths:
        print(f"[*] no chain to goal (clean exit)")
        return

    edges = chain_planner.propose_hypo_edges(board, paths)

    # persist hypo_edges (NEVER chain_to from planner inventions)
    with json_transaction("board.json") as b:
        if b is not None:
            he = b.setdefault("hypo_edges", [])
            existing = {(e.get("from"), e.get("to")) for e in he}
            for e in edges:
                if (e["from"], e["to"]) not in existing:
                    he.append(e)
                    existing.add((e["from"], e["to"]))
            # --auto-link: evidence-backed adjacent confirmed-finding hops only
            linked = 0
            if auto_link:
                confirmed_ids = {f.get("id") for f in b.get("findings", [])
                                 if f.get("status") == "confirmed"}
                for path, _c, _cf, _h in paths:
                    for a, nxt in zip(path, path[1:]):
                        if a in confirmed_ids and nxt in confirmed_ids:
                            fa = next((f for f in b.get("findings", [])
                                       if f.get("id") == a), None)
                            if fa and nxt not in (fa.get("chain_to") or []):
                                fa.setdefault("chain_to", []).append(nxt)
                                linked += 1
    print(f"[*] CHAIN PLAN -> {goal}: {len(paths)} ranked path(s), "
          f"{len(edges)} hypo_edge(s) written to board.hypo_edges")
    for i, (path, cost, conf, hops) in enumerate(paths, 1):
        labels = " -> ".join(chain_planner.label_for(nid, board) for nid in path)
        print(f"  #{i} (conf {conf:.2f}, {hops} hop(s), cost {cost:.2f}): {labels}")
    if auto_link:
        print(f"    --auto-link: {linked} evidence-backed hop(s) linked into chain_to; "
              f"unproven hops remain in hypo_edges only.")
    print("    Unproven hops are HYPOTHETICAL — confirm with evidence to promote.")


def mine_chains(auto_link=False):
    """Propose chain edges from finding primitives/needs. Deterministic: each
    finding's title+details are matched against the primitive/needs table;
    proposals are printed (and optionally linked with --auto-link, still
    gated by being explicit operator action)."""
    board = load_json(BOARD_FILE)
    if not board:
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)
    findings = board.get("findings", [])
    if len(findings) < 2:
        print("[*] Need >= 2 findings before chain mining has anything to mine.")
        return

    proposals = []
    already = []
    for a in findings:
        text_a = (a.get("title", "") + " " + a.get("details", "")).lower()
        for b in findings:
            if a is b or a.get("id") == b.get("id"):
                continue
            text_b = (b.get("title", "") + " " + b.get("details", "")).lower()
            for prim_kws, need_kws, why in PRIMITIVE_NEEDS:
                if any(k in text_a for k in prim_kws) and any(k in text_b for k in need_kws):
                    if b.get("id") in (a.get("chain_to") or []):
                        already.append((a["id"], b["id"], why))
                    else:
                        proposals.append((a["id"], b["id"], why))
                    break

    if not proposals and not already:
        print("[*] No chain proposals — findings don't compose by the primitive/needs table.")
        return

    print(f"[*] CHAIN MINING: {len(proposals)} new proposal(s), "
          f"{len(already)} already linked (deterministic primitive/needs match):\n")
    by_id = {f.get("id"): f for f in findings}
    linked = 0
    for a_id, b_id, why in proposals:
        ta = (by_id.get(a_id, {}).get("title") or "?")[:50]
        tb = (by_id.get(b_id, {}).get("title") or "?")[:50]
        print(f"  {a_id} -> {b_id}")
        print(f"      '{ta}'")
        print(f"        => '{tb}'")
        print(f"      why: {why}\n")
        if auto_link:
            # reuse the guarded link path
            with json_transaction("board.json") as bd:
                if bd is not None:
                    fa = next((f for f in bd.get("findings", []) if f.get("id") == a_id), None)
                    if fa and b_id not in (fa.get("chain_to") or []):
                        fa.setdefault("chain_to", []).append(b_id)
                        linked += 1
    if already:
        print("  Already linked (miner confirms existing edges):")
        for a_id, b_id, why in already:
            print(f"    {a_id} -> {b_id}  ({why[:60]})")
    if auto_link and proposals:
        print(f"[✔] Linked {linked} proposal(s). Review with: chains")
    elif proposals:
        print("\n    Accept with: chains --link <A>,<B> --note '<why>'  "
              "(or --auto-link to accept all proposals at once)")


def load_canary_token() -> str:
    """Returns the workspace canary token, or '' if none is registered."""
    return load_json(CANARY_FILE).get("canary_token", "")


# Binaries that are catastrophic and never legitimate for diagnostic testing.
DESTRUCTIVE_BINARIES = {
    "mkfs", "mke2fs", "dd", "shred", "wipefs", "fdisk", "parted", "mkswap",
    "shutdown", "reboot", "halt", "poweroff", "fastboot",
}


def is_destructive_command(cmd: str) -> tuple[bool, str]:
    """
    Detects clearly destructive operations (data/host destruction) that must be
    refused regardless of scope. This intentionally does NOT flag data-retrieval
    or offensive testing — only irreversible destruction of the host/filesystem.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    basenames = [tok.split("/")[-1] for tok in tokens]

    # rm with a recursive or force flag (e.g. rm -rf, rm -r, rm -f). Only inspect
    # actual flag tokens (those starting with '-') so a filename that merely
    # contains 'r'/'f' after a hyphen (e.g. 'rm file-report.txt') is not blocked.
    for i, base in enumerate(basenames):
        if base == "rm":
            flag_tokens = [t for t in tokens[i + 1:] if t.startswith("-")]
            flags = " ".join(flag_tokens)
            if re.search(r'-\w*[rf]', flags):
                return True, "recursive/forced file deletion (rm -r/-f)"

    # Outright destructive system binaries (incl. mkfs.* filesystem variants)
    for base in basenames:
        if base in DESTRUCTIVE_BINARIES or base.startswith("mkfs"):
            return True, f"destructive system command ({base})"

    # Dangerous full-string constructs
    if re.search(r'>\s*/dev/[sh]d[a-z]', cmd):
        return True, "write to raw disk device"
    if re.search(r':\s*\(\s*\)\s*\{.*\}\s*;?\s*:', cmd):
        return True, "fork bomb"
    if re.search(r'\b(chmod|chown)\s+-R\b\s+.*\s+/(?:\s|$)', cmd):
        return True, "recursive permission/ownership change on root"
    if re.search(r'\binit\s+[06]\b', cmd):
        return True, "system runlevel change"

    return False, ""


def preflight_checks(cmd: str, target: str) -> str:
    """Runs every hard gate before a command may execute. Exits the process on
    any violation. Returns the resolved canary token (for the post-exec scan)."""
    # Scope-signature gate (tamper evidence): a TAMPERED scope authorizes
    # nothing, ever. Unsigned legacy workspaces proceed (operator migration
    # path) — the suite covers both branches.
    verdict = verify_scope()
    if verdict.startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)

    scope = load_json(SCOPE_FILE)

    # Fail-closed scope gate: refuse to execute unless a populated scope exists
    # and an in-scope target has been explicitly declared for this command.
    if not scope:
        print(
            "[!] SCOPE ERROR: .blackboard/scope.json is missing or empty. "
            "Run 'python3 ~/artifactory/init_env.py --target .' and define the "
            "engagement scope before executing any command.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not target:
        print(
            "[!] SCOPE ERROR: a --target is required. Every command must be "
            "validated against scope.json before execution.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not is_target_in_scope(target, scope):
        print(f"[!] SCOPE ERROR: Target '{target}' is not permitted by .blackboard/scope.json", file=sys.stderr)
        sys.exit(1)

    # Canary pre-check: the canary token marks do-not-touch data. A command that
    # explicitly references it is trying to reach protected material — refuse.
    canary = load_canary_token()
    if canary and canary in cmd:
        print(
            f"[!] CANARY TRIPWIRE: command references the protected canary token "
            f"and was blocked before execution.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Destructive-action guard: only irreversible host/filesystem destruction is
    # blocked (enabled by 'DESTRUCTIVE_WRITE' in scope.json disallowed_actions).
    # Offensive testing and proof-of-concept data retrieval are NOT gated here.
    if "DESTRUCTIVE_WRITE" in scope.get("disallowed_actions", []):
        destructive, reason = is_destructive_command(cmd)
        if destructive:
            print(
                f"[!] DESTRUCTIVE-ACTION BLOCK: refused {reason}. "
                f"This is disallowed by scope.json; edit 'disallowed_actions' to override.",
                file=sys.stderr,
            )
            sys.exit(1)

    return canary


def execute_and_log(cmd: str, pointer_id: str, canary: str, quiet: bool = False):
    """Runs a pre-validated command, logs the artifact, updates the board, and
    performs the canary post-check. Assumes preflight_checks already passed."""
    timestamp = datetime.now(timezone.utc).isoformat()

    if not quiet:
        print(f"[*] Executing [{pointer_id}]: {cmd}")

    try:
        cmd_args = shlex.split(cmd)
        result = subprocess.run(
            cmd_args, shell=False, capture_output=True, text=True, timeout=COMMAND_TIMEOUT
        )
        stdout, stderr = result.stdout, result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = f"[!] Command timed out after {COMMAND_TIMEOUT}s and was terminated."
        returncode = 124
    except Exception as e:
        stdout, stderr = "", str(e)
        returncode = 1

    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"
    artifact_content = f"--- COMMAND ---\n{cmd}\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n"
    artifact_path.write_text(artifact_content)

    with open(HISTORY_FILE, "a") as f:
        f.write(f"[{timestamp}] [{pointer_id}] RETURN:{returncode} CMD: {cmd}\n")

    # Canary post-check: if the token surfaced in output, the command reached
    # protected do-not-touch data — flag it loudly and record the tripwire.
    if canary and (canary in stdout or canary in stderr):
        print(
            f"\n[!!!] CANARY TRIPWIRE HIT [{pointer_id}]: the protected canary token "
            f"appeared in command output. This command reached do-not-touch data — "
            f"halt and review scope before continuing.",
            file=sys.stderr,
        )
        with open(HISTORY_FILE, "a") as f:
            f.write(f"[{timestamp}] [{pointer_id}] CANARY_TRIPWIRE cmd touched protected data\n")

    lines = stdout.strip().split("\n") if stdout else []
    summary = lines[0] if lines else ("Error" if stderr else "Empty Output")
    update_board_state(pointer_id, cmd, returncode, summary[:120])

    if not quiet:
        if len(lines) > 100:
            print(f"[+] Output truncated (>100 lines). Full log: .blackboard/artifacts/{pointer_id}.log")
            print("\n".join(redact(l) for l in lines[:20]))
            print(f"\n... [{len(lines) - 40} lines omitted] ...\n")
            print("\n".join(redact(l) for l in lines[-20:]))
        else:
            if stdout:
                print(redact(stdout))
        if stderr:
            print(redact(stderr), file=sys.stderr)


def launch_background(cmd: str, target: str, pointer_id: str):
    """Spawns a detached child that runs the (already-validated) command, logs
    it, and triages the result into leads — without blocking the operator."""
    child = [
        sys.executable, str(Path(__file__).resolve()),
        "_bg-exec", "--cmd", cmd, "--target", target, "--pointer", pointer_id,
    ]
    with open(os.devnull, "wb") as devnull:
        subprocess.Popen(
            child, cwd=str(Path.cwd()), stdout=devnull, stderr=devnull,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )


def repeat_command_notice(cmd: str) -> str:
    """Loop guard (harness observability): surface — never block — when this
    exact command has already been executed in this workspace.

    Re-running an identical command is the canonical agent-loop pathology ("calls
    the same tool eleven times, confidently returning a result it never
    re-validated"). A pentester may legitimately re-run, so this only warns and
    points at the cached artifact so the operator can `inspect` it instead of
    burning a turn. Returns a notice string, or "" if this is a first run.
    """
    board = load_json(BOARD_FILE)
    if not board:
        return ""
    prior = [
        p for p in board.get("execution_log_pointers", [])
        if p.get("command") == cmd and p.get("pointer_id")
    ]
    if not prior:
        return ""
    last = prior[-1]
    return (
        f"[~] LOOP NOTICE: this exact command has already run {len(prior)} time(s). "
        f"Last was {last.get('pointer_id')} (rc={last.get('return_code')}, "
        f"\"{(last.get('summary') or '').strip()}\"). If nothing changed, reuse it: "
        f"sec_flow.py inspect --id {last.get('pointer_id')} — don't re-run in a loop."
    )


def shell_feature_notice(cmd: str) -> str:
    """Warn — never block — when a command contains shell metacharacters.

    The runner executes via shlex.split + shell=False (injection-safe), so pipes,
    redirects, chains and substitutions are passed as LITERAL arguments, not
    interpreted. Without this notice the operator sees confusing output instead
    of an error. Returns a notice string, or "" if the command is a plain argv.
    """
    if re.search(r'(?<!\\)(\||>|<|&&|;|\$\(|`)', cmd):
        return (
            "[~] SHELL NOTICE: this command contains shell metacharacters "
            "(| > < && ; $() `). The runner has no shell, so they are passed as "
            "literal arguments, NOT interpreted. Run the stages as separate "
            "commands, or (if you truly need a pipeline) wrap it: "
            "bash -c '<pipeline>' — it still passes the scope/destructive gates."
        )
    return ""


def run_command(cmd: str, target: str = None, background: bool = False):
    ensure_blackboard_dirs()
    canary = preflight_checks(cmd, target)

    # Per-host pacing (scope.json rate_limit) — enforced before every exec.
    enforce_rate_limit(target, load_json(SCOPE_FILE))

    notice = repeat_command_notice(cmd)
    if notice:
        print(notice, file=sys.stderr)
    shell_notice = shell_feature_notice(cmd)
    if shell_notice:
        print(shell_notice, file=sys.stderr)

    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"

    if background:
        launch_background(cmd, target, pointer_id)
        print(
            f"[*] Backgrounded [{pointer_id}]: {cmd}\n"
            f"    Results + leads will land on board.json when it finishes. "
            f"Pull them with: sec_flow.py leads"
        )
        return

    execute_and_log(cmd, pointer_id, canary)
    trigger_triage(pointer_id)


def bg_exec(cmd: str, target: str, pointer_id: str):
    """Internal entrypoint for the detached background child. Re-runs preflight
    (defense in depth) then executes + triages quietly."""
    ensure_blackboard_dirs()
    canary = preflight_checks(cmd, target)
    execute_and_log(cmd, pointer_id, canary, quiet=True)
    trigger_triage(pointer_id)


def show_leads(status: str = None, ltype: str = None, limit: int = 20,
               lead_id: str = None, set_status: str = None):
    """Operator-facing: the short ranked lead list (not raw logs), or update one."""
    board = load_json(BOARD_FILE)
    if not board:
        print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
        sys.exit(1)
    leads = board.get("leads", [])

    # Mutation mode: update a single lead's status.
    if lead_id and set_status:
        with json_transaction("board.json") as board:
            if board is None:
                print(f"[!] Error: {BOARD_FILE} not found. Run init_env.py first.", file=sys.stderr)
                sys.exit(1)
            found = False
            for l in board.get("leads", []):
                if l.get("id") == lead_id:
                    l["status"] = set_status
                    found = True
                    break
            if not found:
                print(f"[!] Lead '{lead_id}' not found.", file=sys.stderr)
                sys.exit(1)
        print(f"[✔] Lead {lead_id} -> status '{set_status}'")
        return

    view = [
        l for l in leads
        if (not status or l.get("status") == status)
        and (not ltype or l.get("type") == ltype)
    ]
    view.sort(key=lambda l: l.get("confidence", 0), reverse=True)
    if not view:
        print("[*] No leads match (run some recon via 'run' first).")
        return

    print(f"[*] Leads ({len(view)} shown, ranked by confidence):\n")
    for l in view[:limit]:
        print(f"  [{l.get('confidence')}] {l.get('id')} ({l.get('type')}/{l.get('status')}) "
              f"{l.get('value')}")
        if l.get("preconditions"):
            print(f"        ⚙ preconditions: {'; '.join(l['preconditions'])} — "
                  f"lab-enable then test (set --set-status blocked_precondition if blocked)")
        if l.get("suggested_next"):
            print(f"        ↳ next: {l['suggested_next']}  (src {l.get('source_pointer')})")


def inspect_artifact(pointer_id: str, grep_pattern: str = None, json_key: str = None, max_lines: int = 50):
    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"

    if not artifact_path.exists():
        print(f"[!] Error: Artifact '{pointer_id}' not found in {ARTIFACTS_DIR}", file=sys.stderr)
        sys.exit(1)

    raw_text = artifact_path.read_text()

    # Egress redaction: what leaves the engine is scrubbed; the artifact
    # itself stays byte-identical so evidence remains verifiable.
    raw_text = redact(raw_text)

    # Extract STDOUT section only
    stdout_match = re.search(r"--- STDOUT ---\n(.*?)(?=\n--- STDERR ---|\Z)", raw_text, re.DOTALL)
    stdout_content = stdout_match.group(1).strip() if stdout_match else raw_text

    # Mode 1: JSON Key Extractor
    if json_key:
        print(f"[*] Extracting JSON key '{json_key}' from {pointer_id}:")
        found = False
        for line in stdout_content.splitlines():
            try:
                data = json.loads(line)
                if isinstance(data, dict) and json_key in data:
                    print(json.dumps(data[json_key], indent=2))
                    found = True
            except json.JSONDecodeError:
                continue
        if not found:
            print(f"[!] Key '{json_key}' not found or output is not line-delimited JSON.")
        return

    # Mode 2: Regex Grep
    lines = stdout_content.splitlines()
    if grep_pattern:
        regex = re.compile(grep_pattern, re.IGNORECASE)
        matched_lines = [line for line in lines if regex.search(line)]
        print(f"[*] Showing matches for '{grep_pattern}' in {pointer_id} (Limit: {max_lines}):\n")
        for line in matched_lines[:max_lines]:
            print(line)
        if len(matched_lines) > max_lines:
            print(f"\n... [{len(matched_lines) - max_lines} matching lines omitted] ...")
        return

    # Mode 3: Head slice
    print(f"[*] Showing head of {pointer_id} (Limit: {max_lines}):\n")
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        print(f"\n... [{len(lines) - max_lines} lines omitted] ...")


def workspace_status():
    """One-glance engagement dashboard: scope health, findings, leads, chains,
    sessions, tokens, fingerprints. Pulls together what would otherwise be
    eight separate commands — the operator's first stop each session."""
    board = load_json(BOARD_FILE)
    if not board:
        print("[!] No board.json — run init_env.py first.", file=sys.stderr)
        sys.exit(1)

    verdict = verify_scope()
    sig = {"ok": "[✔] signed (tamper-evident)",
           "unsigned": "[~] unsigned (legacy — re-run init_env.py to enable)"}.get(
        verdict, f"[!] {verdict}")

    findings = board.get("findings", [])
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    leads = board.get("leads", [])
    by_status = {}
    for l in leads:
        by_status[l.get("status", "?")] = by_status.get(l.get("status", "?"), 0) + 1
    chains = sum(len(f.get("chain_to", [])) for f in findings)
    sessions = board.get("sessions", [])
    valid_sessions = [s for s in sessions if s.get("valid", True)]

    print("=" * 60)
    print("ENGAGEMENT STATUS")
    print("=" * 60)
    print(f"  Scope:      {sig}")
    sc = load_json(SCOPE_FILE)
    if sc:
        print(f"              hosts={len(sc.get('allowed_hosts', []))} "
              f"domains={len(sc.get('allowed_domains', []))} "
              f"cidrs={len(sc.get('allowed_cidrs', []))} "
              f"pending={len(sc.get('pending_scope', []))} "
              f"rate_limit={bool((sc.get('rate_limit') or {}).get('min_interval_seconds'))}")
    print(f"  Findings:   {len(confirmed)} confirmed / "
          f"{len(findings) - len(confirmed)} informational")
    print(f"  Leads:      {len(leads)} total "
          f"({', '.join(f'{k}={v}' for k, v in sorted(by_status.items())) or 'none'})")
    print(f"  Chains:     {chains} edge(s) — view: sec_flow.py chains")
    print(f"  Sessions:   {len(valid_sessions)} valid role(s) of {len(sessions)} "
          f"— list: auth_manager.py list")
    try:
        from tokens import _load_ledger_totals  # cheap reuse, no side effects
        total = _load_ledger_totals()
        per_m = len(confirmed) / (total / 1_000_000) if total else 0
        print(f"  Tokens:     {total:.0f} spent | {per_m:.2f} vulns/1M-tokens"
              + (" (log spends: tokens.py log)" if not total else ""))
    except Exception:
        pass
    fp = load_json(FINGERPRINTS_FILE) or {}
    if fp:
        print(f"  Fingerprints: {len(fp)} host(s) cached")
    # Blind-spot visibility: classes with no methodology and no ground truth
    try:
        from cross_index import gaps_only
        gaps = gaps_only()
        if gaps:
            print(f"  Blind spots: {len(gaps)} class(es) uncovered "
                  f"({', '.join(gaps[:4])}{'...' if len(gaps) > 4 else ''}) — cross_index.py map")
        else:
            print("  Blind spots: none (full class coverage)")
    except Exception:
        pass
    debrief_hint = "debrief.py debrief"
    print("=" * 60)
    print(f"  Next: leads | chains | tokens.py report | {debrief_hint} (at close-out)")


def run_nuclei(target: str, templates: str = "", severity: str = "", background: bool = False, config: str = None):
    """nuclei integration: the community 1-day template corpus fired at an
    in-scope target. Every matcher hit becomes a `cve` lead flagged
    must_verify (a template match is a CANDIDATE, never a finding — the
    verification gate still applies). No silent drops: a missing nuclei
    binary files an explicit lead so the coverage gap is visible.

    Templates default to the installed nuclei template dir if -templates is
    omitted; `-config` pins a config file (never 'auto' uploads).
    """
    import shutil as _shutil
    ensure_blackboard_dirs()

    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)

    scope = load_json(SCOPE_FILE)
    if not is_target_in_scope(target, scope):
        print(f"[!] SCOPE ERROR: Target '{target}' is not permitted by .blackboard/scope.json",
              file=sys.stderr)
        sys.exit(1)

    if not _shutil.which("nuclei"):
        # No silent drop: file a lead so the operator sees the gap.
        pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
        (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
            f"--- COMMAND ---\nnuclei scan (unavailable)\n\n--- STDOUT ---\n"
            f"nuclei binary not found on PATH\n\n--- STDERR ---\n")
        with json_transaction("board.json", create=True) as board:
            if board is not None:
                board.setdefault("leads", []).append({
                    "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                    "type": "cve",
                    "value": "nuclei template scan (COVERAGE GAP)",
                    "signal": "nuclei not installed — community 1-day corpus not fired",
                    "confidence": 0.0,
                    "suggested_next": "install nuclei to close the coverage gap",
                    "must_verify": False,
                    "preconditions": [],
                    "source_pointer": pointer_id,
                    "status": "new",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
        print("[!] nuclei is not installed — filed a coverage-gap lead on the board "
              "instead of silently skipping.", file=sys.stderr)
        sys.exit(1)

    cmd_parts = ["nuclei", "-target", target, "-json", "-silent"]
    if templates:
        cmd_parts += ["-templates", templates]
    if severity:
        cmd_parts += ["-severity", severity]
    if config:
        cmd_parts += ["-config", config]
    cmd = " ".join(shlex.quote(p) for p in cmd_parts)
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    print(f"[*] Nuclei scan [{pointer_id}]: {cmd}")

    if background:
        launch_background(cmd, target, pointer_id)
        print(f"[*] Backgrounded [{pointer_id}] — results + leads land on the board when done.")
        return

    execute_and_log(cmd, pointer_id, load_canary_token())
    trigger_triage(pointer_id)

    # Parse the JSONL artifact into cve leads (deterministic, no re-read).
    art = (ARTIFACTS_DIR / f"{pointer_id}.log").read_text()
    m = re.search(r"--- STDOUT ---\n(.*?)\n--- STDERR ---", art, re.DOTALL)
    hits = []
    for line in (m.group(1).splitlines() if m else []):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        tid = obj.get("template-id") or obj.get("templateID") or "unknown-template"
        matches = obj.get("matched-at") or obj.get("host") or target
        hits.append((tid, matches, str(obj.get("info", {}).get("severity", ""))))
    if hits:
        leads = []
        for tid, matched, sev in hits:
            leads.append({
                "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                "type": "cve",
                "value": f"nuclei: {tid} @ {matched}",
                "signal": f"template match ({sev or 'unrated'})",
                "confidence": 0.55,
                "suggested_next": "verify version condition + build PoC before any confirmation",
                "must_verify": True,
                "preconditions": [],
                "source_pointer": pointer_id,
                "status": "new",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
        with json_transaction("board.json") as board:
            if board is not None:
                board.setdefault("leads", []).extend(leads)
        print(f"[✔] {len(hits)} nuclei match(es) filed as must_verify cve leads "
              f"(verify before confirming).")
    else:
        print("[*] No template matches.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Flow Execution Engine")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # status (one-glance engagement dashboard)
    subparsers.add_parser("status", help="Engagement dashboard: scope, findings, leads, chains, tokens")

    # run
    run_parser = subparsers.add_parser("run", help="Run command and log artifacts")
    run_parser.add_argument("--cmd", required=True, help="Command to execute")
    run_parser.add_argument("--target", help="Target domain/host to validate against scope")
    run_parser.add_argument(
        "--background", "--bg", action="store_true", dest="background",
        help="Run detached: return immediately, log + triage results to board.json when done",
    )

    # _bg-exec (internal: the detached child entrypoint for --background)
    bg_parser = subparsers.add_parser("_bg-exec", help=argparse.SUPPRESS)
    bg_parser.add_argument("--cmd", required=True)
    bg_parser.add_argument("--target", required=True)
    bg_parser.add_argument("--pointer", required=True)

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect and query artifact logs")
    inspect_parser.add_argument("--id", required=True, help="Pointer ID (e.g., MSG_A1B2C3D4)")
    inspect_parser.add_argument("--grep", help="Regex pattern to filter log lines")
    inspect_parser.add_argument("--json-key", help="JSON field/key to extract from output lines")
    inspect_parser.add_argument("--lines", type=int, default=50, help="Max lines to return (default: 50)")

    # add-asset
    asset_parser = subparsers.add_parser("add-asset", help="Record discovered asset to board.json")
    asset_parser.add_argument("--host", help="Discovered hostname or IP")
    asset_parser.add_argument("--endpoint", help="Discovered URL path or route")
    asset_parser.add_argument("--port", help="Discovered open port (e.g., 8080/tcp)")
    asset_parser.add_argument("--finding", help="Vulnerability or observation title")
    asset_parser.add_argument("--details", default="", help="Short description of the finding")
    asset_parser.add_argument("--severity", default="info", choices=SEVERITIES,
                              help="Finding severity (default: info)")
    asset_parser.add_argument("--status", default="informational", choices=FINDING_STATUSES,
                              help="informational (default) or confirmed (requires evidence)")
    asset_parser.add_argument("--poc", default="",
                              help="Inline proof: the payload / request+response that proves impact")
    asset_parser.add_argument("--evidence-from", dest="evidence_from",
                              help="Pointer ID whose artifact log is the evidence for this finding")
    asset_parser.add_argument("--chain-to", dest="chain_to", default=None,
                              help="Comma-separated prior FINDING_ IDs this finding chains from (attack-path edge)")

    # chains (view/edit the finding chain graph — chain-mining substrate)
    chains_parser = subparsers.add_parser("chains", help="View or edit the finding chain graph")
    chains_parser.add_argument("--link", help="Directed edge FINDING_A,FINDING_B (A enables B)")
    chains_parser.add_argument("--unlink", help="Remove edge FINDING_A,FINDING_B")
    chains_parser.add_argument("--note", default="", help="Annotation for the --link edge")
    chains_parser.add_argument("--mine", action="store_true",
                                help="Propose edges from primitive/needs matching (deterministic)")
    chains_parser.add_argument("--plan", action="store_true",
                                help="B1: multi-hop capability-graph planning toward --goal")
    chains_parser.add_argument("--goal", default=None,
                                help="Named post-condition: RCE | data_exfil | auth_bypass | priv_esc")
    chains_parser.add_argument("--top", type=int, default=3,
                                help="Top-N paths for --plan (default 3)")
    chains_parser.add_argument("--auto-link", dest="auto_link", action="store_true",
                                help="With --mine/--plan: link evidence-backed hops into chain_to (guarded); unproven -> hypo_edges")

    # scope (WS2: per-project scope + subdomain approval)
    scope_parser = subparsers.add_parser("scope", help="View or edit engagement scope")
    scope_parser.add_argument("--list", dest="do_list", action="store_true", help="Show current scope + pending")
    scope_parser.add_argument("--add-host", dest="add_host", help="Authorise a host/IP")
    scope_parser.add_argument("--add-domain", dest="add_domain", help="Authorise a domain/wildcard (e.g. *.example.com)")
    scope_parser.add_argument("--add-cidr", dest="add_cidr", help="Authorise a CIDR range")
    scope_parser.add_argument("--add-code-path", dest="add_code_path",
                              help="Authorise a source directory for SAST/SCA (allowed_code_paths)")
    scope_parser.add_argument("--approve", help="Promote a pending host into allowed_hosts")

    # add-rationale (WS7: decision journal -> 'How we got here')
    rat_parser = subparsers.add_parser("add-rationale", help="Log why an action was taken and its outcome")
    rat_parser.add_argument("--lead", help="Lead ID this decision relates to")
    rat_parser.add_argument("--hypothesis", default="", help="The attack theory being tested")
    rat_parser.add_argument("--why", default="", help="Why this action was chosen")
    rat_parser.add_argument("--action", default="", help="What was done")
    rat_parser.add_argument("--expected", default="", help="Signal that would confirm the hypothesis")
    rat_parser.add_argument("--pointer", help="Related execution pointer ID")
    rat_parser.add_argument("--outcome", default="", help="What actually happened (confirmed|dead|inconclusive + note)")

    # leads (operator-facing: consume ranked leads instead of raw logs)
    leads_parser = subparsers.add_parser("leads", help="Show/triage ranked leads on the board")
    leads_parser.add_argument("--status", help="Filter by status (new|testing|confirmed|dead|blocked_precondition)")
    leads_parser.add_argument("--type", dest="ltype",
                              help="Filter by type (endpoint|port|subdomain|tech|anomaly|sast|cve)")
    leads_parser.add_argument("--limit", type=int, default=20, help="Max leads to show (default: 20)")
    leads_parser.add_argument("--id", dest="lead_id", help="Lead ID to update")
    leads_parser.add_argument("--set-status", dest="set_status",
                              help="New status for --id (new|testing|confirmed|dead|blocked_precondition)")

    # sast (white-box: semgrep finds candidates -> sast leads for the verifier)
    sast_parser = subparsers.add_parser("sast", help="Run semgrep over authorised source -> sast leads")
    sast_parser.add_argument("--path", "-p", required=True, help="Source directory/file to scan")
    sast_parser.add_argument("--config", "-c", default=None,
                             help="semgrep ruleset (default: pinned pack; never 'auto')")
    sast_parser.add_argument("--background", "--bg", action="store_true", dest="background",
                             help="(reserved) run detached; currently synchronous")

    # intel / sca / detect (passive-intel allowlist; never touches the target)
    intel_parser = subparsers.add_parser(
        "intel", help="Changelog-first full-index CVE enumeration for a product/version")
    intel_parser.add_argument("--product", "-P", required=True, help="Product/package name")
    intel_parser.add_argument("--version", "-V", default="", help="Installed/target version")
    intel_parser.add_argument("--cpe", default="", help="Optional exact CPE for NVD match")
    intel_parser.add_argument("--preconditions", default="",
                              help="Comma-separated feature preconditions for the CVE leads")

    sca_parser = subparsers.add_parser(
        "sca", help="Distro SCA: inventory jars/lockfiles -> OSV batch -> cve leads (fail-closed on allowed_code_paths)")
    sca_parser.add_argument("--path", "-p", required=True, help="Directory to inventory")
    sca_parser.add_argument("--offline", action="store_true",
                            help="Air-gapped/rate-limited: skip network, file the full pinned inventory as deterministic cve leads")

    detect_parser = subparsers.add_parser(
        "detect", help="Detect source trees/manifests (analyze auto-wire for SAST+SCA)")
    detect_parser.add_argument("--path", "-p", default=".")

    # nuclei (community 1-day template corpus -> must_verify cve leads)
    nuclei_parser = subparsers.add_parser(
        "nuclei", help="Fire the nuclei template corpus at an in-scope target (matches -> cve leads)")
    nuclei_parser.add_argument("--target", required=True, help="In-scope target URL/host")
    nuclei_parser.add_argument("--templates", default="", help="Template dir/file (default: nuclei's installed set)")
    nuclei_parser.add_argument("--severity", default="", help="Severity filter (e.g. critical,high)")
    nuclei_parser.add_argument("--background", "--bg", action="store_true", dest="background",
                               help="Run detached; leads land on the board when done")
    nuclei_parser.add_argument("--config", default=None, help="Pinned nuclei config file (never auto)")

    # fingerprint (target tech cache — record/lookup)
    fp_parser = subparsers.add_parser("fingerprint", help="Target tech/version cache (never re-learn a stack)")
    fp_parser.add_argument("--host", help="Host to record/lookup")
    fp_parser.add_argument("--tech", default="", help="Tech/version observation to record (with --host)")
    fp_parser.add_argument("--record", action="store_true",
                           help="Record --tech for --host instead of looking up")
    fp_parser.add_argument("--all", action="store_true", help="List every cached host")
    fp_parser.add_argument("--fresh-only", dest="fresh_only", action="store_true", default=True)

    args = parser.parse_args()

    if args.subcommand == "run":
        run_command(args.cmd, args.target, args.background)
    elif args.subcommand == "status":
        workspace_status()
    elif args.subcommand == "_bg-exec":
        bg_exec(args.cmd, args.target, args.pointer)
    elif args.subcommand == "inspect":
        inspect_artifact(args.id, args.grep, args.json_key, args.lines)
    elif args.subcommand == "add-asset":
        add_asset_to_board(args.host, args.endpoint, args.port, args.finding, args.details,
                           args.severity, args.status, args.poc, args.evidence_from,
                           args.chain_to)
    elif args.subcommand == "chains":
        if args.plan:
            if not args.goal:
                print("[!] --plan requires --goal (RCE|data_exfil|auth_bypass|priv_esc)",
                      file=sys.stderr)
                sys.exit(1)
            plan_chains(args.goal, args.top, args.auto_link)
        elif args.mine:
            mine_chains(auto_link=args.auto_link)
        else:
            manage_chains(args.link, args.unlink, args.note)
    elif args.subcommand == "scope":
        manage_scope(args.add_host, args.add_domain, args.add_cidr, args.add_code_path,
                     args.approve, args.do_list)
    elif args.subcommand == "add-rationale":
        add_rationale(args.lead, args.hypothesis, args.why, args.action, args.expected,
                      args.pointer, args.outcome)
    elif args.subcommand == "leads":
        show_leads(args.status, args.ltype, args.limit, args.lead_id, args.set_status)
    elif args.subcommand == "sast":
        import sast
        run_kwargs = {"background": args.background}
        if args.config:
            run_kwargs["config"] = args.config
        sast.run_sast(args.path, **run_kwargs)
    elif args.subcommand in ("intel", "sca", "detect"):
        import intel
        if args.subcommand == "intel":
            pres = [p.strip() for p in (args.preconditions or "").split(",") if p.strip()]
            intel.run_intel(args.product, args.version, args.cpe, pres)
        elif args.subcommand == "sca":
            intel.run_sca(args.path, offline=args.offline)
        else:
            intel.run_detect(args.path)
    elif args.subcommand == "nuclei":
        run_nuclei(args.target, args.templates, args.severity, args.background, args.config)
    elif args.subcommand == "fingerprint":
        if args.all:
            fp = load_json(FINGERPRINTS_FILE) or {}
            if not fp:
                print("[*] Fingerprint cache is empty.")
            for host, entries in fp.items():
                print(f"  {host}:")
                for e in entries:
                    print(f"    {e.get('tech')}  ({e.get('source')}, {e.get('recorded_at')})")
        elif args.host and args.record and args.tech:
            record_fingerprint(args.host, args.tech)
            print(f"[✔] Fingerprint recorded: {clean_host(args.host)} -> {args.tech}")
        elif args.host:
            entries = lookup_fingerprints(args.host, fresh_only=args.fresh_only)
            if not entries:
                print(f"[*] No fresh fingerprints for {clean_host(args.host)} "
                      f"(record one: fingerprint --host <h> --tech '<banner>' --record)")
            for e in entries:
                print(f"  {e.get('tech')}  ({e.get('source')}, {e.get('recorded_at')})")
        else:
            print("[*] Usage: fingerprint --host <h> [--tech '<obs>' --record] | --all")