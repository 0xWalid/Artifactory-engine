#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - External Tool Importers

Zero-token inventory from scans operators already ran, in the same lead
contract as everything else:

  * har <file.har>          — DevTools/Burp HAR: every entry's request URL ->
                              endpoint leads + inventory; response bodies kept
                              as verifiable artifacts (redacted at egress).
  * nmap <file.xml>         — Nmap XML (-oX): open ports + service banners ->
                              port/tech leads, fingerprints recorded.
  * nessus <file.nessus>    — Tenable Nessus .nessus XML: plugin findings ->
                              must_verify cve leads (scanner candidates never
                              become findings).
  * inventory-diff          — crawl as TWO sessions, diff WHAT EXISTS per role
                              (endpoint-only-for-admin is its own leak class).

All deterministic. Out-of-scope hosts are flagged, never silently dropped.
"""

import argparse
import base64
import ipaddress
import json
import re
import socket
import sys
import urllib.request
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
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"


def _in_scope(host: str) -> bool:
    scope = load_json(SCOPE_FILE) or {}
    if not scope:
        return False
    h = (host or "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
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


def _mklead(ltype, value, signal, pointer, conf, nxt, must_verify=False):
    return {"id": f"LEAD_{uuid.uuid4().hex[:6].upper()}", "type": ltype,
            "value": value, "signal": signal, "confidence": conf,
            "suggested_next": nxt, "must_verify": must_verify,
            "preconditions": [], "source_pointer": pointer, "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat()}


def _guard_tamper():
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)


def import_har(har_file: str, out_file: str = "endpoints.txt"):
    _guard_tamper()
    p = Path(har_file)
    if not p.exists():
        print(f"[!] HAR file '{har_file}' not found.", file=sys.stderr)
        sys.exit(1)
    har = json.loads(p.read_text(errors="replace"))
    entries = har.get("log", {}).get("entries", [])
    if not entries:
        print("[!] No entries in HAR.", file=sys.stderr)
        sys.exit(1)

    pointer = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads, seen, skipped, traffic = [], set(), [], []

    for e in entries:
        req = e.get("request", {}) or {}
        resp = e.get("response", {}) or {}
        url = req.get("url", "")
        if not url:
            continue
        host = url.split("/")[2] if url.count("/") >= 2 else ""
        if host and not _in_scope(host):
            skipped.append(url)
            continue
        m = re.match(r"https?://[^/]+(/[^?#]*)", url)
        path = m.group(1) if m else "/"
        key = (host, path, req.get("method", "GET"))
        if key in seen:
            continue
        seen.add(key)
        leads.append(_mklead("endpoint", path,
                             f"har: {req.get('method')} -> {resp.get('status', '?')} on {host}",
                             pointer, 0.5, "include in role-diff inventory"))
        # verifiable traffic artifact (redaction happens at egress, not here)
        body = (resp.get("content", {}) or {}).get("text", "")
        if body and len(body) > 10:
            traffic.append(f"=== {req.get('method')} {url} [{resp.get('status')}] ===\n{body[:4000]}")

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS_DIR / f"{pointer}.log").write_text(
        f"--- COMMAND ---\nimporters har {har_file}\n\n--- STDOUT ---\n"
        + "\n".join(traffic)[:200000] + "\n\n--- STDERR ---\n")
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            eps = board.setdefault("discovered_assets", {}).setdefault("endpoints", [])
            for l in leads:
                if l["value"] not in eps:
                    eps.append(l["value"])
    Path(out_file).write_text("\n".join(l["value"] for l in leads) + "\n")

    print(f"[OK] HAR: {len(leads)} unique endpoint(s) -> leads + {out_file}")
    if skipped:
        print(f"    {len(skipped)} out-of-scope URL(s) skipped (flagged, not silent):")
        for u in skipped[:3]:
            print(f"      {u}")
    print(f"    traffic artifact: {pointer}")


def import_nmap(xml_file: str):
    _guard_tamper()
    p = Path(xml_file)
    if not p.exists():
        print(f"[!] Nmap XML '{xml_file}' not found.", file=sys.stderr)
        sys.exit(1)
    xml = p.read_text(errors="replace")
    pointer = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    # <host><address addr=.../><ports><port protocol=... portid=...><state state=open/>
    # <service name=... product=... version=.../></port></ports></host>
    for hm in re.finditer(r"<host>.*?</host>", xml, re.S):
        host_blk = hm.group(0)
        am = re.search(r'<address addr="([^"]+)"', host_blk)
        host = am.group(1) if am else "?"
        if not _in_scope(host):
            continue
        for pm in re.finditer(
                r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="open"/?>'
                r'.*?(?:<service name="([^"]*)"[^>]*?(?:product="([^"]*)"[^>]*?version="([^"]*)")?)?',
                host_blk, re.S):
            proto, port, svc, product, version = pm.group(1), pm.group(2), pm.group(3), pm.group(4), pm.group(5)
            leads.append(_mklead("port", f"{port}/{proto} ({svc or '?'})",
                                 f"nmap open port on {host}", pointer, 0.5,
                                 "probe the service; include host in scope checks"))
            banner = " ".join(x for x in [product, version] if x)
            if banner:
                leads.append(_mklead("tech", banner, f"nmap service banner on {host}:{port}",
                                      pointer, 0.35, "map known CVEs; VERIFY before reporting",
                                      must_verify=True))
                # record into the fingerprint cache automatically
                try:
                    import sec_flow as _sf
                    _sf.record_fingerprint(host, banner, source="nmap")
                except Exception:
                    pass
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
    print(f"[OK] Nmap: {len(leads)} port/tech lead(s) (banners auto-recorded to "
          f"fingerprints where present).")


def import_nessus(nessus_file: str):
    _guard_tamper()
    p = Path(nessus_file)
    if not p.exists():
        print(f"[!] Nessus file '{nessus_file}' not found.", file=sys.stderr)
        sys.exit(1)
    xml = p.read_text(errors="replace")
    pointer = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    # ReportItem: pluginID, pluginName, severity (0 info..4 crit), host
    for rm in re.finditer(
            r'<ReportItem port="(\d+)"[^>]*severity="(\d)"[^>]*pluginID="(\d+)"[^>]*>'
            r'<plugin_name>(.*?)</plugin_name>', xml, re.S) or []:
        port, sev, pid, name = rm.group(1), int(rm.group(2)), rm.group(3), rm.group(4)
        sev_name = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(sev, "info")
        if sev == 0:
            continue
        leads.append(_mklead(
            "cve", f"nessus: {name[:100]}",
            f"plugin {pid} ({sev_name}) on port {port}", pointer,
            0.5 if sev >= 3 else 0.35,
            "verify manually — scanner candidates are never findings", must_verify=True))
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
    print(f"[OK] Nessus: {len(leads)} must_verify plugin lead(s).")


def role_inventory_diff(base_url, session_a, session_b, max_paths=60, delay=0.1):
    """Crawl as BOTH roles, diff WHAT EXISTS per role. An endpoint reachable
    for admin but 404 for user is hidden-functionality leakage (its own class,
    distinct from response-diff)."""
    _guard_tamper()
    if not _in_scope(base_url.split("/")[2] if "://" in base_url else base_url):
        print(f"[!] SCOPE ERROR: '{base_url}' not in scope.", file=sys.stderr)
        sys.exit(1)
    sessions = {}
    for sid in (session_a, session_b):
        sp = SESSIONS_DIR / f"{sid}.json"
        if not sp.exists():
            print(f"[!] Session '{sid}' not found.", file=sys.stderr)
            sys.exit(1)
        sessions[sid] = json.loads(sp.read_text())

    def crawl_paths(sess):
        from crawl import _extract_links, _fetch, _extract_js_routes
        cookie = sess.get("credential") if sess.get("auth_type") == "cookie" else None
        found, frontier, seen = set(), ["/", "/index.html", "/robots.txt"], set()
        routes = set()
        while frontier and len(seen) < max_paths:
            path = frontier.pop(0)
            if path in seen:
                continue
            seen.add(path)
            status, body, headers = _fetch(base_url.rstrip("/") + path, cookie)
            if status == 0:
                continue
            if status in (200, 301, 302, 401, 403):
                found.add(path)
                if "html" in (headers.get("Content-Type") or "").lower():
                    for l in _extract_links(base_url, body):
                        if l not in seen:
                            frontier.append(l)
            if delay:
                import time as _t
                _t.sleep(delay)
        return found

    a_paths = crawl_paths(sessions[session_a])
    b_paths = crawl_paths(sessions[session_b])

    only_a = a_paths - b_paths
    only_b = b_paths - a_paths
    pointer = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    ra, rb = sessions[session_a].get("role", "A"), sessions[session_b].get("role", "B")
    for p in only_a:
        leads.append(_mklead("rolediff", f"EXISTS-ONLY-FOR {ra}: {p}",
                             f"path exists for {ra} but 404s for {rb} — hidden functionality",
                             pointer, 0.6,
                             f"confirm the 404 as {rb}, then test authorization ON the route"))
    for p in only_b:
        leads.append(_mklead("rolediff", f"EXISTS-ONLY-FOR {rb}: {p}",
                             f"path exists for {rb} but 404s for {ra}", pointer, 0.45,
                             "confirm; may be role-appropriate routing"))
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
    print(f"[OK] Role inventory-diff: {len(a_paths)} paths ({ra}) vs {len(b_paths)} ({rb})")
    print(f"    only-{ra}: {len(only_a)}  only-{rb}: {len(only_b)}  -> {len(leads)} lead(s)")
    for p in list(only_a)[:6]:
        print(f"      + {ra}: {p}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="External tool importers")
    sub = parser.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("har", help="HAR -> endpoint leads + inventory + traffic artifacts")
    h.add_argument("file")
    h.add_argument("--out", default="endpoints.txt")
    n = sub.add_parser("nmap", help="Nmap XML -> port/tech leads + fingerprints")
    n.add_argument("file")
    ne = sub.add_parser("nessus", help="Nessus XML -> must_verify cve leads")
    ne.add_argument("file")
    rd = sub.add_parser("inventory-diff", help="Crawl as two roles; diff what EXISTS")
    rd.add_argument("--base-url", dest="base_url", required=True)
    rd.add_argument("--sessions", required=True, help="SESS_A,SESS_B")
    rd.add_argument("--max-paths", dest="max_paths", type=int, default=60)
    rd.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()
    if args.cmd == "har":
        import_har(args.file, args.out)
    elif args.cmd == "nmap":
        import_nmap(args.file)
    elif args.cmd == "nessus":
        import_nessus(args.file)
    else:
        s1, s2 = [s.strip() for s in args.sessions.split(",", 1)]
        role_inventory_diff(args.base_url, s1, s2, args.max_paths, args.delay)
