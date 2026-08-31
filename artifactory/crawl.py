#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Endpoint Crawler (stdlib-only)

Auto-builds the endpoint inventory that role-diff consumes: fetch the app,
walk same-origin links + parse SPA route hints, replay each discovered path
as the BASELINE session, and write endpoints.txt. This removes the biggest
manual step in the BAC/IDOR flow (the hand-written endpoints file) while
spending ZERO model tokens — discovery is deterministic.

Discovers from:
  * href/action/src in HTML (same-origin, path-normalized)
  * fetch/axios/XMLHttpRequest string literals in inline+linked JS
  * common API path shapes in JS (/api/..., /v1/... quoted strings)

Depth-limited (default 3), per-host politeness delay, scope-gated (reuse the
fail-closed host check), and every fetched path is recorded as an `endpoint`
lead on the board — crawling output feeds the same lead list everything else
uses, so the operator model still consumes leads, not logs.
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SESSIONS_DIR = BLACKBOARD_DIR / "sessions"

MAX_PATHS_DEFAULT = 200
DEFAULT_DELAY = 0.3  # politeness between requests (crawl IS the load)


def host_in_scope(host: str, scope: dict) -> bool:
    if not scope:
        return False
    h = (host or "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if h in scope.get("allowed_hosts", []):
        return True
    for domain in scope.get("allowed_domains", []):
        d = domain.replace("*.", "")
        if h == d or h.endswith("." + d):
            return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(h))
        for cidr in scope.get("allowed_cidrs", []):
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except (socket.gaierror, ValueError):
        return False
    return False


def _fetch(url, cookie=None, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "artifactory-crawler/1.0"})
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})
    except Exception:
        return 0, "", {}


def _extract_links(base, html):
    out = set()
    for m in re.finditer(r"""(?:href|action|src)\s*=\s*["']([^"'#]+)["']""", html, re.I):
        raw = m.group(1)
        if raw.startswith(("javascript:", "data:", "mailto:")):
            continue
        u = urljoin(base, raw)
        p = urlparse(u)
        if p.netloc != urlparse(base).netloc:
            continue
        if p.path and p.path != "/":
            out.add(p.path.split("?")[0])
    return out


def _extract_js_routes(js_text):
    """String literals in JS that look like API routes."""
    out = set()
    for m in re.finditer(r"""["'](/(?:api|v\d|rest|graphql|auth|user|admin|internal)[^"'\s]*)["']""",
                         js_text, re.I):
        out.add(m.group(1).split("?")[0])
    return out


def _calibrate_soft404(base_url, cookie=None):
    """Soft-404 calibration: request a definitely-bogus path and fingerprint
    how THIS app responds to unknown routes (status + normalized body). Content
    discovery without this produces garbage leads (200-with-'not found' pages,
    SPA catch-alls). Returns (status, body_signature) or None."""
    bogus = f"/zz-not-real-{uuid.uuid4().hex[:6]}"
    status, body, _ = _fetch(base_url + bogus, cookie)
    if status == 0:
        return None
    # strip the random token itself so the signature is comparable
    sig = re.sub(r"zz-not-real-[a-f0-9]+", "__BOGUS__", body or "")[:300]
    return (status, sig)


def _is_soft404(status, body, calibration):
    """True when a response matches the app's unknown-route fingerprint."""
    if not calibration:
        return False
    cal_status, cal_sig = calibration
    if status != cal_status:
        return False
    norm = re.sub(r"zz-not-real-[a-f0-9]+", "__BOGUS__", body or "")[:300]
    # identical short signature OR cal_sig contained in body (SPA catch-alls)
    return norm == cal_sig or (cal_sig and cal_sig in (body or ""))


def crawl(base_url, session_id=None, max_paths=MAX_PATHS_DEFAULT, max_depth=3,
          delay=DEFAULT_DELAY, out_file="endpoints.txt", status_ok=(200, 301, 302, 401, 403, 405)):
    scope = load_json(SCOPE_FILE)
    if not host_in_scope(urlparse(base_url).netloc, scope):
        print(f"[!] SCOPE ERROR: '{base_url}' not in scope.json — authorize it first.",
              file=sys.stderr)
        sys.exit(1)

    cookie = None
    role = "anonymous"
    if session_id:
        sp = SESSIONS_DIR / f"{session_id}.json"
        if not sp.exists():
            print(f"[!] Session '{session_id}' not found.", file=sys.stderr)
            sys.exit(1)
        sess = json.loads(sp.read_text())
        cookie = sess.get("credential") if sess.get("auth_type") == "cookie" else None
        role = sess.get("role", "anonymous")

    seen_paths = set()
    # Soft-404 calibration (per role cookie): filters unknown-route responses
    # so the inventory holds REAL surface, not 200-labeled garbage.
    calibration = _calibrate_soft404(base_url, cookie)
    if calibration:
        print(f"    soft-404 calibration: status={calibration[0]} "
              f"sig={calibration[1][:60]!r}")
    # Seed set: apps rarely expose their surface from a bare 404 on /; the
    # standard entry points cover both classic and SPA-ish layouts.
    frontier = ["/", "/index.html", "/robots.txt", "/sitemap.xml"]
    depth_map = {p: 0 for p in frontier}
    found = []  # (path, status)
    js_routes = set()

    print(f"[*] Crawling {base_url} as '{role}' (depth<={max_depth}, "
          f"max {max_paths} paths, {delay}s politeness)\n")

    while frontier and len(found) < max_paths:
        path = frontier.pop(0)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        url = base_url.rstrip("/") + path
        status, body, headers = _fetch(url, cookie)
        if status == 0:
            continue
        # Soft-404 filter: a 200 that is really the app's unknown-route page
        # is not surface — drop it before it pollutes the inventory/leads.
        # (Seeds are exempt: / is exempt-by-definition even if it 404s.)
        if (_is_soft404(status, body, calibration)
                and path not in ("/", "/index.html", "/robots.txt", "/sitemap.xml")):
            continue
        if status in status_ok:
            found.append((path, status))
            ct = (headers.get("Content-Type") or "").lower()
            if "html" in ct:
                for link in _extract_links(url, body):
                    if link not in seen_paths and depth_map.get(path, 0) < max_depth:
                        depth_map[link] = depth_map.get(path, 0) + 1
                        frontier.append(link)
                # inline scripts too
                for script in re.findall(r"<script[^>]*>(.*?)</script>", body, re.S | re.I):
                    js_routes |= _extract_js_routes(script)
            elif "javascript" in ct:
                js_routes |= _extract_js_routes(body)
                for link in _extract_links(url, body):
                    if link not in seen_paths and link.endswith(".js"):
                        pass  # JS assets: routes parsed, not queued
        time.sleep(delay)

    # Merge JS-discovered routes (fetch them for a status if budget remains)
    for route in sorted(js_routes):
        if len(found) >= max_paths:
            break
        if route in seen_paths:
            continue
        seen_paths.add(route)
        status, _, _ = _fetch(base_url.rstrip("/") + route, cookie)
        if status in status_ok:
            found.append((route, status))
        time.sleep(delay)

    # Write the role-diff inventory file
    out = Path(out_file)
    out.write_text("\n".join(p for p, _ in sorted(found)) + "\n")

    # Board: every discovered path as an endpoint lead (leads, not logs)
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    leads = []
    for p, s in found:
        leads.append({
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "endpoint",
            "value": p,
            "signal": f"crawled as {role} (status {s})",
            "confidence": 0.45,
            "suggested_next": "fuzz params / include in role-diff inventory",
            "must_verify": False,
            "preconditions": [],
            "source_pointer": pointer_id,
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    with json_transaction("board.json") as board:
        if board is not None:
            board.setdefault("leads", []).extend(leads)
            (BLACKBOARD_DIR / "artifacts").mkdir(parents=True, exist_ok=True)
            (BLACKBOARD_DIR / "artifacts" / f"{pointer_id}.log").write_text(
                "--- COMMAND ---\ncrawl.py (deterministic crawl)\n\n--- STDOUT ---\n"
                + "\n".join(f"{s} {p}" for p, s in sorted(found))
                + "\n\n--- STDERR ---\n")

    print(f"[✔] Crawled {len(seen_paths)} paths ({len(found)} in-inventory) as '{role}'.")
    print(f"    Inventory written: {out} ({len(found)} endpoints) — feed to role-diff as baseline.")
    print(f"    {len(leads)} endpoint leads on the board (pointer {pointer_id}).")
    print(f"    Next: auth_manager.py role-diff --base-url {base_url} "
          f"--roles <BASELINE_SESS>,<OTHER_SESS...> --endpoints {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deterministic endpoint crawler (role-diff inventory builder)")
    parser.add_argument("--base-url", dest="base_url", required=True)
    parser.add_argument("--session", default=None,
                        help="SESS_ id to crawl AS (baseline = highest-privilege role)")
    parser.add_argument("--max-paths", dest="max_paths", type=int, default=MAX_PATHS_DEFAULT)
    parser.add_argument("--max-depth", dest="max_depth", type=int, default=3)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help="Politeness delay between requests (seconds)")
    parser.add_argument("--out", dest="out_file", default="endpoints.txt")
    args = parser.parse_args()
    crawl(args.base_url, args.session, args.max_paths, args.max_depth, args.delay, args.out_file)
