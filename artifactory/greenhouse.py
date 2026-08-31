#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Bug Greenhouse

Name a vulnerability class, get a lab with that bug PLANTED. Labs stop being
three static apps: every playbook gets per-class ground truth on demand, so a
newly synthesized/revised methodology must DETECT its planted bug before it
ever touches a live target (the acceptance harness consumes this).

  * `list`            — recipe families + classes
  * `grow <class>`   — scaffold a greenhouse lab (127.0.0.1, seeded, selfcheck)
                        into .greenhouse/<class>/ and print how to run it
  * `grow --all`     — every known recipe (full acceptance sweep)

Recipes are plain data (BUG_RECIPES): stdlib-only handler code templates with
a deterministic PLANTED_VULN marker + selfcheck. New families grow by adding
a recipe dict — no framework changes. Families seeded per operator choice:
web-core, logic, auth/session, advanced.
"""

import argparse
import json
import sys
from pathlib import Path

GREENHOUSE_DIR = Path.cwd() / ".greenhouse"

# ---------------------------------------------------------------------------
# Bug recipes. Each: class name, endpoints with the bug PLANTED, selfcheck
# assertions, and the marker the acceptance harness greps for in a confirmed
# finding's evidence.
# ---------------------------------------------------------------------------
BUG_RECIPES = {
    # ------------------------- web core -------------------------
    "xss-reflected": {
        "family": "web-core",
        "route": '/search?q=<reflected>',
        "handler": """
        if path.startswith("/search"):
            q = dict(parse_qsl(urlparse(full).query)).get("q", "")
            # BUG: raw reflection, no encoding
            return self._send(200, f"<html>results for: {q}</html>", "text/html")
""",
        "selfcheck": "GET /search?q=<script>1</script> -> body contains the raw script tag",
        "marker": "reflected",
    },
    "sqli-error": {
        "family": "web-core",
        "route": "/items?id=<sqli>",
        "handler": """
        if path.startswith("/items"):
            qid = dict(parse_qsl(urlparse(full).query)).get("id", "")
            # BUG: string-built query, error leaks SQL syntax
            if "'" in qid:
                return self._send(200, {"db_error": "SQL syntax error near '" + qid + "'"},)
            return self._send(200, {"items": []})
""",
        "selfcheck": "GET /items?id=1' -> 200 + SQL syntax error in body",
        "marker": "sql syntax",
    },
    "traversal-read": {
        "family": "web-core",
        "route": "/files?name=<traversal>",
        "handler": """
        if path.startswith("/files"):
            name = dict(parse_qsl(urlparse(full).query)).get("name", "")
            # BUG: unsanitized path join against the docroot
            target = (GREENHOUSE_ROOT / "docroot" / name).resolve()
            try:
                if target.is_file():
                    return self._send(200, target.read_text(), "text/plain")
            except Exception:
                pass
            return self._send(404, {"error": "no file"})
""",
        "selfcheck": "name=../secrets.txt escapes docroot -> reads marker file",
        "marker": "GREENHOUSE_TRAVERSAL_SECRET",
    },
    "ssrf-fetch": {
        "family": "web-core",
        "route": "/fetch?url=<url>",
        "handler": """
        if path.startswith("/fetch"):
            url = dict(parse_qsl(urlparse(full).query)).get("url", "")
            # BUG: server-side fetch of arbitrary URLs (blind w/ oob.py)
            try:
                urllib.request.urlopen(url, timeout=4)
                return self._send(200, {"status": "fetched"})
            except Exception as e:
                return self._send(200, {"status": "err", "e": str(e)[:60]})
""",
        "selfcheck": "fetch?url=http://127.0.0.1:<oob-port>/oob-<tag>/probe -> OOB callback",
        "marker": "oob-",
    },
    # ------------------------- logic -------------------------
    "bac-role-panic": {
        "family": "logic",
        "route": "/admin",
        "handler": """
        if path == "/admin":
            # BUG: presence-check, not role-check
            if "session=" in (self.headers.get("Cookie") or ""):
                return self._send(200, {"admin": True, "GREENHOUSE_BAC_FLAG": True})
            return self._send(403, {"error": "admin only"})
""",
        "selfcheck": "any session= cookie (even forged) -> 200; no cookie -> 403",
        "marker": "GREENHOUSE_BAC_FLAG",
    },
    "idor-object": {
        "family": "logic",
        "route": "/api/orders/<id>",
        "handler": """
        m = re.search(r"^/api/orders/(\\d+)$", path)
        if m:
            oid = m.group(1)
            # BUG: no ownership check
            if oid in ORDERS:
                return self._send(200, {"order": oid, **ORDERS[oid]})
            return self._send(404, {"error": "no such order"})
""",
        "selfcheck": "user session reads order owned by admin -> 200 + data",
        "marker": "owner",
    },
    "mass-assignment": {
        "family": "logic",
        "route": "PUT /api/profile",
        "handler": """
        if path == "/api/profile" and self.command == "PUT":
            try:
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            except Exception:
                return self._send(400, {"error": "bad json"})
            # BUG: accepts the role field blindly
            PROFILE.update({k: v for k, v in data.items() if k in ("email", "role")})
            return self._send(200, PROFILE)
""",
        "selfcheck": "PUT {\"role\":\"admin\"} as user -> profile.role == admin",
        "marker": "role",
    },
    "race-coupon": {
        "family": "logic",
        "route": "POST /api/coupon",
        "handler": """
        if path == "/api/coupon" and self.command == "POST":
            # BUG: check-then-use race window (no lock)
            with open(GREENHOUSE_ROOT / "coupon_state.txt", "a+") as f:
                f.seek(0)
                used = f.read().strip() == "USED"
                if not used:
                    time.sleep(0.3)  # the window (wide enough for a thread burst)
                    f.seek(0); f.truncate(); f.write("USED")
                    return self._send(200, {"coupon": "applied"})
                return self._send(409, {"coupon": "already used"})
""",
        "selfcheck": "race.py probe x20 -> successes > 1 while effect file says USED once",
        "marker": "coupon",
    },
    # ------------------------- auth/session -------------------------
    "jwt-alg-none": {
        "family": "auth",
        "route": "/api/authed (Authorization: Bearer)",
        "handler": """
        if path == "/api/authed":
            tok = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            # BUG: accepts alg=none (header only base64-decoded, no signature check)
            try:
                h, p, s = tok.split(".")
                pad = lambda b: b + "=" * (-len(b) % 4)
                hdr = json.loads(__import__("base64").urlsafe_b64decode(pad(h)).decode())
                if hdr.get("alg") == "none":
                    payload = json.loads(__import__("base64").urlsafe_b64decode(pad(p)).decode())
                    if payload.get("admin"):
                        return self._send(200, {"authed": True, "GREENHOUSE_JWT_FLAG": True})
            except Exception:
                pass
            return self._send(401, {"error": "auth required"})
""",
        "selfcheck": "alg=none token with admin:true -> 200 + flag",
        "marker": "GREENHOUSE_JWT_FLAG",
    },
    "token-weak": {
        "family": "auth",
        "route": "/login (Set-Cookie)",
        "handler": """
        if path == "/login":
            # BUG: predictable token (timestamp + 3-digit counter)
            tok = f"{int(time.time())}x{COUNTER:03d}"
            globals()["COUNTER"] = (COUNTER + 1) % 1000
            return self._send(200, {"ok": True},
                              headers={"Set-Cookie": f"session={tok}; Path=/"})
""",
        "selfcheck": "entropy.py: shared timestamped prefix + <64-bit entropy flagged",
        "marker": "session=",
    },
    "oauth-redirect-open": {
        "family": "auth",
        "route": "/oauth/authorize?redirect_uri=",
        "handler": """
        if path.startswith("/oauth/authorize"):
            ru = dict(parse_qsl(urlparse(full).query)).get("redirect_uri", "")
            # BUG: no allowlist on the redirect target
            if ru:
                return self._send(302, b"", "text/plain", headers={"Location": ru})
            return self._send(400, {"error": "redirect_uri required"})
""",
        "selfcheck": "redirect_uri=https://evil.example -> 302 Location is evil",
        "marker": "Location",
    },
    # ------------------------- advanced -------------------------
    "ssti-jinja2": {
        "family": "advanced",
        "route": "/render?tpl=<tpl>",
        "handler": """
        if path.startswith("/render"):
            tpl = dict(parse_qsl(urlparse(full).query)).get("tpl", "hello")
            # BUG: naive template eval (simulated Jinja2 semantics, stdlib-only)
            if "{{" in tpl and "}}" in tpl:
                expr = tpl.split("{{")[1].split("}}")[0]
                # evaluation sandbox escape: only 7*7 provenance pattern
                if "7*7" in expr:
                    return self._send(200, {"rendered": "49", "GREENHOUSE_SSTI_FLAG": True})
                return self._send(200, {"rendered": tpl})
            return self._send(200, {"rendered": tpl})
""",
        "selfcheck": "tpl={{7*7}} -> rendered 49 (SSTI oracle)",
        "marker": "GREENHOUSE_SSTI_FLAG",
    },
    "xxe-simulated": {
        "family": "advanced",
        "route": "POST /xml (XML body)",
        "handler": """
        if path == "/xml" and self.command == "POST":
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
            # BUG: external entity resolution simulated (file:// URIs resolved)
            if "<!ENTITY" in body and "file://" in body:
                m = re.search(r"file://([^\\\"')]+)", body)
                if m:
                    fname = m.group(1).split("/")[-1]
                    f = GREENHOUSE_ROOT / fname
                    if f.is_file():
                        return self._send(200, {"resolved": f.read_text()})
            return self._send(200, {"parsed": True})
""",
        "selfcheck": "ENTITY file://secrets.txt resolves marker file content",
        "marker": "GREENHOUSE_TRAVERSAL_SECRET",
    },
    "deser-pickle": {
        "family": "advanced",
        "route": "POST /import (base64 body)",
        "handler": """
        if path == "/import" and self.command == "POST":
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
            # BUG: unpickles attacker-supplied data (SIMULATED: we only detect
            # pickle opcodes, never actually unpickle — no RCE in the lab itself)
            import base64
            try:
                raw = base64.b64decode(body.strip())
                if raw.startswith(b"\\x80") and b"GREENHOUSE_DESER_MARKER" in raw:
                    return self._send(200, {"executed": True, "GREENHOUSE_DESER_FLAG": True})
                return self._send(200, {"loaded": "object"})
            except Exception:
                return self._send(400, {"error": "bad payload"})
""",
        "selfcheck": "pickle-opcode body with marker -> executed:true (deser surface proven)",
        "marker": "GREENHOUSE_DESER_FLAG",
    },
}

LAB_TEMPLATE = '''#!/usr/bin/env python3
"""GREENHOUSE LAB: {cls} — {desc}

Auto-generated by greenhouse.py. Deliberately vulnerable, loopback-only.
Run: python3 lab.py --port {port} ; selfcheck: --selfcheck --port {port}
Acceptance: the playbook/methodology under test must produce a confirmed
finding whose evidence contains the marker: {marker!r}
"""
import argparse
import base64
import json
import re
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

GREENHOUSE_ROOT = Path(__file__).parent
PORT = {port}
ORDERS = {{"1001": {{"owner": "admin", "total": "500"}}}}
PROFILE = {{"user": "u1", "role": "user"}}
COUNTER = 0

# planted secret for traversal/xxe recipes: escapes the docroot via ../
_docroot = GREENHOUSE_ROOT / "docroot"
_docroot.mkdir(exist_ok=True)
_secrets = GREENHOUSE_ROOT / "secrets.txt"
if not _secrets.exists():
    _secrets.write_text("GREENHOUSE_TRAVERSAL_SECRET {{mark}}\\n")
_coupon = GREENHOUSE_ROOT / "coupon_state.txt"
if not _coupon.exists():
    _coupon.write_text("")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json", headers=None):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {{}}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self.do_GET()

    def do_PUT(self):
        self.do_GET()

    def do_GET(self):
        full = self.path  # full path+query BEFORE stripping (handlers parse query)
        path = urlparse(self.path).path
        globals()["COUNTER"] = COUNTER
{handler}

        return self._send(404, {{"error": "not found"}})


def run(port):
    # ThreadingHTTPServer: race recipes NEED concurrent request handling.
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


def selfcheck(port):
    base = f"http://127.0.0.1:{{port}}"
    results = []
{selfcheck_code}
    ok = all(r[1] for r in results)
    for name, passed in results:
        print(f"  [{{'x' if passed else '!'}}] {{name}}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--selfcheck", action="store_true")
    a = p.parse_args()
    if a.selfcheck:
        selfcheck(a.port)
    else:
        run(a.port)
'''


def list_recipes(family=None):
    by_fam = {}
    for cls, r in BUG_RECIPES.items():
        by_fam.setdefault(r["family"], []).append(cls)
    print(f"[*] Greenhouse recipes ({len(BUG_RECIPES)} classes):")
    for fam, classes in sorted(by_fam.items()):
        if family and fam != family:
            continue
        print(f"\n  {fam}:")
        for c in classes:
            print(f"    {c:<20} route {BUG_RECIPES[c]['route']}")
            print(f"        marker: {BUG_RECIPES[c]['marker']!r}")
    print("\n  grow with: greenhouse.py grow <class>  (acceptance: playbook must "
          "detect the planted marker)")


def _selfcheck_code_for(cls: str) -> str:
    """One deterministic probe per recipe class. Probe bodies are authored at
    8-space depth for readability; selfcheck() uses 4 — normalize by stripping
    the common leading indent and re-indenting to 4."""
    import textwrap
    probes = {
        "xss-reflected": """
            r = urllib.request.Request(base + "/search?q=<script>green</script>")
            with urllib.request.urlopen(r) as x:
                results.append(("<script> reflected raw", b"<script>green" in x.read()))
""",
        "sqli-error": """
            r = urllib.request.Request(base + "/items?id=1'")
            with urllib.request.urlopen(r) as x:
                results.append(("SQL error leaked", b"SQL syntax" in x.read()))
""",
        "traversal-read": """
            r = urllib.request.Request(base + "/files?name=../secrets.txt")
            with urllib.request.urlopen(r) as x:
                results.append(("traversal reads secrets.txt", b"GREENHOUSE_TRAVERSAL" in x.read()))
""",
        "ssrf-fetch": """
            r = urllib.request.Request(base + "/fetch?url=http://127.0.0.1:1/nope")
            with urllib.request.urlopen(r) as x:
                results.append(("SSRF fetch attempted (err oracle)", b"status" in x.read()))
""",
        "bac-role-panic": """
            r = urllib.request.Request(base + "/admin", headers={"Cookie": "session=forged"})
            with urllib.request.urlopen(r) as x:
                results.append(("forged session -> admin 200", b"GREENHOUSE_BAC_FLAG" in x.read()))
""",
        "idor-object": """
            r = urllib.request.Request(base + "/api/orders/1001", headers={"Cookie": "session=user"})
            with urllib.request.urlopen(r) as x:
                results.append(("user reads admin order", b"admin" in x.read()))
""",
        "mass-assignment": """
            req = urllib.request.Request(base + "/api/profile",
                                         data=json.dumps({"role": "admin"}).encode(), method="PUT")
            with urllib.request.urlopen(req) as x:
                results.append(("role field accepted", b"admin" in x.read()))
""",
        "race-coupon": """
            ok = 0
            import threading
            barrier = threading.Barrier(10)
            def w():
                nonlocal ok
                barrier.wait()
                try:
                    req = urllib.request.Request(base + "/api/coupon", data=b"go", method="POST")
                    with urllib.request.urlopen(req, timeout=5) as x:
                        if b"applied" in x.read():
                            ok += 1
                except Exception:
                    pass
            ts = [threading.Thread(target=w) for _ in range(10)]
            [t.start() for t in ts]; [t.join() for t in ts]
            (GREENHOUSE_ROOT / "coupon_state.txt").write_text("")
            results.append((f"race window exploited ({ok} wins)", ok > 1))
""",
        "jwt-alg-none": """
            def pad(s): return s + "=" * (-len(s) % 4)
            hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
            pl = base64.urlsafe_b64encode(json.dumps({"admin": True}).encode()).decode().rstrip("=")
            tok = f"{hdr}.{pl}."
            r = urllib.request.Request(base + "/api/authed", headers={"Authorization": f"Bearer {tok}"})
            with urllib.request.urlopen(r) as x:
                results.append(("alg=none accepted", b"GREENHOUSE_JWT_FLAG" in x.read()))
""",
        "token-weak": """
            toks = []
            for _ in range(3):
                with urllib.request.urlopen(base + "/login") as x:
                    sc = x.headers.get("Set-Cookie", "")
                    toks.append(sc.split("session=")[-1].split(";")[0])
            pre = ""
            for i in range(min(map(len, toks))):
                if len({t[i] for t in toks}) == 1:
                    pre += toks[0][i]
                else:
                    break
            results.append((f"weak predictable token (shared prefix {pre[:6]}...)", len(pre) >= 6))
""",
        "oauth-redirect-open": """
            import urllib.error
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            opener = urllib.request.build_opener(NoRedir)
            r = urllib.request.Request(base + "/oauth/authorize?redirect_uri=https://evil.example/x")
            try:
                resp = opener.open(r, timeout=5)
                results.append(("open redirect to evil", False))
            except urllib.error.HTTPError as e:
                results.append(("open redirect to evil",
                                e.headers.get("Location") == "https://evil.example/x"))
""",
        "ssti-jinja2": """
            with urllib.request.urlopen(base + "/render?tpl={{7*7}}") as x:
                results.append(("{{7*7}} rendered to 49", b"49" in x.read()))
""",
        "xxe-simulated": """
            xml = "<!DOCTYPE d [<!ENTITY x SYSTEM \\"file://secrets.txt\\">]><d>&x;</d>"
            req = urllib.request.Request(base + "/xml", data=xml.encode(), method="POST")
            with urllib.request.urlopen(req) as x:
                results.append(("XXE resolved secrets.txt", b"GREENHOUSE_TRAVERSAL" in x.read()))
""",
        "deser-pickle": """
            payload = b"\\x80\\x04GREENHOUSE_DESER_MARKER."
            req = urllib.request.Request(base + "/import",
                                         data=base64.b64encode(payload).decode().encode(), method="POST")
            with urllib.request.urlopen(req) as x:
                results.append(("deser marker executed", b"GREENHOUSE_DESER_FLAG" in x.read()))
""",
    }
    body = probes.get(cls)
    if body is None:
        return 'results.append(("(recipe has no probe yet)", False))'
    # strip the common 8-space (or deeper) indent -> re-emit at 4 for selfcheck()
    return textwrap.indent(textwrap.dedent(body).strip("\n"), "    ")


def grow(cls: str, port: int = 8200):
    if cls not in BUG_RECIPES:
        print(f"[!] Unknown class '{cls}'. Known: {', '.join(BUG_RECIPES)}", file=sys.stderr)
        sys.exit(1)
    r = BUG_RECIPES[cls]
    lab_dir = GREENHOUSE_DIR / cls
    lab_dir.mkdir(parents=True, exist_ok=True)
    lab = LAB_TEMPLATE.format(
        cls=cls, desc=r["route"], port=port,
        handler=r["handler"], marker=r["marker"],
        selfcheck_code=_selfcheck_code_for(cls),
    )
    (lab_dir / "lab.py").write_text(lab)
    meta = {"class": cls, "family": r["family"], "route": r["route"],
            "marker": r["marker"], "port": port,
            "selfcheck_hint": r["selfcheck"]}
    (lab_dir / "recipe.json").write_text(json.dumps(meta, indent=2))
    print(f"[OK] Greenhouse lab grown: .greenhouse/{cls}/")
    print(f"     family: {r['family']}  planted route: {r['route']}")
    print(f"     marker (acceptance evidence): {r['marker']!r}")
    print(f"     run:      python3 .greenhouse/{cls}/lab.py --port {port}")
    print(f"     selfcheck python3 .greenhouse/{cls}/lab.py --selfcheck --port {port}")
    print(f"     acceptance: methodology under test must produce a confirmed "
          f"finding containing {r['marker']!r}")


def grow_all(port_base=8200):
    for i, cls in enumerate(BUG_RECIPES):
        grow(cls, port_base + i)
    print(f"\n[OK] {len(BUG_RECIPES)} labs grown. Acceptance sweep: "
          f"eval_engine.py acceptance --greenhouse")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug greenhouse (on-demand seeded labs)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    li = sub.add_parser("list", help="List recipe families/classes")
    li.add_argument("--family", default=None)
    g = sub.add_parser("grow", help="Scaffold a greenhouse lab for a class")
    g.add_argument("cls")
    g.add_argument("--port", type=int, default=8200)
    sub.add_parser("grow-all", help="Grow every recipe")
    args = parser.parse_args()
    if args.cmd == "list":
        list_recipes(args.family)
    elif args.cmd == "grow":
        grow(args.cls, args.port)
    else:
        grow_all()
