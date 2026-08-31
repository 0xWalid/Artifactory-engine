#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Seeded Vuln Lab 3: HOLD-OUT

Reserved for FINAL promotion checks only. The optimization loop and A/B
comparisons run on labs 1-2; lab 3 stays unseen so a candidate can't overfit
the visible labs. DO NOT use it for iteration — eval_engine only touches it
inside `gate --final`.

Flavor: header/logic-based (again different from labs 1-2):
  V9  Header-based auth bypass     : /api/admin honors X-Role: admin blindly
  V10 Debug mode leak             : /api/debug returns env/config dump
  V11 Verbose CORS misconfig      : reflects arbitrary Origin + credentials=true
  SAFE /api/version               : negative control
"""

import argparse
import json
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

ENV_DUMP = {"DB_PASSWORD": "lab3-db-pass-DO-NOT-LEAK", "DEBUG": "true", "FLAG": "LAB3_ENV_FLAG"}
ROLE_HEADER = "X-Role"  # mutated by --seed (header-name auth bypass surface)


def mutate(seed: int):
    """Deterministic mutation for honest evals (same contract as labs 1-2):
    jitter the trusted header name and flag values; same seed = same lab."""
    import random
    rng = random.Random(seed)
    g = globals()
    headers = ["X-Role", "X-User-Role", "X-Auth-Group", "X-Internal-Role"]
    g["ROLE_HEADER"] = rng.choice(headers)
    n = rng.randrange(10000)
    ENV_DUMP["FLAG"] = f"LAB3_ENV_FLAG_{n}"
    ENV_DUMP["DB_PASSWORD"] = f"lab3-db-pass-{n}-DO-NOT-LEAK"


class Lab3Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json", headers=None):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for h, v in (headers or {}).items():
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        u = urlparse(self.path)

        if u.path == "/api/version":
            return self._send(200, {"version": "1.0.0"})

        # V9: trusts a client-supplied role header
        if u.path == "/api/admin":
            if self.headers.get(ROLE_HEADER) == "admin":
                return self._send(200, {"admin": True, "secret_admin_flag": "LAB3_ADMIN_FLAG"})
            return self._send(403, {"error": "admin only"})

        # V10: debug endpoint ships the env
        if u.path == "/api/debug":
            return self._send(200, ENV_DUMP)

        # V11: CORS reflect + credentials
        origin = self.headers.get("Origin")
        headers = {}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return self._send(200, {"ok": True}, headers=headers)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        hdrs = {"Access-Control-Allow-Origin": origin or "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Headers": f"{ROLE_HEADER}, Content-Type"}
        return self._send(204, b"", "text/plain", headers=hdrs)


def run_lab(port, seed=0):
    if seed:
        mutate(seed)
    server = HTTPServer(("127.0.0.1", port), Lab3Handler)
    print(f"[*] HOLD-OUT lab 3 (header/logic flavor) on http://127.0.0.1:{port} — "
          f"final promotion checks ONLY" + (f" [MUTATED seed={seed}]" if seed else ""))
    print(f"    V9 trusted header: {ROLE_HEADER}")
    server.serve_forever()


def selfcheck(port, seed=0):
    if seed:
        mutate(seed)
    base = f"http://127.0.0.1:{port}"

    def req(path, headers=None, method="GET"):
        r = urllib.request.Request(base + path, method=method)
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, resp.read().decode(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers or {})

    checks = []
    s, body, _ = req("/api/admin", headers={ROLE_HEADER: "admin"})
    checks.append((f"V9 {ROLE_HEADER} header auth bypass", s == 200 and "LAB3_ADMIN_FLAG" in body))
    s, body, _ = req("/api/admin")
    checks.append(("V9b no header -> 403", s == 403))
    s, body, _ = req("/api/debug")
    checks.append(("V10 debug env leak", s == 200 and ENV_DUMP["FLAG"] in body))
    s, _, hdrs = req("/api/anything", headers={"Origin": "https://evil.example"})
    checks.append(("V11 CORS reflects arbitrary Origin",
                   hdrs.get("Access-Control-Allow-Origin") == "https://evil.example"))
    s, body, _ = req("/api/version")
    checks.append(("SAFE /api/version clean", s == 200 and ENV_DUMP["FLAG"] not in body))

    ok = all(c[1] for c in checks)
    for name, passed in checks:
        print(f"  [{'✔' if passed else '!'}] {name}")
    if not ok:
        print("[!] Lab3 self-check FAILED.", file=sys.stderr)
        sys.exit(1)
    print("[✔] Lab3 self-check passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HOLD-OUT Seeded Vuln Lab 3")
    parser.add_argument("--port", type=int, default=8101)
    parser.add_argument("--selfcheck", action="store_true")
    parser.add_argument("--seed", type=int, default=0,
                        help="Deterministic mutation seed (honest evals)")
    args = parser.parse_args()
    if args.selfcheck:
        selfcheck(args.port, args.seed)
    else:
        run_lab(args.port, args.seed)
