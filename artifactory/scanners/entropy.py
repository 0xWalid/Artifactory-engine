#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Session Token Entropy Analyzer

WSTG Session-Management, mechanically: sample a login/refresh endpoint N
times, collect the session tokens it issues, and run the standard checks a
researcher does by hand:

  * length stability       (fixed-length custom tokens vs opaque)
  * charset                (hex? base64? raw base64url = maybe decoded JWT)
  * unique count           (duplicates across samples = token reuse bug)
  * Shannon entropy/char   (rough randomness quality)
  * shared prefixes/suffixes (timestamped or MAC-truncated tokens leak structure)
  * JWT detection + header decode (alg confusion surface)

Zero model tokens. Feed it a curl command that hits YOUR session endpoint
(scope-gated like every target interaction); it extracts tokens from the
response via a regex (default: Set-Cookie values / JSON token fields).
"""

import argparse
import base64
import json
import math
import re
import shlex
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, blackboard_dir  # noqa: E402
from sec_flow import preflight_checks, ensure_blackboard_dirs, load_canary_token, ARTIFACTS_DIR  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"


def _shannon(bits_per_char: float, length: int) -> float:
    return bits_per_char * length


def analyze_tokens(tokens: list) -> dict:
    """Run the deterministic checks over collected tokens."""
    if not tokens:
        return {}
    lengths = {len(t) for t in tokens}
    uniq = set(tokens)
    charset = set("".join(tokens))

    def chars_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) for c in set(s)}
        total = len(s)
        return -sum((n / total) * math.log2(n / total) for n in freq.values())

    avg_bits = chars_entropy("".join(tokens))
    results = {
        "samples": len(tokens),
        "unique": len(uniq),
        "duplicates": len(tokens) - len(uniq),
        "lengths": sorted(lengths),
        "fixed_length": len(lengths) == 1,
        "charset_size": len(charset),
        "bits_per_char": round(avg_bits, 2),
        "est_entropy_bits": round(_shannon(avg_bits, max(lengths)), 1),
        "findings": [],
    }

    f = results["findings"]
    if results["duplicates"] > 0:
        f.append(("duplicate tokens issued across samples — session fixation/reuse bug class",
                  "high"))
    if not results["fixed_length"]:
        f.append(("variable-length tokens (custom scheme — inspect structure)", "info"))
    if results["est_entropy_bits"] < 64 and results["fixed_length"]:
        f.append((f"~{results['est_entropy_bits']} bits entropy — below the 64-bit "
                  f"brute-force-resistance bar", "medium"))

    # JWT detection
    jwt_like = [t for t in tokens if t.count(".") == 2 and t.split(".")[0].startswith("eyJ")]
    if jwt_like:
        try:
            hdr = json.loads(base64.urlsafe_b64decode(
                jwt_like[0].split(".")[0] + "==").decode())
            alg = hdr.get("alg")
            f.append((f"JWT with alg={alg} — test alg-none/key-confusion per JWT playbook",
                      "medium" if alg in ("none", "HS256") else "info"))
        except Exception:
            f.append(("JWT-shaped token, header not parseable", "info"))

    # shared prefix/suffix (structure leak)
    if len(tokens) >= 3 and results["fixed_length"]:
        pre = ""
        for i in range(len(tokens[0])):
            c = {t[i] for t in tokens}
            if len(c) == 1:
                pre += c.pop()
            else:
                break
        if len(pre) >= 4:
            f.append((f"shared {len(pre)}-char prefix '{pre}' — structure/epoch leak, "
                      f"check if prefix is a timestamp", "medium"))
    return results


def collect_tokens(cmd: str, target: str, samples: int, pattern: str) -> list:
    """Run the (scope-gated) command `samples` times, extract tokens via regex."""
    ensure_blackboard_dirs()
    canary = preflight_checks(cmd, target)  # exits on any violation

    rx = re.compile(pattern)
    tokens = []
    logs = []
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    for i in range(samples):
        try:
            r = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=60)
            blob = r.stdout + "\n" + r.stderr
            logs.append(f"--- sample {i} ---\n{blob[:2000]}")
            for m in rx.finditer(blob):
                tok = m.group(1) if m.groups() else m.group(0)
                if len(tok) >= 8:
                    tokens.append(tok.strip())
        except Exception as e:
            logs.append(f"--- sample {i} ERROR: {e}")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
        f"--- COMMAND ---\n{cmd} x{samples}\n\n--- STDOUT ---\n"
        + "\n".join(logs) + "\n\n--- STDERR ---\n")

    if canary and canary in "\n".join(logs):
        print("[!] CANARY TRIPWIRE: protected data surfaced — halting.", file=sys.stderr)
        sys.exit(1)
    return tokens


DEFAULT_PATTERN = r"(?:session|token|auth)[\"'=:\s]+([A-Za-z0-9_\-\.=+/]{12,})"


def run_entropy(cmd: str, target: str, samples: int = 5, pattern: str = DEFAULT_PATTERN):
    tokens = collect_tokens(cmd, target, samples, pattern)
    if not tokens:
        print("[*] No tokens extracted — adjust --pattern "
              f"(default: {DEFAULT_PATTERN!r}).")
        return
    res = analyze_tokens(tokens)
    print(f"\n[*] SESSION TOKEN ANALYSIS ({res['samples']} samples):\n")
    print(f"    unique: {res['unique']}  duplicates: {res['duplicates']}")
    print(f"    lengths: {res['lengths']}  charset: {res['charset_size']} chars")
    print(f"    entropy: ~{res['est_entropy_bits']} bits (bar: 64)")
    if res["findings"]:
        leads = []
        pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
        for text, sev in res["findings"]:
            print(f"    [!] [{sev}] {text}")
            leads.append({
                "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
                "type": "anomaly",
                "value": f"session token: {text[:80]}",
                "signal": f"entropy analysis ({sev})",
                "confidence": 0.6 if sev != "info" else 0.3,
                "suggested_next": "verify manually per WSTG session management; "
                                  "attempt prediction/replay if structure leaked",
                "must_verify": True, "preconditions": [],
                "source_pointer": pointer_id, "status": "new",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
        with json_transaction("board.json") as board:
            if board is not None:
                board.setdefault("leads", []).extend(leads)
        print(f"\n[✔] {len(leads)} lead(s) filed.")
    else:
        print("    [+] No weaknesses flagged.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Session token entropy analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("entropy", help="Sample a session endpoint + analyze issued tokens")
    e.add_argument("--cmd", required=True,
                   help="Command that hits the login/refresh endpoint (scope-gated)")
    e.add_argument("--target", required=True)
    e.add_argument("--samples", type=int, default=5)
    e.add_argument("--pattern", default=DEFAULT_PATTERN,
                   help="Regex over the response to capture the token (group 1 = token)")
    args = parser.parse_args()
    run_entropy(args.cmd, args.target, args.samples, args.pattern)
