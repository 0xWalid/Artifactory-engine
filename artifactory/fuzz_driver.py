#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Fuzz Driver

The P5 fuzz engine, made real with zero dependencies: the LLM authors a tiny
harness (or the driver scaffolds one), the MACHINE fires it millions of times.

Two modes, both stdlib-only:

  * grammar  — deterministic mutation fuzzing of a REQUEST TEMPLATE: takes a
               seed request (file), mutates it with a classic operator set
               (bit flips, boundary values, truncation, case flips, duplica-
               tion, format-string markers) and replays each variant against
               an in-scope target. Any 5xx/timeout/hang response delta becomes
               an anomaly lead. This is radamsa-lite for HTTP surfaces.
  * scaffold — generates a compilable libFuzzer-style C harness skeleton for
               a target function, into the workspace; the operator (or the
               exploit agent) fills the body, the driver runs the campaign
               detached via sec_flow (rate-limit aware, scope-gated).

Design contract: the driver NEVER interprets target responses as instructions;
it only measures status/latency deltas and files leads.
"""

import argparse
import random
import shlex
import sys
import time
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
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"

MUT_BOUNDARY_VALUES = [
    b"", b"\x00", b"\xff" * 8, b"A" * 1000, b"-1", b"0", b"2147483647",
    b"2147483648", b"-2147483649", b"NaN", b"undefined", b"%s%s%s%n",
    b"{{7*7}}", b"${7*7}", b"<%= 7*7 %>", b"../../../etc/passwd",
]


def _scope_ok(target: str) -> bool:
    import json as _json
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


def mutate_bytes(seed: bytes, rng: random.Random) -> bytes:
    """One classic mutation operator applied to the seed."""
    op = rng.randrange(6)
    if not seed:
        return rng.choice(MUT_BOUNDARY_VALUES)
    if op == 0:  # bit flip at a random position
        i = rng.randrange(len(seed))
        return seed[:i] + bytes([seed[i] ^ (1 << rng.randrange(8))]) + seed[i + 1:]
    if op == 1:  # boundary value splice
        i = rng.randrange(len(seed) + 1)
        return seed[:i] + rng.choice(MUT_BOUNDARY_VALUES) + seed[i:]
    if op == 2:  # truncate
        return seed[:rng.randrange(1, len(seed))]
    if op == 3:  # duplicate a chunk
        i = rng.randrange(len(seed))
        j = min(len(seed), i + rng.randrange(1, 32))
        return seed[:j] + seed[i:j] + seed[j:]
    if op == 4:  # case flip on a letter
        s = list(seed.decode("latin1", "replace"))
        letters = [k for k, c in enumerate(s) if c.isalpha()]
        if letters:
            i = rng.choice(letters)
            s[i] = s[i].swapcase()
        return "".join(s).encode("latin1", "replace")
    # op == 5: swap two bytes
    if len(seed) >= 2:
        i, j = sorted(rng.sample(range(len(seed)), 2))
        b = bytearray(seed)
        b[i], b[j] = b[j], b[i]
        return bytes(b)
    return seed


def grammar_fuzz(target_url, seed_file, iterations=100, delay=0.05, timeout=8,
                 timing=False):
    if verify_scope().startswith("TAMPERED"):
        print(tamper_notice(), file=sys.stderr)
        sys.exit(1)
    if not _scope_ok(target_url):
        print(f"[!] SCOPE ERROR: '{target_url}' not in scope.json.", file=sys.stderr)
        sys.exit(1)
    seed = Path(seed_file).read_bytes()
    rng = random.Random()
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"

    mode = "timing-distribution" if timing else "status/anomaly"
    print(f"[*] Grammar fuzz ({mode}): {iterations} mutations of {len(seed)}-byte "
          f"seed -> {target_url}")

    def send(body: bytes):
        req = urllib.request.Request(target_url, data=body, method="POST",
                                     headers={"Content-Type": "application/octet-stream",
                                              "User-Agent": "artifactory-fuzz/1.0"})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, time.time() - t0
        except urllib.error.HTTPError as e:
            return e.code, time.time() - t0
        except Exception:
            return 0, time.time() - t0

    base_status, base_time = send(seed)
    print(f"    baseline: status={base_status} {base_time:.2f}s")

    findings = []
    log_lines = [f"baseline status={base_status} time={base_time:.2f}s"]
    latencies = []  # timing mode: distribution of mutant latencies

    for n in range(iterations):
        mutant = mutate_bytes(seed, rng)
        status, elapsed = send(mutant)
        if timing:
            latencies.append((elapsed, n))
            log_lines.append(f"#{n} status={status} time={elapsed:.3f}s")
            continue
        interesting = (status == 0 and elapsed >= timeout * 0.8) or \
                      (500 <= status <= 599 and status != base_status) or \
                      (status not in (base_status, 400, 401, 403, 404, 422) and status >= 500)
        log_lines.append(f"#{n} status={status} time={elapsed:.2f}s "
                         f"{'<<ANOMALY' if interesting else ''}")
        if interesting:
            findings.append((n, status, elapsed, mutant[:60]))
        time.sleep(delay)

    # timing-mode analysis: outliers vs the latency distribution
    if timing and latencies:
        times = sorted(t for t, _ in latencies)
        med = times[len(times) // 2]
        p95 = times[int(len(times) * 0.95)] if len(times) >= 20 else times[-1]
        outliers = [(t, n) for t, n in latencies if t > max(p95 * 2, med * 5, med + 2.0)]
        log_lines.append(f"timing stats: median={med:.3f}s p95={p95:.3f}s "
                         f"outliers={len(outliers)}")
        for t, n in outliers[:10]:
            findings.append((n, "TIMING", t, b"latency outlier"))
            log_lines.append(f"#{n} <<TIMING-OUTLIER {t:.3f}s (median {med:.3f}s)")

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
        f"--- COMMAND ---\nfuzz_driver grammar {target_url} x{iterations}\n\n"
        f"--- STDOUT ---\n" + "\n".join(log_lines) + "\n\n--- STDERR ---\n")

    if findings:
        leads = [{
            "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
            "type": "anomaly",
            "value": (f"timing oracle: {elapsed:.1f}s on mutation #{n}"
                      if status == "TIMING" else
                      f"fuzz anomaly: {status} in {elapsed:.1f}s on mutation #{n}"),
            "signal": (f"mutant latency {elapsed:.3f}s vs median "
                       f"(time-based blind candidate)"
                       if status == "TIMING" else
                       f"mutated request caused {status} (baseline {base_status}) — "
                       f"sample: {sample!r}"),
            "confidence": 0.6 if status == "TIMING" else 0.7,
            "suggested_next": "reproduce manually with the artifact; minimize the mutation",
            "must_verify": True, "preconditions": [],
            "source_pointer": pointer_id, "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat(),
        } for n, status, elapsed, sample in findings[:10]]
        with json_transaction("board.json") as board:
            if board is not None:
                board.setdefault("leads", []).extend(leads)
        print(f"[OK] {len(findings)} anomaly(ies) filed as leads (pointer {pointer_id}); "
              f"full log in the artifact.")
    else:
        print(f"[*] No anomalies in {iterations} iterations (survived cleanly). "
              f"Log: {pointer_id}")


SCAFFOLD = '''// libFuzzer-style harness scaffold (generated by artifactory fuzz_driver)
// Fill TARGET_BODY with the call that feeds data to the function under test.
// Build: clang -fsanitize=fuzzer,address,undefined harness.c <your_libs> -o fuzz_target
// Run:   ./fuzz_target -max_total_time=86400 -artifact_prefix=crashes/

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// TODO(operator/agent): declare/extern the function under test, e.g.
// int parse_request(const uint8_t *buf, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // TARGET_BODY: feed `data`/`size` to the parser/decoder under test.
    // Keep allocations bounded; return 0 always (crashes ARE the signal).
    (void)data; (void)size;
    return 0;
}
'''


def scaffold(out_file: str = "fuzz_harness.c"):
    Path(out_file).write_text(SCAFFOLD)
    print(f"[✔] Harness scaffold written: {out_file}")
    print("    1) Fill TARGET_BODY with the function-under-test call")
    print("    2) clang -fsanitize=fuzzer,address,undefined harness.c ... -o fuzz_target")
    print("    3) Run the campaign detached: sec_flow.py run --bg --cmd "
          "'./fuzz_target -max_total_time=86400 -artifact_prefix=crashes/' --target <host>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzz driver (grammar mode + harness scaffold)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grammar", help="Mutate-and-replay a request seed against a target")
    g.add_argument("--target", required=True, help="In-scope target URL (POSTed to)")
    g.add_argument("--seed", dest="seed_file", required=True, help="File with the seed request body")
    g.add_argument("--iterations", type=int, default=100)
    g.add_argument("--delay", type=float, default=0.05)
    g.add_argument("--timeout", type=float, default=8)
    g.add_argument("--timing", action="store_true",
                   help="Timing-distribution mode: latency outliers vs median/p95 "
                        "(catches time-based blinds the status check misses)")
    s = sub.add_parser("scaffold", help="Generate a libFuzzer C harness skeleton")
    s.add_argument("--out", dest="out_file", default="fuzz_harness.c")
    args = parser.parse_args()
    if args.cmd == "grammar":
        grammar_fuzz(args.target, args.seed_file, args.iterations, args.delay,
                     args.timeout, timing=args.timing)
    else:
        scaffold(args.out_file)
