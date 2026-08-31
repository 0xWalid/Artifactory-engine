#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - OOB (Out-of-Band) Callback Engine

Blind-vulnerability confirmation without external infrastructure: payloads
carry unique per-probe tags; a local listener records every DNS/HTTP hit and
attributes it to the probe that generated it (payload-tag attribution).

  * `generate` — mint N tagged payload URLs/domains (oob-<tag>.<listener-host>)
  * `listen`   — start the HTTP+DNS listener (foreground or detached)
  * `status`   — poll for callbacks; each hit files a HIGH-CONFIDENCE anomaly
                lead on the board linked to the originating probe tag

Design notes:
  * HTTP listener is stdlib http.server; DNS listener is a minimal UDP responder
    that just LOGS the queried name (does not resolve — blind-SSRF/pingback
    detection only). Running a full resolver is out of scope and unnecessary.
  * If the target is internet-reachable, use interactsh instead (this engine's
    tags map cleanly: generate --format interactsh and attribute by tag).
  * The listener binds 0.0.0.0:<port> by default; scope gates do not apply to
    OUR listener (it receives, never sends). Payload URLs embed the listener's
    advertised host, which the operator supplies (must be resolvable from the
    target's network position).
"""

import argparse
import json
import re
import socket
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
OOB_STATE = BLACKBOARD_DIR / "oob_state.json"
CALLBACKS_LOG = BLACKBOARD_DIR / "oob_callbacks.jsonl"

DEFAULT_HTTP_PORT = 8888
DEFAULT_DNS_PORT = 5353  # unprivileged; run 53 as root if the network path needs it


def _mklead(ltype, value, signal, pointer_id, confidence=0.4, suggested_next="",
            must_verify=True, preconditions=None):
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


def _load_state() -> dict:
    if not OOB_STATE.exists():
        return {"listener": None, "probes": {}}
    try:
        return json.loads(OOB_STATE.read_text())
    except Exception:
        return {"listener": None, "probes": {}}


def _save_state(state: dict):
    # Lock-serialised transaction (parallel agents + listener threads share
    # this file; plain writes would race and lose probes).
    with json_transaction("oob_state.json", create=True) as cur:
        if cur is None:
            return
        cur.clear()
        cur.update(state)
        cur["updated_at"] = datetime.now(timezone.utc).isoformat()


def record_callback(kind: str, tag: str, detail: str):
    """Append a callback hit and (best-effort) file a lead on the board.
    Called from listener threads — must never crash the listener."""
    try:
        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": kind,  # http | dns
            "tag": tag,
            "detail": detail,
        }
        with open(CALLBACKS_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        state = _load_state()
        probe = state.get("probes", {}).get(tag)
        purpose = probe.get("purpose", "unknown probe") if probe else "UNREGISTERED TAG"
        lead = _mklead(
            "anomaly",
            f"OOB callback hit [{tag}] — {purpose}",
            f"{kind} callback: {detail}",
            probe.get("pointer", "OOB_LISTENER") if probe else "OOB_LISTENER",
            0.9,
            "blind interaction confirmed — build the full PoC (capture request + response) and confirm the finding",
        )
        with json_transaction("board.json") as board:
            if board is not None:
                board.setdefault("leads", []).append(lead)
        print(f"[!] OOB HIT [{kind}] tag={tag} {detail} — lead filed ({purpose})",
              file=sys.stderr)
    except Exception as e:  # listener must survive
        print(f"[!] callback-record error: {e}", file=sys.stderr)


def extract_tag_from_host(host: str) -> str:
    """oob-<tag>.anything -> <tag>; returns '' if not an OOB name."""
    host = (host or "").strip().rstrip(".")
    m = host.split(".")[0] if host else ""
    if m.startswith("oob-"):
        return m[len("oob-"):]
    return ""


# ---------------------------------------------------------------- listeners
class HTTPCallbackHandlerBase:
    def log_message(self, fmt, *args):  # silence default stderr chatter
        pass


def start_http_listener(port: int):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(HTTPCallbackHandlerBase, BaseHTTPRequestHandler):
        def _handle(self):
            host = self.headers.get("Host", "")
            # Tag lives in the Host (DNS-style probes) OR the path (HTTP
            # probe URLs are http://host:port/oob-<tag>/probe) — check both.
            tag = extract_tag_from_host(host)
            if not tag:
                m = re.search(r"/oob-([a-f0-9]{8})(?:/|$)", self.path)
                tag = m.group(1) if m else ""
            ua = self.headers.get("User-Agent", "")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            record_callback("http", tag,
                            f"{self.command} {self.path} Host={host} UA={ua} "
                            f"from={self.client_address[0]}")

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_DELETE = _handle

    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"[*] OOB HTTP listener on 0.0.0.0:{port} "
          f"(payload URLs must use a host the TARGET can resolve to this box)")
    server.serve_forever()


def start_dns_listener(port: int):
    """Minimal DNS responder: answers nothing usefully, but LOGS every query —
    which is the entire signal (blind SSRF/XXE pingback). Non-authoritative,
    never resolves recursively; only observes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[*] OOB DNS observer on 0.0.0.0:{port} (logs queries; does not resolve)")

    def _read_name(data: bytes, off: int):
        parts = []
        while True:
            if off >= len(data):
                break
            ln = data[off]
            if ln == 0:
                off += 1
                break
            parts.append(data[off + 1:off + 1 + ln].decode("latin1", "replace"))
            off += ln + 1
        return ".".join(parts), off

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            name, _ = _read_name(data, 12)
            if not name:
                continue
            tag = extract_tag_from_host(name)
            record_callback("dns", tag, f"query {name} from {addr[0]}")
            # Minimal NXDOMAIN-ish refusal (we are not a resolver)
            tid = data[0:2]
            flags = b"\x81\x83"  # response, recursion-avail, refused... keep tiny
            counts = struct.pack(">HHHH", 1, 0, 0, 0)
            # Echo the question back
            q_end = 12
            while q_end < len(data) and data[q_end] != 0:
                q_end += data[q_end] + 1
            q_end += 1 + 4
            question = data[12:q_end]
            sock.sendto(tid + flags + counts + question, addr)
        except Exception:
            continue


def cmd_listen(http_port, dns_port, dns, foreground=False):
    state = _load_state()
    state["listener"] = {
        "http_port": http_port,
        "dns_port": dns_port if dns else None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_state(state)

    threads = []
    t = threading.Thread(target=start_http_listener, args=(http_port,), daemon=True)
    threads.append(t)
    if dns:
        t2 = threading.Thread(target=start_dns_listener, args=(dns_port,), daemon=True)
        threads.append(t2)

    for t in threads:
        t.start()

    print("[*] Listener(s) running. Poll with: oob.py status")
    if foreground:
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\n[*] Listener stopped.")
    else:
        # Detached mode: park the main thread so daemon threads survive
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\n[*] Listener stopped.")


# ---------------------------------------------------------------- probes
def cmd_generate(count, host, http_port, dns, purpose, pointer, fmt):
    """Mint `count` tagged payload endpoints, register them in oob_state.json."""
    state = _load_state()
    probes = state.setdefault("probes", {})
    out = []
    for _ in range(count):
        tag = uuid.uuid4().hex[:8]
        http_url = f"http://{host}:{http_port}/oob-{tag}/probe"
        dns_name = f"oob-{tag}.{host}" if dns else ""
        probes[tag] = {
            "tag": tag,
            "purpose": purpose,
            "pointer": pointer,
            "http_url": http_url,
            "dns_name": dns_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hits": 0,
        }
        if fmt == "interactsh":
            out.append(f"{{{http_url}}}")  # placeholder format for chaining tools
        else:
            out.append(http_url if not dns else f"{http_url} | DNS: {dns_name}")
    _save_state(state)
    print(f"[✔] Generated {count} tagged probe(s) for purpose '{purpose or 'unspecified'}'")
    for o in out:
        print(f"    {o}")
    print("[*] Listener must be running (oob.py listen) on a host the target can reach.")


def cmd_status(wait, poll):
    state = _load_state()
    lst = state.get("listener")
    if not lst:
        print("[!] No listener registered in oob_state.json. Start one: oob.py listen")
    else:
        print(f"[*] Listener: http:{lst.get('http_port')}"
              f"{' dns:' + str(lst.get('dns_port')) if lst.get('dns_port') else ''} "
              f"(since {lst.get('started_at')})")

    def _summary():
        if not CALLBACKS_LOG.exists():
            return None
        total = 0
        hits = {}
        for line in CALLBACKS_LOG.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            total += 1
            hits.setdefault(rec.get("tag", "?"), []).append(rec)
        return total, hits

    deadline = time.time() + wait
    while True:
        s = _summary()
        if s:
            total, hits = s
            print(f"\n[*] Callbacks: {total} total across {len(hits)} tag(s)\n")
            for tag, recs in hits.items():
                probe = state.get("probes", {}).get(tag)
                purpose = probe.get("purpose") if probe else "UNREGISTERED"
                print(f"  oob-{tag}  ({len(recs)} hit(s))  purpose: {purpose}")
                for r in recs[:3]:
                    print(f"      [{r.get('kind')}] {r.get('detail')}")
                if len(recs) > 3:
                    print(f"      ... {len(recs) - 3} more")
        else:
            print("[*] No callbacks yet.")
        if wait <= 0 or time.time() >= deadline:
            return
        print(f"\n[*] polling every {poll}s (total wait {wait}s)...", end="\r")
        time.sleep(poll)


def cmd_cleanup():
    """Archive callbacks into the artifacts store and reset the callback log.
    Keeps probes registered (attribution history) but clears the hit counter."""
    if CALLBACKS_LOG.exists():
        art_dir = BLACKBOARD_DIR / "artifacts"
        art_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = art_dir / f"OOB_CALLBACKS_{ts}.log"
        dest.write_text(CALLBACKS_LOG.read_text())
        CALLBACKS_LOG.unlink()
        print(f"[✔] Archived callbacks to {dest.name}; log cleared. Probes kept.")
    else:
        print("[*] Nothing to clean.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OOB Callback Engine (blind vuln confirmation)")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    gen_p = subparsers.add_parser("generate", help="Mint tagged payload endpoints")
    gen_p.add_argument("--count", type=int, default=1, help="How many distinct tags (default 1)")
    gen_p.add_argument("--host", required=True,
                       help="Advertised host/IP of THIS listener as reachable from the target")
    gen_p.add_argument("--http-port", dest="http_port", type=int, default=DEFAULT_HTTP_PORT)
    gen_p.add_argument("--dns", action="store_true",
                       help="Also mint DNS probe names (requires DNS observer)")
    gen_p.add_argument("--format", default="url", choices=["url", "interactsh"])
    gen_p.add_argument("--purpose", default="",
                       help="What this probe tests (e.g. 'blind SSRF via image importer')")
    gen_p.add_argument("--pointer", default="",
                       help="Related MSG_ pointer for attribution")

    lis_p = subparsers.add_parser("listen", help="Start the HTTP+DNS callback listener")
    lis_p.add_argument("--http-port", dest="http_port", type=int, default=DEFAULT_HTTP_PORT)
    lis_p.add_argument("--dns-port", dest="dns_port", type=int, default=DEFAULT_DNS_PORT)
    lis_p.add_argument("--dns", action="store_true", help="Also run the DNS observer")
    lis_p.add_argument("--foreground", action="store_true", help="Stay attached (Ctrl-C to stop)")

    sta_p = subparsers.add_parser("status", help="Poll callbacks / show probe attribution")
    sta_p.add_argument("--wait", type=int, default=0, help="Poll for N seconds before returning")
    sta_p.add_argument("--poll", type=float, default=5.0, help="Poll interval (default 5s)")

    subparsers.add_parser("cleanup", help="Archive callbacks; reset for a fresh round")

    args = parser.parse_args()

    if args.subcommand == "generate":
        cmd_generate(args.count, args.host, args.http_port, args.dns,
                     args.purpose, args.pointer, args.format)
    elif args.subcommand == "listen":
        cmd_listen(args.http_port, args.dns_port, args.dns, args.foreground)
    elif args.subcommand == "status":
        cmd_status(args.wait, args.poll)
    elif args.subcommand == "cleanup":
        cmd_cleanup()
