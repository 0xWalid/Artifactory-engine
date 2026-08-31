#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - MCP-as-Backend Broker (B2)

MCP capability WITHOUT context bloat: tool schemas NEVER enter the operator's
context. The broker runs the MCP stdio JSON-RPC handshake (initialize →
tools/list → tools/call) in stdlib, stores the raw result as a MSG_* pointer
artifact, files a lead — exactly the sec_flow.run contract.

TRUST MODEL (hard):
  * A local/stdio MCP server is ARBITRARY CODE EXECUTION — same trust as a
    tool binary. No server is usable until the operator approves it.
  * Config lives OUT OF WORKSPACE at ~/.artifactory/mcp.json (workspace files
    are agent-writable; a tampered config must not silently register an
    arbitrary-command server). Entries carry declared capabilities.
  * 'Passive' is a property of the CALL, never assumed of a server: any
    net/fs-capable server's calls go through the in-scope --target check.
  * All MCP output is untrusted DATA (never instructions); egress redacted.

CLI:
  mcp_broker.py list                                  # servers+tools+purposes, NO schemas
  mcp_broker.py describe --tool T                     # arg names + types ONLY (~1 line/arg)
  mcp_broker.py call --server S --tool T --args '{...}' [--target <in-scope>]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402
from redact import redact  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
MCP_CONFIG = Path.home() / ".artifactory" / "mcp.json"

MCP_PROTOCOL_VERSION = "2024-11-05"
HANDSHAKE_TIMEOUT = 20
CALL_TIMEOUT = 120


# ---------------------------------------------------------------- config
def load_config() -> dict:
    """Engine-only config load. NEVER print entries into model context —
    list/describe emit names + one-line purposes only."""
    if not MCP_CONFIG.exists():
        return {}
    try:
        return json.loads(MCP_CONFIG.read_text())
    except Exception:
        return {}


def _server_entry(name: str):
    cfg = load_config()
    srv = (cfg.get("servers") or {}).get(name)
    if not srv:
        return None
    if not srv.get("approved"):
        return None  # unapproved servers are never usable (allowlist)
    return srv


# ---------------------------------------------------------------- handshake
class MCPStdioClient:
    """Minimal MCP stdio JSON-RPC client (stdlib only). The handshake IS this
    module's complexity: initialize → (initialized) → tools/list → tools/call."""

    def __init__(self, command: list, timeout: int = HANDSHAKE_TIMEOUT):
        self.timeout = timeout
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True)
        self._id = 0

    def _send(self, method: str, params: dict = None, timeout: int = None):
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP server closed stdout")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue  # non-JSON noise on stdout: skip
            if msg.get("id") == self._id and ("result" in msg or "error" in msg):
                if "error" in msg:
                    raise RuntimeError(f"MCP error: {msg['error']}")
                return msg["result"]
        raise TimeoutError(f"MCP {method} timed out")

    def initialize(self):
        res = self._send("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "artifactory-broker", "version": "1.0"},
        })
        self._send("notifications/initialized", None, timeout=5) if False else None
        # notification (no id): fire-and-forget per spec
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()
        return res

    def list_tools(self):
        return self._send("tools/list", {}, timeout=self.timeout) or {}

    def call_tool(self, tool: str, args: dict, timeout: int = CALL_TIMEOUT):
        return self._send("tools/call",
                          {"name": tool, "arguments": args or {}},
                          timeout=timeout)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------- gates
def _scope_ok(target: str) -> bool:
    if not target:
        return True  # local-only call (no target reach)
    import ipaddress
    import socket
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


def _gate_call(server: str, tool: str, target: str):
    """Call-level capability gate: fs/net-capable servers REQUIRE an in-scope
    --target; local-capable servers may run target-less. Never a 'passive'
    bypass."""
    entry = _server_entry(server)
    if not entry:
        print(f"[!] MCP server '{server}' is not registered/approved in "
              f"{MCP_CONFIG}. Operator approval required (stdio server = "
              f"arbitrary code execution; same trust as a tool binary).",
              file=sys.stderr)
        sys.exit(1)
    caps = set(entry.get("capabilities", []))
    if caps & {"net", "fs"}:
        if not target:
            print(f"[!] SCOPE ERROR: server '{server}' declares net/fs capability "
                  f"— every call must pass an in-scope --target (no 'passive' "
                  f"bypass; passive is a property of the call).", file=sys.stderr)
            sys.exit(1)
        if not _scope_ok(target):
            print(f"[!] SCOPE ERROR: target '{target}' not in scope.json.",
                  file=sys.stderr)
            sys.exit(1)
    return entry


# ---------------------------------------------------------------- commands
def list_servers():
    cfg = load_config()
    servers = cfg.get("servers") or {}
    if not servers:
        print(f"[*] No MCP servers configured at {MCP_CONFIG}.")
        print("    Config shape (operator-approved entries only):")
        print('    {"servers": {"name": {"transport": "stdio",')
        print('        "command": ["python3", "/path/server.py"],')
        print('        "capabilities": ["local|net|fs"], "approved": true}}}')
        return
    print(f"[*] MCP servers ({len(servers)}) — names + purposes ONLY (schemas stay behind the broker):")
    for name, e in servers.items():
        if not e.get("approved"):
            print(f"  {name}: REGISTERED BUT NOT APPROVED (unusable until the operator approves)")
            continue
        caps = ",".join(e.get("capabilities", ["local"]))
        print(f"  {name} [{caps}]")
        # tool names + 1-line purposes (live tools/list; tolerate offline)
        try:
            cl = MCPStdioClient(e["command"])
            cl.initialize()
            tools = cl.list_tools().get("tools", [])
            cl.close()
            for t in tools:
                desc = (t.get("description") or "").split("\n")[0][:70]
                print(f"    - {t.get('name', '?')}: {desc}")
            if not tools:
                print("    (no tools exposed)")
        except Exception as ex:
            print(f"    (server unreachable: {str(ex)[:60]})")


def describe_tool(tool: str):
    """Arg NAMES + TYPES only (~1 line/arg, no doc schema) — the anti-guess
    surface. Without this the model guess-and-retries --args and burns tokens."""
    cfg = load_config()
    for name, e in (cfg.get("servers") or {}).items():
        if not e.get("approved"):
            continue
        try:
            cl = MCPStdioClient(e["command"])
            cl.initialize()
            tools = cl.list_tools().get("tools", [])
            cl.close()
        except Exception:
            continue
        for t in tools:
            if t.get("name") != tool:
                continue
            schema = t.get("inputSchema") or {}
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            print(f"[*] {tool} (server: {name}) — arg names+types ONLY:")
            if not props:
                print("    (no args)")
            for arg, spec in props.items():
                typ = spec.get("type", "?")
                req = " (required)" if arg in required else ""
                print(f"    {arg}: {typ}{req}")
            return
    print(f"[!] Tool '{tool}' not found on any approved server.", file=sys.stderr)
    sys.exit(1)


def call_tool(server: str, tool: str, args_json: str, target: str = ""):
    entry = _gate_call(server, tool, target)
    try:
        args = json.loads(args_json) if args_json else {}
    except Exception:
        print("[!] --args must be a JSON object.", file=sys.stderr)
        sys.exit(1)

    try:
        cl = MCPStdioClient(entry["command"])
        cl.initialize()
        result = cl.call_tool(tool, args)
        cl.close()
    except Exception as e:
        print(f"[!] MCP call failed: {e}", file=sys.stderr)
        sys.exit(1)

    # results are untrusted DATA: redact at egress, store raw as pointer
    raw = json.dumps(result, indent=2, default=str)
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS_DIR / f"{pointer_id}.log").write_text(
        f"--- COMMAND ---\nmcp_broker call {server}.{tool} target={target or '-'}\n\n"
        f"--- STDOUT ---\n{raw}\n\n--- STDERR ---\n")

    # lead: tool output becomes a triage-able lead (text content summarized)
    texts = []
    if isinstance(result, dict):
        for c in result.get("content") or []:
            if isinstance(c, dict) and c.get("type") == "text":
                texts.append(str(c.get("text", "")))
    blob = "\n".join(texts)[:400]
    lead = {
        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
        "type": "anomaly" if result.get("isError") else "endpoint",
        "value": f"mcp: {server}.{tool}",
        "signal": redact(blob)[:150] or "tool completed",
        "confidence": 0.4,
        "suggested_next": "inspect the pointer for the full result: "
                          f"sec_flow.py inspect --id {pointer_id}",
        "must_verify": bool(result.get("isError")),
        "preconditions": [],
        "source_pointer": pointer_id,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with json_transaction("board.json", create=True) as board:
        if board is not None:
            board.setdefault("leads", []).append(lead)

    # operator sees pointer + REDACTED preview — never the schema, never raw secrets
    print(f"[+] MCP call complete: {server}.{tool}")
    print(f"    pointer: {pointer_id} | lead: {lead['id']}")
    preview = redact(raw).splitlines()
    for line in preview[:20]:
        print(f"    {line}")
    if len(preview) > 20:
        print(f"    ... ({len(preview) - 20} more lines in the artifact; "
              f"inspect --id {pointer_id})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP-as-backend broker")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="Servers + tool names + 1-line purposes (no schemas)")
    d = sub.add_parser("describe", help="Arg names + types only for one tool")
    d.add_argument("--tool", required=True)
    c = sub.add_parser("call", help="Run a tool; result -> MSG_* + lead (redacted)")
    c.add_argument("--server", required=True)
    c.add_argument("--tool", required=True)
    c.add_argument("--args", default="{}", help="JSON object of tool arguments")
    c.add_argument("--target", default="",
                   help="In-scope target (REQUIRED for net/fs-capable servers)")
    args = parser.parse_args()
    if args.cmd == "list":
        list_servers()
    elif args.cmd == "describe":
        describe_tool(args.tool)
    else:
        call_tool(args.server, args.tool, args.args, args.target)
