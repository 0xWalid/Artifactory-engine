#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Capability-Graph Chain Planner (B1)

Multi-hop attack-path planning: search for chains of findings AND unconfirmed
primitives toward a named goal (RCE / data_exfil / auth_bypass / priv_esc),
using Dijkstra over capability edges weighted by -log(confidence) so the
returned path is the MOST-PROBABLE one, not merely the shortest.

Contract with the board (unchanged elsewhere):
  * `chain_to`  — evidence-backed hops ONLY (never written by this planner).
  * `hypo_edges` — board-level list holding planner-PROPOSED unproven hops:
    [{from, to, why, confidence, source}] where source is "deterministic" or
    "model:<name>" (provenance keeps hallucinated model edges debuggable).

CLI (wired through sec_flow.py chains):
  chains --plan --goal RCE [--top N] [--auto-link]
"""

import fnmatch
import heapq
import json
import math
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"

CONF_FLOOR = 0.05          # clamp: near-zero primitives can't explode weights
UNCONFIRMED_PENALTY = 0.35  # per-unconfirmed-node tie-break penalty

# ---------------------------------------------------------------------------
# Capability model. gives/needs are capability TYPE STRINGS; a primitive
# satisfies a need when the types fnmatch (glob: "cred:*" matches "cred:jwt").
# The keyword families extend sec_flow's PRIMITIVE_NEEDS with typed edges.
# ---------------------------------------------------------------------------
CAP_FAMILIES = [
    # (matcher over title+details, [gives], [needs])
    (["leak", "secret", "key leak", "token leak", "credential", "password leak",
      "api key", "jwt leak"],
     ["cred:*"], []),
    (["auth bypass", "bac", "access control", "privilege", "role", "unauthorized"],
     ["auth_bypass", "role_admin"], ["cred:*", "header_trust"]),
    (["idor", "object reference", "bola", "ownership"],
     ["data_reach", "object_access"], ["auth_bypass", "cred:*"]),
    (["ssrf", "server-side request", "fetch"],
     ["network_reach", "internal_access", "file_read:metadata"], ["url_param"]),
    (["xss", "script execution", "dom injection"],
     ["code_exec:browser", "victim_action"], ["origin_presence"]),
    (["traversal", "lfi", "file read", "path traversal"],
     ["file_read:*"], ["path_param"]),
    (["rce", "command injection", "code execution", "deserialization", "ssti",
      "template injection", "xxe"],
     ["code_exec"], ["param_presence", "file_read:*", "network_reach"]),
    (["file upload", "upload"],
     ["file_write"], ["upload_endpoint"]),
    (["redirect", "open redirect"],
     ["victim_redirect"], ["redirect_param"]),
    (["data reach", "data exposure", "exfiltration", "dump"],
     ["data_reach"], ["object_access", "network_reach"]),
]

# GOALS: named post-conditions -> satisfying capability types (glob).
GOALS = {
    "RCE": ["code_exec"],
    "data_exfil": ["data_reach"],
    "auth_bypass": ["auth_bypass", "cred:*"],
    "priv_esc": ["role_admin"],
}


def _capabilities_for(text: str) -> dict:
    """Derive {gives, needs} from title+details via the keyword families."""
    t = (text or "").lower()
    gives, needs = [], []
    for kws, g, n in CAP_FAMILIES:
        if any(k in t for k in kws):
            gives.extend(g)
            needs.extend(n)
    return {"gives": sorted(set(gives)), "needs": sorted(set(needs))}


class Node:
    __slots__ = ("id", "kind", "label", "caps", "confidence")

    def __init__(self, id, kind, label, gives, needs, confidence):
        self.id, self.kind, self.label = id, kind, label
        self.caps = {"gives": gives, "needs": needs}
        self.confidence = confidence


def build_graph(board: dict):
    """Nodes = confirmed findings (conf 1.0) + informational findings (conf
    0.35) + unconfirmed leads whose title/value suggests a capability (conf
    scaled by lead confidence). Returns (nodes, node_by_id)."""
    nodes, by_id = [], {}
    for f in board.get("findings", []):
        caps = _capabilities_for(f.get("title", "") + " " + (f.get("details") or ""))
        if not caps["gives"]:
            continue
        conf = 1.0 if f.get("status") == "confirmed" else 0.35
        n = Node(f.get("id"), "finding", (f.get("title") or "?")[:70],
                 caps["gives"], caps["needs"], conf)
        nodes.append(n)
        by_id[n.id] = n
    for l in board.get("leads", []):
        if l.get("status") in ("dead",):
            continue
        caps = _capabilities_for(str(l.get("value", "")) + " " + str(l.get("signal", "")))
        if not caps["gives"]:
            continue
        conf = min(float(l.get("confidence", 0.3)), 0.9) * 0.8  # unconfirmed: cap below proof
        n = Node(l.get("id"), "lead", str(l.get("value", "?"))[:70],
                 caps["gives"], caps["needs"], conf)
        nodes.append(n)
        by_id[n.id] = n
    return nodes, by_id


def _satisfies(gives: str, need: str) -> bool:
    """Glob match either direction: a primitive 'gives' satisfies a 'need' when
    their capability types overlap (fnmatch, not equality)."""
    return fnmatch.fnmatch(gives, need) or fnmatch.fnmatch(need, gives)


def _goal_nodes(nodes, goal: str):
    goals = GOALS.get(goal)
    if not goals:
        return []
    out = []
    for n in nodes:
        if any(_satisfies(g, want) for g in n.caps["gives"] for want in goals):
            out.append(n)
    return out


def plan_paths(board: dict, goal: str, top: int = 3, max_hops: int = 5):
    """Dijkstra over capability edges: edge A->B exists when some `gives` of A
    satisfies some `need` of B. Edge weight = -log(conf_edge); node weight
    = -log(conf_node) counted at entry (the cost of ACQUIRING the primitive).
    Total path cost = -log(prod conf) => most-probable path. Tie-breaks:
    (cost, unconfirmed-penalty, hops). Returns [(path, cost, prod_conf, hops)]."""
    nodes, by_id = build_graph(board)
    goal_nodes = _goal_nodes(nodes, goal)
    if not goal_nodes:
        return []

    def node_cost(n):
        return -math.log(max(n.confidence, CONF_FLOOR))

    # start: any node with no unsatisfied needs relative to known facts, or
    # simply every node (attacker can begin anywhere they have SOMETHING).
    # We search from every plausible entry and keep best paths to goal nodes.
    results = []
    for start in nodes:
        # Dijkstra from `start`
        best = {start.id: (node_cost(start), 0, 1)}  # id -> (cost, penalty, conf)
        heap = [(node_cost(start), 0, start.id, [start.id])]
        visited = set()
        found_this_start = []
        while heap:
            cost, pen, nid, path = heapq.heappop(heap)
            if nid in visited:
                continue
            visited.add(nid)
            n = by_id[nid]
            if n in goal_nodes and len(path) >= 1 and n is not start:
                found_this_start.append((path, cost, math.exp(-cost), len(path)))
                # keep exploring: a LONGER chain through more primitives may
                # still rank (composition is the point); stop at max_hops
                if len(path) >= max_hops:
                    continue
            if len(path) >= max_hops:
                continue
            for m in nodes:
                if m.id in path:
                    continue
                if not any(_satisfies(g, need)
                           for g in n.caps["gives"] for need in m.caps["needs"]):
                    continue
                # edge confidence: product of both ends' confidences
                edge_conf = max(n.confidence, CONF_FLOOR) * max(m.confidence, CONF_FLOOR)
                w = -math.log(edge_conf) + node_cost(m)
                nc = cost + w
                np_ = pen + (0 if m.kind == "finding" and m.confidence == 1.0
                             else UNCONFIRMED_PENALTY)
                if m.id not in best or (nc, np_) < (best[m.id][0], best[m.id][1]):
                    best[m.id] = (nc, np_, best[nid][2] * edge_conf)
                    heapq.heappush(heap, (nc, np_, m.id, path + [m.id]))
        results.extend(found_this_start)

    # rank + dedupe. Diversity matters: top-N must show DISTINCT routes to the
    # goal (unique terminal nodes), not N trivial variants of one endpoint.
    # Among equal-confidence paths, longer composed chains are the planner's
    # product — so ties break by MORE hops before fewer (composition first).
    seen_paths, seen_terminals = set(), set()
    ranked = []
    for path, cost, conf, hops in sorted(results,
                                         key=lambda r: (r[1], -r[3])):
        key = tuple(path)
        term = path[-1]
        if key in seen_paths or term in seen_terminals:
            continue
        seen_paths.add(key)
        seen_terminals.add(term)
        ranked.append((path, cost, conf, hops))
        if len(ranked) >= top:
            break
    return ranked


def propose_hypo_edges(board: dict, paths: list):
    """Planner output -> hypo_edges entries (board-level; NEVER chain_to).
    Consecutive path hops become hypo edges with provenance 'deterministic'."""
    nodes, by_id = build_graph(board)
    edges = []
    for path, cost, conf, hops in paths:
        for a, b in zip(path, path[1:]):
            na, nb = by_id.get(a), by_id.get(b)
            if not na or not nb:
                continue
            edges.append({
                "from": a, "to": b,
                "why": f"{na.kind} '{na.label[:40]}' satisfies a need of {nb.kind} "
                       f"'{nb.label[:40]}' (path conf {conf:.2f})",
                "confidence": round(min(na.confidence, nb.confidence), 2),
                "source": "deterministic",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
    return edges


def render(paths, edges, goal):
    if not paths:
        return "[*] no chain to goal (clean exit)"
    nodes, by_id = None, None
    lines = [f"[*] CHAIN PLAN -> {goal}: {len(paths)} ranked path(s) "
             f"(most-probable first; hypothetical hops labeled)\n"]
    for i, (path, cost, conf, hops) in enumerate(paths, 1):
        lines.append(f"  #{i} conf={conf:.2f} hops={hops} cost={cost:.2f}")
        for j, nid in enumerate(path):
            # label resolution happens at render: caller passes the board
            lines.append(f"      {'-> ' if j else '   '}{nid}")
        lines.append("")
    lines.append(f"  hypo_edges proposed: {len(edges)} (board-level; never chain_to). "
                 f"Confirm hops with evidence to promote them.")
    return "\n".join(lines)


def label_for(node_id: str, board: dict) -> str:
    """Resolve a node id to a HUMAN label: finding title or lead value.
    (Report renderers import this so lead-referencing hypo nodes never render
    as bare LEAD_xxx.)"""
    for f in board.get("findings", []):
        if f.get("id") == node_id:
            return f"F: {(f.get('title') or '?')[:60]}"
    for l in board.get("leads", []):
        if l.get("id") == node_id:
            return f"H: {str(l.get('value', '?'))[:60]}"  # H = hypothetical/unproven
    return node_id
