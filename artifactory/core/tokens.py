#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Token Accounting Engine

First-class token ledger: every LLM/model expenditure is logged to
.blackboard/tokens.jsonl with a role and a purpose. Supports per-role budgets
and computes the north-star metric — PROVEN VULNS PER 1M TOKENS.

The ledger is append-only JSONL (one record per spend). Agents/opencode log
spends via `log`; the operator reviews via `report` / `status`.

Why this exists: token discipline was previously enforced only by mechanics
(don't read the firehose). The plan requires it to be *measured* — you cannot
optimize what you don't count, and the eval gate needs the metric as its
north-star (eval_engine.py reads engagement totals from here).
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction, load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
BOARD_FILE = BLACKBOARD_DIR / "board.json"
TOKENS_FILE = BLACKBOARD_DIR / "tokens.jsonl"

# Roles in the two-tier cognition split. The Scout/local tier is cheap; the
# operator/frontier tier is where the budget discipline matters.
ROLES = ["operator", "scout", "exploit", "verifier", "skeptic", "recon", "synthesis", "other"]
UNITS = ["tokens", "credits", "usd"]


def ensure_tokens_file():
    BLACKBOARD_DIR.mkdir(parents=True, exist_ok=True)
    if not TOKENS_FILE.exists():
        TOKENS_FILE.touch()


def log_spend(role, purpose, amount, unit="tokens", engagement=None, note="",
              context_bytes=None, step=None):
    """Append one spend record to the append-only ledger.

    Flight-recorder fields (optional): `context_bytes` = the agent's current
    context size at this step (they can estimate from their own context
    window usage), `step` = a short step name. Filling them per-step turns the
    ledger into a text flame-chart: WHERE context grew during the engagement,
    not just how much was spent overall.
    """
    if role not in ROLES:
        role = "other"
    if unit not in UNITS:
        unit = "tokens"
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "role": role,
        "purpose": purpose,
        "amount": float(amount),
        "unit": unit,
        "engagement": engagement or "",
        "note": note,
    }
    if context_bytes is not None:
        record["context_bytes"] = int(context_bytes)
    if step:
        record["step"] = step
    ensure_tokens_file()
    with open(TOKENS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    # Budget enforcement lives in board.json `token_budget` (set via set-budget).
    budget = _check_budget(role)
    print(f"[OK] Logged {amount} {unit} [{role}] — {purpose}")
    if budget:
        print(budget)


def flamechart():
    """The flight recorder's view: per-step context sizes over the engagement.
    Shows where context grew (the expensive steps) vs where it stayed lean."""
    records = [r for r in _load_ledger() if r.get("context_bytes") is not None]
    if not records:
        print("[*] No context-size captures yet. Log steps with:")
        print("    tokens.py log --role operator --purpose 'x' --amount N \\")
        print("         --context-bytes <size> --step <name>")
        return
    print(f"[*] CONTEXT FLAME-CHART ({len(records)} step captures):\n")
    max_ctx = max(r["context_bytes"] for r in records)
    width = 40
    for r in records:
        ctx = r["context_bytes"]
        bar = "#" * max(1, int(ctx / max_ctx * width))
        step = (r.get("step") or r.get("purpose") or "?")[:28]
        print(f"  {r['timestamp'][11:19]} {step:<30} {ctx:>9,} B {bar}")
    print(f"\n  peak: {max_ctx:,} B | growth to peak: "
          f"{(max_ctx - records[0]['context_bytes']):+,} B from first capture")
    print("  (long flat-then-jump bars = a step that pulled big context — the optimization target)")


def _load_ledger() -> list:
    if not TOKENS_FILE.exists():
        return []
    records = []
    for line in TOKENS_FILE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    return records


def _check_budget(role) -> str:
    """Returns a warning notice if the role has a budget and is over 80% of it."""
    board = load_json(BOARD_FILE)
    budgets = board.get("token_budget") or {}
    if role not in budgets:
        return ""
    limit = float(budgets[role])
    spent = sum(
        r.get("amount", 0) for r in _load_ledger()
        if r.get("role") == role and r.get("unit") == "tokens"
    )
    pct = (spent / limit * 100) if limit else 0
    if pct >= 100:
        return (f"[!] BUDGET EXCEEDED [{role}]: {spent:.0f}/{limit:.0f} tokens "
                f"({pct:.0f}%). Stop non-essential calls; surface to operator.")
    if pct >= 80:
        return (f"[~] BUDGET WARNING [{role}]: {spent:.0f}/{limit:.0f} tokens "
                f"({pct:.0f}%) — remaining headroom is thin.")
    return ""


def set_budget(role, limit):
    """Persist a per-role token budget on the board (board.json token_budget)."""
    if role not in ROLES:
        print(f"[!] Unknown role '{role}'. Valid: {', '.join(ROLES)}", file=sys.stderr)
        sys.exit(1)
    with json_transaction("board.json", create=True) as board:
        if board is None:
            print("[!] Error: board.json missing. Run init_env.py first.", file=sys.stderr)
            sys.exit(1)
        board.setdefault("token_budget", {})[role] = float(limit)
    print(f"[✔] Token budget for '{role}': {float(limit):.0f} tokens")


def _proven_vulns() -> int:
    board = load_json(BOARD_FILE)
    return sum(
        1 for f in board.get("findings", [])
        if f.get("status") == "confirmed"
    )


def token_report(filter_role=None):
    """Aggregated ledger report + the north-star metric (proven vulns / 1M tokens)."""
    records = _load_ledger()
    if filter_role:
        records = [r for r in records if r.get("role") == filter_role]
    if not records:
        who = f" for role '{filter_role}'" if filter_role else ""
        print(f"[*] No token spends recorded{who}.")
        print("    Log spends with: tokens.py log --role operator --purpose 'recon phase' --amount 12000")
        return

    total_tokens = sum(r.get("amount", 0) for r in records if r.get("unit") == "tokens")
    total_usd = sum(r.get("amount", 0) for r in records if r.get("unit") == "usd")
    by_role = {}
    by_purpose = {}
    for r in records:
        key = (r.get("role"), r.get("unit"))
        by_role[key] = by_role.get(key, 0) + r.get("amount", 0)
        purpose = (r.get("purpose") or "unspecified")[:40]
        key2 = (r.get("role"), purpose, r.get("unit"))
        by_purpose[key2] = by_purpose.get(key2, 0) + r.get("amount", 0)

    print(f"[*] Token ledger: {len(records)} records "
          f"({TOKENS_FILE.relative_to(Path.cwd()) if TOKENS_FILE.is_absolute() and str(Path.cwd()) in str(TOKENS_FILE) else '.blackboard/tokens.jsonl'})\n")
    print(f"    Total: {total_tokens:.0f} tokens | {total_usd:.4f} USD-equivalent\n")

    print("    By role:")
    for (role, unit), amt in sorted(by_role.items(), key=lambda kv: -kv[1]):
        print(f"      {role:<10} {amt:>12.0f} {unit}")
    print("\n    Top purposes:")
    for (role, purpose, unit), amt in sorted(by_purpose.items(), key=lambda kv: -kv[1])[:10]:
        print(f"      [{role}] {purpose:<40} {amt:>10.0f} {unit}")

    # North-star metric: proven vulns per 1M tokens.
    if total_tokens > 0:
        vulns = _proven_vulns()
        per_m = vulns / (total_tokens / 1_000_000)
        print(f"\n    ★ NORTH-STAR: {vulns} proven vuln(s) / 1M tokens = {per_m:.2f}")
        if per_m < 1 and vulns == 0:
            print("      (no confirmed findings yet on this workspace — metric starts mattering at engagement end)")


def budget_status():
    """Budget dashboard: spent vs limit per role, with the north-star metric."""
    board = load_json(BOARD_FILE)
    budgets = board.get("token_budget") or {}
    records = _load_ledger()
    print("[*] Budget status:\n")
    if not budgets:
        print("    No budgets set. Set one with: tokens.py budget --role operator --limit 200000")
    for role, limit in budgets.items():
        spent = sum(
            r.get("amount", 0) for r in records
            if r.get("role") == role and r.get("unit") == "tokens"
        )
        pct = (spent / limit * 100) if limit else 0
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        flag = "[!]" if pct >= 100 else "[~]" if pct >= 80 else "[+]"
        print(f"    {flag} {role:<10} {bar} {spent:>10.0f}/{limit:.0f} ({pct:.0f}%)")
    total_tokens = sum(r.get("amount", 0) for r in records if r.get("unit") == "tokens")
    if total_tokens:
        vulns = _proven_vulns()
        print(f"\n    Total spent: {total_tokens:.0f} tokens | "
              f"{vulns} proven | {vulns / (total_tokens / 1_000_000):.2f} vulns/1M-tokens")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Token Accounting Engine")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    log_p = subparsers.add_parser("log", help="Append one model spend to the ledger")
    log_p.add_argument("--role", default="other", choices=ROLES,
                       help="Which tier/agent spent it (default: other)")
    log_p.add_argument("--purpose", required=True,
                       help="Short purpose tag, e.g. 'recon triage', 'chain synthesis'")
    log_p.add_argument("--amount", type=float, required=True, help="Amount spent")
    log_p.add_argument("--unit", default="tokens", choices=UNITS,
                       help="tokens (default), credits, or usd")
    log_p.add_argument("--engagement", default="", help="Engagement tag (grouping)")
    log_p.add_argument("--note", default="", help="Free-text note")
    log_p.add_argument("--context-bytes", dest="context_bytes", type=int, default=None,
                       help="Flight recorder: agent context size at this step")
    log_p.add_argument("--step", default="", help="Flight recorder: step name")

    bud_p = subparsers.add_parser("budget", help="Set a per-role token budget")
    bud_p.add_argument("--role", required=True, choices=ROLES)
    bud_p.add_argument("--limit", type=float, required=True,
                       help="Token limit for the role (workspaces are per-engagement)")

    subparsers.add_parser("report", help="Aggregated spend report + north-star metric") \
        .add_argument("--role", default=None, help="Filter to one role")

    subparsers.add_parser("status", help="Budget dashboard + north-star metric")
    subparsers.add_parser("flamechart", help="Per-step context-size view (flight recorder)")

    args = parser.parse_args()

    if args.subcommand == "log":
        log_spend(args.role, args.purpose, args.amount, args.unit, args.engagement,
                 args.note, args.context_bytes, args.step)
    elif args.subcommand == "budget":
        set_budget(args.role, args.limit)
    elif args.subcommand == "report":
        token_report(args.role)
    elif args.subcommand == "status":
        budget_status()
    elif args.subcommand == "flamechart":
        flamechart()
