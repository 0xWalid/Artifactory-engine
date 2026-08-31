#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Model Router (B0 shared prerequisite)

Role→tier routing for every LLM call the engine itself makes: offensive roles
run on permissive/self-hosted open models, the capable (expensive) model is
reserved for planner/verifier/skeptic/operator. Provider-agnostic and
OpenAI-compatible (reuses the Scout base_url/model/key pattern).

NEVER BLOCKS: if a tier is unset, unreachable, or errors, callers fall back to
the next cheaper working tier — and if none answer, return None so the caller
continues deterministically (the engine never depends on a model to function).

Config: .blackboard/models.json (workspace) merged over a global default at
~/.artifactory/models.json. Roles are the EXISTING tokens.py ROLES verbatim
(plus `planner`, added once for the chain planner).

Usage (library):
    from model_router import route, complete
    tier = route("exploit")            # -> {"base_url", "model", "api_key_env"}
    reply = complete("exploit", messages=[...])  # None on total failure

CLI (for humans/tests):
    model_router.py show [--role exploit]
    model_router.py complete --role exploit --prompt "..."   (integration test)
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import load_json, blackboard_dir  # noqa: E402

BLACKBOARD_DIR = blackboard_dir()
LOCAL_MODELS = BLACKBOARD_DIR / "models.json"
GLOBAL_MODELS = Path.home() / ".artifactory" / "models.json"

# EXISTING tokens.py ROLES verbatim, plus `planner` (B1's chain-planner agent).
ROLES = ["operator", "scout", "exploit", "verifier", "skeptic", "recon",
         "synthesis", "planner", "other"]

# Tier assignments (the routing matrix)
ROLE_TIERS = {
    # cheap-or-free tier: high-volume background work
    "scout": "cheap", "recon": "cheap",
    # mid tier: offensive execution (permissive/self-hosted open models)
    "exploit": "mid", "synthesis": "mid",
    # capable tier: judgment, adversarial review, strategy
    "planner": "capable", "verifier": "capable", "skeptic": "capable",
    "operator": "capable",
    "other": "mid",
}
TIERS = ["capable", "mid", "cheap"]  # fallback order: cheaper = later


def _load_config() -> dict:
    cfg = {}
    if GLOBAL_MODELS.exists():
        cfg.update(load_json(GLOBAL_MODELS))
    if LOCAL_MODELS.exists():
        cfg.update(load_json(LOCAL_MODELS))
    return cfg


def _tier_entry(cfg: dict, tier: str) -> dict:
    e = cfg.get(tier) or {}
    if not isinstance(e, dict):
        return {}
    return e


def route(role: str):
    """Resolve a role to a provider entry: its assigned tier first, then
    cheaper tiers. Returns {'base_url','model','api_key'} or None."""
    tier = ROLE_TIERS.get(role, "mid")
    cfg = _load_config()
    for t in [tier] + [x for x in TIERS if x != tier]:
        e = _tier_entry(cfg, t)
        base_url = e.get("base_url")
        model = e.get("model")
        if not base_url or not model:
            continue
        key_env = e.get("api_key_env", "")
        api_key = os.environ.get(key_env, "") if key_env else ""
        return {"base_url": base_url, "model": model,
                "api_key": api_key, "tier": t,
                "fallback": t != tier}
    return None  # unset everywhere: caller continues deterministically


def complete(role: str, messages: list, timeout: int = 30,
             temperature: float = 0.2) -> str:
    """One OpenAI-compatible chat completion for the role's routed model.
    NEVER RAISES for infrastructure reasons — returns '' so callers degrade.
    Returns the content string, or '' when no provider is configured/reachable
    (callers must treat '' as 'no model answer' and proceed deterministically)."""
    prov = route(role)
    if not prov:
        return ""
    api_key = prov.get("api_key", "")
    if not api_key and not prov.get("base_url", "").startswith("http://localhost"):
        # most providers need a key; local/self-hosted may not
        return ""
    import urllib.request
    import urllib.error
    body = json.dumps({"model": prov["model"], "messages": messages,
                       "temperature": temperature}).encode()
    req = urllib.request.Request(
        f"{prov['base_url'].rstrip('/')}/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {api_key}"} if api_key else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        content = data["choices"][0]["message"]["content"].strip()
        # Output is model-generated text: the CALLER decides how to use it as
        # DATA (never executed); engine-side consumers parse JSON defensively.
        return content
    except Exception:
        return ""


def show(role: str = None):
    cfg = _load_config()
    print(f"[*] MODEL ROUTER — config: " +
          (f"local+global" if LOCAL_MODELS.exists() and GLOBAL_MODELS.exists()
           else "local" if LOCAL_MODELS.exists()
           else "global" if GLOBAL_MODELS.exists() else "NONE (deterministic-only)"))
    if role:
        prov = route(role)
        tier = ROLE_TIERS.get(role, "mid")
        if not prov:
            print(f"    {role} (tier {tier}): no provider configured — "
                  f"engine continues deterministically (never blocks)")
        else:
            fb = " [FALLBACK]" if prov.get("fallback") else ""
            print(f"    {role} -> tier {prov['tier']}{fb}: {prov['model']} @ {prov['base_url']}")
        return
    print(f"\n    {'role':<12} {'tier':<9} routed model")
    for r in ROLES:
        prov = route(r)
        mark = f"{prov['model']} @ {prov['base_url']}" + (
            " [FB]" if prov.get("fallback") else "") if prov else "(deterministic-only)"
        print(f"    {r:<12} {ROLE_TIERS.get(r, 'mid'):<9} {mark}")
    print(f"\n    Config shape ({LOCAL_MODELS}):")
    print('    {"cheap":  {"base_url": "...", "model": "...", "api_key_env": "GROQ_API_KEY"},')
    print('     "mid":    {"base_url": "...", "model": "...", "api_key_env": "..."},')
    print('     "capable":{"base_url": "...", "model": "...", "api_key_env": "..."}}')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Role→tier model router")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("show", help="The routing matrix")
    s.add_argument("--role", default=None)
    c = sub.add_parser("complete", help="Integration test: one completion via the routed model")
    c.add_argument("--role", required=True)
    c.add_argument("--prompt", required=True)
    args = parser.parse_args()
    if args.cmd == "show":
        show(args.role)
    else:
        out = complete(args.role, [{"role": "user", "content": args.prompt}])
        print(out if out else "(no model answered — engine proceeds deterministically)")
