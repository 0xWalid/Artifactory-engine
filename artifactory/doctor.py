#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Doctor (environment self-test)

One command, run on any new machine: is the framework ready? Checks tools,
config, permissions, the engine suite (fast tier), greenhouse health, and the
coverage map — with a pass/fail verdict and fix hints. --json for CI.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)


def _engine_root() -> Path:
    """Engine root = the dir containing art.py (works whether this module sits
    at the root or inside a feature package)."""
    p = Path(__file__).resolve()
    for anc in [p.parent, *p.parents]:
        if (anc / "art.py").exists():
            return anc
    return p.parent


_ROOT = _engine_root()
if str(_ROOT / "core") not in sys.path:
    sys.path.insert(0, str(_ROOT / "core"))


def _check(name, ok, hint=""):
    return {"name": name, "ok": bool(ok), "hint": hint}


# Modules that are LIBRARIES or engines-without-CLI — exempt from the wiring
# reachability check by design (they are reached *through* entrypoints, or are
# imported by other modules rather than documented for direct invocation).
WIRING_EXEMPT = {
    "board_io.py": "shared lock library",
    "scope_sig.py": "signing library",
    "redact.py": "redaction library",
    "component_aliases.py": "alias data library",
    "vuln_lab.py": "lab engine (driven by eval-lab/lab_runner)",
    "vuln_lab2.py": "lab engine (driven by eval-lab/lab_runner)",
    "vuln_lab3.py": "hold-out lab engine (gate --final only)",
}


def wiring_check(install_sh: str = None):
    """True orphans = engine tool modules that are (a) NOT reachable from any
    emitted command/agent doc AND (b) NOT covered by a suite check AND (c) NOT
    on the curated library exemption list. Module discovery is registry-driven
    (recurses into feature packages; kernel infra art/bootstrap/registry and
    data dirs are excluded by the registry itself). Returns (ok, orphans)."""
    from registry import registry as _tool_registry

    root = _ROOT
    if install_sh is None:
        install_sh = str(root.parent / "install.sh")

    inst = Path(install_sh).read_text()
    eval_src = (Path(_tool_registry()["eval_engine"]["path"])).read_text()

    orphans = []
    for stem, meta in sorted(_tool_registry().items()):
        name = stem + ".py"
        if name in WIRING_EXEMPT:
            continue
        # reachable if the stem appears in install.sh (command/agent docs)
        # OR is exercised by the suite (stem mentioned in eval_engine.py checks)
        documented = stem in inst
        tested = stem in eval_src
        if not documented and not tested:
            orphans.append(name)
    return (not orphans), orphans


def run_doctor(with_suite=False, with_wiring=False):
    results = []

    # 1) core python + engine modules importable
    import importlib
    core = ["sec_flow", "auth_manager", "oob", "tokens", "eval_engine",
            "greenhouse", "lineage", "cross_index", "debrief", "importers",
            "board_merge", "tripwires", "skeptic_ledger", "poc_delta"]
    bad = []
    for m in core:
        try:
            importlib.import_module(m)
        except Exception as e:
            bad.append(f"{m}: {str(e)[:50]}")
    results.append(_check("engine modules import", not bad,
                          "; ".join(bad[:2]) if bad else ""))

    # 2) optional external tools
    for tool, why in [("curl", "HTTP tier"), ("semgrep", "SAST"), ("nuclei", "1-day corpus"),
                      ("docker", "ZAP fallback"), ("ffuf", "content discovery")]:
        results.append(_check(f"tool: {tool} ({why})", shutil.which(tool) is not None,
                              "optional — install for that capability" ))

    # 3) signing key + scope sanity
    key = Path.home() / ".artifactory" / "scope_signing.key"
    results.append(_check("scope signing key", key.exists(),
                          "created on first init_env.py in a workspace"))
    from board_io import load_json, blackboard_dir
    scope = load_json(blackboard_dir() / "scope.json") or {}
    results.append(_check("workspace initialized (scope.json present)", bool(scope),
                          "run init_env.py --target . in your engagement dir"))

    # 4) knowledge stores present
    stores = {
        "research library": Path(_engine_dir) / "knowledge" / "sources.json",
        "payload corpus": Path(_engine_dir) / "payloads" / "index.json",
        "interaction table": Path(_engine_dir) / "knowledge" / "interactions_local.json",
    }
    for name, path in stores.items():
        results.append(_check(f"knowledge: {name}", path.exists(),
                              "created on first use (payload_corpus.py init)" ))

    # 5) greenhouse recipes importable + count
    try:
        import greenhouse
        results.append(_check(f"greenhouse recipes ({len(greenhouse.BUG_RECIPES)} classes)",
                              len(greenhouse.BUG_RECIPES) >= 10))
    except Exception as e:
        results.append(_check("greenhouse recipes", False, str(e)[:60]))

    # 6) coverage map blind spots (informational)
    try:
        from cross_index import gaps_only
        gaps = gaps_only()
        results.append(_check(f"coverage blind spots ({len(gaps)})", True,
                              ", ".join(gaps[:3]) if gaps else "full coverage"))
    except Exception:
        pass

    # 7) engine suite (optional — the deeper check)
    if with_suite:
        rc = subprocess.run([sys.executable, f"{_engine_dir}/eval_engine.py",
                             "suite", "engine"], capture_output=True).returncode
        results.append(_check("engine suite (full machinery)", rc == 0,
                              "run eval_engine.py suite engine --verbose for detail"))

    # 8) wiring (A3): true-orphan modules fail the doctor
    if with_wiring:
        ok, orphans = wiring_check()
        results.append(_check("wiring: no orphan modules (documented or tested)",
                              ok, f"orphans: {', '.join(orphans)}" if orphans else ""))

    return results


def main():
    parser = argparse.ArgumentParser(description="Environment self-test")
    parser.add_argument("--suite", action="store_true", help="Include the full engine suite")
    parser.add_argument("--wiring", action="store_true",
                        help="Include the orphan-module wiring check (A3)")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    results = run_doctor(with_suite=args.suite, with_wiring=args.wiring)
    if args.as_json:
        print(json.dumps(results, indent=2))
        fails = sum(1 for r in results if not r["ok"])
        sys.exit(1 if fails else 0)
    fails = 0
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"  [{mark}] {r['name']}")
        if not r["ok"] and r["hint"]:
            print(f"         -> {r['hint']}")
        if not r["ok"]:
            fails += 1
    print(f"\n  {'DOCTOR: READY' if not fails else f'DOCTOR: {fails} item(s) need attention'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
