"""Single source of truth: tool stem -> {path, group}.

Every place that used to hardcode ``f"{engine_dir}/X.py"`` resolves through
``path_for("X")`` instead, so a module's physical location lives in exactly
ONE place. Also backs ``doctor --wiring`` orphan detection and the ``catalog``
listing.

Tool stems are globally unique (the modules were flat before the refactor),
so the map is unambiguous whether a module sits at the root or inside a
feature package.
"""
from pathlib import Path

from bootstrap import engine_root  # sibling in core/

# Data/asset dirs with no dispatchable tools.
_SKIP_DIRS = {"__pycache__", ".blackboard", "prompts", "payloads"}
# Infrastructure stems that are not runnable tools.
_NON_TOOL = {"__init__", "bootstrap", "registry", "art"}

_cache = None


def _scan():
    root = engine_root()
    reg = {}
    for py in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in py.parts):
            continue
        stem = py.stem
        if stem in _NON_TOOL:
            continue
        group = py.parent.name if py.parent != root else "(root)"
        # First occurrence wins; stems are unique across the tree.
        reg.setdefault(stem, {"path": str(py), "group": group})
    return reg


def registry():
    global _cache
    if _cache is None:
        _cache = _scan()
    return _cache


def path_for(stem: str) -> str:
    entry = registry().get(stem)
    if not entry:
        raise KeyError(f"unknown tool: {stem}")
    return entry["path"]


def all_tools():
    return sorted(registry().keys())
