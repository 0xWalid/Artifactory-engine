"""Shared sys.path / PYTHONPATH bootstrap for the Artifactory microkernel.

Registers the engine root and every feature-package directory so the flat
sibling imports the modules already use (`from board_io import ...`,
`import sec_flow`, `import playbook_engine as pe`) keep resolving no matter
which package a module physically lives in after the refactor.

It also propagates the same set to ``PYTHONPATH`` so any child process a tool
spawns (sec_flow's ``_bg-exec`` self-spawn, oob listeners, lab servers)
inherits the path without needing its own knowledge of the layout.

Idempotent: safe to call repeatedly.
"""
import os
import sys
from pathlib import Path

# Directories under artifactory/ that hold data/assets, not importable tools.
_SKIP = {"__pycache__", ".blackboard", "prompts", "payloads"}


def engine_root() -> Path:
    # core/bootstrap.py -> core -> artifactory
    return Path(__file__).resolve().parent.parent


def group_dirs(root: Path):
    """Immediate subpackage directories (feature groups) under the root."""
    return [d for d in sorted(root.iterdir())
            if d.is_dir() and d.name not in _SKIP]


def register_paths():
    """Put the engine root + every feature-package dir on sys.path and
    PYTHONPATH. Returns the engine root Path."""
    root = engine_root()
    dirs = [root] + group_dirs(root)
    for d in dirs:
        s = str(d)
        if s not in sys.path:
            sys.path.insert(0, s)
    # Propagate to child processes so self-spawns/listeners inherit the layout.
    existing = os.environ.get("PYTHONPATH", "")
    parts = [str(d) for d in dirs]
    if existing:
        parts.append(existing)
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)
    return root
