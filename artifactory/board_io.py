#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Shared Blackboard I/O + Locking

Every mutation of a .blackboard JSON file (board.json, scope.json) must go
through a transaction here. A single OS advisory lock (.blackboard/board.lock)
serialises ALL blackboard writes across processes, so parallel agents
(recon + exploit + verifier) and the background triage child cannot corrupt
state with interleaved read-modify-write races.
"""

import contextlib
import json
from datetime import datetime, timezone
from pathlib import Path

try:  # POSIX advisory locking (Linux/WSL/macOS). No-op fallback elsewhere.
    import fcntl
    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows without fcntl
    _HAVE_FCNTL = False


def blackboard_dir() -> Path:
    return Path.cwd() / ".blackboard"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


@contextlib.contextmanager
def _flock():
    """Hold an exclusive lock on the shared blackboard lockfile."""
    bd = blackboard_dir()
    bd.mkdir(parents=True, exist_ok=True)
    lock_path = bd / "board.lock"
    f = open(lock_path, "w")
    try:
        if _HAVE_FCNTL:
            fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        if _HAVE_FCNTL:
            fcntl.flock(f, fcntl.LOCK_UN)
        f.close()


@contextlib.contextmanager
def json_transaction(filename: str, create: bool = False):
    """Exclusive read-modify-write on a .blackboard JSON file.

    Yields the parsed dict. On clean exit the (possibly mutated) dict is stamped
    with `updated_at` and written back atomically. If the body raises, nothing is
    written. If the file is missing and create=False, yields None (caller decides).
    """
    with _flock():
        target = blackboard_dir() / filename
        if not target.exists() and not create:
            yield None
            return
        data = load_json(target)
        yield data
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        target.write_text(json.dumps(data, indent=2))
