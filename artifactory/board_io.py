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
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:  # POSIX advisory locking (Linux/WSL/macOS). No-op fallback elsewhere.
    import fcntl
    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows without fcntl
    _HAVE_FCNTL = False

# Re-entrancy depth for THIS process. A nested json_transaction() (a transaction
# body that opens another transaction) would otherwise self-deadlock on the same
# advisory lock; we hold the OS lock once at the outermost level and treat inner
# acquisitions as no-ops, so cross-process serialisation is preserved.
_LOCK_DEPTH = 0


def blackboard_dir() -> Path:
    return Path.cwd() / ".blackboard"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _atomic_write(path: Path, text: str):
    """Write via a temp file + os.replace so a crash mid-write can never leave a
    truncated/half-written JSON file (board.json is the single source of truth)."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def _flock():
    """Hold an exclusive lock on the shared blackboard lockfile.

    Re-entrant within a single process: only the outermost acquisition takes the
    OS lock, so nested transactions don't deadlock while cross-process writers
    still serialise correctly.
    """
    global _LOCK_DEPTH
    bd = blackboard_dir()
    bd.mkdir(parents=True, exist_ok=True)

    if _LOCK_DEPTH > 0:  # already held by this process -> reentrant no-op
        _LOCK_DEPTH += 1
        try:
            yield
        finally:
            _LOCK_DEPTH -= 1
        return

    lock_path = bd / "board.lock"
    f = open(lock_path, "w")
    try:
        if _HAVE_FCNTL:
            fcntl.flock(f, fcntl.LOCK_EX)
        _LOCK_DEPTH += 1
        yield
    finally:
        _LOCK_DEPTH -= 1
        if _HAVE_FCNTL:
            fcntl.flock(f, fcntl.LOCK_UN)
        f.close()


@contextlib.contextmanager
def json_transaction(filename: str, create: bool = False):
    """Exclusive read-modify-write on a .blackboard JSON file.

    Yields the parsed dict. On clean exit the (possibly mutated) dict is stamped
    with `updated_at` and written back atomically (temp file + os.replace). If the
    body raises, nothing is written. If the file is missing and create=False,
    yields None (caller decides).

    Data-loss guard: if the file exists and is non-empty but does NOT parse as
    JSON, the transaction refuses to run (raises) rather than silently starting
    from {} and overwriting real state with an empty document.
    """
    with _flock():
        target = blackboard_dir() / filename
        if not target.exists() and not create:
            yield None
            return

        if target.exists():
            raw = target.read_text()
            if raw.strip():
                try:
                    data = json.loads(raw)
                except Exception as e:
                    raise RuntimeError(
                        f"Refusing to write {filename}: the existing file is not "
                        f"valid JSON ({e}). Fix or remove it before continuing so "
                        f"real blackboard state is not overwritten."
                    )
            else:
                data = {}
        else:
            data = {}

        yield data
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_write(target, json.dumps(data, indent=2))
