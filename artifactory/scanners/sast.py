#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - White-box SAST Bridge (semgrep)

Philosophy: a deterministic scanner is CONSISTENT, an LLM is NOT. So semgrep
produces candidates (the "logic finds"), each becomes a `sast` lead flagged
must_verify, and the AI verifier's job is to DISPROVE false positives with
guided questions, then PROVE the survivors with a runtime PoC before the
existing verification gate promotes them to `confirmed`.

Scanning local source is not a network action, so it has its OWN fail-closed
gate: `scope.json -> allowed_code_paths`. The host/CIDR gate is untouched.
"""

import json
import shutil
import sys
import uuid
from pathlib import Path

# Shared engine imports (execute_and_log / artifact plumbing, triage).
_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
import sec_flow  # noqa: E402
import triage  # noqa: E402

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"

# Rule pack: a pinned registry pack downloads RULES only (no source upload).
# Deliberately NOT `auto`, which phones semgrep.dev with project metadata.
DEFAULT_CONFIG = "p/default"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def is_code_path_in_scope(path: str, scope: dict) -> bool:
    """Fail-closed: an empty/missing allowed_code_paths grants nothing. True only
    when `path` is equal to, or nested under, an authorised code path."""
    if not scope:
        return False
    allowed = scope.get("allowed_code_paths", [])
    if not allowed:
        return False
    try:
        target = Path(path).resolve()
    except Exception:
        return False
    for entry in allowed:
        try:
            base = Path(entry).resolve()
        except Exception:
            continue
        if target == base or target.is_relative_to(base):
            return True
    return False


def extract_context(file: str, line: int, context_lines: int = 6) -> str:
    """Best-effort enclosing context for a scanner hit.

    First cut: the flagged line plus a window, and (for brace/indent languages)
    a heuristic reach back to the enclosing block opener. This is intentionally
    modest — the talk shows fixed windows and regex cannot truly parse C/C++ —
    so the verifier can always pull the full file via `sec_flow.py inspect`.
    Full tree-sitter function extraction is a documented follow-up.
    """
    try:
        src = Path(file).read_text(errors="replace").splitlines()
    except Exception as e:
        return f"[context unavailable: {e}]"
    if not src:
        return "[context unavailable: empty file]"

    idx = max(0, min(line - 1, len(src) - 1))
    start = max(0, idx - context_lines)

    # Heuristic: walk upward to a plausible block/function opener so the snippet
    # starts at meaningful scope rather than mid-statement.
    for j in range(idx, max(-1, idx - 60), -1):
        s = src[j].rstrip()
        if s.endswith("{") or s.endswith(":") or (
            s and not s[0].isspace() and s.endswith(")")
        ):
            start = j
            break

    end = min(len(src), idx + context_lines + 1)
    out = []
    for n in range(start, end):
        marker = ">>" if n == idx else "  "
        out.append(f"{marker} {n + 1:>5}│ {src[n]}")
    return "\n".join(out)


def run_sast(path: str, config: str = DEFAULT_CONFIG, background: bool = False):
    """Code-path preflight -> run semgrep (SARIF) -> store artifact -> triage to leads."""
    sec_flow.ensure_blackboard_dirs()

    scope = load_json(SCOPE_FILE)
    if not scope:
        print(
            "[!] SCOPE ERROR: .blackboard/scope.json is missing or empty. "
            "Run 'python3 ~/artifactory/init_env.py --target .' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not is_code_path_in_scope(path, scope):
        print(
            f"[!] CODE-SCOPE ERROR: '{path}' is not under any authorised entry in "
            f"scope.json -> allowed_code_paths. Authorise it explicitly (edit "
            f"scope.json) before scanning source. Fail-closed by design.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not shutil.which("semgrep"):
        print(
            "[!] semgrep not found on PATH. Install it, e.g.:\n"
            "      pipx install semgrep   # or: pip install semgrep\n"
            "    then re-run this scan.",
            file=sys.stderr,
        )
        sys.exit(1)

    if background:
        print("[*] --background is not yet supported for SAST; running synchronously.",
              file=sys.stderr)

    # SARIF to stdout, quiet, no auto (no code/metadata egress).
    cmd = f"semgrep --sarif -q --config {config} {path}"
    pointer_id = f"MSG_{uuid.uuid4().hex[:8].upper()}"

    # Reuse the network engine's runner purely for artifact/board/history plumbing.
    # canary="" -> the canary post-check is a no-op for a local source scan.
    sec_flow.execute_and_log(cmd, pointer_id, canary="")
    triage.triage_sast(pointer_id)
    print(f"[✔] SAST scan logged as {pointer_id}. "
          f"Review leads: sec_flow.py leads --type sast")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SBA White-box SAST Bridge (semgrep)")
    parser.add_argument("--path", "-p", required=True, help="Source directory/file to scan")
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG,
                        help=f"semgrep ruleset (default: {DEFAULT_CONFIG}; no 'auto')")
    parser.add_argument("--background", "--bg", action="store_true", dest="background",
                        help="(reserved) run detached; currently runs synchronously")
    args = parser.parse_args()
    run_sast(args.path, args.config, args.background)
