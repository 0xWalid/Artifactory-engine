#!/usr/bin/env python3
"""Artifactory microkernel dispatcher (the "plugin loader").

    python3 art.py <tool> [args...]

Boots sys.path / PYTHONPATH so every flat sibling import resolves regardless
of which feature package a module lives in, then runs the requested tool
EXACTLY as a script (its ``if __name__ == "__main__":`` block fires unchanged,
argv is what the tool expects). Physical paths never appear in callers.
"""
import runpy
import sys
from pathlib import Path

# Make the kernel importable, then let it register every package dir.
sys.path.insert(0, str(Path(__file__).resolve().parent / "core"))
from bootstrap import register_paths            # noqa: E402
from registry import all_tools, path_for, registry  # noqa: E402


def _usage(stream=sys.stdout):
    stream.write("usage: art <tool> [args...]\n\ntools:\n")
    reg = registry()
    for stem in all_tools():
        stream.write(f"  {stem:26} {reg[stem]['group']}\n")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        _usage()
        return 0
    tool = argv[0]
    try:
        path = path_for(tool)
    except KeyError:
        sys.stderr.write(f"art: unknown tool '{tool}'\n\n")
        _usage(sys.stderr)
        return 2
    register_paths()
    # Present argv to the tool as though it were invoked directly.
    sys.argv = [path] + list(argv[1:])
    runpy.run_path(path, run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
