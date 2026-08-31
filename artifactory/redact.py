#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Redaction Layer (library)

A deterministic scrubber that sits between raw evidence and anything that
leaves the engine: cookie values, bearer tokens, basic-auth pairs, API keys,
JWTs, private keys, and the workspace canary. The RAW artifact on disk is
never modified — redaction happens on the way out (inspect output, previews,
frontier-bound briefs), so evidence stays verifiable while context stays clean.

Deterministic on purpose: same input, same output, zero tokens spent.
Usage:
    from redact import redact
    safe = redact(raw_text)                      # scrub everything known
    safe = redact(raw_text, keep=["session"])    # allowlist exceptions

Can be used as a CLI one-off for pasting logs to the operator:
    python3 redact.py < artifacts/MSG_X.log
"""

import json
import re
import sys
from pathlib import Path

_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
CANARY_FILE = BLACKBOARD_DIR / "canaries.json"
SESSIONS_DIR = BLACKBOARD_DIR / "sessions"

# Ordered, deterministic patterns. Each returns (regex, replacement).
# Longest/most-specific first so e.g. a JWT isn't half-eaten by a bearer rule.
_PATTERNS = [
    # Cookie headers (whole header value)
    (re.compile(r"(?i)(cookie:\s*)[^\r\n]+"), r"\1__REDACTED_COOKIE__"),
    # Bearer / Basic auth headers
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[A-Za-z0-9\-._~+/=]+"),
     r"\1__REDACTED__"),
    # Bare bearer tokens (token=..., access_token=...)
    (re.compile(r"(?i)\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)\s*[=:]\s*)[\"']?[A-Za-z0-9\-._~+/=]{8,}[\"']?"),
     r"\1__REDACTED__"),
    # JSON-style secret pairs: "DB_PASSWORD": "value" / 'api_key': 'value'
    (re.compile(r"(?i)([\"'](?:db[_-]?(?:pass(?:word)?|pwd)|api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|pwd|credential)[_a-z0-9]*[\"']\s*:\s*)[\"'][^\"'\n]{6,}[\"']"),
     r"\1\"__REDACTED__\""),
    # JWTs (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "__REDACTED_JWT__"),
    # Private key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.|\n)*?-----END [A-Z ]*PRIVATE KEY-----",
                re.DOTALL),
     "__REDACTED_PRIVATE_KEY__"),
    # AWS-style secrets
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "__REDACTED_AWS_ID__"),
    (re.compile(r"(?i)\baws_secret_access_key\s*[=:]\s*\"?[A-Za-z0-9/+=]{20,}\"?"),
     "aws_secret_access_key=__REDACTED__"),
    # Basic auth in URLs
    (re.compile(r"(?i)https?://[A-Za-z0-9._-]+:[A-Za-z0-9._-]+@"), "__REDACTED_AUTH__@"),
]


def _canary_token() -> str:
    try:
        return json.loads(CANARY_FILE.read_text()).get("canary_token", "") if CANARY_FILE.exists() else ""
    except Exception:
        return ""


def _session_credentials() -> list:
    """Every credential stored in session artifacts — these are the most
    sensitive values in the workspace; they must never appear in context."""
    creds = []
    if not SESSIONS_DIR.exists():
        return creds
    for p in SESSIONS_DIR.glob("SESS_*.json"):
        try:
            data = json.loads(p.read_text())
            cred = data.get("credential", "")
            if cred and len(cred) > 4:
                creds.append(cred)
        except Exception:
            continue
    return creds


def redact(text: str, keep: list = None) -> str:
    """Scrub known secret shapes + workspace-specific secrets (canary, session
    credentials) from text. `keep` = substrings to leave alone (e.g. a marker
    you're grepping for that happens to look like a token)."""
    if not text:
        return text
    keep = keep or []
    out = text
    for cred in _session_credentials():
        if cred in out and not any(k in cred for k in keep):
            out = out.replace(cred, "__REDACTED_SESSION__")
    canary = _canary_token()
    if canary and canary in out and not any(k in canary for k in keep):
        out = out.replace(canary, "__REDACTED_CANARY__")
    for regex, repl in _PATTERNS:
        out = regex.sub(repl, out)
    return out


if __name__ == "__main__":
    raw = sys.stdin.read()
    print(redact(raw))
