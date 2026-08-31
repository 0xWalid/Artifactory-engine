#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Scope Signature Module (library)

HMAC-signs .blackboard/scope.json so silent tampering is detectable: the
engagement's hard boundary gets tamper evidence, and a run refuses to proceed
on a scope file whose signature doesn't verify (fail-closed).

Threat model: an attacker (or a prompt-injected agent) who gains file write
tries to widen allowed_hosts/allowed_cidrs mid-engagement. With signing, the
tampered file fails verification and every gate that checks scope stops.

Key handling:
  * The key lives OUTSIDE the workspace at ~/.artifactory/scope_signing.key
    (0600) — a workspace-local key would be forgeable by the same write access
    that tampers with scope.json.
  * init_env.py creates the key on first workspace init; verify() tolerates a
    missing key for LEGACY unsigned scopes but marks them 'unsigned' so gates
    can require an operator decision (eval suite covers both paths).

Usage from other engine modules:
    from scope_sig import sign_scope, verify_scope, tamper_notice
    verify_scope() -> "ok" | "unsigned" | "TAMPERED:<reason>"
"""

import hashlib
import hmac
import json
import os
from pathlib import Path

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
SCOPE_FILE = BLACKBOARD_DIR / "scope.json"
SIGNATURE_FILE = BLACKBOARD_DIR / "scope.sig"
KEY_PATH = Path.home() / ".artifactory" / "scope_signing.key"

# The scope fields covered by the signature: everything that AUTHORIZES.
# pending_scope is advisory (not authorization), updated_at is metadata —
# neither is signed, so scope --approve / subdomain queuing re-signs cheaply.
_SIGNED_FIELDS = (
    "allowed_hosts", "allowed_domains", "allowed_cidrs",
    "allowed_code_paths", "disallowed_actions",
)


def _load_key() -> bytes:
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes().strip()
    return b""


def create_key_if_missing() -> bool:
    """Generate the signing key on first use. Returns True if created."""
    if KEY_PATH.exists():
        return False
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    KEY_PATH.write_bytes(key)
    os.chmod(KEY_PATH, 0o600)
    return True


def _canonical_payload(scope: dict) -> bytes:
    covered = {k: scope.get(k, []) for k in _SIGNED_FIELDS}
    return json.dumps(covered, sort_keys=True, separators=(",", ":")).encode()


def sign_scope(scope_file: Path = None, key_path: Path = None):
    """(Re)sign a scope.json. Defaults to the CWD workspace; init_env passes the
    --target workspace explicitly so the signature lands beside the right file.
    Called by init_env and by every scope mutation path (sec_flow.manage_scope,
    classify_and_expand_scope)."""
    scope_file = Path(scope_file) if scope_file else SCOPE_FILE
    key_path = Path(key_path) if key_path else KEY_PATH
    if not scope_file.exists():
        return
    key = key_path.read_bytes().strip() if key_path.exists() else b""
    if not key:
        # create_key uses the default KEY_PATH; honor explicit key_path too
        if key_path == KEY_PATH:
            create_key_if_missing()
            key = key_path.read_bytes().strip() if key_path.exists() else b""
        if not key:
            return  # no key possible — leave unsigned (verify reports 'unsigned')
    scope = json.loads(scope_file.read_text())
    sig = hmac.new(key, _canonical_payload(scope), hashlib.sha256).hexdigest()
    sig_file = scope_file.parent / "scope.sig"
    sig_file.write_text(sig + "\n")
    # Ever-signed marker: once a workspace has been signed, a MISSING sig file
    # is tampering, not "legacy unsigned" (closes the delete-to-downgrade hole).
    (scope_file.parent / "scope.sig.ever").touch()


# Backwards-compatible alias (older callers used the old name).
def _sign_scope():
    sign_scope()


def verify_scope(scope_file: Path = None, key_path: Path = None) -> str:
    """Returns one of:
      'ok'        — signature matches current scope.json
      'unsigned'  — legacy workspace (no sig file); gates may proceed but the
                    operator should re-init or sign to enable tamper evidence
      'TAMPERED:<reason>' — signature mismatch or malformed sig: hard stop
    Accepts explicit paths (init_env/target workspaces); defaults to CWD.
    """
    scope_file = Path(scope_file) if scope_file else SCOPE_FILE
    key_path = Path(key_path) if key_path else KEY_PATH
    if not scope_file.exists():
        return "unsigned"
    sig_file = scope_file.parent / "scope.sig"
    ever_file = scope_file.parent / "scope.sig.ever"
    if not sig_file.exists():
        # Downgrade attack: a workspace that WAS signed must never pass as
        # "legacy unsigned" just because scope.sig was deleted.
        if ever_file.exists():
            return "TAMPERED:scope.sig deleted from a previously-signed workspace"
        return "unsigned"
    key = key_path.read_bytes().strip() if key_path.exists() else b""
    if not key:
        return "TAMPERED:signing key missing — cannot verify a signed scope"
    sig_line = sig_file.read_text().strip()
    if not sig_line or len(sig_line) != 64:
        return "TAMPERED:malformed signature file"
    try:
        scope = json.loads(scope_file.read_text())
    except Exception as e:
        return f"TAMPERED:scope.json unparseable ({e})"
    expected = hmac.new(key, _canonical_payload(scope), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_line):
        return ("TAMPERED:authorization fields changed without re-signing "
                "(hosts/domains/cidrs/code_paths/actions)")
    return "ok"


def tamper_notice() -> str:
    """Human-facing notice for gate refusals caused by tamper evidence."""
    return (
        "[!] SCOPE SIGNATURE INVALID: the engagement scope failed signature "
        "verification. Either scope.json was modified outside the approved "
        "flow, or the signature file is corrupted. The scope gate will not "
        "authorize commands until this is resolved: restore scope.json from "
        "git/backup, or re-approve scope with the operator present and "
        "re-run init_env.py to re-sign."
    )
