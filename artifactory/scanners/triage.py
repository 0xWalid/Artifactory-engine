#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Background Triage & Scout Brain

Digests raw command artifacts into ranked *leads* on board.json so the
expensive operator model never has to read the firehose of tool output.

Two layers, in order:
  1. Deterministic extractors (free, instant, no model): parse endpoints,
     ports, subdomains, tech banners and high-signal anomalies out of the log.
  2. Optional "Scout" model (cheap/free, OpenAI-compatible, provider-agnostic):
     ranks/annotates the extracted candidates. Controlled by .blackboard/scout.json.
     If disabled or unreachable, deterministic leads are still saved.

Nothing here blocks the operator: it runs inline for sync commands and inside
the detached child for backgrounded ones.
"""

import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Shared, lock-serialised blackboard writes (no interleaving with sec_flow).
_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
from board_io import json_transaction  # noqa: E402

BLACKBOARD_DIR = Path.cwd() / ".blackboard"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
SCOUT_FILE = BLACKBOARD_DIR / "scout.json"

# Known OpenAI-compatible free providers, tried in THIS order whenever their
# API key is exported. This lives in code (not just scout.json) so the failover
# chain is robust even if a workspace's scout.json is old, partial, or missing:
# export GROQ_API_KEY and/or OPENROUTER_API_KEY and ranking just works.
KNOWN_PROVIDERS = [
    {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
    },
    {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "api_key_env": "OPENROUTER_API_KEY",
    },
]

# Defaults merged UNDER whatever scout.json provides, so missing keys never break
# a run. `enabled` defaults on: with no keys exported the chain is empty and we
# fall back to deterministic-only anyway, so it is safe. Set enabled=false in
# scout.json to hard-disable the model layer.
DEFAULT_SCOUT = {
    "enabled": True,
    "max_leads_per_triage": 8,
    "request_timeout": 20,
}


def load_scout_cfg() -> dict:
    """scout.json merged over code defaults -> always a usable config."""
    return {**DEFAULT_SCOUT, **load_json(SCOUT_FILE)}

# High-signal substrings that turn a line into an "anomaly" lead outright.
ANOMALY_SIGNALS = [
    ("traceback (most recent call last)", "python stack trace leaked"),
    ("exception in thread", "java exception leaked"),
    ("sql syntax", "SQL error - possible SQLi"),
    ("you have an error in your sql", "SQL error - possible SQLi"),
    ("root:x:0:0", "/etc/passwd contents - possible LFI/traversal"),
    ("begin rsa private key", "private key material exposed"),
    ("begin openssh private key", "private key material exposed"),
    ("aws_secret_access_key", "AWS secret leaked"),
    ("authorization: bearer", "bearer token in output"),
    ("set-cookie", "session cookie observed"),
    ("index of /", "directory listing enabled"),
    ("debug = true", "debug mode enabled"),
]


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def read_artifact(pointer_id: str):
    """Returns (command, stdout, stderr) for a pointer, or (None, None, None)."""
    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"
    if not artifact_path.exists():
        return None, None, None
    raw = artifact_path.read_text()

    def _section(tag, nxt):
        pat = rf"--- {tag} ---\n(.*?)(?=\n--- {nxt} ---|\Z)" if nxt else rf"--- {tag} ---\n(.*)"
        m = re.search(pat, raw, re.DOTALL)
        return m.group(1).strip() if m else ""

    cmd = _section("COMMAND", "STDOUT")
    stdout = _section("STDOUT", "STDERR")
    stderr = _section("STDERR", None)
    return cmd, stdout, stderr


def _mklead(ltype, value, signal, pointer_id, confidence=0.4, suggested_next="",
            must_verify=False, preconditions=None):
    return {
        "id": f"LEAD_{uuid.uuid4().hex[:6].upper()}",
        "type": ltype,
        "value": value,
        "signal": signal,
        "confidence": confidence,
        "suggested_next": suggested_next,
        "must_verify": must_verify,
        # Precondition matrix: feature-gated bugs list what must be enabled in a
        # lab before they are testable ("FGAPv2 enabled", ...). Set status to
        # 'blocked_precondition' to schedule them instead of skipping.
        "preconditions": [p for p in (preconditions or []) if p],
        "source_pointer": pointer_id,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def deterministic_extract(cmd: str, stdout: str, stderr: str, pointer_id: str) -> list:
    """Parse structured/known tool output into leads without any model call."""
    leads = []
    combined = f"{stdout}\n{stderr}"
    lines = stdout.splitlines()

    # --- nmap open ports:  "80/tcp   open  http" ---
    for m in re.finditer(r"(?m)^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", stdout):
        port, proto, svc = m.group(1), m.group(2), m.group(3)
        leads.append(_mklead(
            "port", f"{port}/{proto} ({svc})",
            f"open {svc} service", pointer_id, 0.5,
            f"probe the {svc} service on port {port}",
        ))

    # --- ffuf / gobuster / feroxbuster / httpx JSON-ish endpoint discovery ---
    for line in lines:
        s = line.strip()
        # JSON object lines with a url/input/path key
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
            except Exception:
                obj = None
            if isinstance(obj, dict):
                url = obj.get("url") or obj.get("input") or obj.get("path")
                status = obj.get("status") or obj.get("status_code")
                if url:
                    leads.append(_mklead(
                        "endpoint", str(url),
                        f"discovered path (status {status})" if status else "discovered path",
                        pointer_id, 0.45, "fuzz params / test this endpoint",
                    ))
                    continue
        # gobuster-style "/admin  (Status: 200)"
        gm = re.match(r"^(/\S*)\s+\(Status:\s*(\d{3})\)", s)
        if gm:
            leads.append(_mklead(
                "endpoint", gm.group(1),
                f"discovered path (status {gm.group(2)})",
                pointer_id, 0.45, "fuzz params / test this endpoint",
            ))

    # --- subdomains (subfinder/amass): bare host-only lines ---
    for line in lines:
        s = line.strip()
        if re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+\.[a-z]{2,}", s, re.I):
            leads.append(_mklead(
                "subdomain", s, "resolved subdomain", pointer_id, 0.4,
                "resolve + probe this host for its own surface",
            ))

    # --- tech / version banners --- (flagged must_verify: a version -> known-CVE
    # claim must be actively proven before it can become a confirmed finding).
    for m in re.finditer(r"(?im)^(?:Server|X-Powered-By):\s*(.+)$", combined):
        leads.append(_mklead(
            "tech", m.group(1).strip(), "server/framework banner", pointer_id, 0.35,
            "map known CVEs / default paths, then VERIFY before reporting",
            must_verify=True,
        ))

    # --- high-signal anomalies (case-insensitive substring hits) ---
    low = combined.lower()
    for needle, meaning in ANOMALY_SIGNALS:
        if needle in low:
            leads.append(_mklead(
                "anomaly", meaning, needle, pointer_id, 0.8,
                "confirm + escalate this signal into a finding",
                must_verify=True,
            ))

    return leads


SCOUT_SYSTEM_PROMPT = (
    "You are a penetration-testing triage scout. Given discovered items from a "
    "scan, return ONLY a compact JSON array. Each element: "
    '{"value": <the item value verbatim>, "confidence": <0.0-1.0 how likely '
    'this leads to a real vuln>, "suggested_next": <one concrete next test, '
    "terse>}. No prose, no markdown fences."
)


def _provider_chain(scout_cfg: dict) -> list:
    """Ordered providers to try. Built from, in order:
      1. the explicit primary in scout.json (base_url/model), then its 'fallbacks';
      2. any KNOWN_PROVIDERS whose API key is exported but that config omitted.
    De-duplicated by (base_url, model), so an old scout.json still gets the full
    Groq -> OpenRouter chain automatically as long as the keys are exported."""
    import os

    chain, seen = [], set()

    def _add(p):
        if not (isinstance(p, dict) and p.get("base_url") and p.get("model")):
            return
        key = (p["base_url"].rstrip("/"), p.get("model"))
        if key in seen:
            return
        seen.add(key)
        chain.append(p)

    if scout_cfg.get("base_url") and scout_cfg.get("model"):
        _add({
            "base_url": scout_cfg.get("base_url"),
            "model": scout_cfg.get("model"),
            "api_key_env": scout_cfg.get("api_key_env", ""),
        })
    for fb in scout_cfg.get("fallbacks") or []:
        _add(fb)
    # Robustness net: activate any known provider whose key is present.
    for p in KNOWN_PROVIDERS:
        if os.environ.get(p["api_key_env"]):
            _add(p)
    return chain


def _query_provider(compact: list, provider: dict, api_key: str, timeout: int) -> dict:
    """Single OpenAI-compatible chat call. Raises on any transport/parse error
    (including HTTP 429 rate-limits) so the caller can fall through to the next
    provider. Returns {value: {confidence, suggested_next}}."""
    import urllib.request

    base_url = (provider.get("base_url") or "").rstrip("/")
    body = json.dumps({
        "model": provider.get("model"),
        "messages": [
            {"role": "system", "content": SCOUT_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(compact)},
        ],
        "temperature": 0.2,
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    content = data["choices"][0]["message"]["content"].strip()
    content = re.sub(r"^```(?:json)?|```$", "", content, flags=re.M).strip()
    ranked = json.loads(content)
    out = {}
    for r in ranked:
        if isinstance(r, dict) and "value" in r:
            out[str(r["value"])] = {
                "confidence": r.get("confidence"),
                "suggested_next": r.get("suggested_next"),
            }
    return out


def scout_rank(candidates: list, scout_cfg: dict) -> dict:
    """
    Optional cheap-model pass. Sends ONLY the compact candidate list (never the
    raw log) and asks for a ranking. Tries the primary provider first, then each
    'fallbacks' entry in order (e.g. Groq rate-limited -> OpenRouter) until one
    answers. Returns {value: {confidence, suggested_next}}.
    Fails silent -> deterministic leads stand on their own.
    """
    import os

    if scout_cfg.get("enabled") is False:
        return {}

    # Compact payload: type + value + signal only. Keeps request tiny.
    compact = [
        {"value": c["value"], "type": c["type"], "signal": c["signal"]}
        for c in candidates[: scout_cfg.get("max_leads_per_triage", 8)]
    ]
    timeout = scout_cfg.get("request_timeout", 20)

    chain = _provider_chain(scout_cfg)
    for provider in chain:
        api_key = os.environ.get(provider.get("api_key_env", ""), "")
        if not api_key:
            # No key exported for this provider; quietly skip to the next.
            continue
        label = provider.get("model", "?")
        try:
            result = _query_provider(compact, provider, api_key, timeout)
            if result:
                return result
            # Reachable but returned nothing usable -> try the next provider.
        except Exception as e:
            print(f"[!] Scout provider '{label}' skipped ({e}); trying fallback.",
                  file=sys.stderr)
            continue

    return {}


def _merge_leads(candidates: list, pointer_id: str):
    """Dedup `candidates` against board.json and append the new ones under a
    single serialised transaction. Shared by network triage and SAST triage."""
    board = load_json(BOARD_FILE)
    if not board:
        print(f"[!] Triage: {BOARD_FILE} not found; run init_env.py first.", file=sys.stderr)
        return
    existing_snapshot = board.get("leads", [])
    seen = {(l.get("type"), l.get("value")) for l in existing_snapshot}
    new_leads = []
    for lead in candidates:
        key = (lead["type"], lead["value"])
        if key in seen:
            continue
        seen.add(key)
        new_leads.append(lead)

    if not new_leads:
        return

    # Serialised write so a parallel agent's board update is not clobbered.
    added = 0
    top = None
    with json_transaction("board.json") as board:
        if board is None:
            return
        existing = board.setdefault("leads", [])
        live_keys = {(l.get("type"), l.get("value")) for l in existing}
        for lead in new_leads:
            if (lead["type"], lead["value"]) in live_keys:
                continue
            existing.append(lead)
            added += 1
        existing.sort(key=lambda l: l.get("confidence", 0), reverse=True)
        top = existing[0] if existing else None

    if added and top:
        print(f"[+] Triage [{pointer_id}]: +{added} lead(s). "
              f"Top: [{top['type']}] {top['value']} (conf {top.get('confidence')})")


def sast_extract(sarif_obj: dict, pointer_id: str) -> list:
    """Convert a semgrep SARIF document into `sast` leads.

    Each result is a *candidate* the deterministic scanner is confident about;
    it is flagged must_verify at low confidence because the AI still has to
    disprove false positives (guided questions) and prove survivors at runtime
    before the verification gate will ever mark it confirmed.
    """
    leads = []
    for run in sarif_obj.get("runs", []) or []:
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or "unknown-rule"
            message = ((res.get("message") or {}).get("text") or "").strip()

            file_uri, start_line, snippet = "", None, ""
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0] or {}).get("physicalLocation") or {}
                file_uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
                region = phys.get("region") or {}
                start_line = region.get("startLine")
                snippet = ((region.get("snippet") or {}).get("text") or "").strip()

            loc = f"{file_uri}:{start_line}" if start_line else (file_uri or "?")
            value = f"{loc} {rule_id}".strip()
            signal = message or rule_id
            if snippet:
                signal = f"{signal} — `{snippet[:160]}`"

            leads.append(_mklead(
                "sast", value, signal, pointer_id,
                confidence=0.3,
                suggested_next=(
                    "load prompts/sast/<class> guided questions, answer the data-flow "
                    "questions (low temp) to disprove or keep, then PROVE with a runtime PoC"
                ),
                must_verify=True,
            ))
    return leads


def triage_sast(pointer_id: str):
    """Parse a stored semgrep-SARIF artifact into sast leads on the board."""
    if not BOARD_FILE.exists():
        print(f"[!] Triage: {BOARD_FILE} not found; run init_env.py first.", file=sys.stderr)
        return
    _, stdout, _ = read_artifact(pointer_id)
    if not stdout:
        print(f"[!] Triage: SARIF artifact {pointer_id} empty or not found.", file=sys.stderr)
        return
    try:
        sarif_obj = json.loads(stdout)
    except Exception as e:
        print(f"[!] Triage: {pointer_id} stdout is not valid SARIF JSON ({e}).", file=sys.stderr)
        return
    candidates = sast_extract(sarif_obj, pointer_id)
    if not candidates:
        return
    _merge_leads(candidates, pointer_id)


def triage_pointer(pointer_id: str):
    if not BOARD_FILE.exists():
        print(f"[!] Triage: {BOARD_FILE} not found; run init_env.py first.", file=sys.stderr)
        return

    cmd, stdout, stderr = read_artifact(pointer_id)
    if cmd is None:
        print(f"[!] Triage: artifact {pointer_id} not found.", file=sys.stderr)
        return

    candidates = deterministic_extract(cmd, stdout or "", stderr or "", pointer_id)
    if not candidates:
        return

    # Optional cheap-model ranking pass (fails silent).
    ranked = scout_rank(candidates, load_scout_cfg())
    for lead in candidates:
        hit = ranked.get(lead["value"])
        if hit:
            if isinstance(hit.get("confidence"), (int, float)):
                lead["confidence"] = round(float(hit["confidence"]), 2)
            if hit.get("suggested_next"):
                lead["suggested_next"] = hit["suggested_next"]

    _merge_leads(candidates, pointer_id)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SBA Background Triage / Scout")
    parser.add_argument("--pointer", "-p", required=True, help="Artifact pointer ID to triage")
    args = parser.parse_args()
    triage_pointer(args.pointer)



