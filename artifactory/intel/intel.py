#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Vulnerability Intelligence & SCA Bridge

Implements five post-mortem improvements from a live product engagement:

  1. CHANGELOG-FIRST   `intel` pulls the authoritative CVE index for a product +
                       version (OSV.dev full-index + NVD), so enumeration starts
                       from ground truth instead of keyword-search ranking. The
                       agent directive (fetch the vendor release notes of the
                       first patched version and enumerate EVERY issue as a
                       lead) lives in the /artifactory command doc.
  2. DISTRO SCA        `sca` inventories shipped dependency artifacts on disk
                       (lib/**/*.jar, package-lock.json, requirements*.txt,
                       go.sum) — semgrep never sees these.
  3. FULL-INDEX QUERY  OSV.dev querybatch (keyless, covers Maven/npm/PyPI/Go/
                       RubyGems/crates/NuGet AND distro ecosystems incl. Red
                       Hat) queried once per engagement instead of ad-hoc
                       keyword searches.
  4. NO SILENT DROPS   Every candidate becomes a `cve` lead flagged must_verify.
                       A candidate that cannot be checked (network down) still
                       lands as a lead so coverage gaps stay visible.
  5. PRECONDITION MATRIX  Leads may carry `preconditions` (feature-gated bugs:
                       "FGAPv2 enabled", "vault mounted", ...). Set status to
                       'blocked_precondition' to schedule them as lab-enable-
                       then-test instead of skipping them.
  6. CODE-SCOPE GATE   `sca` reads source/dependency manifests off disk, so it
                       is fail-closed on scope.json -> allowed_code_paths, exactly
                       like SAST. Authorise the path (scope --add-code-path) first.
  7. OFFLINE FALLBACK  Air-gapped / rate-limited engagements: `sca --offline`
                       (or automatic fallback when OSV is fully unreachable)
                       emits a deterministic `cve` lead for EVERY pinned
                       dependency — the full inventory stays visible for manual
                       OSV/GHSA/NVD matching, with no network dependency and no
                       silent drops.

PASSIVE-INTEL EGRESS: these lookups are read-only queries against third-party
intel services about PUBLIC data — they never touch the target. They are
governed by a hardcoded passive-intel allowlist (PASSIVE_INTEL_HOSTS), not by
the engagement scope gate, which continues to fail-closed for all TARGET
traffic in sec_flow.py.
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

# Shared engine imports (board plumbing + lead helpers).
_engine_dir = str(Path(__file__).resolve().parent)
if _engine_dir not in sys.path:
    sys.path.insert(0, _engine_dir)
import sec_flow  # noqa: E402
import triage  # noqa: E402
import sast  # noqa: E402  (reuses the fail-closed allowed_code_paths gate + loaders)

# Read-only public intel services this module may contact. Nothing else.
PASSIVE_INTEL_HOSTS = {
    "api.osv.dev",
    "osv.dev",
    "services.nvd.nist.gov",
}

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_VULN_ENDPOINT = "https://api.osv.dev/v1/vulns/"
OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ecosystems tried for a bare product name, in order. Maven entries built from
# jar filenames only carry the artifactId (no groupId), so a hit there is a
# candidate, not a certainty -> must_verify anyway.
OSV_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "RubyGems", "crates.io", "NuGet", "Packagist", "Maven",
]

REQUEST_TIMEOUT = 30
BATCH_SIZE = 100
MAX_DETAIL_FETCHES = 80


def _assert_intel_host(url: str):
    """Fail-closed egress check: only PASSIVE_INTEL_HOSTS may be contacted."""
    host = url.split("/")[2] if "://" in url else url.split("/")[0]
    if host not in PASSIVE_INTEL_HOSTS:
        raise RuntimeError(
            f"[!] INTEL EGRESS BLOCK: '{host}' is not on the passive-intel "
            f"allowlist {sorted(PASSIVE_INTEL_HOSTS)}."
        )


def http_json(url: str, payload: dict = None, timeout: int = REQUEST_TIMEOUT):
    """GET/POST JSON against an allowlisted passive-intel host."""
    _assert_intel_host(url)
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def osv_query_batch(queries: list) -> list:
    """Batched OSV lookup; returns results aligned to input order."""
    out = []
    for i in range(0, len(queries), BATCH_SIZE):
        chunk = queries[i:i + BATCH_SIZE]
        try:
            resp = http_json(OSV_BATCH_ENDPOINT, {"queries": chunk})
            out.extend(resp.get("results", []))
        except Exception as e:
            print(f"[!] OSV batch failed ({e}); those candidates are re-queried individually.", file=sys.stderr)
            out.extend([{"error": str(e)}] * len(chunk))
        time.sleep(0.4)
    return out


def osv_fetch_details(vuln_ids: list, cap: int = MAX_DETAIL_FETCHES) -> dict:
    """Fetch full records (aliases/summary/severity) for vuln ids."""
    details = {}
    for vid in list(dict.fromkeys(vuln_ids))[:cap]:
        try:
            details[vid] = http_json(OSV_VULN_ENDPOINT + vid)
        except Exception:
            continue
        time.sleep(0.12)
    return details


def nvd_cves(params: dict) -> list:
    """Query the NVD CVE API (keyless tier). Returns cve id+description list."""
    qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
    try:
        resp = http_json(f"{NVD_CVE_ENDPOINT}?{qs}")
    except Exception as e:
        print(f"[!] NVD query failed ({e}); falling back to OSV-only.", file=sys.stderr)
        return []
    out = []
    for item in resp.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        descs = [d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"]
        if cid:
            out.append({"id": cid, "summary": (descs[0] if descs else "")[:220]})
    return out


# --------------------------------------------------------------------------
# Dependency inventory parsers (DISTRO SCA)
# --------------------------------------------------------------------------

def parse_jars(root: Path) -> list:
    """lib/**/*.jar style inventory: name-1.2.3.jar -> (artifact, version)."""
    found = []
    for jar in root.rglob("*.jar"):
        stem = jar.stem
        m = re.match(r"^(.*?)-(\d.+)$", stem)
        if m:
            found.append({"ecosystem": "Maven", "name": m.group(1),
                          "version": m.group(2), "source_file": str(jar.relative_to(root))})
    return found


def parse_package_lock(path: Path) -> list:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []
    pkgs = []
    seen = set()
    for key, meta in (data.get("packages") or {}).items():
        name = key.replace("node_modules/", "")
        ver = meta.get("version")
        if name and ver and (name, ver) not in seen and not key.startswith("node_modules/_"):
            seen.add((name, ver))
            pkgs.append({"ecosystem": "npm", "name": name, "version": ver,
                         "source_file": path.name})
    return pkgs


def parse_requirements(path: Path) -> list:
    pkgs = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^;\s]+)", line)
        if m:
            pkgs.append({"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2),
                         "source_file": path.name})
    return pkgs


def parse_go_sum(path: Path) -> list:
    pkgs, seen = [], set()
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and "/" in parts[0]:
            mod, ver = parts[0], parts[1].lstrip("v")
            # go.sum lists /go.mod and hash lines; keep first version per module
            if (mod, ver.split("/")[0]) not in seen and not ver.endswith("/go.mod"):
                seen.add((mod, ver))
                pkgs.append({"ecosystem": "Go", "name": mod, "version": ver,
                             "source_file": path.name})
    return pkgs


# --- Broader offline parsers (ported from P1's air-gapped SCA fallback) ------
# These extend inventory coverage well beyond the four network-era manifests so
# that `--offline` on a locked-down engagement still yields a complete pinned
# inventory instead of a near-empty board.

def parse_package_json(path: Path) -> list:
    """Direct declared deps (dependencies + devDependencies). Versions may be
    ranges ("^1.2.3"); the offline lead flags them as declared-not-locked."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []
    pkgs = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in (data.get(section) or {}).items():
            ver = str(ver).lstrip("^~>=< ").strip() or "*"
            pkgs.append({"ecosystem": "npm", "name": name, "version": ver,
                         "source_file": path.name})
    return pkgs


def parse_gemfile_lock(path: Path) -> list:
    pkgs = []
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", line)
        if m:
            pkgs.append({"ecosystem": "RubyGems", "name": m.group(1),
                         "version": m.group(2), "source_file": path.name})
    return pkgs


def parse_cargo_lock(path: Path) -> list:
    pkgs, name = [], None
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            name = m.group(1)
            continue
        v = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if v and name:
            pkgs.append({"ecosystem": "crates.io", "name": name,
                         "version": v.group(1), "source_file": path.name})
            name = None
    return pkgs


def parse_composer_lock(path: Path) -> list:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return []
    pkgs = []
    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            name, ver = pkg.get("name"), pkg.get("version")
            if name and ver:
                pkgs.append({"ecosystem": "Packagist", "name": name,
                             "version": str(ver).lstrip("v"), "source_file": path.name})
    return pkgs


def parse_pom(path: Path) -> list:
    """Regex-only <dependency> extraction (no XML dep). groupId is dropped to
    the artifactId to match the jar-inventory naming; a hit is a candidate."""
    pkgs = []
    text = path.read_text(errors="replace")
    for dep in re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        art = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", dep)
        ver = re.search(r"<version>\s*([^<]+?)\s*</version>", dep)
        if art and ver and "${" not in ver.group(1):
            pkgs.append({"ecosystem": "Maven", "name": art.group(1).strip(),
                         "version": ver.group(1).strip(), "source_file": path.name})
    return pkgs


def parse_generic_lock_json(path: Path) -> list:
    """poetry.lock / Pipfile.lock style pinned Python deps."""
    pkgs = []
    text = path.read_text(errors="replace")
    if path.name == "Pipfile.lock":
        try:
            data = json.loads(text)
        except Exception:
            return []
        for section in ("default", "develop"):
            for name, meta in (data.get(section) or {}).items():
                ver = str(meta.get("version", "")).lstrip("=").strip()
                if name and ver:
                    pkgs.append({"ecosystem": "PyPI", "name": name,
                                 "version": ver, "source_file": path.name})
    else:  # poetry.lock (TOML [[package]] blocks)
        for block in re.split(r"\[\[package\]\]", text)[1:]:
            n = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.M)
            v = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.M)
            if n and v:
                pkgs.append({"ecosystem": "PyPI", "name": n.group(1),
                             "version": v.group(1), "source_file": path.name})
    return pkgs


def parse_archives(root: Path) -> list:
    """Bundled build outputs beyond jars: *.whl / *.gem carry name-version."""
    found = []
    for pat, eco in (("*.whl", "PyPI"), ("*.gem", "RubyGems")):
        for arc in root.rglob(pat):
            m = re.match(r"^([A-Za-z0-9_.\-]+?)-(\d[\w.\-+]*)", arc.stem)
            if m:
                found.append({"ecosystem": eco, "name": m.group(1),
                              "version": m.group(2),
                              "source_file": str(arc.relative_to(root))})
    return found


def inventory_dependencies(root: Path) -> list:
    """Inventory every supported dependency manifest under root."""
    items = []
    items.extend(parse_jars(root))
    items.extend(parse_archives(root))
    for pattern, parser in (
        ("**/package-lock.json", parse_package_lock),
        ("**/npm-shrinkwrap.json", parse_package_lock),
        ("**/package.json", parse_package_json),
        ("**/requirements*.txt", parse_requirements),
        ("**/poetry.lock", parse_generic_lock_json),
        ("**/Pipfile.lock", parse_generic_lock_json),
        ("**/go.sum", parse_go_sum),
        ("**/Gemfile.lock", parse_gemfile_lock),
        ("**/Cargo.lock", parse_cargo_lock),
        ("**/composer.lock", parse_composer_lock),
        ("**/pom.xml", parse_pom),
    ):
        for path in root.glob(pattern):
            if ".blackboard" in path.parts or "node_modules" in path.parts:
                continue
            items.extend(parser(path))
    # Dedup identical (ecosystem, name, version).
    dedup, seen = [], set()
    for it in items:
        key = (it["ecosystem"], it["name"], it["version"])
        if key not in seen:
            seen.add(key)
            dedup.append(it)
    return dedup


# --------------------------------------------------------------------------
# Lead construction (NO SILENT DROPS: everything becomes a visible lead)
# --------------------------------------------------------------------------

def make_cve_lead(value: str, summary: str, pointer_id: str, preconditions=None,
                  suggested_next: str = ""):
    return triage._mklead(
        "cve", value, summary or "candidate CVE (unverified)", pointer_id,
        confidence=0.35,
        suggested_next=suggested_next or (
            "changelog-first: read the vendor release notes for the first patched "
            "release; verify the version condition holds at runtime; then build a PoC"
        ),
        must_verify=True,
        preconditions=preconditions or [],
    )


def _dedup_leads(leads: list) -> list:
    """Collapse advisories that resolve to the same CVE id (GHSA/alias doubles),
    keeping the record with the richest signal."""
    best = {}
    for l in leads:
        key = (l["type"], l["value"])
        if key not in best or len(l.get("signal", "")) > len(best[key].get("signal", "")):
            best[key] = l
    return list(best.values())


def _emit_leads(leads: list, label: str):
    leads = _dedup_leads(leads)
    if not leads:
        print(f"[*] {label}: no candidate advisories found.")
        return
    triage._merge_leads(leads, label_to_pointer(label))
    by_conf = sorted(leads, key=lambda l: l.get("confidence", 0), reverse=True)[:10]
    print(f"[✔] {label}: +{len(leads)} candidate CVE lead(s) filed on the board "
          f"(no silent drops). Top matches:")
    for l in by_conf:
        print(f"    - {l['value']}  ::  {(l.get('signal') or '')[:110]}")


def label_to_pointer(label: str) -> str:
    """Stable pseudo-pointer so intel batches are traceable on the board."""
    import hashlib
    return "INTEL_" + hashlib.sha1(label.encode()).hexdigest()[:8].upper()


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

def run_intel(product: str, version: str = "", cpe: str = "", preconditions: list = None):
    """FULL-INDEX + CHANGELOG-FIRST enumeration for one product/version."""
    preconditions = preconditions or []
    candidates = {}  # cve_id -> summary
    fix_refs_by_cve = {}  # cve_id -> [fix commit / advisory URLs] (patch auto-chain)

    if cpe:
        print(f"[*] Querying NVD index for CPE {cpe} ...")
        for hit in nvd_cves({"cpeName": cpe}):
            candidates[hit["id"]] = hit["summary"]

    # OSV full-index pass across ecosystems (one query each, once per engagement).
    for eco in OSV_ECOSYSTEMS:
        q = {"package": {"ecosystem": eco, "name": product}}
        if version:
            q["version"] = version
        try:
            resp = http_json(OSV_QUERY_ENDPOINT, q)
        except Exception as e:
            print(f"[!] OSV '{eco}' unreachable ({e}) — filing an intel-gap lead so "
                  f"this blind spot stays visible.", file=sys.stderr)
            gap = triage._mklead(
                "cve", f"{product} {version or ''}(index-unreachable:{eco})".strip(),
                "OSV index could not be queried — COVERAGE GAP, retry manually",
                label_to_pointer(f"osv-gap-{eco}"), confidence=0.2,
                suggested_next="retry intel later or query https://osv.dev manually",
                must_verify=True, preconditions=preconditions,
            )
            candidates.setdefault(f"GAP-{eco}", "")
            triage._merge_leads([gap], f"intel-gap-{eco}")
            continue
        for vuln in resp.get("vulns", []):
            vid = vuln.get("id", "")
            aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
            cve_id = aliases[0] if aliases else vid
            summary = (vuln.get("summary") or vuln.get("details") or "")[:220]
            candidates[cve_id] = summary
            # CVE -> patch auto-chain: OSV references often carry the FIX
            # commit / advisory link. Capture them so patch_diff can hunt
            # variants from the actual fix ("read the diff, not the advisory").
            fix_refs = []
            for ref in vuln.get("references", []) or []:
                rtype = (ref.get("type") or "").upper()
                url = ref.get("url", "")
                if url and rtype in ("FIX", "GIT", "WEB") and "github.com" in url or rtype == "FIX":
                    fix_refs.append(url)
            if fix_refs:
                fix_refs_by_cve.setdefault(cve_id, fix_refs[:3])

    # NVD keyword fallback catches CPE-only products OSV lacks (e.g. appliances).
    # Two stages: precise "<product> <version>" first; if the version string
    # over-filters to zero (NVD matches it as free text), fall back to the
    # product name alone — candidates stay must_verify, the agent confirms the
    # version condition at runtime.
    kw = f"{product} {version}".strip()
    print(f"[*] NVD keyword pass: '{kw}' ...")
    nvd_hits = nvd_cves({"keywordSearch": kw, "resultsPerPage": 50})
    if not nvd_hits and version:
        print(f"[*] No hits with version; retrying name-only: '{product}' ...")
        nvd_hits = nvd_cves({"keywordSearch": product, "resultsPerPage": 50})
    for hit in nvd_hits:
        candidates.setdefault(hit["id"], hit["summary"])

    leads = []
    # Component aliasing: appliances embed components (nginx-in-artifactory etc);
    # a product-name pass misses embedded-component CVEs, so hint the broadening.
    alias_hint = ""
    try:
        from component_aliases import alias_hint as _ah
        alias_hint = _ah(product)
    except Exception:
        pass
    for cid, summary in sorted(candidates.items()):
        if cid.startswith("GAP-"):
            continue
        refs = fix_refs_by_cve.get(cid, [])
        hint = ""
        if refs:
            hint = (f" | fix-ref: {refs[0]} — feed patch_diff.py --diff with the "
                    f"commit .patch/.diff URL to hunt variants on YOUR surface")
        if alias_hint:
            hint += alias_hint
        leads.append(make_cve_lead(
            f"{product} {version or ''}: {cid}".strip(),
            summary, label_to_pointer(f"intel-{product}-{version}-{cid}"),
            preconditions=preconditions,
            suggested_next=(
                "changelog-first: read the vendor release notes for the first patched "
                "release; verify the version condition holds at runtime; then build a PoC"
            ) + hint,
        ))
    _emit_leads(leads, f"intel({product} {version or ''})")


def _offline_inventory_leads(deps: list, reason: str) -> list:
    """Air-gapped / rate-limited fallback: turn EVERY pinned dependency into a
    visible `cve` lead without any network call. The version is ground truth
    from disk; the agent matches it against OSV/GHSA/NVD manually. No cap, no
    silent drops — the whole inventory stays on the board."""
    leads = []
    for d in deps:
        leads.append(make_cve_lead(
            f"{d['ecosystem']}:{d['name']}@{d['version']}",
            f"[offline inventory — {reason}] pinned dependency present; "
            f"match {d['name']} {d['version']} against OSV/GHSA/NVD manually "
            f"(source: {d.get('source_file', '?')})",
            label_to_pointer(f"sca-offline-{d['ecosystem']}-{d['name']}-{d['version']}"),
            suggested_next=(
                f"when connectivity returns: `sec_flow.py sca --path <root>`; "
                f"meanwhile check https://osv.dev / GHSA for {d['name']} {d['version']}"
            ),
        ))
    return leads


def _code_scope_preflight(path: str):
    """Fail-closed allowed_code_paths gate (ported from P1). SCA reads source
    off disk, so it is gated exactly like SAST — an unauthorised path aborts."""
    scope = sast.load_json(sast.SCOPE_FILE)
    if not scope:
        print(
            "[!] SCOPE ERROR: .blackboard/scope.json is missing or empty. "
            "Run 'python3 ~/artifactory/init_env.py --target .' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not sast.is_code_path_in_scope(path, scope):
        print(
            f"[!] CODE-SCOPE ERROR: '{path}' is not under any authorised entry in "
            f"scope.json -> allowed_code_paths. Authorise it explicitly first:\n"
            f"      python3 ~/artifactory/sec_flow.py scope --add-code-path \"{path}\"\n"
            f"    Fail-closed by design (SCA reads source off disk, like SAST).",
            file=sys.stderr,
        )
        sys.exit(1)


def run_sca(path: str, offline: bool = False):
    """DISTRO SCA: inventory on-disk dependencies -> OSV batch -> cve leads.

    Fail-closed on allowed_code_paths (reads source off disk). With --offline,
    or automatically when OSV is fully unreachable, falls back to a deterministic
    inventory-only pass so air-gapped / rate-limited engagements still get the
    full pinned dependency list on the board."""
    _code_scope_preflight(path)

    root = Path(path).resolve()
    if not root.exists():
        print(f"[!] Path not found: {root}", file=sys.stderr)
        sys.exit(1)

    deps = inventory_dependencies(root)
    if not deps:
        print("[*] No dependency manifests/jars inventoried under this path.")
        return

    if offline:
        print(f"[*] OFFLINE mode: inventoried {len(deps)} pinned dependencies; "
              f"filing them as deterministic leads (no network).")
        _emit_leads(_offline_inventory_leads(deps, "operator forced --offline"),
                    f"sca-offline({root.name})")
        return

    print(f"[*] Inventoried {len(deps)} pinned dependencies. Querying OSV batch index ...")
    queries = [{"package": {"ecosystem": d["ecosystem"], "name": d["name"]},
                "version": d["version"]} for d in deps]
    results = osv_query_batch(queries)

    # Air-gapped / total-outage detection: if OSV answered nothing usable for any
    # query, do not degrade to a handful of gap leads — fall back to the full
    # deterministic inventory so nothing is silently lost.
    reachable = any(isinstance(r, dict) and not r.get("error") for r in results)
    if not reachable:
        print("[!] OSV unreachable for the entire batch (air-gapped / rate-limited) "
              "— falling back to OFFLINE deterministic inventory.", file=sys.stderr)
        _emit_leads(_offline_inventory_leads(deps, "OSV unreachable — verify online later"),
                    f"sca-offline({root.name})")
        return

    vuln_ids_by_dep, no_hits, unmatched = {}, [], []
    for dep, res in zip(deps, results):
        ids = [v.get("id") for v in (res or {}).get("vulns", []) if v.get("id")]
        if ids:
            vuln_ids_by_dep[(dep["ecosystem"], dep["name"], dep["version"])] = ids
        elif isinstance(res, dict) and res.get("error"):
            unmatched.append(dep)
        else:
            no_hits.append(dep)

    # Maven jars carry only the artifactId (no groupId), so OSV's group:artifact
    # naming misses them. Fallback: one NVD keyword lookup per clean dep so the
    # candidate still becomes a visible lead (must_verify), never a silent zero.
    nvd_only = []
    for dep in [d for d in no_hits if d["ecosystem"] == "Maven"][:10]:
        for hit in nvd_cves({"keywordSearch": f"{dep['name']} {dep['version']}",
                             "resultsPerPage": 20}):
            if dep["name"].lower() not in hit["summary"].lower():
                continue
            nvd_only.append((dep, hit))

    details = osv_fetch_details([i for ids in vuln_ids_by_dep.values() for i in ids])

    leads = []
    for (eco, name, ver), ids in vuln_ids_by_dep.items():
        for vid in ids:
            rec = details.get(vid, {})
            cve = next((a for a in rec.get("aliases", []) if a.startswith("CVE-")), vid)
            summary = (rec.get("summary") or rec.get("details") or vid)[:220]
            fixed = ""
            for aff in rec.get("affected", []):
                if name in json.dumps(aff.get("package", {})):
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fixed = ev["fixed"]
            note = f" fix: upgrade to {fixed}" if fixed else ""
            leads.append(make_cve_lead(
                f"{eco}:{name}@{ver} → {cve}",
                f"{summary}{note}", label_to_pointer(f"sca-{eco}-{name}-{ver}-{cve}"),
                suggested_next=(
                    f"confirm the shipped artifact really is {name}@{ver} at runtime "
                    f"(banner/buildinfo), then test the PoC from the advisory"
                ),
            ))

    if unmatched:
        print(f"[!] {len(unmatched)} dep(s) could not be batch-checked — filing "
              f"ALL of them as visible coverage gaps (no silent drops).", file=sys.stderr)
        gap_leads = [
            make_cve_lead(
                f"{d['ecosystem']}:{d['name']}@{d['version']}",
                "SCA batch check failed (network/index error) — UNVERIFIED, do not assume clean",
                label_to_pointer(f"sca-gap-{d['name']}"),
            ) for d in unmatched
        ]
        leads.extend(gap_leads)

    for dep, hit in nvd_only:
        leads.append(make_cve_lead(
            f"{dep['ecosystem']}:{dep['name']}@{dep['version']} → {hit['id']}",
            f"[nvd-candidate — groupId unverified] {hit['summary']}",
            label_to_pointer(f"sca-nvd-{dep['name']}-{hit['id']}"),
        ))

    _emit_leads(leads, f"sca({root.name})")


DETECT_MANIFESTS = [
    ("pom.xml", "Maven project"), ("build.gradle*", "Gradle project"),
    ("package.json", "Node.js project"), ("requirements*.txt", "Python project"),
    ("pyproject.toml", "Python project"), ("go.mod", "Go project"),
    ("Gemfile", "Ruby project"), ("Cargo.toml", "Rust project"),
    ("composer.json", "PHP project"), ("*.csproj", ".NET project"),
]


def run_detect(path: str = "."):
    """Source-tree detection for the analyze flow (auto-wire SAST + SCA)."""
    root = Path(path).resolve()
    stacks, jars = [], 0
    for pattern, label in DETECT_MANIFESTS:
        hits = [p for p in root.glob(pattern) if ".blackboard" not in p.parts]
        if hits:
            stacks.append(f"{label} ({', '.join(p.name for p in hits[:3])})")
    jars = len(list(root.rglob("*.jar")))
    has_any = bool(stacks) or jars > 0

    print(f"[*] Source detection for {root}")
    if stacks:
        print(f"    manifests: {'; '.join(stacks)}")
    if jars:
        print(f"    bundled jars: {jars} (*.jar) — SCA-relevant")
    if not has_any:
        print("[*] No source tree detected — black-box flow only.")
        return

    print(
        "\n[>] SOURCE DETECTED — white-box pipeline available. Next actions:\n"
        f"    1. Ask the operator ONCE to authorize the code path, then:\n"
        f"       python3 ~/artifactory/sec_flow.py scope --add-code-path \"{root}\"\n"
        f"    2. SAST (semgrep -> sast leads):\n"
        f"       python3 ~/artifactory/sec_flow.py sast --path \"{root}\"\n"
        f"    3. SCA (dependency inventory -> cve leads); same code-scope gate as SAST.\n"
        f"       python3 ~/artifactory/sec_flow.py sca --path \"{root}\"\n"
        f"       (air-gapped / rate-limited? add --offline for a deterministic inventory pass)\n"
        f"    Then consume: sec_flow.py leads --type sast   |   sec_flow.py leads --type cve"
    )


def main():
    parser = argparse.ArgumentParser(description="SBA Intel & SCA bridge")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_intel = sub.add_parser("intel", help="Full-index CVE enumeration for a product/version")
    p_intel.add_argument("--product", "-P", required=True)
    p_intel.add_argument("--version", "-V", default="")
    p_intel.add_argument("--cpe", default="", help="Optional exact CPE for an NVD match")
    p_intel.add_argument("--preconditions", default="",
                         help="Comma-separated feature preconditions (e.g. 'FGAPv2 enabled,vault mounted')")

    p_sca = sub.add_parser("sca", help="Dependency inventory + OSV batch check (fail-closed on allowed_code_paths)")
    p_sca.add_argument("--path", "-p", required=True)
    p_sca.add_argument("--offline", action="store_true",
                       help="Air-gapped/rate-limited: skip network, file the full pinned inventory as deterministic cve leads")

    p_det = sub.add_parser("detect", help="Detect source trees / manifests (analyze auto-wire)")
    p_det.add_argument("--path", "-p", default=".")

    args = parser.parse_args()
    if args.subcommand == "intel":
        pres = [p.strip() for p in args.preconditions.split(",") if p.strip()]
        run_intel(args.product, args.version, args.cpe, pres)
    elif args.subcommand == "sca":
        run_sca(args.path, offline=args.offline)
    elif args.subcommand == "detect":
        run_detect(args.path)


if __name__ == "__main__":
    main()
