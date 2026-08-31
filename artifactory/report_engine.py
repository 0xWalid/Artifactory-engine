#!/usr/bin/env python3
"""
Sovereign Blackboard Architecture - Modular Report Generator
Generates per-vulnerability reports and evidence logs directly in the local project directory.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Execution context is the local project directory
CWD = Path.cwd()
BLACKBOARD_DIR = CWD / ".blackboard"
BOARD_FILE = BLACKBOARD_DIR / "board.json"
ARTIFACTS_DIR = BLACKBOARD_DIR / "artifacts"
REPORTS_DIR = CWD / "reports"
EVIDENCE_DIR = REPORTS_DIR / "evidence"
RATIONALE_FILE = BLACKBOARD_DIR / "rationale.jsonl"


def load_rationale() -> list:
    """WS7: the decision journal (why an action was taken and what resulted)."""
    if not RATIONALE_FILE.exists():
        return []
    records = []
    for line in RATIONALE_FILE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    return records


def ensure_report_dirs():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def slugify(text: str) -> str:
    slug = re.sub(r'[^a-zA-Z0-9_-]', '_', text.lower())
    return re.sub(r'_+', '_', slug).strip('_')


def load_artifact_content(pointer_id: str) -> str:
    artifact_path = ARTIFACTS_DIR / f"{pointer_id}.log"
    if artifact_path.exists():
        return artifact_path.read_text()
    return "Artifact log not found."


def extract_juicy_details(raw_artifact_text: str) -> str:
    """Extracts sensitive headers, reflected tokens, cookies, or path disclosures."""
    extracted = []
    lines = raw_artifact_text.splitlines()

    for line in lines:
        # Check for interesting response headers or disclosures
        if re.search(r'(Set-Cookie|Authorization|X-Forwarded|Location|Server|X-Powered-By):', line, re.I):
            extracted.append(f"  [Header] {line.strip()}")
        elif re.search(r'(\/var\/www|\/home\/|C:\\|[a-zA-Z0-9_-]+\.(php|sql|env|json|bak|conf))', line, re.I):
            extracted.append(f"  [Path/File Disclosure] {line.strip()}")
        elif re.search(r'(token|jwt|api_key|password|secret|hash)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]{8,}', line, re.I):
            extracted.append(f"  [Key/Credential Signal] {line.strip()}")

    if not extracted:
        return "No specific credential patterns or paths auto-flagged. Check full artifact evidence."
    return "\n".join(extracted[:25])


def generate_individual_reports():
    ensure_report_dirs()

    if not BOARD_FILE.exists():
        print(f"[!] Error: {BOARD_FILE} not found. Run analysis first.", file=sys.stderr)
        return

    try:
        board_data = json.loads(BOARD_FILE.read_text())
    except Exception as e:
        print(f"[!] Error parsing board.json: {e}")
        return

    # board.json stores the target under 'target_path' (init_env). Fall back
    # gracefully so the advisory never mislabels the engagement as "Target System".
    target = board_data.get("target_path") or board_data.get("target") or "Target System"
    findings = board_data.get("findings", [])
    execution_logs = board_data.get("execution_log_pointers", [])
    assets = board_data.get("discovered_assets", {})

    # WS3: only CONFIRMED findings (status set + evidence-backed) become full
    # vulnerability advisories. Everything else is an informational observation
    # and is listed separately so reports stop presenting unproven info as vulns.
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    informational = [f for f in findings if f.get("status") != "confirmed"]

    if not findings:
        print("[*] No findings recorded in board.json. Generating surface summary only.")
    elif not confirmed:
        print(f"[*] {len(informational)} informational observation(s), 0 confirmed "
              f"vulnerabilities. Advisories are only generated for confirmed findings.")

    generated_files = []

    # 1. Generate Individual Advisories — CONFIRMED findings only
    for idx, finding in enumerate(confirmed, 1):
        finding_id = finding.get("id", f"FINDING_{idx:02d}")
        title = finding.get("title", "Unnamed Vulnerability")
        details = finding.get("details", "No details supplied.")
        severity = finding.get("severity", "info")
        evidence_poc = finding.get("evidence", "")
        timestamp = finding.get("timestamp", datetime.now(timezone.utc).isoformat())

        slug_title = slugify(title)
        report_filename = f"{finding_id}_{slug_title}.md"
        report_path = REPORTS_DIR / report_filename

        # Correlate execution pointers to THIS finding. If the finding recorded
        # its own related pointer IDs at add-asset time, use only those so each
        # advisory shows its real reproduction commands; otherwise fall back to
        # the most recent commands as a best-effort signal.
        related_ids = finding.get("related_pointers") or []
        if related_ids:
            matching_logs = [log for log in execution_logs if log.get("pointer_id") in related_ids]
        else:
            matching_logs = execution_logs[-5:]

        # Flag static-origin findings: if a related command was a semgrep scan,
        # this bug started as a SAST candidate and was then dynamically proven —
        # make that provenance explicit in the advisory.
        static_origin = any(
            (log.get("command") or "").strip().startswith("semgrep")
            for log in execution_logs
            if log.get("pointer_id") in related_ids
        )
        if static_origin:
            details = f"_(Static candidate found by SAST, dynamically confirmed.)_\n\n{details}"

        # Save dedicated evidence dump
        evidence_filename = f"evidence_{finding_id}_{slug_title}.txt"
        evidence_path = EVIDENCE_DIR / evidence_filename

        evidence_buffer = [f"=== EVIDENCE DUMP FOR {finding_id}: {title} ===", f"Timestamp: {timestamp}\n"]

        reproduction_steps = []
        for log_idx, log in enumerate(matching_logs[-5:], 1):  # Last relevant commands
            pid = log.get("pointer_id")
            cmd = log.get("command")
            rc = log.get("return_code")
            summary = log.get("summary")

            reproduction_steps.append(f"{log_idx}. **Execute CLI Verification:**\n   ```bash\n   {cmd}\n   ```\n   *Output Signature:* `{summary}` (Exit code: `{rc}`)\n")
            
            raw_log = load_artifact_content(pid)
            evidence_buffer.append(f"--- [Pointer: {pid}] CMD: {cmd} ---\n{raw_log}\n")

        evidence_path.write_text("\n".join(evidence_buffer))

        # Build Individual Report Content
        poc_block = evidence_poc.strip() if evidence_poc else (
            "_No inline PoC captured — see the reproduction commands and evidence log below._"
        )

        # Chain context: if this finding links into a larger path, show it —
        # composed impact is the real severity story.
        chain_bits = []
        for nxt in finding.get("chain_to", []) or []:
            nt = next((f.get("title") for f in findings if f.get("id") == nxt), nxt)
            note = (finding.get("chain_notes", {}) or {}).get(nxt, "")
            chain_bits.append(f"  - enables `{nxt}` — {nt}" + (f" _({note})_" if note else ""))
        chain_section = ("\n## Chain Impact (this finding enables)"
                         + ("\n".join(chain_bits) if chain_bits
                            else "\n_Standalone finding (no chain edges; see SUMMARY for paths)._")
                         + "\n") if chain_bits else ""
        report_lines = [
            f"# Vulnerability Advisory: {title}",
            f"**Advisory ID:** `{finding_id}`  ",
            f"**Severity:** `{severity.upper()}`  ",
            f"**Status:** `CONFIRMED`  ",
            f"**Target:** `{target}`  ",
            f"**Date Identified:** `{timestamp}`  ",
            f"**Evidence File:** `reports/evidence/{evidence_filename}`  ",
            "\n---",
            "\n## 1. Executive Summary & Impact",
            f"{details}",
            "\n## 2. Proof of Concept",
            "```text",
            poc_block,
            "```",
            "\n## 3. Step-by-Step Reproduction Steps",
            "\n".join(reproduction_steps) if reproduction_steps else "_Execute the verification commands stored in the evidence log._",
            "\n## 4. Key Disclosures & Captured Artifact Highlights",
            "```text",
            extract_juicy_details("\n".join(evidence_buffer)),
            "```",
            chain_section,
            "\n## 5. Remediation & Defense",
            "- **Input Validation:** Enforce strict type, length, and format whitelisting on all incoming fields.",
            "- **Access Control:** Verify authentication and authorization checks on the server side prior to processing data.",
            "- **Output Encoding:** Sanitize and restrict returned debug headers, paths, and internal error stacks.",
            "\n---",
            f"_Generated by Artifactory Engine at {datetime.now(timezone.utc).isoformat()}_"
        ]

        report_path.write_text("\n".join(report_lines))
        generated_files.append((finding_id, title, report_filename, severity))
        print(f"[✔] Created advisory: reports/{report_filename}")

    # 2. Generate Consolidated Project Summary (SUMMARY.md)
    summary_path = REPORTS_DIR / "SUMMARY.md"
    summary_lines = [
        f"# Security Assessment Summary: {target}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Confirmed vulnerabilities:** {len(confirmed)}  |  "
        f"**Informational observations:** {len(informational)}\n",
        "## Discovered Attack Surface",
        f"- **Hosts:** {', '.join(assets.get('hosts', [])) or 'None'}",
        f"- **Open Ports:** {', '.join(assets.get('open_ports', [])) or 'None'}",
        f"- **Endpoints Mapped:** {', '.join(assets.get('endpoints', [])) or 'None'}\n",
        "## Confirmed Vulnerabilities (Individual Advisories)",
    ]

    if not generated_files:
        summary_lines.append("_No confirmed vulnerabilities. Findings below are unverified observations only._")
    else:
        for fid, ftitle, fname, fsev in generated_files:
            summary_lines.append(f"- **[{fsev.upper()}]** `{fid}` [{ftitle}](./{fname})")

    # Informational observations — explicitly NOT confirmed vulnerabilities.
    summary_lines.append("\n## Informational Observations (unconfirmed — not vulnerabilities)")
    if not informational:
        summary_lines.append("_None._")
    else:
        for f in informational:
            sev = f.get("severity", "info").upper()
            summary_lines.append(
                f"- **[{sev}]** {f.get('title', 'Observation')} — {f.get('details', '')} "
                f"_(no PoC/evidence; verify before reporting)_"
            )

    # Demonstrated attack paths (chain graph): composed impact > isolated findings.
    edges = []
    by_id = {f.get("id"): f for f in findings}
    for f in findings:
        for b in f.get("chain_to", []):
            note = f.get("chain_notes", {}).get(b, "")
            edges.append((f.get("id"), b, note))
    # B1: hypo_edges (planner-proposed, UNPROVEN) render in a separate labeled
    # section — never inside Demonstrated. Labels resolve for findings AND leads
    # (no bare LEAD_xxx / dangling nodes).
    from chain_planner import label_for as _label_for
    hypo = []
    for e in board_data.get("hypo_edges", []):
        a, b = e.get("from"), e.get("to")
        if a and b:
            hypo.append((a, b, e.get("why", "")))
    summary_lines.append("\n## Demonstrated Attack Paths (finding chains)")
    if not edges:
        summary_lines.append("_No chains recorded — see `sec_flow.py chains --mine` to compose impact._")
    else:
        graph = {}
        for a, b, _ in edges:
            graph.setdefault(a, []).append(b)

        def walk(start, path=None):
            path = path or [start]
            best = [path]
            for nxt in graph.get(start, []):
                if nxt in path:
                    continue
                best.append(walk(nxt, path + [nxt]))
            return max(best, key=len)

        longest = []
        for fid in by_id:
            p = walk(fid)
            if len(p) > len(longest):
                longest = p
        for a, b, note in edges:
            ta = (by_id.get(a, {}).get("title") or "?")[:60]
            tb = (by_id.get(b, {}).get("title") or "?")[:60]
            summary_lines.append(f"- `{a}` **{ta}** → `{b}` **{tb}**" + (f" — _{note}_" if note else ""))
        if len(longest) > 1:
            steps = " → ".join(f"`{fid}`" for fid in longest)
            summary_lines.append(f"\n**Longest demonstrated path ({len(longest)} steps):** {steps}")
    if hypo:
        summary_lines.append("\n## Hypothesized Paths (UNPROVEN — planner proposals)")
        summary_lines.append("_Hypo edges never count as demonstrated impact; confirm hops with evidence to promote them._")
        for a, b, why in hypo[:12]:
            la, lb = _label_for(a, board_data), _label_for(b, board_data)
            summary_lines.append(f"- ~~`{a}` **{la}** ~~> `{b}` **{lb}**~~ — _{why[:100]}_")

    # Coverage gaps (no-silent-drops): every lead that never reached a terminal
    # state is an explicit blind spot in this engagement — surface them so
    # 'we didn't test X' is visible instead of silently dropped.
    leads = board_data.get("leads", [])
    open_leads = [l for l in leads if l.get("status") not in ("confirmed", "dead")]
    summary_lines.append("\n## Coverage Gaps (unworked/unresolved leads — potential blind spots)")
    if not open_leads:
        summary_lines.append("_All leads were worked to a terminal state (confirmed/dead)._")
    else:
        by_status = {}
        for l in open_leads:
            by_status.setdefault(l.get("status", "?"), []).append(l)
        stat_bits = [f"{len(v)} `{k}`" for k, v in sorted(by_status.items())]
        summary_lines.append(
            f"**{len(open_leads)} lead(s) never resolved** ({', '.join(stat_bits)} of "
            f"{len(leads)} total). Highest-confidence unworked items:"
        )
        open_sorted = sorted(open_leads, key=lambda l: l.get("confidence", 0), reverse=True)
        for l in open_sorted[:10]:
            pre = f" — preconditions: {'; '.join(l['preconditions'])}" if l.get("preconditions") else ""
            summary_lines.append(
                f"- **[{l.get('confidence')}]** ({l.get('type')}/{l.get('status')}) "
                f"{l.get('value')}{pre}"
            )
        if len(open_sorted) > 10:
            summary_lines.append(f"- _...and {len(open_sorted) - 10} more (see board.json `leads`)._")

    # WS7: 'How we got here' — the decision journal, so a reader can see WHY the
    # engine did what it did and HOW each result was reached.
    rationale = load_rationale()
    if rationale:
        summary_lines.append("\n## How We Got Here (Decision Journal)")
        for r in rationale:
            lead = r.get("lead_id") or "-"
            summary_lines.append(
                f"- `{r.get('timestamp', '')}` [{lead}] **{r.get('action', '')}** — "
                f"hypothesis: _{r.get('hypothesis', '')}_; why: {r.get('why_chosen', '')}; "
                f"outcome: **{r.get('outcome', 'n/a')}** "
                f"{'(ptr ' + r['pointer_id'] + ')' if r.get('pointer_id') else ''}"
            )

    summary_path.write_text("\n".join(summary_lines))
    print(f"[✔] Created summary index: reports/SUMMARY.md")


if __name__ == "__main__":
    generate_individual_reports()
