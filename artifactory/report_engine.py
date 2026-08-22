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
