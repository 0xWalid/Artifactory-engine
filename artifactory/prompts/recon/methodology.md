# Micro-Playbook: Recon Methodology
**Practitioner / Methodology:** Jason Haddix (TBHM) · PortSwigger Research · OWASP WSTG
**Category:** recon

> This is a DECISION GUIDE, not a script. Do NOT run every command. Read the
> target's signals, run only what fits, and stop once you have enough to form an
> attack theory. All commands go through
> `sec_flow.py run --cmd "<tool ...>" --target "{{TARGET_HOST}}"`, and every
> output is digested into ranked `leads` by the background Scout — consume leads,
> not raw output.

## Operating Principles
1. **Passive before active.** Do not send a packet to the target until passive
   sources are exhausted. This is the only always-on rule.
2. **Active recon is triggered by need**, not run wholesale. Each step in Phase B
   has a trigger — if the trigger is not met, skip that step.
3. **Heavy/slow scans go to the background:** add `--bg`, then read `leads`.
4. **Be polite by default:** rate-limit and cap concurrency (profiles below).
   Localhost/lab targets have no network cost — scan freely there.
5. **Stop early.** Enough recon to form a hypothesis beats exhaustive mapping.

## Decision Map (signal → next action)
| You have / see | Do this | Skip if |
| --- | --- | --- |
| A domain / wildcard scope | Passive subdomain + cert-log enum (Phase A) | Bare IP, no domain |
| New subdomains resolved | Probe each for its own surface (B4) | None resolve |
| A live host / IP | Polite service map, `nmap -T3` (B1) | Already fully mapped |
| An open web port | Tech fingerprint (B2), then content discovery (B3) | Not HTTP(S) |
| A tech / framework banner | Map that stack's default paths + known CVEs | Banner unknown |
| Nothing new surfacing | STOP recon, pivot to testing the leads | — |

## Phase A — Passive (always first, no packets to the target)
Trigger: the engagement has a domain / company scope.
- Certificate transparency: `curl -s "https://crt.sh/?q=%25.{{TARGET_HOST}}&output=json"`
- Passive subdomains: `subfinder -silent -d {{TARGET_HOST}}`
- Historical URLs: `curl -s "http://web.archive.org/cdx/search/cdx?url=*.{{TARGET_HOST}}/*&output=text&fl=original&collapse=urlkey"`

For a bare IP or a localhost lab, passive sources rarely apply — note that and move to Phase B.

## Phase B — Active, triggered (polite by default)
Run a step ONLY if its trigger (see Decision Map) is met.

- **B1 — Host / service map.** Trigger: a live host to characterize.
  `nmap -sV -T3 --top-ports 1000 {{TARGET_HOST}}`  (escalate to `-p-` only if the top-ports result justifies it)
- **B2 — Web tech fingerprint.** Trigger: an open HTTP(S) port.
  `curl -sSI {{TARGET_URL}}`  (or `httpx -title -tech-detect -status-code -u {{TARGET_URL}}`)
- **B3 — Content discovery.** Trigger: a confirmed web app. Run with `--bg`.
  `ffuf -u {{TARGET_URL}}/FUZZ -w <wordlist> -mc 200,204,301,302,401,403 -rate 50 -t 20`
- **B4 — Subdomain probing.** Trigger: subdomains found in Phase A.
  `httpx -silent -status-code -title` over the resolved hosts.

## Politeness / Rate Profiles
- **nmap:** default `-T3`; add `--max-rate 100` on fragile or remote targets. Avoid `-T4`/`-T5` off-lab.
- **ffuf / gobuster:** `-rate 50 -t 20` (lower for shaky targets); add `-p 0.1` for jitter.
- **Localhost / lab (e.g. 127.0.0.1):** loopback, zero internet cost — timing/rate caps are unnecessary.

## Hand-off to Testing
Every command's output is auto-triaged into ranked `leads` (anomaly > port/endpoint > tech). Pull them with `python3 ~/artifactory/sec_flow.py leads`, work them top-down, and pivot into vector testing (`/artifactory test <target> for <vuln>`) as soon as a lead suggests a hypothesis. Deepen recon in the background as you go — do not front-load it and burn the budget.
