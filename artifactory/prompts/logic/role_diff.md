# Role-Diff Methodology: Broken Access Control & IDOR at Scale

> Practitioner: Artifactory engine synthesis (references: OWASP WSTG 4.5 Authorization Testing / Access Control; PortSwigger Academy access-control labs; IDOR bug-pattern writeups). Broken access control is OWASP #1: a logic property invisible to injection scanners — but nearly FREE to test mechanically by replaying the endpoint inventory across roles and diffing.

## Preconditions & Indicators
- A mixed authenticated/unauthenticated target with >= 2 distinguishable roles (e.g. anon, user, admin).
- Sessions captured per role: `auth_manager.py add --role <role> --auth-type cookie|bearer|header --target <base> --credential '<value>'` (credential is stored OUT of context as a session artifact; the board only keeps the pointer).
- An endpoint inventory: crawl as the HIGHEST-privilege role first (that's your surface superset), one path per line.

## Enumeration (build the role matrix)
1. Register every role: admin, user, support, anonymous (anonymous = simply not registering a session; use it as a comparison baseline where useful).
2. Record expiry/rotation: if tokens rotate, put the re-obtain command in `--refresh-hook` (it runs outside any context).
3. `auth_manager.py list` — verify the full role matrix before diffing.

## Diagnostic Checks (the mechanical replay)
4. Baseline role = FIRST in the list. Replay every endpoint under every role:
   `auth_manager.py role-diff --base-url <base> --roles SESS_ADMIN,SESS_USER,SESS_ANON --endpoints endpoints.txt`
5. The engine normalizes volatile content (CSRF tokens, nonces, timestamps, request IDs) deterministically BEFORE comparing — a delta is therefore meaningful, not noise.
6. Every delta lands on the board as a `rolediff` lead: `sec_flow.py leads --type rolediff`.

## Verification & Impact (work the deltas)
7. For each delta lead, ask: SHOULD this role's response differ here?
   - Admin-only function returning 200+content to USER/ANON -> broken access control.
   - Same endpoint, object IDs in reach: swap IDs per role -> IDOR (test object ownership, not just status codes: 200 with ANOTHER user's data is the finding).
   - Verify manually with the proving request, then record: `sec_flow.py add-asset --finding "..." --status confirmed --evidence-from <POINTER> --poc "<request+response>"`.
8. Mass-assignment check (same replay logic): send role-bearing fields (`role`, `isAdmin`, `groupId`) as the LOW-priv role; diff the resulting object.

## Escalation & Chaining
- Chain IDOR read -> write: if the flaw ignores ownership on GET, test PUT/PATCH/DELETE on the same object route.
- Chain BAC -> function abuse: reaching an admin panel as user is step 1; enumerate its actual capabilities for step 2 (`sec_flow.py chains --link ...`).
- Role-diff the API DISCOVERY surface too: endpoints that 404 as anon but 200 as user are hidden-functionality leaks.
