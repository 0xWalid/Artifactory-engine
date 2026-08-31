# Chaining Methodology: Composing Findings into Attack Paths

> Practitioner: Artifactory engine synthesis (references: PortSwigger research chainning writeups, OWASP attack-path modeling, real disclosed HackerOne chains).

Chaining is where low-severity findings compose into critical impact. A reflected XSS alone is medium; a reflected XSS + a CSRF-token leak + an admin function = account takeover. The engine's chain graph (`sec_flow.py chains`) makes this a first-class operation.

## Preconditions & Indicators
- >= 2 findings on the board (any severity; informational observations can seed chains too — they just can't be the final link without evidence).
- The final link of a chain must be a `confirmed` finding with evidence. The chain itself demonstrates end-to-end impact.

## Enumeration (build the graph from the board)
1. Pull all findings + their evidence pointers:
   `sec_flow.py` board state — findings are keyed FINDING_*; every finding carries `related_pointers` (what it was proven with) and `evidence_pointer`.
2. For each finding, list its PRIMITIVES (what capability does it grant?):
   - read X / write X / execute / authenticate-as / reach network / leak secret / change state
3. For each finding, list its NEEDS (what would upgrade its impact?):
   - needs a victim, needs a token, needs an internal host, needs write access

## Diagnostic Checks (edge candidates — when does A enable B?)
A -> B is a valid chain edge when A's PRIMITIVE satisfies B's NEED:
| A primitive | Satisfies B needing |
|---|---|
| leak secret/token | authenticate-as, CSRF bypass, API access |
| reach network (SSRF) | internal-only endpoint, cloud metadata (169.254.169.254) |
| XSS in origin O | cookie theft, CSRF bypass (SameSite), request forgery as victim |
| IDOR read object | pivot to write? (test same flaw for PUT/DELETE) |
| file read | source/secret disclosure (config, .env, keys) -> new findings |
| low-priv write | privilege escalation paths (role fields, group membership) |

4. Test the composed path END-TO-END: the chain must be demonstrated, not inferred. Execute A, capture its output, feed it into B, capture B's proving response.
5. Record the edge: `sec_flow.py chains --link FINDING_A,FINDING_B --note "A's leaked token authenticates B's admin action"`.

## Verification & Impact
- A chain is verified when the FINAL link produced evidence and every intermediate link was exercised during the demonstration (pointer artifacts exist for each step).
- Impact statement = final link's impact, prefixed by the chain: "3-step chain: reflected token leak -> session fixation -> admin password reset -> full account takeover".
- View demonstrated paths: `sec_flow.py chains` (longest attack path is highlighted).

## Escalation & Chaining
- Cloud metadata is a chain multiplier: any SSRF is one hop from credential theft (`http://169.254.169.254/latest/metaleta/iam/...`).
- File-read primitives chain into config disclosure which chains into new findings (DB creds -> direct DB reach if in scope).
- Ask "what does the attacker HOLD after this chain?" — each additional held primitive is a new chain root.
- Grep the board for unused primitives: any finding whose primitive satisfies no recorded NEED is an unexplored edge — file it as a lead.
