# SAST Guided Questions: SQL Injection

**Usage:** When a `sast` lead points at a SQLi rule hit, DO NOT ask the model "is
this a bug?". Instead, at **low temperature**, make it *describe the data flow* by
answering the questions below in order, using the flagged function + its callees
(pull more via `sec_flow.py inspect`). Only after the description does it rule
True Positive / False Positive. The verdict must then be **proven at runtime**
against the in-scope live host before it can become a `confirmed` finding.

## Describe-the-flow questions (answer each, cite line numbers)
1. Where is the value that reaches the SQL sink first **declared**, and what is
   its origin (request param, header, body, cookie, DB row, constant)?
2. Is that origin **user-controllable** end to end, or is it fixed/derived from
   trusted server state?
3. Between source and sink, is the value passed as a **bound parameter**
   (prepared statement / parameterised query) or **concatenated/interpolated**
   into the query string?
4. Is there any **validation, allow-listing, casting, or escaping** applied on
   the path to the sink? Name the function and what exactly it enforces.
5. Does an ORM / query builder sit in between? Does the flagged call use its
   safe parameter API or a raw/`literal`/`exec` escape hatch?
6. What **query context** does the value land in (WHERE value, column/table name,
   ORDER BY, LIMIT)? Identifier positions can't be parameterised — note that.

## Ruling
- **False Positive** if the value is not user-controllable, or reaches the sink
  strictly via a bound parameter with no identifier-position injection.
- **Keep (candidate)** otherwise → design a minimal, non-destructive runtime PoC
  (e.g. a boolean/time-based probe) against the live endpoint; log it with
  `add-asset --status confirmed --poc "<request+response>"`.
