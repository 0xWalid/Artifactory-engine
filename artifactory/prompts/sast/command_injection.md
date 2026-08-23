# SAST Guided Questions: OS Command Injection

**Usage:** For a `sast` command-injection hit, at **low temperature** make the
model *describe the data flow* via the questions below (flagged function +
callees; pull more with `sec_flow.py inspect`) BEFORE it rules TP/FP. Survivors
must be **proven at runtime** against the in-scope host before `confirmed`.

## Describe-the-flow questions (answer each, cite line numbers)
1. Which exact API executes the command (`system`, `exec*`, `popen`,
   `subprocess`, `child_process`, backticks, `Runtime.exec`)?
2. Is the command invoked **via a shell** (shell=True / `/bin/sh -c` / string
   form) or as a **direct argv array** with no shell?
3. Where is the injected value first declared and is it **user-controllable**?
4. Is the value used as the **program name**, an **argument**, or spliced into a
   **command string**?
5. What sanitisation sits between source and sink (allow-list, shell-quoting,
   arg-array construction)? Name it and state what it actually blocks.
6. Are shell metacharacters (`; | & $() \` > <`) reachable to the sink, or are
   they neutralised / impossible because there is no shell?

## Ruling
- **False Positive** if execution is a direct argv array (no shell) with the
  user value confined to a single argument, or input is strictly allow-listed.
- **Keep (candidate)** otherwise → craft a benign runtime PoC (e.g. a timing or
  echo marker, never destructive) and log with evidence.
