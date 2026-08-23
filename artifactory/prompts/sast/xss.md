# SAST Guided Questions: Cross-Site Scripting (XSS)

**Usage:** For a `sast` XSS hit, at **low temperature** make the model *describe
the data flow* via the questions below before ruling TP/FP. Prove survivors at
runtime against the in-scope host before `confirmed`.

## Describe-the-flow questions (answer each, cite line numbers)
1. What is the sink (`innerHTML`, `document.write`, `dangerouslySetInnerHTML`,
   template raw-output, `v-html`, unescaped server template, `eval`)?
2. Where does the reflected/stored value originate and is it
   **user-controllable**?
3. Into which **output context** does it land (HTML body, attribute, JS string,
   URL, CSS, event handler)? Context decides the required encoding.
4. Is **context-appropriate encoding/sanitisation** applied at the sink (auto-
   escaping template, DOMPurify, encoder) or is output raw?
5. If a framework auto-escapes by default, is this an explicit **raw/bypass**
   API, and is a sanitiser wired correctly before it?
6. Is it **reflected, stored, or DOM**-based, and what user/session would fire it?

## Ruling
- **False Positive** if output is auto-escaped for its context, or the value is
  not user-controllable, or a correct sanitiser is provably applied at the sink.
- **Keep (candidate)** otherwise → PoC uses a **benign non-destructive marker**
  (e.g. `alert`-free DOM signal / logging payload) against the live endpoint;
  log with evidence.
