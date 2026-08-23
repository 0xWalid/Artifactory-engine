# SAST Guided Questions: Path Traversal / Arbitrary File Access

**Usage:** For a `sast` path-traversal hit, at **low temperature** make the model
*describe the data flow* via the questions below before ruling TP/FP. Prove
survivors at runtime against the in-scope host before `confirmed`.

## Describe-the-flow questions (answer each, cite line numbers)
1. What filesystem API is the sink (`open`, `read_file`, `sendFile`,
   `File(...)`, `include`/`require`, archive extraction)?
2. Where does the path segment originate and is it **user-controllable**?
3. Is the input **joined** to a base directory, used **as-is**, or normalised?
   Show the join/normalise call.
4. Is there a **canonicalisation + containment check** (resolve realpath, then
   assert it stays under an allowed root) AFTER joining — or only a naive
   substring/`..` filter that normalisation could bypass?
5. Can `../`, absolute paths, symlinks, NUL bytes, or URL/'%2e' encodings reach
   the sink unfiltered?
6. What is the effective **base directory** and what would escaping it expose?

## Ruling
- **False Positive** if the resolved path is provably contained under an allowed
  root after canonicalisation, or the segment is not user-controllable.
- **Keep (candidate)** otherwise → PoC reads a benign in-scope marker file (e.g.
  a known-safe path), never sensitive host data; log with evidence.
