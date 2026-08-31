# Fuzz-Harness Generation: LLM Authors, Machine Fires

> Practitioner: Artifactory engine synthesis (references: AFL++ docs, libFuzzer docs, OSS-Fuzz architecture, Google "Fuzzing: the science of making bugs" writeups). Division of labor: an LLM writes the harness ONCE (it's good at API-shape reasoning), the fuzzer runs it millions of times at ZERO token cost.

## Preconditions & Indicators
- White-box: source available under an authorized code path (`scope --add-code-path`).
- A fuzzable target: a function that parses/decodes/transforms untrusted input (parsers, deserializers, protocol handlers, file-format decoders).
- `afl-gcc`/`clang -fsanitize=fuzzer` available, OR a black-box HTTP surface where a template/grammar fuzzer (ffuf + custom wordlists, radamsa) applies instead.

## Enumeration (pick the harness style)
1. **libFuzzer style (C/C++)**: target function -> `LLVMFuzzerTestOneInput` shim that feeds bytes to the parser. Best when the code compiles standalone.
2. **AFL++ style**: forkserver/persistent-mode harness when the function needs a driver loop.
3. **Python property harness**: `hypothesis`-style invariants for pure-Python parsers (cheaper to write, slower per exec).
4. **Black-box grammar**: when no source — mutate captured request templates with radamsa and replay through `sec_flow.py run` (rate-limit aware).

## Diagnostic Checks (author the harness)
5. Read ONLY the flagged function + its direct callees (`sec_flow.py inspect --id <PTR>` on the sast lead's artifact) — never the whole codebase.
6. Write the harness: initialize once OUTSIDE the fuzz entry, feed the input, check return/abort. Add a sanitizer build (`-fsanitize=address,undefined`).
7. Seed corpus: 10-20 minimal valid inputs (the LLM writes them from the format's shape — no downloads).
8. Build + smoke-run locally for 60s: `clang -fsanitize=fuzzer harness.c parser.c && ./a.out -max_total_time=60` — a harness that finds its own assertion/SEGV in a minute is either buggy or already winning.

## Verification & Impact
9. Run the real campaign detached (hours/days, zero tokens): `sec_flow.py run --bg --cmd "./a.out -max_total_time=86400 -artifact_prefix=crashes/"`.
10. On a crash: minimize (`./a.out crash-<id>` reproduces), reduce the input (`-minimize_crash=1`), then record a `sast`-style lead with the crash artifact as the evidence pointer — it still passes the verification gate (reproduce deterministically, assess impact) before becoming a finding.

## Escalation & Chaining
- Coverage-guided beats blind: add `-fsanitize-coverage=trace-pc-guard` and let the corpus compound.
- Chain crash -> exploitability: a sanitizer report (heap-overflow) files the lead; turning it into RCE/impact is the exploit agent's job.
- Dictionaries from format tokens (`-dict=`) massively help parser fuzzing — generate the dict from the seed corpus.
