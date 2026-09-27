# Bob Session 03 — Adversarial Verification & Mutation Assurance

### Objective
Ensure that security patches are not merely syntactic changes, but robustly withstand adversarial bypasses and mutant testing.

### Tasks Completed with IBM Bob
1. **Adversarial Variant Generator (`app/verification/variants.py`):**
   - Synthesizes bounded attack variants (e.g. parameter manipulation, boundary conditions, URL encoding, type confusion) to probe whether the remediation can be circumvented.
2. **Controlled AST Mutation Engine (`app/verification/mutation.py`):**
   - Generates deliberate faulty mutants of the proposed patch (e.g. inverted boolean checks, removed authorization barriers, loosened regex).
   - Verifies whether the test suite detects and fails on these weakened mutants (calculating an empirical mutation score).
3. **Verification Independence:**
   - Enforced that deterministic test outputs (`PASS`, `BYPASS`, `ERROR`) cannot be overridden by AI confidence scores.
