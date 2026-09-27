# MUTATION_TESTING.md
# SECUREFIX X — Phase 4: Controlled Security Patch Mutation Testing

**Status:** Phase 4 complete. All 237 backend tests pass.  
**Scope:** `backend/app/verification/mutation.py` · `backend/app/models.py`  
**Tests:** `backend/tests/test_mutation_phase4.py`

---

## 1. Why Controlled Security Mutation Testing Exists

SECUREFIX Phases 1–3 answer:

> "Does the repaired application resist the adversarial attack?"

This is necessary but not sufficient.

A verification suite can produce false confidence if it would accept a plausibly incorrect patch.
Phase 4 adds a second-order assurance question:

> "Would our verification system detect a plausible faulty security patch?"

This requires deliberately creating a small set of faulty patches and verifying that the
existing verification suite catches them.

If the verification suite fails to detect a faulty patch:

- That is valuable evidence about a **verification gap**
- It is reported as **SURVIVED**, not hidden
- The test does not "fail" — the *verification* failed, and that is the finding

---

## 2. SECUREFIX Mutation Testing vs General Mutation Testing

| Property | Generic mutation testing | SECUREFIX security mutation testing |
|---|---|---|
| **Purpose** | Measure test suite coverage | Measure security verification sensitivity |
| **Mutant source** | Automated syntactic transforms (any code) | Allowlisted security-specific transforms |
| **Scope** | Entire codebase | Security boundary only |
| **Execution target** | Test suite | Security oracle + legitimate-use checks |
| **Outcome of concern** | Surviving mutant = untested code path | Surviving mutant = verification gap |
| **Isolation** | Often in-process | Always isolated disposable copy |
| **Determinism** | May be probabilistic | Fully deterministic |
| **Arbitrary code execution** | Common | Explicitly prohibited |

SECUREFIX mutation testing is not generic fault injection.  It produces a bounded, structured
set of plausible faulty security patches and measures whether the verification suite detects them.

---

## 3. Supported Mutant Types

Phase 4 supports exactly four allowlisted mutation types.  No others can be applied
without a code change.

### 3.1 REMOVE_OWNERSHIP_CHECK

**What it does:** Removes the ownership authorization check from the patched endpoint.
The endpoint remains authenticated but reverts to the baseline BOLA-vulnerable state.

**Expected detection dimension:** `security_resistance` — the adversarial exploit replay
will succeed (BYPASS).

**SecureBank behavior:** On the baseline (unpatched) app, the ownership check is already
absent — this mutant applies trivially and results in the already-vulnerable state.
DETECTED via security_resistance.

### 3.2 INVERT_OWNERSHIP_COMPARISON

**What it does:** Inverts `!=` to `==` in the ownership comparison, so the authorization
decision is logically reversed: owners are denied and non-owners are permitted.

**Expected detection dimension:** `security_resistance` (non-owner gets through) AND/OR
`legitimate_behavior` (owner is denied).

**SecureBank baseline note:** The baseline SecureBank has no ownership check to invert.
The mutation is UNSUPPORTED on the baseline app — this is an honest result, not a failure.
When applied to a patched app with the check present, it would be DETECTED.

### 3.3 SIBLING_ROUTE_UNPROTECTED

**What it does:** Protects the primary account route while leaving the transactions sibling
route without an ownership check.

**Expected detection dimension:** `verification_sensitivity` via sibling-route variant — the
Phase 3 AdversarialVariant for the sibling route detects the bypass.

**SecureBank behavior:** The transactions route is already unprotected in the baseline app.
This mutant confirms the sibling route is unprotected and documents the detection path.

### 3.4 UNCONDITIONAL_DENIAL

**What it does:** Replaces the ownership check with an unconditional 403 that blocks
all authenticated users including the legitimate owner.

**Expected detection dimension:** `legitimate_behavior` — the owner is denied access
(legitimate-use contract check fails).  The attacker is also blocked, but blocking the
attacker is not sufficient evidence of a correct fix.

This is the most important mutant type.  It demonstrates that:

> "An endpoint that denies everyone appears secure against the attack  
> but breaks legitimate use — and that failure must be detected."

---

## 4. Isolation Model

Every mutation trial operates on a **disposable temporary copy** of the target application.

```
Original working tree          Isolated copy (tmp dir)
─────────────────────          ──────────────────────────
demo-app/                      /tmp/securefix_mutant_XXXX/
  app/routes/accounts.py  ──▶  app/routes/accounts.py  ← MUTATED here
  app/routes/transactions.py   app/routes/transactions.py
  [unchanged throughout]       [destroyed after trial]
```

### Isolation lifecycle

```
1. _create_isolated_copy(source_path)
   → shutil.copytree to tempfile.mkdtemp()
   → returns (absolute_path, sanitized_reference)
   → sanitized_reference = basename only (not absolute path)

2. _apply_mutation(isolated_path, mutant)
   → reads and writes files inside isolated_path only
   → verifies pattern found before claiming success
   → returns (applied: bool, note: str)

3. _run_checks_in_isolation(isolated_path, invariant)
   → subprocess TestClient with cwd=isolated_path
   → credentials passed as json.loads() — never via shell args

4. _classify_detection(result, mutant, checks)
   → maps checks to three assurance dimensions
   → DETECTED / SURVIVED / ERROR / UNSUPPORTED

5. shutil.rmtree(isolated_path)
   → always executed in finally block
   → result.cleanup_completed = True on success
```

The original working tree is verified unchanged by `TestWorkingTreeIntegrity` tests that
hash the relevant files before and after each mutation trial.

---

## 5. Detection Semantics

### DETECTED

At least one assurance dimension identified behavior inconsistent with the SecurityInvariant.

| Mutant type | Detection dimension |
|---|---|
| REMOVE_OWNERSHIP_CHECK | `security_resistance` — attacker succeeds (BYPASS) |
| INVERT_OWNERSHIP_COMPARISON | `security_resistance` and/or `legitimate_behavior` |
| SIBLING_ROUTE_UNPROTECTED | `security_resistance` via sibling-route variant |
| UNCONDITIONAL_DENIAL | `legitimate_behavior` — owner denied (BYPASS) |

### SURVIVED

All verification checks passed — the faulty patch was not detected.

This is a **verification gap finding**, not a test pass.  It must be reported explicitly.
The `MutationResult.survived_detail` field records which check was expected to detect
the mutant and did not.

### ERROR

The trial could not execute cleanly:
- Application crashed
- Subprocess timed out
- Environment failure
- Import error

An ERROR result is **not** evidence that the mutation was caught.  A crashing application
is not a security control.

### UNSUPPORTED

The mutation could not be applied:
- Target pattern not found in the file (e.g. INVERT on a baseline file with no check)
- Target file not found
- Mutation type not applicable to this invariant class

UNSUPPORTED is an honest result.  It documents a limitation, not a failure.

---

## 6. PASS/FAIL vs DETECTED/SURVIVED

These are different things:

| Concept | What it means |
|---|---|
| VerificationCheck.status = "passed" | One check ran and the observed behavior matches expected |
| VerificationCheck.status = "failed" | One check ran and found a violation |
| MutationDetectionState.DETECTED | A mutant trial found at least one violation |
| MutationDetectionState.SURVIVED | A mutant trial found no violations — gap identified |

A mutation trial where UNCONDITIONAL_DENIAL causes:
- `security_resistance` = PASS (attacker blocked — good)  
- `legitimate_behavior` = BYPASS (owner blocked — bad)

is classified as DETECTED — because the *legitimate_behavior* dimension caught the flaw.
The PASS on security_resistance does not override the BYPASS on legitimate_behavior.

The three dimensions are **never collapsed into a single score**.

---

## 7. Three Assurance Dimensions

```python
MutationResult.security_resistance:    MutationAssuranceDimension
    # Does the faulty patch still resist the adversarial attack?
    # PASS   = attacker blocked (mutant evaded this check)
    # BYPASS = attacker succeeded (mutant detected by this dimension)

MutationResult.legitimate_behavior:    MutationAssuranceDimension
    # Does the faulty patch still allow legitimate owner access?
    # PASS   = owner can access own resource
    # BYPASS = owner denied (regression — mutant detected by this dimension)

MutationResult.verification_sensitivity: MutationAssuranceDimension
    # Combined: was the mutant detected by EITHER dimension?
    # BYPASS = yes, detected
    # PASS   = no, survived (gap)
    # ERROR  = inconclusive
```

---

## 8. Error Handling

| Situation | Classification | Rationale |
|---|---|---|
| Application crashes | ERROR | Crash ≠ security control |
| Subprocess timeout | ERROR | Result is inconclusive |
| Mutation target not found | UNSUPPORTED | Honest limitation |
| Target file not found | UNSUPPORTED | Honest limitation |
| Source path missing | ERROR | Environment failure |
| No SecurityInvariant | Empty assessment | Prerequisite missing |
| Non-BOLA invariant | Empty assessment | Phase 4 scope is BOLA only |

---

## 9. Evidence Generated

Each `MutationResult` carries a sanitized `evidence` dict containing:

```python
{
    "isolation_reference": "securefix_mutant_XXXX_YYYY",  # basename only
    "mutation_type": "remove_ownership_check",
    "affected_file": "app/routes/accounts.py",            # relative path
    "mutation_applied": True,
    "mutation_note": "Ownership check removed from patched endpoint",
    "check_count": 2,
    "observed_outcomes": [
        {"name": "Exploit replay (mutant)", "status": "failed",
         "outcome": "bypass", "status_code": 200},
        {"name": "Legitimate-use contract (mutant)", "status": "passed",
         "outcome": "pass", "status_code": 200},
    ],
    "detection_state": "detected",
    "detected_by": {
        "security_resistance": True,
        "legitimate_behavior": False,
    }
}
```

**What evidence must not contain:**
- Passwords or auth credentials
- Absolute filesystem paths beyond the sanitized reference
- Arbitrary system information

---

## 10. Current SecureBank Demonstration

Given the SecureBank BOLA scenario with the baseline (vulnerable) application:

| Mutant | Applied? | security_resistance | legitimate_behavior | detection_state |
|---|---|---|---|---|
| REMOVE_OWNERSHIP_CHECK | ✅ (already absent) | BYPASS (200 returned) | PASS | **DETECTED** |
| INVERT_OWNERSHIP_COMPARISON | ❌ (check absent in baseline) | — | — | UNSUPPORTED |
| SIBLING_ROUTE_UNPROTECTED | ✅ (already unprotected) | BYPASS (sibling route) | PASS | **DETECTED** |
| UNCONDITIONAL_DENIAL | ✅ | PASS (attacker blocked) | BYPASS (owner denied) | **DETECTED** |

### Notes on the INVERT_OWNERSHIP_COMPARISON result

The baseline SecureBank app has no ownership check — there is nothing to invert.
This mutant returns UNSUPPORTED with the explanation "Ownership check pattern not found".

This is the correct, honest result.  The mutant becomes meaningful when applied to a
patched version of accounts.py that contains:

```python
if row["user_id"] != current_user["id"]:
    raise HTTPException(status_code=403, detail="Access forbidden")
```

When that check is present, INVERT_OWNERSHIP_COMPARISON would change `!=` to `==`,
producing an endpoint that denies owners and permits non-owners.  The verification suite
would detect this via both assurance dimensions.

### Key demonstration: UNCONDITIONAL_DENIAL

The UNCONDITIONAL_DENIAL mutant inserts:

```python
raise HTTPException(status_code=403, detail="Access forbidden")
```

unconditionally before the return statement.  This causes:

- Attacker GET /api/accounts/2 → 403 → security_resistance = PASS
- Owner GET /api/accounts/1 → 403 → legitimate_behavior = BYPASS

Detection state: **DETECTED** — because blocking everyone is not a correct security fix.

The verification suite correctly distinguishes "properly restricted" from "deny all."

---

## 11. Known Limitations

1. **BOLA only.** Phase 4 mutation testing covers CWE-639/BOLA exclusively.
   SQL injection, path traversal, command injection, and other classes require
   separate mutation strategies.

2. **Four mutation types only.** The allowlist is intentionally narrow.
   Arbitrary mutations are not permitted.

3. **Baseline app.** Two of the four mutants (REMOVE, SIBLING_UNPROTECTED) are
   effectively testing the baseline vulnerable state.  INVERT and a
   "correct-but-incomplete patch" scenario require a patched app.

4. **TestClient, not live server.** Verification uses FastAPI's TestClient subprocess.
   It does not exercise TLS, rate limiting, or production middleware.

5. **No automatic remediation.** Surviving mutants are reported as verification gaps —
   the system does not automatically improve the verification suite.

6. **INVERT_OWNERSHIP_COMPARISON** is UNSUPPORTED on the baseline app.  This is
   expected behavior, not a bug.  It will produce DETECTED when applied to a patched app.

7. **No mutation score.** The assessment reports counts per dimension, not a single
   coverage percentage.  A single number would obscure which dimension has gaps.

The appropriate conclusion when all tested mutants are detected is:

> **VERIFIED WITHIN TESTED SCOPE**

with explicit acknowledgment of what is outside the tested scope.

---

## 12. Files

| File | Role |
|---|---|
| `backend/app/verification/mutation.py` | MutationEngine + mutation strategies |
| `backend/app/models.py` | `MutationType`, `MutationExecutionStatus`, `MutationDetectionState`, `SecurityMutant`, `MutationAssuranceDimension`, `MutationResult`, `MutationAssessment` |
| `backend/tests/test_mutation_phase4.py` | 64 Phase 4 tests |

---

## 13. Test Coverage

```
tests/test_mutation_phase4.py       64 tests
  TestMutantModel                    7 — model validation
  TestMutationTypesAllowlisted       4 — allowlist enforcement
  TestMutationScopeControl           5 — path / target scope
  TestMutantBuilding                 8 — four mutant definitions
  TestIsolation                      4 — isolated copy lifecycle
  TestWorkingTreeIntegrity           3 — original unchanged
  TestMutationApplication            4 — each mutation type applied
  TestMutationTargetVerification     3 — target-not-found → UNSUPPORTED
  TestErrorSemantics                 3 — crash/error → ERROR not DETECTED
  TestAssuranceDimensions            3 — three dimensions separate
  TestDetectionClassification        5 — DETECTED/SURVIVED/ERROR logic
  TestMutationAssessment             5 — aggregate assessment model
  TestNoCredentialsInEvidence        3 — evidence sanitization
  TestLiveSecureBankMutation         7 — end-to-end against demo-app

Total (Phase 4):                    64 tests
Total (all backend tests):         237 tests, 237 passing
Demo-app tests:                      3 tests, 2 passing, 1 intentionally failing (BOLA)
Working-tree integrity:              CLEAN — no changes to demo-app source
```
