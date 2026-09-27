# Verification Engine — Phase 2: Invariant-Driven

> **Status:** Phase 2 complete. All 100 backend tests pass.

## Overview

The `VerificationEngine` executes after a patch is applied. It orchestrates five checks and
produces a `VerificationResult` with a formal `overall_status` and a list of `VerificationCheck`
records — each carrying both a legacy `status` string (backward-compatible) and a typed
`ExploitCheckOutcome` (PASS / BYPASS / ERROR / UNSUPPORTED).

The **key Phase 2 change** is that exploit replay and legitimate-use verification are now driven
entirely by the `SecurityInvariant` stored on the `Investigation`, rather than by
application-specific hardcoded assumptions.

---

## Architecture

```
Investigation
  └── security_invariant: SecurityInvariant
        ├── attack: AttackScenario          ← route, method, credentials, auth endpoint
        ├── oracle: SecurityOracle          ← blocked_outcome + violated_outcome
        └── legitimate_use: [LegitimateUseCase]   ← owner access contract
                    │
                    ▼
           VerificationEngine.verify()
                    │
         ┌──────────┼──────────────────┬──────────────────┬──────────────────┐
         ▼          ▼                  ▼                  ▼                  ▼
   Regression   Test Suite      Static re-scan    Exploit replay     Legitimate-use
   test write                                     (invariant-driven)  contract check
```

---

## Verification Checks (in order)

| # | Check name | Driven by | HTTP executed |
|---|---|---|---|
| 1 | Regression test written | `remediation.regression_test` | No |
| 2 | Test suite | pytest subprocess | No |
| 3 | Static security re-scan | `investigation.issue_description` patterns | No |
| 4 | Exploit replay blocked | `SecurityInvariant.attack` + `SecurityOracle` | **Yes** |
| 5 | Legitimate-use contract | `SecurityInvariant.legitimate_use` | **Yes** |
| 6 | Application build | `import app.main` subprocess | No |

Check 5 only executes when `invariant.supported is True` and `invariant.legitimate_use` is
non-empty.

---

## Outcome Taxonomy

`ExploitCheckOutcome` (enum, `backend/app/models.py`):

| Value | Meaning |
|---|---|
| `PASS` | Attack blocked OR owner access confirmed — invariant holds |
| `BYPASS` | Attack succeeded OR owner denied — invariant violated |
| `ERROR` | HTTP call failed / unexpected status / subprocess error — result inconclusive |
| `UNSUPPORTED` | No supported invariant available — manual verification required |

### Oracle evaluation logic (`_evaluate_oracle`)

```
status_code is None               → ERROR
status_code in forbidden_codes    → BYPASS   (invariant violated)
status_code in allowed_codes:
  any protected_data_indicator
  appears in response body        → BYPASS   (data leaked)
  otherwise                       → PASS     (invariant holds)
status_code in neither list       → ERROR    (unclassified response)
```

This logic is stateless and isolated in the module-level `_evaluate_oracle()` function,
making it independently unit-testable without any HTTP infrastructure.

---

## Backward Compatibility

`VerificationCheck.status` still holds the legacy strings used by the existing API and UI:

| Outcome | Legacy `status` |
|---|---|
| PASS | `"passed"` |
| BYPASS | `"failed"` |
| ERROR | `"failed"` |
| UNSUPPORTED | `"skipped"` |

This mapping is applied automatically by `VerificationCheck.set_outcome_fields()` and is
never set manually in the engine.

---

## HTTP Execution Strategy

Checks 4 and 5 execute real HTTP requests against the target application using FastAPI's
`TestClient` in a subprocess. The subprocess approach ensures test isolation and avoids
importing the target application's dependencies into the SECUREFIX backend process.

### Authenticated request flow

```
1. Read auth_endpoint + auth_credentials from invariant (scenario data)
2. POST to auth_endpoint with credentials dict → get access_token
3. Make exploit/owner request with Authorization: Bearer <token>
4. Return {status_code, body} as JSON on stdout
5. Engine parses JSON, calls _evaluate_oracle()
```

### Credential handling

Credentials are stored in the `SecurityInvariant` as **scenario data** — they belong to the
specific attack scenario, not to the engine. They are passed into the subprocess script via
`json.loads(...)` deserialization, never via shell arguments.

```python
# CORRECT — creds becomes a Python dict inside the script:
f"creds = json.loads({creds_json!r})\n"

# WRONG (pre-Phase-2 bug) — creds was a JSON string, causing 422 from FastAPI:
# f"creds = {creds_json!r}\n"
```

### Execution tiers (most preferred first)

1. **Authenticated TestClient** — when `attack.auth_endpoint` and `attack.auth_credentials` are set
2. **Unauthenticated TestClient** — when no auth is required (`attack.auth_endpoint` is None)
3. **Static fallback** — when HTTP execution fails entirely; returns UNSUPPORTED (not BYPASS)

The static fallback intentionally cannot return BYPASS — static code inspection cannot confirm
that an exploit succeeds.

---

## Fallback Behavior (No Invariant)

When `investigation.security_invariant` is absent or `invariant.supported is False`:

- Exploit check falls back to static code inspection of patched files
- Looks for ≥2 security-fix patterns (authorization check, 403 status, etc.)
- Returns `PASS` if patterns found, `UNSUPPORTED` otherwise
- `check.execution_error` records the reason

---

## Overall Status Aggregation

| Condition | `overall_status` |
|---|---|
| No failed checks | `"verified"` |
| Failed checks exist, but none are "Test suite" or "Static security re-scan" | `"partial"` |
| "Test suite" or "Static security re-scan" failed | `"failed"` |

`VerificationResult.exploit_blocked` is `True` only when the exploit-replay check outcome is
`ExploitCheckOutcome.PASS`.

---

## Key Invariants the Engine Does NOT Hardcode

The following values must come from the `SecurityInvariant`, never from the engine source:

| Not hardcoded | Where it lives |
|---|---|
| Attack route (e.g., `/api/accounts/2`) | `SecurityInvariant.attack.route_example` |
| HTTP method | `SecurityInvariant.attack.method` |
| Attacker credentials | `SecurityInvariant.attack.auth_credentials` |
| Auth endpoint | `SecurityInvariant.attack.auth_endpoint` |
| Expected blocked status codes | `SecurityInvariant.oracle.blocked_outcome.allowed_status_codes` |
| Expected bypass status codes | `SecurityInvariant.oracle.blocked_outcome.forbidden_status_codes` |
| Owner credentials | `SecurityInvariant.legitimate_use[0].auth_credentials` |
| Owner expected status codes | `SecurityInvariant.legitimate_use[0].expected_status_codes` |
| User names ("alice", "bob") | `SecurityInvariant.attack.auth_credentials` (scenario data) |
| Specific account IDs | `SecurityInvariant.attack.route_example` (scenario data) |

The test `test_no_hardcoded_alice_in_engine_source` (in `tests/test_verification_phase2.py`)
enforces this as an executable constraint.

---

## Modules

| File | Role |
|---|---|
| `backend/app/verification/engine.py` | Main engine |
| `backend/app/models.py` | `ExploitCheckOutcome`, `VerificationCheck`, `SecurityInvariant`, etc. |
| `backend/app/remediation/root_cause.py` | `derive_invariant()` — populates the invariant |
| `backend/app/orchestrator.py` | Phase 4b: calls `derive_invariant()`, stores on investigation |
| `backend/tests/test_verification_phase2.py` | 37 engine tests |
| `backend/tests/test_invariant.py` | 42 invariant model + derivation tests |
| `backend/tests/test_api.py` | 21 API/integration tests (includes `test_exploit_execution_detects_vulnerability`) |

---

## Test Coverage

```
tests/test_verification_phase2.py  37 tests
  TestEvaluateOracle               7 — pure oracle logic
  TestVerificationCheckOutcomeFields  5 — backward-compat status sync
  TestExploitCheck                 9 — _check_exploit_blocked()
  TestLegitimateUseCheck           4 — _check_legitimate_use()
  TestExploitCheckOutcomeEnum      3 — enum values / serialization
  TestCredentialFields             5 — credential model fields
  TestInvariantCredentialInference 4 — derive_invariant() credential population

tests/test_invariant.py            42 tests
  TestSecurityInvariantModel       7
  TestInvariantScope               2
  TestAttackScenario               1
  TestSecurityOracle               3
  TestLegitimateUseCase            1
  TestInvariantProvenance          2
  TestDeriveInvariantBOLA          16
  TestDeriveInvariantUnsupported   8
  TestInvestigationModelIntegration 3

tests/test_api.py                  21 tests (includes exploit test)

Total: 100 tests, 100 passing
```

---

## Known Limitations

1. **Single attack scenario** — only the first attack scenario in the invariant is executed.
   Adversarial variant generation (multiple variants) is a planned Phase 3 feature.

2. **BOLA/CWE-639 only** — `derive_invariant()` only produces a supported invariant for
   BOLA-class findings. SQL injection, path traversal, command injection, missing auth, and
   hardcoded secrets return `supported=False` and fall back to static checks.

3. **TestClient subprocess** — the subprocess approach means the demo application must be
   importable from `repo_path` with its own `.venv`. If the venv is absent, checks 4 and 5
   degrade gracefully to UNSUPPORTED.

4. **No live server mode** — all HTTP execution uses FastAPI's TestClient (in-process request
   simulation), not actual TCP connections to a running server. This is intentional for test
   isolation but means some middleware behaviors (rate limiting, TLS) are not exercised.

5. **Mutation testing not yet implemented** — controlled security-patch mutation testing
   (the third assurance dimension) is not yet part of the verification pipeline.
