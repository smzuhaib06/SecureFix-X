# SECURITY_INVARIANT.md
# SECUREFIX X — Security Invariant

**Status:** Phase 1 — Foundation  
**Scope:** `backend/app/models.py` · `backend/app/remediation/root_cause.py`  
**Tests:** `backend/tests/test_invariant.py`

---

## 1. Why the Invariant Exists

The audit identified a fundamental gap in the existing SECUREFIX implementation:

> *"A patch is not proof of remediation."*

The existing verification pipeline (pytest + static re-scan + exploit replay) is
functional for the demo scenario, but it is hardcoded around specific values:
Alice, Bob, `/api/accounts/2`, HTTP 200 as "vulnerable", HTTP 403 as "fixed".

This means:
- Verification for a different repository would require editing source code.
- There is no machine-readable record of *what the system is asserting* — only
  the assertion's implementation in test runner calls.
- Future capabilities (adversarial variant generation, legitimate-use contract
  testing, controlled security patch mutation testing) have no structured
  foundation to build on.

The `SecurityInvariant` model solves this by giving every SECUREFIX investigation
a structured, machine-readable statement of the security property that was
violated, how it should be verified, and what must remain true after a fix.

---

## 2. Schema

All types are Pydantic v2 `BaseModel` subclasses in [`backend/app/models.py`](../backend/app/models.py).

### 2.1 `VulnerabilityClass` (enum)

```
BOLA            — Broken Object Level Authorization (CWE-639)
SQL_INJECTION   — CWE-89
PATH_TRAVERSAL  — CWE-22
COMMAND_INJECTION — CWE-78
MISSING_AUTH    — CWE-306
HARDCODED_SECRET — CWE-798
UNKNOWN         — unclassified
```

### 2.2 `InvariantScope`

Defines what the invariant applies to.

| Field | Type | Description |
|-------|------|-------------|
| `routes` | `List[str]` | URL route patterns (e.g. `/api/accounts/{account_id}`) |
| `resources` | `List[str]` | Logical resource types (e.g. `["account", "transaction"]`) |
| `actor_roles` | `List[str]` | Roles, not usernames (e.g. `["non_owner", "resource_owner"]`) |
| `relevant_files` | `List[str]` | Repository-relative file paths |

### 2.3 `AttackScenario`

Parameterized representation of the attack. **Instance values only — no global constants.**

| Field | Type | Description |
|-------|------|-------------|
| `method` | `str` | HTTP method (`GET`, `POST`, …) |
| `route_template` | `str` | Template with placeholders (e.g. `/api/accounts/{account_id}`) |
| `route_example` | `str` | Concrete URL for this scenario (scenario data) |
| `actor_credential_hint` | `str` | Description of attacker identity (scenario data) |
| `parameters` | `Dict[str, Any]` | Scenario-specific parameters; must include `_note` key identifying them as instance data |

### 2.4 `OracleExpectedOutcome`

One expected outcome of the security oracle.

| Field | Type | Description |
|-------|------|-------------|
| `label` | `str` | Human-readable label (`attack_blocked`, `exploit_active`, …) |
| `allowed_status_codes` | `List[int]` | HTTP codes indicating this outcome |
| `forbidden_status_codes` | `List[int]` | HTTP codes that contradict this outcome |
| `protected_data_indicators` | `List[str]` | Response body field names that must NOT appear if the oracle passes |

### 2.5 `SecurityOracle`

Machine-readable verification specification.

| Field | Type | Description |
|-------|------|-------------|
| `description` | `str` | Human-readable summary |
| `outcomes` | `List[OracleExpectedOutcome]` | All expected outcomes |
| `blocked_outcome` | property | First outcome matching `block`/`secure`/`pass` in label |
| `violated_outcome` | property | First outcome matching `active`/`bypass`/`fail`/`vuln` in label |

### 2.6 `LegitimateUseCase`

One valid usage pattern that must remain functional after the fix.

| Field | Type | Description |
|-------|------|-------------|
| `description` | `str` | Human-readable description |
| `method` | `str` | HTTP method |
| `route_example` | `str` | Concrete URL (scenario data) |
| `actor_credential_hint` | `str` | Description of the legitimate actor (scenario data) |
| `expected_status_codes` | `List[int]` | HTTP codes expected for a legitimate call |
| `parameters` | `Dict[str, Any]` | Scenario-specific parameters (scenario data) |

### 2.7 `InvariantProvenance`

Records where the invariant was derived from.

| Field | Type | Description |
|-------|------|-------------|
| `investigation_id` | `str` | Parent investigation ID |
| `source_agents` | `List[str]` | Agents that contributed findings |
| `root_cause_cwe` | `Optional[str]` | Anchoring CWE identifier |
| `derived_at` | `datetime` | UTC timestamp of derivation |

### 2.8 `SecurityInvariant` (top-level)

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Auto-generated `INV-XXXXXXXX` |
| `vulnerability_class` | `VulnerabilityClass` | Canonical class |
| `cwe` | `Optional[str]` | CWE identifier |
| `statement` | `str` | Role-based invariant statement (no usernames) |
| `scope` | `InvariantScope` | Scope of the invariant |
| `attack` | `AttackScenario` | Parameterized attack description (scenario data) |
| `oracle` | `SecurityOracle` | Machine-readable verification specification |
| `legitimate_use` | `List[LegitimateUseCase]` | Legitimate-use contract |
| `provenance` | `Optional[InvariantProvenance]` | Derivation metadata |
| `limitations` | `str` | Explicit statement of what this invariant does NOT cover |
| `supported` | `bool` | `True` if a full invariant was derived; `False` if unsupported |
| `unsupported_reason` | `Optional[str]` | When `supported=False`, explains why |

---

## 3. Invariant vs Scenario Parameters

This distinction is the most important design principle in the model.

### The invariant (global, repository-agnostic)

```
statement: "An authenticated user may access a resource if and only if
            that user is the owner of the resource.  Access by a non-owner
            must be denied regardless of the resource identifier supplied."

oracle.outcomes[0].label: "attack_blocked"
oracle.outcomes[0].allowed_status_codes: [403, 404]
oracle.outcomes[0].forbidden_status_codes: [200, 201]
```

This is true of **any** system with BOLA. It mentions no usernames, no
specific route paths, no concrete IDs.

### The scenario parameters (instance data, repository-specific)

```python
attack.route_template = "/api/accounts/{account_id}"   # inferred from this repo
attack.route_example  = "/api/accounts/2"              # scenario data
attack.parameters["_note"] = "Instance data, not global assumptions"
attack.actor_credential_hint = "Authenticated as a non-owner user (e.g. alice)"

legitimate_use[0].route_example = "/api/accounts/1"    # scenario data
legitimate_use[0].actor_credential_hint = "Authenticated as the resource owner (e.g. alice)"
```

If the same vulnerability class were found in a different repository with
routes like `/api/orders/{order_id}`, the engine would produce:

```python
attack.route_template = "/api/orders/{order_id}"
attack.route_example  = "/api/orders/2"
```

The invariant **statement** and **oracle** remain identical. Only the scenario
parameters change.

---

## 4. How BOLA Maps to the Invariant — SecureBank Example

| Invariant concept | SecureBank instance value | Where stored |
|-------------------|--------------------------|--------------|
| Vulnerability class | `BOLA` | `vulnerability_class` |
| CWE | `CWE-639` | `cwe` |
| Invariant statement | "An authenticated user may access a resource if and only if that user is the owner…" | `statement` |
| Attacker role | `non_owner` | `attack.parameters["attacker_role"]` |
| Attack route template | `/api/accounts/{account_id}` | `attack.route_template` (inferred) |
| Attack URL example | `/api/accounts/2` | `attack.route_example` (scenario data) |
| Attacker identity hint | "alice accessing bob's resource" | `attack.actor_credential_hint` (scenario data) |
| Oracle: blocked codes | `[403, 404]` | `oracle.outcomes[0].allowed_status_codes` |
| Oracle: violated codes | `[200, 201]` | `oracle.outcomes[1].allowed_status_codes` |
| Protected data fields | `["balance", "account_number", "ssn"]` | `oracle.outcomes[0].protected_data_indicators` |
| Legitimate use: owner access | `/api/accounts/1`, expects 200 | `legitimate_use[0]` (scenario data) |
| Legitimate use: unauth blocked | `/api/accounts/2`, expects 401/403 | `legitimate_use[1]` (scenario data) |

The `"alice"` and `"bob"` names appear only in `actor_credential_hint` strings
and only as descriptions, not as hard-coded test values.  The oracle status
codes are properties of the **vulnerability class** (BOLA → 403 means access
denied), not global assumptions about HTTP semantics.

---

## 5. What Is Intentionally Unsupported

Phase 1 derives a full invariant only for **BOLA**.

For all other classes, `derive_invariant()` returns a `SecurityInvariant` with
`supported=False` and an explicit `unsupported_reason`.  No oracle outcomes,
no scope routes, no legitimate-use cases are fabricated.

| Class | `supported` | Reason |
|-------|------------|--------|
| SQL_INJECTION | `False` | Requires identification of specific query parameter and parameterisation pattern |
| PATH_TRAVERSAL | `False` | Requires knowledge of the allowed base directory and user-controlled path parameter |
| COMMAND_INJECTION | `False` | Requires identification of the shell sink and injection characters |
| MISSING_AUTH | `False` | Requires knowing which route is unprotected and the authentication mechanism |
| HARDCODED_SECRET | `False` | Requires identifying the specific secret and its location |
| UNKNOWN | `False` | Vulnerability class could not be classified |

This is deliberate.  Fabricating a partial invariant for an unsupported class
would be worse than returning nothing, because downstream consumers
(verification, variant generation) would act on incorrect data.

---

## 6. How Phase 2 Will Consume the Invariant

The `SecurityInvariant` is the data contract between Phase 1 (derivation) and
Phase 2 (execution).  Phase 2 will:

### 6.1 Parameterize `VerificationEngine._check_exploit_blocked()`

Instead of hardcoded strings:
```python
# CURRENT (hardcoded)
script = "client.get('/api/accounts/2', headers={'Authorization': f'Bearer {token}'})"
```

Phase 2 will read from the invariant:
```python
# PHASE 2 (parameterized)
attack = investigation.security_invariant.attack
script = f"client.{attack.method.lower()}('{attack.route_example}', headers=...)"
```

### 6.2 Parameterize regression test generation

`TestAgent.generate_regression_test()` will read `legitimate_use` cases and
`oracle.outcomes` to produce tests that express the actual invariant contract
rather than hardcoded Alice/Bob values.

### 6.3 Adversarial variant generation (Phase 3)

The `oracle` and `attack` fields provide the template for generating variants:
- Different resource IDs in `route_template`
- Different HTTP methods
- URL encoding variations in the route parameter
- Integer boundary values

Each variant is a parameterized instantiation of the same invariant.

### 6.4 Legitimate-use contract testing

The `legitimate_use` list drives negative tests (things that must still work):
- Owner access must return a code in `expected_status_codes`
- Unauthenticated access must be rejected

### 6.5 Controlled security patch mutation testing (Phase 4)

A faulty patch variant can be evaluated by running the oracle against an
isolated copy of the patched repository.  The oracle's `blocked_outcome` and
`violated_outcome` define exactly what "detected" means.

---

## 7. Pipeline Integration

The invariant is derived between root-cause analysis and patch generation:

```
Phase 4:  RootCauseEngine.analyze()        → investigation.root_cause
Phase 4b: RootCauseEngine.derive_invariant() → investigation.security_invariant  ← NEW
Phase 5:  RemediationEngine.propose()       → investigation.remediation
```

The orchestrator emits two SSE events:
- `invariant_started` — before derivation
- `invariant_done` — after derivation, carries `{supported: bool, cwe: str|null}`

The invariant is stored on the `Investigation` model and persists through the
existing SQLite write-through mechanism (stored in `data_json`).  No schema
migration is required.

---

## Phase 2 — Invariant-Driven Verification Engine

**Status:** Complete. All 100 backend tests pass.

Phase 2 connects the `SecurityInvariant` model (Phase 1) to the `VerificationEngine`,
making exploit replay and legitimate-use verification fully invariant-driven.

### What Changed

| Component | Phase 1 | Phase 2 |
|---|---|---|
| `VerificationEngine._check_exploit_blocked()` | Hardcoded Alice/Bob/route/codes | Reads route, credentials, and expected codes from `SecurityInvariant.attack` |
| Legitimate-use check | Did not exist | New `_check_legitimate_use()` driven by `SecurityInvariant.legitimate_use` |
| Outcome taxonomy | `"passed"` / `"failed"` / `"skipped"` | + `ExploitCheckOutcome` enum: PASS / BYPASS / ERROR / UNSUPPORTED |
| Oracle evaluation | Embedded in engine body | Isolated in `_evaluate_oracle()` — independently testable |
| Credential handling | Hardcoded in engine source | Scenario data in `SecurityInvariant`; passed to subprocess as `json.loads(...)` |

### New `VerificationCheck` Evidence Fields

```python
class VerificationCheck(BaseModel):
    # Legacy (unchanged)
    name: str
    status: str                           # "passed" / "failed" / "skipped"
    detail: str

    # Phase 2 evidence fields
    outcome: Optional[ExploitCheckOutcome]   # PASS / BYPASS / ERROR / UNSUPPORTED
    route: Optional[str]                     # e.g. /api/accounts/2
    http_method: Optional[str]               # e.g. GET
    observed_status_code: Optional[int]      # e.g. 403
    expected_outcome_label: Optional[str]    # e.g. "attack_blocked"
    response_evidence: Optional[str]         # truncated/sanitized response body
    execution_error: Optional[str]           # set for ERROR / UNSUPPORTED cases
```

All evidence fields are set atomically via `set_outcome_fields()`, which also keeps the
legacy `status` string in sync.

### Enforcement Tests

Two tests act as executable architectural constraints:

- `test_no_hardcoded_alice_in_engine_source` — asserts that the string `"alice"` does not
  appear in `engine.py` source code.
- `test_inferred_credentials_are_not_hardcoded_in_engine` — asserts that credentials live
  in the `SecurityInvariant`, not in engine constants.

### Execution Tiers

```
1. Authenticated TestClient subprocess (primary)
   └── Reads: attack.auth_endpoint, attack.auth_credentials, attack.auth_token_path
   └── Evaluates: _evaluate_oracle(status_code, body, oracle.blocked_outcome)

2. Unauthenticated TestClient subprocess
   └── Used when: attack.auth_endpoint is None
   └── Same oracle evaluation

3. Static fallback (last resort)
   └── Used when: subprocess execution fails entirely
   └── Returns: UNSUPPORTED (never BYPASS — cannot confirm exploitability statically)
```

### Known Limitations (Phase 2)

- Only BOLA/CWE-639 produces a supported invariant. Five other classes return
  `supported=False` and use static fallback.
- Only the first attack scenario in the invariant is executed. Adversarial variants
  are Phase 3.
- TestClient simulates HTTP in-process; it does not test a live TCP server.
- Mutation testing (third assurance dimension) is not yet implemented.

---

*End of Phase 2 documentation.*
