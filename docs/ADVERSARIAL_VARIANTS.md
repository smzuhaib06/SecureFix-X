# ADVERSARIAL_VARIANTS.md
# SECUREFIX X — Phase 3: Adversarial Variant Generator

**Status:** Phase 3 complete. All 173 backend tests pass.  
**Scope:** `backend/app/verification/variants.py` · `backend/app/models.py`  
**Tests:** `backend/tests/test_variants_phase3.py`

---

## 1. Why Variants Exist

A patch is not proof of remediation.

A single exploit-replay check (Phase 2) answers one question:  
> "Does this exact attack, replayed against the patched application, still succeed?"

This is necessary but not sufficient.

A developer might fix only the specific endpoint that was identified in the security report while leaving related endpoints — sharing the same resource scope — unpatched.  The original exploit replay would return PASS, but a complete BOLA bypass would remain available through a sibling route.

Adversarial variants answer a broader set of questions from the same SecurityInvariant:

| Variant dimension | Question answered |
|---|---|
| Original attack | Does the patched primary route block the known attack? |
| Identity | Does the fix block any non-owner, not just the specific attacker from the report? |
| Identifier | Is ownership enforcement consistent across adjacent resource IDs? |
| Sibling route | Was ownership enforcement applied to all routes in the same resource scope? |
| Request variant | Does a malformed request accidentally expose resource data? |

Together these address one of the three SECUREFIX X assurance dimensions:

> **Does the repaired application resist the relevant attack?**

---

## 2. Invariant vs Variant

| Concept | SecurityInvariant | AdversarialVariant |
|---|---|---|
| **Level** | Invariant — a security property that must always hold | Instance — one verification scenario that tests the property |
| **Source** | Derived from root-cause analysis by `RootCauseEngine.derive_invariant()` | Derived from the invariant by `VariantGenerator.generate()` |
| **Content** | Statement, scope, oracle, attack scenario, legitimate-use contract | Route, method, actor role, expected oracle, provenance |
| **Credentials** | Stored as scenario data | Never stored — resolved from invariant at execution time |
| **Multiplicity** | One per investigation | Multiple per invariant |

The chain is:

```
Finding
  ↓
Root Cause Analysis
  ↓
SecurityInvariant          ← Phase 1 (invariant.py)
  ↓
VariantGenerator           ← Phase 3 (variants.py)
  ↓
AdversarialVariant[]
  ↓
VerificationEngine         ← Phase 2 (engine.py)
  ↓
PASS / BYPASS / ERROR / UNSUPPORTED
```

Every result is traceable back to the finding through this chain.

---

## 3. Supported Variant Dimensions

Phase 3 supports five dimensions:

### 3.1 ORIGINAL_ATTACK

Re-packages the invariant's primary attack scenario as a typed variant.  
This is always the first variant generated — the baseline exploit-replay.

**Source:** `SecurityInvariant.attack`  
**Actor role:** `non_owner`  
**Oracle:** `SecurityInvariant.oracle.blocked_outcome`  

### 3.2 IDENTITY

Same route, different actor.  Tests that the ownership check is role-based,
not user-specific.

**Condition for generation:** Invariant must have a second `legitimate_use` entry
with non-empty `auth_credentials` that represents a second non-owner actor.

**Actor role:** `alternate_non_owner`  
**Oracle:** Same as original attack — both non-owners must be blocked.

If the second actor is not available from the invariant, the dimension is skipped
with a recorded reason. The generator does not invent users.

### 3.3 IDENTIFIER

Same route and actor, different resource identifier.  Tests that ownership
enforcement is consistent across IDs — a fix that hardcodes a specific ID check
would fail this variant.

**Condition for generation:** The attack `route_example` must contain a numeric ID.

The generator produces one adjacent-ID variant (distance of 1).  It never produces
an enumeration scan.  It avoids generating an ID that collides with the owner's
resource (which would become a legitimate-use test, not an attack variant).

**Oracle:** Same blocked_outcome.  
**Safety note:** The adjacent ID may not exist in the database; a 404 would be
classified as ERROR rather than PASS.

### 3.4 SIBLING_ROUTE

The most important Phase 3 dimension.

Discovers routes from repository API metadata that:
- Share a common path prefix with the primary attack route
- Are explicitly present in `repository_info.api_routes` (indexed by the RepositoryAgent)
- Use a safe HTTP method (GET only)
- Are not identical to the primary route

Path parameter placeholders are resolved using the attack scenario's numeric ID.

**Example (scenario data from SecureBank):**  
Primary: `GET /api/accounts/2`  
Sibling: `GET /api/accounts/2/transactions`  
If the patch only fixed the primary route, the sibling may still return 200 for a non-owner — producing a BYPASS result.

**Oracle:** Same blocked_outcome as the invariant oracle (same resource scope assumption).  
**Limitation:** If the sibling uses different semantics, the result may be ERROR rather than PASS.

### 3.5 REQUEST_VARIANT

Limited safe mutations of the primary request representation.

Currently supported:
- **Malformed identifier**: substitutes a non-numeric sentinel (`INVALID`) where a numeric ID is expected.

The malformed-ID variant is generated but immediately marked `supported=False`
with an explicit `unsupported_reason`.  The BOLA oracle cannot safely evaluate
a 422 Unprocessable Entity response from FastAPI's type validation layer.

Future work: add a dedicated `malformed_id_outcome` to the oracle to enable execution.

---

## 4. How Sibling Routes Are Discovered

Sibling routes come exclusively from `Investigation.repository_info.api_routes`,
which is populated by the `RepositoryAgent` during Phase 1 of the investigation workflow.

The RepositoryAgent scans source files with the pattern:
```python
re.findall(r'@(?:app|router)\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', content)
```

and stores results as `"METHOD /path"` strings.

The VariantGenerator:

1. Extracts the resource prefix from the attack route (e.g. `/api/resources` from `/api/resources/5`)
2. Iterates over api_routes and selects routes that start with that prefix
3. Excludes the primary route and any route already in `invariant.scope.routes`
4. Excludes routes with destructive methods (DELETE/PUT/PATCH)
5. Resolves path parameter placeholders using the attack scenario's ID
6. Produces one variant per discovered sibling route

No routes are invented. No external systems are queried.

---

## 5. Bounded-Generation Rules

Generation is **deterministic** and **data-driven**:

| Rule | Implementation |
|---|---|
| Count comes from data | Variant count = number of sibling routes discovered + 1 (original) + 0-1 per other dimension |
| No fixed marketing numbers | `supported_count` is computed from actual variants, not set to "7" |
| No combinatorial explosion | Each dimension produces at most one variant (except sibling_route) |
| Deterministic | Same invariant + same api_routes → same variant list in same order |
| No wide enumeration | Identifier dimension: adjacent distance of 1 only |

The `VariantGenerationResult` reports:
- `supported_count` — executable variants
- `skipped_count` — unsupported/skipped variants
- `skipped_reasons` — audit trail for each skip decision
- `unsupported_dimensions` — dimensions not applicable for this invariant

---

## 6. Provenance Model

Every `AdversarialVariant` carries a `VariantProvenance` that records:

```python
class VariantProvenance(BaseModel):
    source: str           # "security_invariant" | "repository_api_routes" |
                          # "identity_dimension" | "identifier_dimension" |
                          # "request_variant_dimension"
    parent_route: str     # primary route this variant was derived from
    reason: str           # why this variant was generated
    invariant_id: str     # SecurityInvariant.id that anchors it
```

Example provenance for a sibling-route variant in the SecureBank scenario:

```json
{
  "source": "repository_api_routes",
  "parent_route": "/api/accounts/2",
  "reason": "Discovered in repository api_routes; shares resource prefix '/api/accounts' with primary attack route /api/accounts/2. Tests whether ownership enforcement was applied consistently.",
  "invariant_id": "INV-A3F2B1C9"
}
```

The complete traceability chain:

```
Finding: "BOLA on GET /api/accounts/{account_id}"
  ↓ root cause analysis
SecurityInvariant INV-A3F2B1C9 (CWE-639)
  ↓ VariantGenerator, dimension: sibling_route
AdversarialVariant VAR-7E3D9F12 (sibling_route)
  route: GET /api/accounts/2/transactions
  provenance.source: repository_api_routes
  provenance.parent_route: /api/accounts/2
  provenance.invariant_id: INV-A3F2B1C9
  ↓ VerificationEngine
VerificationCheck outcome: BYPASS
  observed_status_code: 200
  response_evidence: "[{\"id\": 1, \"account_id\": 2, ...}]..."
  ↓
NOT VERIFIED — sibling route remains vulnerable
```

---

## 7. Oracle Handling

The VariantGenerator **never reconstructs oracle semantics**.

This means:
- The generator does not hardcode `200 = vulnerable` or `403 = secure`
- `expected_oracle` is always copied from `SecurityInvariant.oracle.blocked_outcome`
- The oracle's `allowed_status_codes`, `forbidden_status_codes`, and
  `protected_data_indicators` are whatever the invariant specifies

For variants where the oracle cannot be safely applied:
- `supported = False`
- `expected_oracle = None`
- `unsupported_reason` explains why

This design means changing the oracle in the invariant automatically changes the oracle for all variants derived from it.

---

## 8. Safety Boundaries

The VariantGenerator enforces these boundaries at the code level:

| Boundary | Enforcement |
|---|---|
| Repository-scoped routes only | Sibling routes sourced from `api_routes` only |
| No external URLs | All routes start with `/`; no `http://`/`https://` prefix |
| No arbitrary shell commands | No subprocess execution in this module |
| No destructive HTTP operations | `_DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH"}` — excluded from sibling discovery |
| No credential storage in variants | `AdversarialVariant` model has no `auth_credentials` field |
| No credential generation | Credentials always come from `SecurityInvariant` scenario data |
| No production deployment | No infrastructure operations |
| No working-tree mutation | The generator produces descriptions only |

The generator test `test_no_delete_variants_for_bola` is an executable safety constraint.

---

## 9. Unsupported Cases

| Case | Outcome |
|---|---|
| No `SecurityInvariant` on investigation | Empty `VariantGenerationResult`, `generation_note` explains |
| `invariant.supported = False` | Empty result, `generation_note` carries `unsupported_reason` |
| Non-BOLA vulnerability class | Empty result — Phase 3 supports BOLA only |
| No numeric ID in attack route | Identifier dimension skipped; reason recorded |
| No sibling routes in `api_routes` | Sibling-route dimension skipped; reason recorded |
| No second non-owner actor in invariant | Identity dimension skipped; reason recorded |
| Sibling route has no oracle | Variant generated with `supported=False` and reason |
| Malformed-ID request variant | Generated with `supported=False` — oracle cannot classify 422 safely |

All skipped cases are recorded in `VariantGenerationResult.skipped_reasons` and
`unsupported_dimensions` for audit purposes.

---

## 10. Current SecureBank Demonstration

Given the SecureBank BOLA invariant (auto-derived by `RootCauseEngine.derive_invariant()`):

```
Invariant: An authenticated user may access a resource if and only if that user
           is the owner of the resource.
CWE:       CWE-639
Attack:    GET /api/accounts/2 (attacker = alice, owner = bob)
Oracle:    blocked → [403, 404]; violated → [200]
```

With SecureBank's `api_routes` (as indexed by the RepositoryAgent):

```
GET /api/accounts/{account_id}
GET /api/accounts/{account_id}/transactions    ← sibling route
GET /api/transactions/{transaction_id}
GET /api/profiles/{profile_id}
```

The VariantGenerator produces:

| # | variant_type | route | supported | description |
|---|---|---|---|---|
| 1 | original_attack | GET /api/accounts/2 | ✅ | Primary attack from invariant |
| 2 | identifier | GET /api/accounts/3 | ✅ | Adjacent ID (not alice's account) |
| 3 | sibling_route | GET /api/accounts/2/transactions | ✅ | Shares /api/accounts prefix |
| 4 | request_variant | GET /api/accounts/INVALID | ❌ | Malformed ID — oracle cannot evaluate 422 |

**Identity:** Skipped — the BOLA invariant from `derive_invariant()` produces only one
non-owner actor in `legitimate_use`; the second entry is the unauthenticated scenario
(no credentials), so no alternate-identity variant can be generated without inventing a user.

**Key demonstration:** If the developer patches only `GET /api/accounts/{account_id}` but
leaves `GET /api/accounts/{account_id}/transactions` unpatched:

```
Variant 1 (original_attack):  GET /api/accounts/2          → HTTP 403 → PASS
Variant 3 (sibling_route):    GET /api/accounts/2/transactions → HTTP 200 → BYPASS
                                                                        ↓
                                                            NOT VERIFIED
```

The BYPASS on the sibling route prevents the investigation from reaching "VERIFIED" status.

---

## 11. Mutation Testing is NOT Part of Phase 3

Phase 3 generates test descriptions from the **existing** SecurityInvariant and
**existing** repository API metadata.

It does NOT:
- Generate faulty patches
- Create mutant working trees or containers
- Compute mutation scores
- Test whether the verification suite would catch a bad patch

Controlled security-patch mutation testing is planned as a separate capability and
must be implemented in **isolated disposable copies** (worktrees or containers) that
do not affect the approved working tree.

This is explicitly Phase 4+ work. The current implementation stops here.

---

## 12. Files

| File | Role |
|---|---|
| `backend/app/verification/variants.py` | VariantGenerator + helper functions |
| `backend/app/models.py` | `VariantType`, `VariantProvenance`, `AdversarialVariant`, `VariantGenerationResult` |
| `backend/tests/test_variants_phase3.py` | 73 Phase 3 tests |

---

## 13. Test Coverage Summary

```
tests/test_variants_phase3.py  73 tests
  TestAdversarialVariantModel         6 — model validation
  TestVariantProvenance               4 — provenance validation
  TestOriginalAttackVariant           6 — original attack dimension
  TestIdentityVariants                5 — identity dimension
  TestIdentifierVariants              5 — identifier dimension
  TestSiblingRouteVariants            6 — sibling-route discovery
  TestNoInventedRoutes                1 — safety: no invented routes
  TestNoExternalURLs                  2 — safety: no external URLs
  TestNoDestructiveMethods            2 — safety: no DELETE/PUT/PATCH
  TestOracleIntegration               3 — oracle from invariant only
  TestUnsupportedHandling             3 — unsupported/skipped cases
  TestDeterminism                     2 — same inputs → same outputs
  TestBoundedGeneration               3 — data-driven count
  TestVariantCountReporting           2 — count metadata
  TestScenarioDataNotGlobal           2 — alice/bob/IDs as scenario data
  TestNoHardcodedSecureBankAssumptions 4 — generic generator audit
  TestHelperFunctions                11 — helper function unit tests
  TestVariantGenerationResult         3 — result model
  TestNoInvariantOrUnsupported        3 — graceful degradation

Total (Phase 3):                     73 tests
Total (all backend tests):          173 tests, 173 passing
Demo-app tests:                       3 tests, 2 passing, 1 intentionally failing (BOLA)
```
