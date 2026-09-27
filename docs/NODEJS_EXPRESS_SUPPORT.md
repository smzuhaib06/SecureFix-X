# Node.js / Express Support

**Phase 5 — Cross-Stack Extension**

> "A patch is not proof of remediation."

This document describes the Node.js/Express security analysis support added to SECUREFIX X in Phase 5.

---

## Scope

**One vulnerability class.  One well-understood attack.  Evidence first.**

SECUREFIX X now supports evidence-backed security investigation for Node.js/Express repositories targeting:

| Dimension | Value |
|---|---|
| Vulnerability class | NoSQL Injection (CWE-943) |
| Attack pattern | MongoDB operator injection into Mongoose queries |
| Target evidence | `routes/index.js` — `User.find({ username: req.body.username, password: req.body.password })` |
| Demo target | [`nodejs-goof`](https://github.com/snyk/nodejs-goof) |
| HTTP verification | UNSUPPORTED (see limitations) |

This deliberately does **not** claim general Node.js SAST coverage.  The focus is
demonstrating that SECUREFIX X's evidence-backed investigation chain — Repository Agent →
Security Agent → Root Cause → Security Invariant — works for a non-Python, non-FastAPI stack.

---

## New Files

### `backend/app/nodejs/__init__.py`
Package marker.

### `backend/app/nodejs/js_analyzer.py`
Core static analysis module for Node.js/Express repositories.

**Public API:**
```python
from app.nodejs.js_analyzer import NodejsAnalyzer

info = NodejsAnalyzer().analyze("/path/to/repo")
# info.is_nodejs       — bool
# info.is_express      — bool
# info.express_version — e.g. "4.12.4"
# info.mongoose_version
# info.routes          — List[ExpressRoute]
# info.nosql_sinks     — List[NoSqlSink]
# info.detection_evidence  — List[str]
```

**Data structures:**
- `ExpressRoute` — method, path, source_file, line_number, auth_middleware, raw_line
- `NoSqlSink` — source_file, line_number, raw_line, model_name, method_call,
  input_sources, has_operator_sanitization, context_lines
- `NodejsRepoInfo` — aggregated analysis result

**Pure module-level functions (independently testable):**
- `_extract_express_routes(content, source_file)` — regex-based Express route extractor
- `_detect_nosql_sinks(content, source_file)` — Mongoose sink detector

### `backend/app/verification/nodejs_verifier.py`
Framework-aware verification component.

**Why it exists:** The existing `VerificationEngine` uses a FastAPI `TestClient`
subprocess.  This cannot start or connect to a Node.js process.

**Behaviour:**
- `check_exploit_blocked(investigation)` — static analysis of patched files first;
  falls back to `UNSUPPORTED` with a clear reason
- `check_legitimate_use(investigation)` — always returns `UNSUPPORTED` with reason
- `_static_nosql_check(investigation)` — detects `mongo-sanitize` / `mongoSanitize` /
  `sanitizeFilter` in patched files; returns PASS if found

---

## Modified Files

### `backend/app/models.py`
Added `VulnerabilityClass.NOSQL_INJECTION = "NOSQL_INJECTION"` (CWE-943).

### `backend/app/agents/repository_agent.py`
- Added `_run_nodejs_analysis()` — calls `NodejsAnalyzer`, merges Express routes
  into `api_routes`, attaches `_nodejs_info` to the investigation's raw output.
- When Express is detected, `"Express"` is added to `frameworks` list.

### `backend/app/agents/security_agent.py`
- Added `JS_NOSQL_PATTERNS` — regex patterns for Mongoose + req.body injection.
- Added `JS_NOSQL_ANTI_PATTERNS` — suppression patterns (express-mongo-sanitize, etc.).
- Added `_analyze_js_nosql()` — called from `_analyze_file()` for `.js`/`.ts` files.
- Produces evidence-backed `AgentFinding` with source line, context, root cause, attack path.
- **Gated** on issue description containing NoSQL/injection/mongo/login keywords.

### `backend/app/agents/dependency_agent.py`
Added to `KNOWN_VULNS`:

| Package | Version threshold | CVE | Description |
|---|---|---|---|
| `mongoose` | < 5.7.5 | CVE-2019-17426 | NoSQL operator injection — authentication bypass (CWE-943) |
| `express` | < 4.19.2 | CVE-2024-29041 | Open redirect via malformed Host header (CWE-601) |

### `backend/app/remediation/root_cause.py`
Added two methods to `RootCauseEngine`:

**`_nosql_injection_root_cause(investigation)`**
- `cwe_id = "CWE-943"`, `cvss_score = 9.8`
- Explains operator injection, JavaScript dynamic typing, and authentication bypass impact
- No hardcoded application-specific values

**`_nosql_injection_invariant(investigation)`**
- Returns a fully-structured `SecurityInvariant` with `supported=True`
- Falls back to `UNSUPPORTED` when no login route is discoverable in `api_routes`
- Oracle: `attack_blocked` → allowed `[400, 401]`, forbidden `[200, 201, 302]`
- Legitimate use: valid scalar credentials → `[200, 201, 302]`
- `limitations` field explicitly states that HTTP verification is UNSUPPORTED for
  Node.js/Express targets

---

## Verification Behaviour for Node.js Targets

| Check | Outcome | Reason |
|---|---|---|
| Repository detection | ✅ COMPLETE | `NodejsAnalyzer` detects framework from package.json + source |
| Security finding | ✅ COMPLETE | `SecurityAgent._analyze_js_nosql()` with evidence |
| Root cause analysis | ✅ COMPLETE | `_nosql_injection_root_cause()` — CWE-943 |
| Security invariant | ✅ COMPLETE | `_nosql_injection_invariant()` — supported=True |
| Dependency advisory | ✅ COMPLETE | `DependencyAgent` flags mongoose < 5.7.5 |
| Static patch verification | ✅ COMPLETE | `NodejsVerifier._static_nosql_check()` |
| Live HTTP exploit replay | ⛔ UNSUPPORTED | Requires running Express server (see below) |
| Legitimate-use HTTP check | ⛔ UNSUPPORTED | Requires running Express server (see below) |

### Why HTTP verification is UNSUPPORTED

The existing `VerificationEngine._run_authenticated_exploit()` generates a Python
subprocess that imports `from app.main import app` and runs `FastAPI.TestClient`.
This mechanism:

1. Assumes the target is a Python/FastAPI application
2. Cannot start or connect to a Node.js/Express process
3. Cannot run `npm start` without explicit lifecycle management

**How to complete verification manually:**
```bash
# 1. Start the goof application
cd nodejs-goof && npm start

# 2. Test vulnerable state (expect HTTP 200 — exploit active)
curl -s -X POST http://localhost:3001/login \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# 3. Apply the fix (add express-mongo-sanitize)

# 4. Test fixed state (expect HTTP 401/400 — exploit blocked)
curl -s -X POST http://localhost:3001/login \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# 5. Verify legitimate use still works
curl -s -X POST http://localhost:3001/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "user@yourcompany.com", "password": "correctpassword"}'
```

**Phase 6 extension point:** When a Node.js runner integration is added, replace
`NodejsVerifier._http_check_unsupported()` with a subprocess call to
`npx jest --testPathPattern securefix_verify` or equivalent.

---

## nodejs-goof Integration

The `nodejs-goof` repository is symlinked at `nodejs-goof/` in the workspace root.

Verified against the real goof codebase:

| Property | Result |
|---|---|
| Framework detection | `is_nodejs=True`, `is_express=True` |
| Mongoose version | `4.2.4` (below CVE-2019-17426 threshold of 5.7.5) |
| Routes extracted | ✅ Login route detected |
| NoSQL sinks found | ✅ `User.find({...req.body...})` in `routes/index.js` |
| Evidence quality | Source line + context lines captured |
| CVE flagged | CVE-2019-17426 via `DependencyAgent` |

---

## Test Suite

**File:** `backend/tests/test_nodejs_support.py`
**Count:** 83 tests (10 integration tests require `nodejs-goof` symlink; auto-skipped otherwise)

| Area | Class | Tests |
|---|---|---|
| 1 | `TestNosqlInjectionEnumValue` | 4 |
| 2 | `TestNodejsAnalyzerRejection` | 3 |
| 3 | `TestNodejsDetection` | 3 |
| 4 | `TestExpressDetection` | 5 |
| 5 | `TestExpressRouteExtraction` | 6 |
| 6 | `TestExpressRouteNoFalsePositives` | 4 |
| 7 | `TestNosqlSinkDetection` | 7 |
| 8 | `TestNosqlSinkSuppression` | 2 |
| 9 | `TestNosqlSinkNoFalsePositives` | 4 |
| 10 | `TestNosqlRootCauseAnalysis` | 6 |
| 11 | `TestNosqlInjectionInvariant` | 12 |
| 12 | `TestNosqlInvariantFallback` | 3 |
| 13 | `TestDependencyAgentNodejs` | 7 |
| 14 | `TestNodejsVerifier` | 8 |
| Integration | `TestGoofIntegration` | 10 |

All 83 tests pass.  All existing 237 backend tests continue to pass (total: 320).

**Fixtures:** All unit tests use synthetic JS fixtures written inline — no hardcoded
goof output, no hardcoded line numbers.

**SecureBank isolation:** No `alice`, `alice123`, `/api/accounts`, `app.main`, or other
SecureBank-specific values appear in this test file or the new Node.js modules.

---

## Security Invariant for NoSQL Injection

```
Statement:
  A login endpoint must reject any credential field whose value is not a
  plain scalar string.  Object-valued credential fields that contain MongoDB
  query operators must never be forwarded to the database query layer.

CWE: CWE-943
Supported: True

Oracle (attack_blocked):
  allowed_status_codes:   [400, 401]
  forbidden_status_codes: [200, 201, 302]
  protected_data_indicators: [token, access_token, session, jwt]

Legitimate use:
  POST /login with valid scalar credentials → [200, 201, 302]

Limitations:
  - Covers operator-injection into credential fields only
  - Does not cover second-order injection, URL parameter injection,
    non-authentication queries, or non-Mongoose ODMs
  - HTTP verification is UNSUPPORTED for Node.js/Express
    (requires running Express server)
```

---

## Architectural Isolation

The Node.js/Express support is implemented as an **extension**, not a replacement:

- Existing BOLA/FastAPI verification path is unchanged
- `SecurityAgent._analyze_file()` calls `_analyze_js_nosql()` **only** for `.js`/`.ts`
  files and **only** when the issue description mentions NoSQL-related keywords
- `RepositoryAgent._run_nodejs_analysis()` is called **after** the existing Python
  analysis and only populates additional fields
- `DependencyAgent` KNOWN_VULNS addition is purely additive
- `NodejsVerifier` is a standalone class; `VerificationEngine` is unchanged

---

## Known Limitations

1. **No live HTTP verification** — UNSUPPORTED (documented, not silently omitted)
2. **Single vulnerability class** — only NoSQL injection via Mongoose
3. **No data-flow analysis** — regex-based; may miss indirect injection via middleware chains
4. **No TypeScript AST** — TypeScript files are scanned as text; type annotations not used
5. **Route extractor is conservative** — may miss routes registered via factory functions
   or late-bound `app.route()` chaining; will not produce false denials
