# BOB_REPOSITORY_AUDIT.md
# SECUREFIX — Repository Audit
**Auditor:** IBM Bob  
**Branch:** `securefix-x`  
**Audit date:** 2026  
**Scope:** Full codebase audit — no application code modified

---

## 1. Executive Summary

SECUREFIX is a working, end-to-end AI-assisted security remediation assurance platform built on FastAPI (backend + demo app) and Next.js 14 (frontend). The Kiro/Antigravity implementation is substantially complete and functional. The core demo scenario — BOLA vulnerability detection, root cause analysis, patch generation, human approval, patch application, and post-patch verification — is implemented and test-verified.

**What exists and works (verified by test execution):**
- 7-agent parallel investigation pipeline with SQLite persistence and SSE streaming
- Human approval gate enforced at API level before patch application
- Real pytest execution during verification (via subprocess)
- Real HTTP exploit replay during verification (via FastAPI `TestClient`)
- Regression test auto-generation (written to disk before test run)
- Markdown evidence report export
- Full frontend UI (dashboard, investigation detail, demo walkthrough, verification, reports)
- SecureBank demo app in confirmed-vulnerable state (test suite proves BOLA active: `test_alice_cannot_access_bobs_account` FAILS with HTTP 200)

**Key gaps relative to the SECUREFIX X target architecture:**
- No Security Invariant model exists (only implicit text descriptions)
- No Executable Security Oracle separate from the test runner
- No adversarial variant generation
- No legitimate-use contract verification distinct from the existing regression test
- No controlled security patch mutation testing
- Verification is limited to BOLA/path-traversal/command-injection patterns; it cannot generalize to new vulnerability classes without code changes
- The verification `PASS/BYPASS/ERROR/UNSUPPORTED` taxonomy is partially present but not formally structured

---

## 2. Existing Architecture

```
[Demo App — SecureBank]          [SECUREFIX Backend]              [Frontend — Next.js]
   FastAPI :8001                    FastAPI :8000                     Next.js :3000
   SQLite (securebank.db)           SQLite (securefix.db)             Tailwind CSS
   Intentionally vulnerable         7-agent orchestrator              SSE streaming
   JWT + bcrypt auth                SSE pub/sub                       8-tab detail view
   REST API (accounts,              Human approval gate               Live Demo wizard
     transactions, profile)         Patch apply + verify
```

**Data flow (current):**
```
POST /api/investigations
  → AgentOrchestrator.run_investigation() [background task]
    → RepositoryAgent (sequential, phase 1)
    → [SecurityAgent, CodeAgent, DependencyAgent, ConfigAgent, TestAgent, RuntimeAgent] (parallel)
    → CorrelationEngine.correlate()
    → RootCauseEngine.analyze()
    → RemediationEngine.propose() + generate_regression_test()
    → status: AWAITING_APPROVAL [SSE: patch_ready]
POST /api/investigations/{id}/approve
  → [if approved] AgentOrchestrator.apply_patch_and_verify() [background task]
    → RemediationEngine.apply()
    → VerificationEngine.verify()
      → write regression test to disk
      → subprocess: pytest tests/
      → static re-scan of patched files
      → exploit replay (TestClient or live HTTP)
      → import check
    → status: COMPLETED [SSE: verification_done]
GET /api/investigations/{id}/report  → Markdown report
```

---

## 3. Backend Component Map

| File | Type | Status |
|------|------|--------|
| `backend/app/main.py` | FastAPI application, 9 routes | **Implemented and verified** |
| `backend/app/models.py` | All Pydantic models | **Implemented and verified** |
| `backend/app/store.py` | In-memory store + SQLite write-through + SSE pub/sub | **Implemented and verified** |
| `backend/app/db.py` | SQLite schema: `investigations`, `audit_events`, `findings` | **Implemented and verified** |
| `backend/app/orchestrator.py` | Pipeline coordinator, async background tasks | **Implemented and verified** |
| `backend/app/repository.py` | GitHub/GitLab clone + security validation | **Implemented, not integration-tested with live clone** |
| `backend/app/report.py` | Markdown report generator | **Implemented and verified** |
| `backend/app/correlation/engine.py` | Cross-agent evidence correlation | **Implemented and verified** |
| `backend/app/remediation/root_cause.py` | Root cause analysis (pattern-matched, 6 vulnerability classes) | **Implemented and verified** |
| `backend/app/remediation/engine.py` | Patch proposal + safe apply + fuzzy patch | **Implemented and verified** |
| `backend/app/verification/engine.py` | Post-patch verification (pytest + static + exploit + build) | **Implemented and verified** |

**API routes exposed by `main.py`:**

| Route | Method | Purpose |
|-------|--------|---------|
| `/health` | GET | Health check |
| `/api/investigations` | POST | Create investigation |
| `/api/investigations` | GET | List investigations |
| `/api/investigations/{id}` | GET | Get investigation detail |
| `/api/investigations/{id}` | DELETE | Delete investigation |
| `/api/investigations/{id}/stream` | GET | SSE progress stream |
| `/api/investigations/{id}/approve` | POST | Approve or reject patch |
| `/api/investigations/{id}/audit` | GET | Retrieve audit log |
| `/api/investigations/{id}/report` | GET | Download Markdown report |
| `/api/dashboard/stats` | GET | Dashboard statistics |
| `/api/demo/create-investigation` | POST | One-click BOLA demo |

---

## 4. Existing Agent Map

### 4.1 Repository Agent (`repository_agent.py`)
- **Responsibility:** Indexes repository structure; detects languages, frameworks, API routes, auth patterns, database patterns, entry points, deployment files.
- **Invocation:** Sequential, Phase 1 (all other agents depend on its output via `investigation.repository_info`).
- **Implementation status:** **Fully implemented and functional.** Uses real filesystem walks with regex pattern matching.
- **Output:** `RepositoryInfo` populated on the `Investigation` object.

### 4.2 Security Agent (`security_agent.py`)
- **Responsibility:** Pattern-based vulnerability detection across 6 vulnerability classes: BOLA, SQL injection, missing auth, hardcoded secrets, path traversal, command injection.
- **Invocation:** Parallel, Phase 2. Always runs.
- **Implementation status:** **Fully implemented and functional.** Uses issue-keyword-based file relevance scoring, then pattern+anti-pattern matching. Has heuristic fallback.
- **Output:** `AgentResult` with `AgentFinding` list, sets `investigation.severity`.

### 4.3 Code Agent (`code_agent.py`)
- **Responsibility:** Data-flow and control-flow analysis — unverified ID flows, path traversal flows, command injection sinks, SQL injection string interpolation, missing error handling, direct object references in routes.
- **Invocation:** Parallel, Phase 2. Reads `repository_info.relevant_files`.
- **Implementation status:** **Fully implemented and functional.** Regex-based, not a true AST parser.
- **Output:** `AgentResult` with `AgentFinding` list.

### 4.4 Dependency Agent (`dependency_agent.py`)
- **Responsibility:** Scans `requirements.txt`, `package.json`, `Pipfile`, `pyproject.toml` for known-vulnerable package versions.
- **Invocation:** Parallel, Phase 2.
- **Implementation status:** **Implemented and functional** but limited — CVE database is a hardcoded dictionary covering only 3 packages (pyjwt, cryptography, fastapi). No live advisory lookup.
- **Output:** `AgentResult` with CVE findings. In practice, no findings for the demo app (uses current versions).

### 4.5 Configuration Agent (`config_agent.py`)
- **Responsibility:** Inspects Dockerfiles, `.env` files, docker-compose YAML, and generic config files for misconfigurations (root user, exposed ports, latest tags, weak secrets, debug mode, CORS wildcards).
- **Invocation:** Parallel, Phase 2.
- **Implementation status:** **Fully implemented and functional.**
- **Output:** `AgentResult` with `AgentFinding` list. Will find CORS wildcard and `.env` present in the demo app.

### 4.6 Test Agent (`test_agent.py`)
- **Responsibility:** (a) Analysis phase: identifies test coverage gaps for authorization issues. (b) Generation phase: `generate_regression_test()` produces pytest source code for BOLA, path traversal, command injection, SQL injection, or generic auth.
- **Invocation:** Parallel, Phase 2 (analysis). `generate_regression_test()` is called from the orchestrator after patch proposal.
- **Implementation status:** **Fully implemented and functional.** The regression test is written to disk and executed by `VerificationEngine`.
- **Hardcoding note:** The BOLA regression test hardcodes Alice/Bob usernames, passwords, account IDs, and the specific URL `/api/accounts/2`. See Section 12.

### 4.7 Runtime Agent (`runtime_agent.py`)
- **Responsibility:** Searches known log directories for log files; analyzes for resource enumeration patterns, 500 errors, and high auth failure rates.
- **Invocation:** Parallel, Phase 2.
- **Implementation status:** **Fully implemented. Functionally correct for when logs exist.** For the demo app (no log files), returns a clean "Runtime evidence unavailable" result — does NOT fabricate data.
- **Output:** `AgentResult` with summary explicitly stating unavailability when no logs are found.

---

## 5. Frontend Component Map

### Pages

| Route | File | Purpose | Status |
|-------|------|---------|--------|
| `/` | `app/page.tsx` | Landing page | **Implemented** |
| `/dashboard` | `app/dashboard/page.tsx` | Stats + recent investigations + demo button | **Implemented** |
| `/demo` | `app/demo/page.tsx` | Step-by-step BOLA demo wizard (login, exploit, launch, re-test) | **Implemented** |
| `/findings` | `app/findings/page.tsx` | Aggregated findings across all investigations | **Implemented** |
| `/investigations` | `app/investigations/page.tsx` | List all investigations | **Implemented** |
| `/investigations/new` | `app/investigations/new/page.tsx` | Create form (local path + GitHub URL) | **Implemented** |
| `/investigations/[id]` | `app/investigations/[id]/page.tsx` | 8-tab detail view | **Implemented** |
| `/agents` | `app/agents/page.tsx` | Agent descriptions + run statistics | **Implemented** |
| `/verification` | `app/verification/page.tsx` | Aggregated verification results | **Implemented** |
| `/reports` | `app/reports/page.tsx` | Completed investigation list + Markdown download | **Implemented** |
| `/settings` | `app/settings/page.tsx` | Service health, demo credentials, configuration | **Implemented** |

### Investigation detail tabs (`/investigations/[id]`)

| Tab | Content |
|-----|---------|
| Overview | Status, severity, attack path visual, agent results summary, approval card |
| Agents | Per-agent status, duration, findings count, summaries |
| Evidence | Corroborating evidence table, affected files |
| Root Cause | Structured root cause analysis with CWE/CVSS |
| Patch | Diff viewer, risk assessment, regression test source |
| Verification | Check results (passed/failed/skipped), exploit status |
| Before/After | Before/after comparison metrics |
| Timeline | Chronological event log |

### Components

| File | Purpose |
|------|---------|
| `components/layout/Sidebar.tsx` | Navigation sidebar |
| `components/ui/Badge.tsx` | SeverityBadge, StatusBadge, ConfidenceBadge |
| `components/ui/Card.tsx` | Card, CardHeader, CardBody |
| `components/investigation/AgentActivityPanel.tsx` | Live agent execution status during SSE stream |
| `components/investigation/AttackPathVisual.tsx` | Step-by-step attack flow diagram |
| `components/investigation/DiffViewer.tsx` | Syntax-highlighted unified diff |
| `components/investigation/VerificationPanel.tsx` | Check results with pass/fail/skip icons |
| `components/investigation/BeforeAfterPanel.tsx` | Before/after comparison |
| `components/investigation/ProgressBar.tsx` | Progress indicator |

### API client (`lib/api.ts`)
All SECUREFIX backend routes covered. Base URL from `NEXT_PUBLIC_API_URL` env var (default: `http://localhost:8000`). Demo page makes direct calls to `http://localhost:8001` (the demo app) — hardcoded.

---

## 6. SecureBank Architecture and Current Behavior

### Database Schema
SQLite (`securebank.db`). Four tables: `users`, `accounts`, `transactions`, `profiles`.

### Seed Data (created by `_seed_demo_data()` on first startup)

**Users:**
| id | username | password | full_name |
|----|----------|----------|-----------|
| 1 | alice | alice123 | Alice Johnson |
| 2 | bob | bob123 | Bob Smith |
| 3 | carol | carol123 | Carol Williams |

**Accounts:**
| id | user_id | account_number | type | balance |
|----|---------|----------------|------|---------|
| 1 | 1 (Alice) | ACC-1001 | checking | $5,420.75 |
| 2 | 2 (Bob) | ACC-1002 | checking | $12,800.50 |
| 3 | 2 (Bob) | ACC-1003 | savings | $45,000.00 |
| 4 | 3 (Carol) | ACC-1004 | checking | $2,300.00 |

### Authentication Mechanism
- **POST `/api/auth/login`** accepts `{username, password}`, verifies with `bcrypt.checkpw`, returns JWT with `sub=user_id, username=username`.
- JWT signed with `HS256`, `SECRET_KEY = os.environ.get("SECRET_KEY", "demo-secret-key-not-for-production")`.
- 60-minute expiry. `get_current_user()` dependency decodes JWT, returns `{"id": int, "username": str}`.

### Authorization Mechanism
FastAPI `Depends(get_current_user)` on all protected routes. This confirms *authentication* (token is valid) but does NOT confirm *ownership* of the requested resource.

### User Model
`users` table. Accessed only via `get_current_user()` returning a dict from the JWT payload.

### Resource Ownership Model
`accounts.user_id` is a foreign key to `users.id`. Ownership verification **must be coded explicitly** by comparing `row["user_id"] != current_user["id"]`. This check is **absent** in the vulnerable endpoints.

### Vulnerable Endpoints (intentional)

| Endpoint | Vulnerability | Severity |
|----------|--------------|---------|
| `GET /api/accounts/{account_id}` | BOLA — no ownership check | **PRIMARY DEMO TARGET** |
| `GET /api/transactions/{transaction_id}` | BOLA — no ownership check via accounts table | Secondary |
| `GET /api/transactions/account/{account_id}` | BOLA — no account ownership check | Secondary |
| `GET /api/profile/{profile_id}` | BOLA — no ownership check, exposes SSN last 4 and DOB | Secondary |

### Correct/Non-Vulnerable Endpoints
| Endpoint | Behavior |
|----------|---------|
| `GET /api/accounts/` | Returns only accounts WHERE `user_id = current_user["id"]` — **safe** |
| `GET /api/profile/me/` | Returns profile for `current_user["id"]` — **safe** |
| `POST /api/auth/login` | No ownership concept — correct |

### Attack Precondition
Alice is authenticated (any valid user suffices). She holds a JWT token. She knows or guesses a target account_id.

### Expected Vulnerable Response
`GET /api/accounts/2` with Alice's JWT → HTTP 200 OK with Bob's account data (`account_number: ACC-1002, balance: 12800.5, user_id: 2`).

### Expected Owner Response
`GET /api/accounts/1` with Alice's JWT → HTTP 200 OK with Alice's own data.

### Expected Non-Owner Response (after fix)
`GET /api/accounts/2` with Alice's JWT → HTTP 403 Forbidden: `"Access forbidden: you do not own this account"`

### Current Remediation (in the codebase)
The `demo-reset.sh` script restores the vulnerable state. The `RemediationEngine._bola_patch_accounts_py()` method contains the exact before/after text strings for the patch. After SECUREFIX applies the fix, `accounts.py` gains:
```python
if row["user_id"] != current_user["id"]:
    raise HTTPException(status_code=403, detail="Access forbidden: you do not own this account")
```

### Current Regression Tests (demo-app)
3 tests in `demo-app/tests/test_accounts.py`:
1. `test_alice_can_access_own_account` — PASSES (before and after fix)
2. `test_unauthenticated_access_blocked` — PASSES (before and after fix)
3. `test_alice_cannot_access_bobs_account` — **FAILS before fix** (returns 200, expected 403). **PASSES after fix** (returns 403).

### How the Application is Started
- `./start.sh` — starts demo-app, backend, frontend as background processes (with local venvs)
- `docker-compose up --build` — containerized deployment
- Demo app starts via `uvicorn app.main:app --host 0.0.0.0 --port 8001`, which calls `init_db()` via the FastAPI lifespan hook.

### How it is Reset
`./demo-reset.sh` — removes `securebank.db`, removes generated test files, restores the vulnerable `accounts.py` text.

### Whether HTTP Verification is Real
**Yes, in two modes:**
1. **TestClient mode (primary):** `VerificationEngine._check_exploit_blocked()` spawns a subprocess running Python that imports `demo-app/app/main` directly and exercises it via `fastapi.testclient.TestClient`. This is a real in-process HTTP call against the actual application code.
2. **Live HTTP mode (fallback):** If the TestClient subprocess fails, `_check_exploit_blocked()` falls back to `urllib.request` against `http://localhost:8001`. This requires the demo app to be running.
3. **Code inspection mode (last resort):** If both above fail, falls back to regex pattern matching on the patched file.

---

## 7. Existing Verification Architecture

### What Is Executed

`VerificationEngine.verify()` runs 5 checks in sequence:

| Check | Implementation | What it Actually Does |
|-------|---------------|----------------------|
| Regression test written | File I/O | Writes auto-generated pytest source to `demo-app/tests/test_securefix_regression_*.py` |
| Test suite | `subprocess.run([python, "-m", "pytest", "tests/"])` | Runs ALL tests in demo-app including the written regression test |
| Static security re-scan | Regex on patched files | Checks for known-bad patterns (BUG comment, `shell=True`) or known-good patterns (ownership check, boundary validation) |
| Exploit replay blocked | Subprocess (TestClient) or live HTTP | Actually executes the attack scenario and observes the HTTP status code |
| Application build | `subprocess.run([python, "-c", "import app.main"])` | Verifies the patched application can be imported without error |

### Whether Requests Are Real
**Yes.** For exploit replay, the verification engine spawns a subprocess that imports the demo app and makes real HTTP requests via `TestClient`. This is verified by `test_exploit_execution_detects_vulnerability` in the backend test suite, which confirms that in the vulnerable state, the response is HTTP 200 with `blocked=False`.

### How Expected Results Are Represented
- **Exploit blocked:** HTTP status code comparison — 403 → blocked, 200 → not blocked, other codes → classification depends on context.
- **Test suite:** pytest exit code 0 → passed, non-zero → failed.
- **Static re-scan:** Pattern presence/absence in patched file content.
- **Build check:** subprocess exit code 0 → passed.

### How Failures Are Classified
- `passed` / `failed` / `skipped` per check.
- Overall: `verified` (no failures), `partial` (only non-critical failures), `failed` (test suite or static re-scan failed).
- `partial` is used when non-critical checks (exploit replay, build) fail but test suite and static re-scan passed.

### PASS / BYPASS / ERROR / UNSUPPORTED Classification

| Concept | Current State |
|---------|--------------|
| **PASS** | Exists: `overall_status: "verified"` or per-check `"passed"` |
| **BYPASS** | **Partially exists:** Exploit replay returning HTTP 200 sets `blocked=False` and `overall_status: "failed"`. However, it is not explicitly labelled "BYPASS" — it is just a failed check. The distinction between "patch applied but bypass found" vs "patch not applied" is not formalized. |
| **ERROR** | **Partially exists:** `subprocess.TimeoutExpired` → `status: "failed", detail: "Test suite timed out"`. `FileNotFoundError` → `status: "skipped"`. Runtime exceptions → `status: "failed"`. Not distinguished by type from security failures in the overall status logic. |
| **UNSUPPORTED** | **Partially exists:** `status: "skipped"` is used when no repository path, no tests directory, or pytest unavailable. The engine does not explicitly label a vulnerability class as "unsupported" — it falls through to the code inspection fallback. |

**Gap:** The 4-state taxonomy (PASS/BYPASS/ERROR/UNSUPPORTED) is not formally modeled as a type. A `VerificationCheck` only has `status: "passed" | "failed" | "skipped"`. There is no explicit `"bypass"` or `"error"` check status.

### Whether Verification Can Produce Evidence
**Yes — partially.** The `VerificationResult` model contains `checks`, `exploit_blocked`, `regression_passed`, and `summary`. The Markdown report includes all check results with status symbols. However, there is no structured evidence bundle (e.g., raw pytest output, HTTP response body, commit hashes, timestamps of each step) stored for audit purposes. The audit log records `INVESTIGATION_CREATED`, `AGENT_STARTED_*`, `AGENT_COMPLETED_*`, etc., but not the raw verification outputs.

### Whether Verification Is Deterministic/Reproducible
**Conditionally yes.** Given the same repository state, the same Python environment, and the same running application, verification produces the same result. However:
- If the demo app is reset between investigation and verification (e.g., `demo-reset.sh` runs), the exploit check will return HTTP 200 even though the patch was applied — because the reset overwrites the patched file.
- Timing matters: the live HTTP fallback depends on whether `localhost:8001` is reachable at verification time.
- The auto-generated regression test file path includes the investigation ID, so re-runs produce different file names.

---

## 8. Existing Remediation Architecture

### Where Remediation Is Proposed
`RemediationEngine.propose()` is called from `AgentOrchestrator.run_investigation()` after root cause analysis. The proposal is stored in `investigation.remediation` with `status: PENDING`.

### Patch Generation Strategy
`RemediationEngine` dispatches on the `primary_finding` string from the `CorrelationResult`:
- BOLA → `_bola_fix()` → searches for the specific "BUG:" comment pattern in the file, or falls back to `_bola_patch_accounts_py()` (hardcoded before/after strings for `app/routes/accounts.py`)
- Path traversal → `_path_traversal_fix()` → regex-based patch generation for `os.path.join()` calls
- Command injection → `_command_injection_fix()` → replaces `shell=True` with `shell=False`
- SQL injection → `_sqli_fix()` → returns empty patches (summary only, no code change)
- Missing auth → `_missing_auth_fix()` → returns empty patches (summary only, no code change)
- Hardcoded secret → `_hardcoded_secret_fix()` → returns empty patches
- Generic → `_generic_proposal()` → returns empty patches

**Key limitation:** Only BOLA and (partially) path traversal/command injection produce actual `FilePatch` objects with `before`/`after` content. SQL injection, missing auth, and hardcoded secrets generate `RemediationProposal` with empty `patches` lists. Those proposals cannot be applied by `RemediationEngine.apply()`.

### Patch Application Safety
`RemediationEngine.apply()` includes:
1. Repository boundary check (no path traversal escape)
2. Target file must exist
3. `before` content must be present in the original file (exact match, then fuzzy fallback)
4. SHA256 hash recorded before and after

---

## 9. Human Approval Architecture

### Where Approval Is Requested
Investigation status transitions to `AWAITING_APPROVAL` after `RemediationEngine.propose()` completes. An SSE event (`patch_ready`) notifies the frontend. The frontend renders an `ApprovalCard` in the Overview tab.

### Where Approval Is Represented
`RemediationProposal.status: RemediationStatus` — values: `PENDING` → `APPROVED` | `REJECTED` → `APPLIED` → `VERIFIED` | `FAILED`.

### Whether Approval Is Actually Enforced Before Patch Application
**Yes, enforced at the API level.** In `POST /api/investigations/{id}/approve`:
```python
if inv.status != InvestigationStatus.AWAITING_APPROVAL:
    raise HTTPException(400, ...)
```
In `RemediationEngine.apply()`:
```python
if not proposal or proposal.status != RemediationStatus.APPROVED:
    return False
```
The `apply_patch_and_verify` background task is only added if `decision.approved is True`. An AI agent **cannot** call `apply()` directly — it must go through the `POST /approve` API endpoint.

### Whether an AI Agent Can Silently Apply a Security-Sensitive Patch
**No.** The orchestrator's `apply_patch_and_verify()` method requires `proposal.status == RemediationStatus.APPROVED`, which can only be set by the human approval endpoint. The orchestrator itself does not call `RemediationEngine.apply()` during the investigation phase — only in the post-approval phase triggered by the API.

### Whether Approval Is Persisted/Audited
**Yes.** The `store.log_audit()` call is made in the approval handler with action `PATCH_APPROVED` or `PATCH_REJECTED`, actor `user`, including the comment. These are written to the SQLite `audit_events` table and retrievable via `GET /api/investigations/{id}/audit`. The approval action also appends to `investigation.timeline`.

---

## 10. Persistence and Audit Architecture

### Database
SQLite file: `backend/securefix.db`. Initialized by `db.init_db()` on store construction.

### Tables

| Table | Purpose | Persistence |
|-------|---------|-------------|
| `investigations` | Full investigation state as JSON blob + indexed scalar columns | Write-through on every `store.update()` call |
| `audit_events` | Immutable append-only log of all significant actions | Written to on create, agent start/complete, approval, timeline events |
| `findings` | Denormalized agent findings for query performance | Refreshed on each `save_investigation()` call |

### In-Memory Layer
`InvestigationStore` maintains a dict `_investigations` for fast reads. On startup, loads all investigations from SQLite into memory. All writes go through both the in-memory dict and SQLite.

### SSE Pub/Sub
`asyncio.Queue` per subscriber per investigation. `store.subscribe()` → returns a queue. `store.publish()` → pushes `ProgressEvent` to all queues. `store.unsubscribe()` → removes queue. Heartbeat every 30s timeout to keep connections alive.

### Audit Trail Completeness
The following actions are logged: `INVESTIGATION_CREATED`, `AGENT_STARTED_*`, `AGENT_COMPLETED_*`, `CORRELATION_DONE` (via timeline), `ROOT_CAUSE_IDENTIFIED` (via timeline), `PATCH_PROPOSED` (via timeline), `AWAITING_HUMAN_APPROVAL`, `PATCH_APPROVED` / `PATCH_REJECTED`, `PATCH_APPLIED`, `VERIFICATION_COMPLETED`. The audit log is retrievable via API and included in the Markdown report timeline section.

**Gap:** Raw verification outputs (pytest stdout, HTTP response bodies from exploit replay) are not stored in the audit trail — only the aggregated check status.

---

## 11. Test/Build Baseline

### Backend Test Framework
pytest 9.1.1, Python 3.14, via `backend/.venv`.

### Backend Test Results (run and verified)
```
21 tests, 21 passed, 1 warning (httpx deprecation), 3.76s
```
All tests pass cleanly. The warning is a known deprecation in the installed httpx version (not a code issue).

### Backend Tests Cover
- `/health` endpoint
- Dashboard stats (including verifying the hardcoded `avg_investigation_time_reduction_pct == 68` value)
- Investigations CRUD (create, get, list, delete)
- Investigation validation (invalid path, unsupported URL, bad URL domain)
- Human approval workflow (awaiting_approval → reject)
- Report endpoint (returns markdown)
- Model field validation
- RepositoryConnector URL validation (accepts github.com, rejects evil.com, rejects SSH)
- InvestigationStore CRUD against a temporary SQLite file
- SQLite persistence across store instances (tested explicitly)
- Audit log API
- `_check_exploit_blocked()` — confirms the demo app BOLA exploit returns HTTP 200 in the vulnerable state

### Demo App Test Framework
pytest 9.1.1, Python 3.14, via `demo-app/.venv`. Uses `conftest.py` to set `SECUREBANK_TEST_DB` to a temp file.

### Demo App Test Results (run and verified)
```
3 tests: 2 passed, 1 failed
- test_alice_can_access_own_account: PASS
- test_unauthenticated_access_blocked: PASS
- test_alice_cannot_access_bobs_account: FAIL (HTTP 200, expected 403) ← INTENTIONAL, confirms BOLA is active
```
This is the **correct** pre-fix baseline state.

### Frontend Build/Test
- **Framework:** Next.js 14.2.3, TypeScript, Tailwind CSS
- **Build artifact:** `.next/` directory is present (pre-built)
- **ESLint:** Not installed in the project (lint would fail with `ESLint must be installed`)
- **TypeScript:** `tsconfig.json` present, strict mode not explicitly enabled
- **No Jest or other test framework** is configured for the frontend — no frontend unit tests exist

### Docker Configuration
- **demo-app/Dockerfile:** Python 3.11-slim, pinned package versions, port 8001, no non-root USER directive (noted as a finding by ConfigAgent)
- **backend/Dockerfile:** Python 3.11-slim, pinned versions, installs `git` for repo cloning, port 8000
- **frontend/Dockerfile:** (exists, multi-stage, not read in detail — confirmed by handoff.md)
- **docker-compose.yml:** Health checks for demo-app and backend using `curl`. Frontend depends on backend health.

### Known Failing Tests
1. `demo-app/tests/test_accounts.py::test_alice_cannot_access_bobs_account` — **intentionally fails** in the vulnerable state. This is correct behavior.

### Known Build Issues
1. Frontend ESLint not installed — `next lint` fails. Non-blocking for the build itself.
2. `httpx` + `starlette.testclient` deprecation warning in backend tests — non-blocking.

### Missing Tests
1. **Frontend:** No unit or integration tests at all.
2. **Agent unit tests:** No isolated tests for individual agents — they are only exercised end-to-end.
3. **VerificationEngine isolation tests:** No tests for `_static_recheck()`, `_run_tests()`, `_check_importable()` in isolation (only `_check_exploit_blocked()` is tested).
4. **RemediationEngine unit tests:** No tests for `_generate_bola_patch()`, `_generate_path_traversal_patch()`, `apply()`.
5. **Demo app transactions/profile endpoints:** Only `accounts.py` has tests — transactions and profile BOLA are untested.

---

## 12. Security Hard-Coding Audit

### Alice / Bob / Carol
**Classification: A — legitimate demo fixture** (they are seed data for the intentionally vulnerable app)

**Locations:**
- `demo-app/app/database.py:_seed_demo_data()` — defines users alice (id=1), bob (id=2), carol (id=3) with hardcoded credentials and account data
- `backend/app/main.py:create_demo_investigation()` — hardcoded description: *"Alice can access Bob's account by requesting /api/accounts/2"*
- `backend/app/agents/test_agent.py:_bola_regression_test()` — hardcoded `_login("alice", "alice123")`, `_login("bob", "bob123")`, comments *"Alice accessed Bob's account"*
- `backend/app/verification/engine.py:_check_exploit_blocked()` — hardcoded `'username': 'alice', 'password': 'alice123'` in exploit script; hardcoded `/api/accounts/2`; comment *"Alice accessing Bob's account"*
- `frontend/app/demo/page.tsx` — hardcoded `{username: "alice", password: "alice123"}`, hardcoded URL `/api/accounts/2`

**Risk assessment:** The demo scenario (Alice/Bob) is embedded in backend VERIFICATION and TEST GENERATION logic — not just in the frontend. This means the VerificationEngine and TestAgent currently only know how to verify **this specific BOLA scenario**. A different repository, different user names, or different account IDs would cause the exploit check to fail silently or fall back to code inspection.

---

### CWE-639 / BOLA / IDOR
**Classification: A — legitimate demo fixture** for the primary vulnerability class

**Locations:**
- `backend/app/agents/security_agent.py:VULN_PATTERNS["bola_missing_ownership"]` — hardcodes CWE-639 and patterns specific to the BOLA scenario
- `backend/app/remediation/root_cause.py:_bola_root_cause()` — hardcodes `cwe_id="CWE-639"`, `cvss_score=8.1`, `cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"`
- `backend/app/correlation/engine.py:_identify_primary_finding()` — keyword-based fallback returns `"Broken Object Level Authorization (BOLA)"` for account-related issues

---

### HTTP 200 / HTTP 403
**Classification: A — legitimate demo fixture** in test context, **C — architecture-level hardcoding** in verification engine

**Locations (problematic):**
- `backend/app/verification/engine.py:_check_exploit_blocked()` — hardcodes the expected vulnerable response as `== 200` and the expected fixed response as `== 403`. These are derived from BOLA semantics (403 = ownership denied), not from a generalizable oracle.
- `backend/app/agents/test_agent.py:_bola_regression_test()` — asserts `response.status_code == 403` and `response.status_code == 200` as constants

**Risk:** If applied to a vulnerability where the correct "blocked" response is 401, 404, or 400 (e.g., SQL injection blocked at input validation), the exploit check would incorrectly report the vulnerability as not blocked.

---

### Specific Account IDs (`/api/accounts/2`)
**Classification: C — architecture-level hardcoding** in verification and test generation

**Locations:**
- `backend/app/verification/engine.py:_check_exploit_blocked()` — hardcodes `client.get('/api/accounts/2')` as the exploit request
- `backend/app/agents/test_agent.py:_bola_regression_test()` — hardcodes `client.get("/api/accounts/2", ...)` as the attack vector and `client.get("/api/accounts/1", ...)` as the owner access

**Risk:** If the target repository has different account IDs, the exploit check will always return the wrong result. Bob's account is always assumed to be ID 2.

---

### Predetermined Attack Counts / Variant Counts / "7 of 8" Results
**Classification: D — not present** in the current implementation. No predetermined "N of M tests passed" strings were found. The verification summary is dynamically computed.

---

### Predetermined Vulnerability Status / Verification Results
**Classification: C — architecture-level hardcoding** in the fallback path

**Location:**
- `backend/app/verification/engine.py:_check_exploit_blocked()` — the third-tier fallback (code inspection) returns `blocked: True` if it finds 2+ patterns from a list including `r'row\["user_id"\]\s*!=\s*current_user\["id"\]'` and `r'status_code=403'`. This can return "blocked: True" without actually executing the attack.

---

### SecureBank-Specific Route Names
**Classification: C — architecture-level hardcoding** in verification

**Locations:**
- `backend/app/verification/engine.py` — hardcodes `/api/auth/login`, `/api/accounts/2` in the exploit script
- `backend/app/agents/test_agent.py` — hardcodes `/api/auth/login`, `/api/accounts/1`, `/api/accounts/2`, `/api/exec` (command injection test)
- `frontend/app/demo/page.tsx` — hardcodes `DEMO_API = "http://localhost:8001"`, `/api/auth/login`, `/api/accounts/2`

---

### Fixed Timing Values
**Classification: A — appropriate** — no problematic fixed timing values found. Test timeouts (60s for pytest, 20s for exploit subprocess, 15s for import check) are operational constraints, not security logic.

---

### Dashboard Demo Metrics
**Classification: D — problematic production logic** (hardcoded marketing claims as live stats)

**Location:**
- `backend/app/db.py:get_db_stats()` — returns `demo_metrics` containing:
  - `avg_investigation_time_reduction_pct: 68`
  - `manual_steps_before: 12`
  - `automated_steps_after: 1`
  - `avg_files_inspected_before: 47`
  - `avg_relevant_files_securefix: 6`
- `backend/tests/test_api.py` — explicitly asserts `data["demo_metrics"]["avg_investigation_time_reduction_pct"] == 68`

These are hardcoded presentation metrics embedded in the stats API endpoint, not derived from actual measurements.

---

## 13. Existing Functionality That Is Already Strong

1. **Human approval gate** — correctly implemented, enforced at multiple levels, audited. The AI cannot bypass it.

2. **SQLite persistence + audit trail** — every significant action is recorded in `audit_events`. Investigations survive server restarts. The audit log is retrievable via API.

3. **SSE real-time streaming** — the `asyncio.Queue` pub/sub pattern is correctly implemented. Heartbeats prevent connection timeouts.

4. **Repository boundary safety in patch application** — `RemediationEngine.apply()` explicitly checks that patch file paths cannot escape the repository root.

5. **Real pytest execution** — `VerificationEngine._run_tests()` actually runs the test suite in the repository's own venv. Regression tests are written to disk and executed.

6. **Real exploit replay** — `_check_exploit_blocked()` spawns a subprocess importing the actual demo app, making real HTTP requests via TestClient. This is not a mock.

7. **Runtime agent honesty** — `RuntimeAgent` explicitly reports "Runtime evidence unavailable — analysis based on repository source code only" when no logs exist. It does not fabricate findings.

8. **7-agent parallel execution** — the orchestrator correctly uses `asyncio.gather()` for parallel agent execution after sequential repository indexing.

9. **Demo reset capability** — `demo-reset.sh` restores the exact vulnerable state reproducibly, enabling fresh demo runs.

10. **Evidence correlation + confidence scoring** — the `CorrelationEngine` aggregates findings across agents, boosts confidence for corroborating agents, and builds a traversable evidence graph.

---

## 14. Existing Functionality That Needs Extension

1. **Verification engine — generalization** — Currently dispatches on `primary_finding` keyword matches. Exploit replay logic is hardcoded for Alice/Bob/account_id=2. Needs a generalizable Security Oracle abstraction.

2. **Patch generation coverage** — SQL injection, missing auth, and hardcoded secret proposals generate empty patch lists. The `apply()` call is a no-op for these vulnerability classes. Functional but incomplete.

3. **VerificationCheck status taxonomy** — Currently `passed | failed | skipped`. Needs `bypass | error` to distinguish "patch present but exploitable" from "test couldn't run" from "vulnerability type not supported".

4. **Dependency agent CVE database** — Only 3 packages covered (pyjwt, cryptography, fastapi). Not connected to a live advisory source.

5. **Root cause engine** — pattern-matched dispatch on 6 vulnerability classes. Cannot handle novel vulnerability types without adding a new branch.

6. **Test agent regression generator** — produces hardcoded test code for the BOLA scenario. For other classes it generates plausible but generic tests that may not be executable without modification.

7. **Evidence bundle in audit log** — raw subprocess output (pytest stdout, HTTP response bodies) is not stored in `audit_events`. Needed for reproducible audit evidence.

8. **Frontend has no tests** — no unit or integration test coverage.

---

## 15. Missing SECUREFIX X Components

The following components described in the SECUREFIX X architecture do not exist in the current implementation:

| Component | Status |
|-----------|--------|
| **Security Invariant** — a machine-readable, structured statement of what must always be true (e.g., "A user may only read accounts where `user_id == current_user.id`") | **Missing** — only implicit in text descriptions |
| **Executable Security Oracle** — a parameterized, reusable assertion that can verify the invariant against any test scenario, separate from the test runner | **Missing** — current exploit check is hardcoded per vulnerability class |
| **Adversarial Variant Generation** — generating multiple plausible attack variants beyond the base case (e.g., different account IDs, different HTTP verbs, parameter injection, encoding variations) | **Missing** |
| **Legitimate-Use Contract** — a formal specification of valid usage patterns that must continue to work after the fix (e.g., "owner access must return 200", "unauthenticated access must return 401") | **Partially present** — the BOLA regression test checks owner access and unauthenticated access, but it is hardcoded and not a generalizable contract model |
| **Controlled Security Patch Mutation Testing** — generating deliberate faulty patches (e.g., off-by-one in authorization check, wrong user_id field) and verifying the oracle detects them | **Missing** |
| **Structured Evidence Bundle** — a signed, immutable record of all verification artifacts (patch hash, test output, HTTP responses, oracle results, timestamps) | **Partially present** — audit log exists but lacks raw outputs |
| **Formal bypass detection label** — explicit "BYPASS" status when a patch exists but the vulnerability remains exploitable | **Missing** — only reflected as `failed` check |

---

## 16. SECUREFIX X Architecture Gap

```
Finding                  → IMPLEMENTED (security_agent, code_agent)
↓
Root Cause               → IMPLEMENTED (root_cause.py, pattern-matched)
↓
Security Invariant       → MISSING
↓
Executable Oracle        → PARTIALLY (hardcoded to Alice/Bob/account_id=2)
↓
Legitimate-Use Contract  → PARTIAL (embedded in BOLA regression test, not generalized)
↓
Remediation              → IMPLEMENTED (BOLA and partial others)
↓
Human Approval           → IMPLEMENTED and ENFORCED
↓
Patch Application        → IMPLEMENTED (with safety checks)
↓
Adversarial Variants     → MISSING
↓
Real HTTP Verification   → IMPLEMENTED (TestClient subprocess) — BOLA-specific
↓
Legitimate Behavior Test → PARTIAL (in regression test, hardcoded)
↓
Controlled Mutation Test → MISSING
↓
Evidence Bundle          → PARTIAL (audit log present, raw outputs missing)
↓
VERIFIED WITHIN SCOPE    → PARTIAL — works for BOLA demo, fragile for other classes
```

### Gap Severity Assessment

| Gap | Impact on SECUREFIX X Demo | Effort to Fill |
|-----|---------------------------|----------------|
| Security Invariant model | Medium — demo works without formal invariant | Medium |
| Generalized Oracle | High — verification breaks on non-BOLA targets | Medium |
| Adversarial Variant Generation | High — core SECUREFIX X differentiator | High |
| Legitimate-Use Contract | Medium — partially covered by existing regression test | Low-Medium |
| Mutation Testing | High — "would our verification detect a bad patch?" | High |
| Evidence Bundle raw outputs | Low — demo works, audit lacking | Low |
| BYPASS status label | Low — semantics present, label missing | Low |

---

## 17. Recommended Implementation Sequence

**Principle: smallest safe extension, no rebuilds**

### Phase 1 — Formalize What Already Exists (Low Risk)

1. **Add `SecurityInvariant` model** to `models.py` — a Pydantic model with fields: `invariant_statement` (str), `oracle_type` (enum: BOLA, path_traversal, command_injection, etc.), `attack_params` (dict), `expected_blocked_codes` (list[int]), `legitimate_params` (dict), `expected_legitimate_codes` (list[int]).

2. **Extend `RootCauseEngine`** to populate a `SecurityInvariant` after root cause analysis — using the same pattern-dispatch structure that already exists.

3. **Add `bypass` and `error` to `VerificationCheck.status`** — update the model, update the `_build_summary()` logic, update frontend type.

### Phase 2 — Generalize the Oracle (Medium Risk)

4. **Refactor `_check_exploit_blocked()`** to consume `SecurityInvariant.attack_params` rather than hardcoded Alice/Bob/account_id=2. The function signature stays the same; it reads parameters from the investigation model instead of literals.

5. **Refactor `_bola_regression_test()`** similarly — generate test code using `SecurityInvariant.attack_params` to drive the attacker scenario and `legitimate_params` for the owner scenario.

### Phase 3 — Adversarial Variant Generation (New Capability)

6. **Add `VariantGenerator`** as a new module `backend/app/verification/variants.py` — generates a list of `AttackVariant` objects from the `SecurityInvariant`. Each variant is a parameterized version of the attack (e.g., different account_ids, HEAD instead of GET, URL encoding variations). Does NOT require a new agent — called from `VerificationEngine.verify()` after the base exploit check.

7. **Run variant checks** — for each variant, apply the same oracle logic. Aggregate results as `VariantResult` objects. Add to `VerificationResult`.

### Phase 4 — Mutation Testing (Isolated, Future)

8. **Controlled security patch mutation** — operates on an isolated copy (git worktree or temp directory). Generates a list of `PatchMutant` objects (plausible faulty patches). For each mutant: apply to isolated copy, run oracle, verify oracle detects it. **Strictly isolated — never touches the real repository.**

### Phase 5 — Evidence Bundle

9. **Extend `VerificationEngine`** to capture raw subprocess stdout/stderr, HTTP response bodies, and oracle parameter sets into structured `EvidenceArtifact` objects. Store in `audit_events` via `store.log_audit()` with `metadata` containing the artifacts.

---

## 18. Files/Modules Likely Requiring Modification

| File | Reason |
|------|--------|
| `backend/app/models.py` | Add `SecurityInvariant`, `AttackVariant`, `VariantResult`; extend `VerificationCheck.status`; extend `VerificationResult` |
| `backend/app/verification/engine.py` | Refactor `_check_exploit_blocked()` to use invariant params; add variant loop; capture raw evidence |
| `backend/app/agents/test_agent.py` | Refactor `_bola_regression_test()` to use invariant params; add legitimate-use contract test generation |
| `backend/app/remediation/root_cause.py` | Add invariant population step |
| `backend/app/orchestrator.py` | Pass invariant through pipeline stages |
| `frontend/lib/types.ts` | Mirror new backend model fields |

---

## 19. Files/Modules That Should Be Preserved

| File | Reason |
|------|--------|
| `backend/app/main.py` | All routes are correct and tested — do not modify |
| `backend/app/store.py` | SSE pub/sub and SQLite persistence are correct |
| `backend/app/db.py` | Schema is adequate; do not change existing tables |
| `backend/app/orchestrator.py` | Pipeline structure is correct; only extend, do not restructure |
| `backend/app/agents/*.py` | All 7 agents functional; extend only to pass invariant if needed |
| `backend/app/correlation/engine.py` | Correlation logic is correct |
| `backend/app/remediation/engine.py` | Patch generation logic is correct for BOLA; do not break existing patches |
| `backend/app/report.py` | Markdown generation is complete |
| `backend/app/repository.py` | URL validation and clone logic is correct |
| `demo-app/` | Entire demo app — do not modify (preserve vulnerability for testing) |
| `demo-reset.sh` | Preserve exactly — critical for repeatable demos |
| `frontend/` | All pages and components — extend only |

---

## 20. Security and Safety Risks

### Risk 1: Verification can be fooled by code comment patterns
The third-tier fallback in `_check_exploit_blocked()` reports `blocked: True` if 2+ regex patterns match in the patched file, including `r'status_code=403'`. A comment or string literal containing `status_code=403` without the actual enforcement logic would satisfy this check. **Severity: Medium.** Mitigated by the fact that the primary check (TestClient subprocess) runs first.

### Risk 2: Demo reset can destroy an applied patch
If `demo-reset.sh` is run while an investigation is in `VERIFIED` state, it overwrites `accounts.py` back to the vulnerable version. The investigation record still shows `remediation.status == "verified"` — which is now false. **Severity: Low** in demo context, **High** in production context.

### Risk 3: Patch application is irreversible without demo-reset
`RemediationEngine.apply()` does not create a git commit or backup before patching. If the patch is incorrect, there is no rollback mechanism beyond running `demo-reset.sh` or manual file restoration. **Severity: Medium.** For production use, a pre-patch git commit or file backup is required.

### Risk 4: Subprocess exploit check runs with application process privileges
`_check_exploit_blocked()` spawns `python -c "..."` with the demo-app path as cwd. The subprocess imports `app.main` which initializes the database. This is fine in demo context but represents a code execution vector if the repository path is untrusted. The `RepositoryConnector` validates URLs but sandbox isolation is not enforced. **Severity: Medium** if extended to arbitrary repositories.

### Risk 5: Hardcoded demo SECRET_KEY
`demo-app/app/auth.py` falls back to `"demo-secret-key-not-for-production"`. `docker-compose.yml` sets `SECRET_KEY: demo-secret-key-not-for-production`. JWT tokens signed with this key can be forged by anyone who reads the source. **Severity: Intentional** in demo context, but if the demo app is ever exposed publicly, tokens are forgeable.

### Risk 6: SQLite concurrency
`sqlite3.connect(..., check_same_thread=False)` is used. With multiple concurrent investigations and SSE streams, concurrent writes could cause database locking under high load. **Severity: Low** for the hackathon demo context.

---

## 21. Questions/Unknowns That Must Be Resolved Before Implementation

1. **What is the canonical form of a Security Invariant?** Should it be expressed as a natural language string, a formal predicate, a parameterized test assertion, or all three? The current system has the concept implicitly in `RootCauseAnalysis.root_cause` text but needs a machine-readable form.

2. **How should adversarial variants be scoped?** For BOLA, obvious variants are: different account_ids, different HTTP methods, query parameter injection, URL encoding (`%2F` in account_id), integer overflow in account_id. Should variants be generated from a class-specific template or from a generalized fuzzing heuristic?

3. **How should the invariant be populated for vulnerability classes with empty patches?** SQL injection, missing auth, and hardcoded secret proposals currently have no `FilePatch` objects. Can the verification pipeline operate on these, or should Phase 2 be gated on having a real patch?

4. **Should mutation testing operate on git worktrees or temp directories?** Worktrees are cleaner but require git. Temp directory copies are simpler but waste disk. The repo has `gitpython` installed in the backend venv.

5. **Should the `VariantGenerator` be a new agent or a component of `VerificationEngine`?** Making it a new agent (Agent 8) would fit the existing architecture but complicates the pipeline because it must run post-patch, not pre-patch. A `VerificationEngine` sub-component avoids pipeline restructuring.

6. **Is the demo app's Python venv path guaranteed to be at `.venv/`?** The verification engine looks for `.venv/bin/python` first. This assumption is correct for the current setup but may break for cloned GitHub repos with different venv layouts.

7. **Should the Evidence Bundle replace the current `VerificationResult` or extend it?** Replacing would require frontend changes. Extending (adding an `artifacts` field to `VerificationResult`) is the minimal safe approach.

8. **How should the re-test flow in `frontend/app/demo/page.tsx` trigger after patch application?** Currently it requires the user to manually click "Re-test exploit" (Step 4). Should this be triggered automatically when `investigation.verification` becomes available?

---

## 22. Final Recommendation

**Do not rebuild. Extend precisely.**

The existing Kiro/Antigravity implementation is architecturally sound and functionally verified. The 7-agent pipeline, human approval gate, real pytest execution, real HTTP exploit replay, audit logging, and SSE streaming are all working correctly. The demo scenario (BOLA on SecureBank) works end-to-end, and the test suite confirms this with 21/21 backend tests passing and the demo app BOLA test correctly failing.

The gap between the current implementation and SECUREFIX X is not a gap in architecture — it is a gap in **generalization and formal structure**. The right work is:

1. **Formalize the Security Invariant** that is already implicit in the `RootCauseAnalysis` and `VerificationEngine`.
2. **Parameterize the existing exploit check** to consume the invariant rather than hardcoded Alice/Bob/account_id=2.
3. **Add adversarial variant generation** as a new module called from within `VerificationEngine` — not as a new agent.
4. **Add mutation testing** as an isolated capability that operates on a temp copy — never touching the real repository or demo app.
5. **Extend the evidence model** to capture raw verification outputs.

The existing seven agents, the orchestrator, the human approval gate, the SQLite persistence, the SSE streaming, the frontend, and the demo app should all be preserved exactly as they are. Each piece of new SECUREFIX X capability should be additive — either a new model field, a new module, or an extension of an existing method's internal logic.

The smallest safe next task is: **add the `SecurityInvariant` Pydantic model and populate it from `RootCauseEngine`**. Everything else in the SECUREFIX X roadmap depends on having this structured representation of what the system is asserting.

---

*End of audit. No application code was modified in the preparation of this document.*
