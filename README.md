# SECUREFIX

> **Detect. Understand. Fix. Verify.**

Autonomous AI engineering workflow for investigating, fixing, testing, and verifying software security failures — end to end.

Built for the **IBM Bob 2.0 Hackathon 2026**.

---

## Problem

Security findings don't end when a scanner produces an alert.

Developers still have to:

1. Understand the finding
2. Search the repository manually
3. Trace the data flow
4. Identify the root cause
5. Write a fix
6. Write a regression test
7. Run tests
8. Verify the fix actually works

That workflow is fragmented, time-consuming, and error-prone.

---

## Solution

SECUREFIX compresses that workflow into one coordinated AI-assisted process.

```
Detection → Investigation → Evidence Correlation →
Root Cause → Patch → Human Approval → Regression Test →
Verification → Report
```

> **AI investigates. Human approves. System verifies.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SECUREFIX Frontend                   │
│            Next.js · TypeScript · Tailwind CSS          │
└────────────────────────┬────────────────────────────────┘
                         │ REST + SSE
┌────────────────────────▼────────────────────────────────┐
│                   SECUREFIX Backend                     │
│                FastAPI · Python · SQLite                │
│                                                         │
│  AgentOrchestrator                                      │
│     ├── RepositoryAgent                                 │
│     ├── SecurityAgent                                   │
│     ├── CodeAgent          (parallel)                   │
│     ├── DependencyAgent    (parallel)                   │
│     ├── ConfigAgent        (parallel)                   │
│     ├── TestAgent          (parallel)                   │
│     └── RuntimeAgent       (parallel)                   │
│                                                         │
│  CorrelationEngine → RootCauseEngine                    │
│  RemediationEngine → VerificationEngine                 │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│               SecureBank Demo App                       │
│          FastAPI · SQLite · JWT · bcrypt                │
│     (Intentionally vulnerable for demonstration)        │
└─────────────────────────────────────────────────────────┘
```

---

## Multi-Agent Workflow

| Agent | Responsibility |
|-------|---------------|
| Repository Intelligence | Index structure, languages, frameworks, API routes, auth/DB components |
| Security Investigation | Find vulnerable data flows, missing checks, attack paths |
| Code Analysis | Data-flow and control-flow analysis on relevant files |
| Dependency Analysis | Scan manifests for vulnerable packages |
| Configuration Analysis | Dockerfile, .env, CORS, debug mode |
| Test Coverage | Identify missing tests, generate regression test |
| Runtime / Log | Analyze logs for exploitation evidence |

All agents after Repository Intelligence run **in parallel**.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS, Lucide Icons |
| Backend | Python, FastAPI, Pydantic, SQLite |
| Demo App | Python, FastAPI, SQLite, PyJWT, bcrypt |
| Tests | pytest, FastAPI TestClient |
| Streaming | Server-Sent Events (SSE) |

---

## Demo Application

**SecureBank API** — a realistic banking API with intentional security vulnerabilities.

### Credentials

| User | Password | User ID |
|------|----------|---------|
| alice | alice123 | 1 |
| bob | bob123 | 2 |
| carol | carol123 | 3 |

### Vulnerability: Broken Object Level Authorization (BOLA)

```
GET /api/accounts/{account_id}
```

The endpoint authenticates the user (validates JWT) but does **not** verify that the authenticated user owns the requested account.

**Exploit:** Alice logs in, then requests `/api/accounts/2` (Bob's account) and receives Bob's balance and account details.

---

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+

### Quick Start

```bash
git clone <repo>
cd securefix
./start.sh
```

This starts:
- Demo app on http://localhost:8001
- SECUREFIX backend on http://localhost:8000
- SECUREFIX frontend on http://localhost:3000

---

## Running Locally (Manual)

### Demo App

```bash
cd demo-app
python3 -m venv .venv
.venv/bin/pip install fastapi uvicorn PyJWT bcrypt python-multipart
.venv/bin/uvicorn app.main:app --port 8001 --reload
```

### SECUREFIX Backend

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install fastapi uvicorn pydantic python-dotenv aiofiles httpx
DEMO_REPO_PATH=../demo-app .venv/bin/uvicorn app.main:app --port 8000 --reload
```

### SECUREFIX Frontend

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

---

## Example Investigation

1. Open http://localhost:3000
2. Click **Start Demo Investigation** — one click launches the BOLA scenario
3. Watch 7 agents execute in parallel (SSE live feed)
4. Review correlated evidence across all agents
5. Read the root cause analysis
6. Inspect the proposed patch (diff view)
7. Click **Approve & Apply**
8. Watch verification run tests
9. Confirm the exploit is blocked

---

## Verification Workflow

After approval, SECUREFIX:

1. Applies the patch to the repository
2. Writes the generated regression test
3. Executes the full test suite (pytest)
4. Re-scans the patched file for vulnerable patterns
5. Confirms the exploit vector is blocked
6. Reports: VERIFIED or FAILED

Before fix → `test_alice_cannot_access_bobs_account` **FAILS** (200 returned)  
After fix → `test_alice_cannot_access_bobs_account` **PASSES** (403 returned)

---

## Security Model

- Human approval required before any code modification
- No silent repository changes
- Audit timeline on every investigation
- Input validation on all API endpoints
- Path traversal protection on repository access
- No secrets in repository — environment variables only

---

## IBM Bob 2.0 Usage

Bob 2.0 was used throughout development for:

- Understanding repository architecture before implementing agents
- Implementing the multi-agent orchestration pattern
- Generating the correlation engine logic
- Debugging the SSE streaming implementation
- Refactoring the remediation engine
- Writing and fixing tests
- Implementing UI components

---

## Future Roadmap

- GitHub/GitLab pull request integration
- Docker sandbox for isolated verification
- PDF report export
- Multi-repository support
- Enterprise RBAC
- Slack/Jira integration
- Historical analytics dashboard
- Support for more vulnerability classes (SSRF, XXE, deserialization)

---

## Team

Built for the IBM Bob 2.0 Hackathon 2026.

---

*SECUREFIX — Detect. Understand. Fix. Verify.*
