# SECUREFIX X

**AI-Assisted Security Remediation Assurance**

> *Find it. Understand it. Fix it. Break the fix. Prove it.*

[![Backend Tests](https://img.shields.io/badge/backend%20tests-368%20passed-brightgreen.svg)](#15-testing)
[![Frontend Build](https://img.shields.io/badge/frontend%20build-passing-brightgreen.svg)](#14-deployment)
[![Multi-Stack](https://img.shields.io/badge/multi--stack-Python%20%7C%20Node.js%20%7C%20TypeScript-blue.svg)](#10-github-repository-analysis)
[![Platform](https://img.shields.io/badge/hackathon-IBM%20Bob%202.0-blueviolet.svg)](#11-supported-demonstration)

---

## 1. Problem

Modern cybersecurity scanners (SAST, DAST, SCA) excel at generating hundreds of vulnerability alerts. Similarly, generative AI coding assistants can generate syntactically plausible code patches in seconds.

However: **A patch is not proof of remediation.**

In modern software development:
1. **Unverified Patches Cause Regressions:** A patch may superficially silence a scanner while leaving alternate attack paths or breaking legitimate business logic.
2. **Context Fragmentation:** Developers must manually correlate dependencies, Dockerfiles, route definitions, and dataflow paths across fragmented tools.
3. **Absence of Proof:** Code review teams have no automated way to prove whether a patch actually withstands adversarial bypass attempts before merging.

---

## 2. Solution

**SECUREFIX X** transforms vulnerability remediation from superficial code editing into **verifiable security assurance**.

Rather than relying on ungrounded chatbot suggestions, SECUREFIX X:
1. Discovers and traces the vulnerability across the codebase using **7 specialized deterministic agents**.
2. Correlates findings with authoritative security standards (CWE, OWASP ASVS v4.0.3) via **local RAG**.
3. Synthesizes a formal **Security Invariant** using **grounded AI reasoning**.
4. Enforces an explicit **Human-in-the-Loop Approval Gate** before code modification.
5. Applies a minimal, auditable patch to the repository.
6. **Actively attacks the patch** using bounded adversarial variant replay.
7. Evaluates patch resilience through **controlled AST mutation testing**.
8. Issues an unembellished guarantee: **VERIFIED WITHIN TESTED SCOPE**.

---

## 3. Seven Evidence Agents

SECUREFIX X replaces monolithic prompt engineering with seven specialized, deterministic evidence agents:

| Agent | Responsibility | Output Type |
|---|---|---|
| **Repository Intelligence Agent** | Analyzes project manifests, entrypoints, framework routers, and dependencies to construct a `TechnologyProfile`. | Deterministic Profile |
| **Security Investigation Agent** | Detects high-risk vulnerability classes (BOLA/IDOR, SQLi, NoSQLi, Path Traversal). | Finding List |
| **Code Analysis Agent** | Performs AST-level dataflow tracing from untrusted HTTP request sources (`req.body`, `params`) to database sinks (`Account.find`, `open`). | Direct AST Sinks |
| **Dependency Agent** | Scans dependency manifests (`package.json`, `requirements.txt`) and audits versions against advisory databases. | Advisory Records |
| **Configuration Agent** | Audits infrastructure and container security (`Dockerfile` root execution, environment handling, CORS). | Config Flaws |
| **Test Analysis Agent** | Analyzes existing test suites, measures coverage, and synthesizes targeted regression tests. | Test Matrix |
| **Runtime / Log Agent** | Evaluates execution logs and telemetry, honestly reporting status without inventing synthetic logs. | Telemetry Record |

---

## 4. Security Evidence Package

All agent outputs are aggregated into a cryptographically grounded `SecurityEvidencePackage`:
- **Evidence Strength Categorization:** Classifies evidence as `DIRECT`, `CORROBORATED`, `INFERRED`, or `UNAVAILABLE`.
- **Line-Level Provenance:** Every code excerpt retains source file paths, line ranges, and SHA-256 commit hashes.
- **Untrusted Code Quarantine:** Untrusted user code is quarantined inside defensive markdown boundaries to prevent prompt-injection attacks.

---

## 5. RAG (Retrieval-Augmented Generation)

SECUREFIX X incorporates an offline, local RAG knowledge retrieval engine (`app/ai/rag.py`):
- **Curated Knowledge Base:** Contains authoritative guidance from:
  - OWASP ASVS v4.0.3 (Application Security Verification Standard)
  - OWASP Top 10 (2021)
  - Common Weakness Enumeration (CWE-943, CWE-639, CWE-22, CWE-250)
  - Framework Hardening Guides (Express, Mongoose, FastAPI)
- **Deterministic Vector Index:** Uses TF-IDF and BM25 lexical-semantic scoring with score thresholds that suppress unrelated queries.
- **Attributed Provenance:** Citations include exact standard identifiers, titles, and relevance scores.

---

## 6. Grounded AI Reasoning

The AI reasoning layer translates evidence into actionable explanations without hallucination:
- **Dual-Mode AI Provider:**
  - **Live LLM:** Fully integrated support for Google Gemini 2.0 Flash (`google-genai`) and OpenAI GPT-4o.
  - **Deterministic Fallback:** Automatically active when no external API credentials are configured, ensuring 100% offline functionality.
- **Strict Grounding Validator (`AIGroundingValidator`):** Programmatically verifies that all entities, routes, variables, and files referenced in reasoning exist within the `SecurityEvidencePackage`.

---

## 7. Human-in-the-Loop Approval Gate

Security remediation requires human accountability:
- The system pauses in state `AWAITING_APPROVAL`.
- Developers inspect an interactive unified diff viewer detailing the exact code modifications.
- Remediation and test execution only proceed upon explicit authorized human approval.

---

## 8. Adversarial Verification

A fix that only passes the developer's unit test is not enough. SECUREFIX X's **Verification Engine** (`app/verification/engine.py`):
- Replays bounded adversarial attack variants against the patched code (e.g. BSON `$gt` / `$ne` operator injections, parameter type confusion, directory traversal encodings).
- Verifies that all exploit variants are cleanly rejected (e.g. HTTP 401/403/400).
- Verifies legitimate user contract behavior to prevent breaking legitimate application workflows.

---

## 9. Mutation Assurance

To ensure the verification process is not generating false-positive passes, SECUREFIX X features a **Controlled Mutation Testing Engine** (`app/verification/mutation.py`):
- Generates deliberately flawed mutants of the proposed patch (e.g. inverted boolean checks, removed sanitizers, loosened regex).
- Executes the verification suite against the mutants to prove the test suite reliably catches and fails on weakened fixes.
- Computes an empirical Mutation Score (100% on benchmark targets).

---

## 10. GitHub Repository Analysis

SECUREFIX X supports analyzing public GitHub repositories on-the-fly:
- **Safe Sandboxing:** Validates URLs against strict regex and executes `git clone --depth 1 --single-branch` using discrete argument arrays (immune to shell injection).
- **Ephemeral Sandbox Isolation:** Repositories are cloned to unique temporary sandbox directories in `/tmp` and automatically cleaned up in `finally:` blocks.
- **Verified Remote Targets:**
  - `https://github.com/vulnerable-apps/nodejs-goof` (Cloned & analyzed in 6.6s; detected JavaScript, Express, Mongoose, and CWE-943 NoSQL injection).
  - `https://github.com/vulnerable-apps/juice-shop` (Cloned & analyzed in 17.6s; detected TypeScript, Express, 136 routes, Docker root execution).

---

## 11. Supported Demonstration

The primary demonstration target is **Node.js Goof**:
```text
https://github.com/vulnerable-apps/nodejs-goof
      ↓
Detected Stack: JavaScript / Express / MongoDB
      ↓
Discovered Vulnerability: CWE-943 NoSQL Injection
Source: routes/index.js (req.body.username, req.body.password)
Sink: Account.find({ username: req.body.username, password: req.body.password })
      ↓
RAG Citations: CWE-943 + Express/Mongo Query Hardening
      ↓
Human Approval Gate → Remediation Applied
      ↓
Adversarial Verification → 0 / 3 Bypasses Succeeded
      ↓
Mutation Testing → 100% Mutation Detection Score
      ↓
VERIFIED WITHIN TESTED SCOPE
```

---

## 12. Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   SECUREFIX X Web Application                          │
│          Next.js 14 App Router · TypeScript · Tailwind CSS             │
│        (Investigations, Multi-Agent Milestones, Live SSE)              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP REST + Server-Sent Events
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   SECUREFIX X Backend Service                          │
│                    FastAPI · Python · SQLite                           │
├────────────────────────────────────────────────────────────────────────┤
│  AgentOrchestrator                                                     │
│     ├── 7 Security Evidence Agents (Deterministic AST & Manifests)     │
│     ├── TechnologyProfile Builder (Python, JS, TS detection)          │
│     ├── Local RAG Vector Knowledge Base (OWASP, CWE, ASVS)             │
│     ├── AI Security Reasoner (Gemini / OpenAI / Deterministic Engine)  │
│     ├── AIGroundingValidator & Untrusted Code Isolation               │
│     ├── Human Approval Gate State Machine                              │
│     ├── RemediationEngine & Patch Application                          │
│     ├── VerificationEngine & Adversarial Variant Replay                │
│     └── Controlled AST Mutation Testing Engine                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Discrete Git CLI (Safe Sandboxing)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 Ephemeral Repository Sandbox (/tmp)                    │
│   • Local target repositories (SecureBank)                             │
│   • Public GitHub repositories (nodejs-goof, juice-shop)               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 13. Setup

### Prerequisites
- Python 3.10+ (tested on 3.11/3.14)
- Node.js 18+ & npm
- Git CLI

### Quick Start (Local Development)

```bash
# 1. Clone repository
git clone https://github.com/smzuhaib06/SecureFix-X.git
cd SecureFix-X

# 2. Setup backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 8000 &

# 3. Setup frontend
cd ../frontend
npm install
npm run dev

# 4. Open in Browser
# Frontend: http://localhost:3000
# Backend API Docs: http://localhost:8000/docs
```

---

## 14. Deployment

### Frontend (Vercel)
The frontend is optimized for **Vercel**:
- **Framework:** Next.js
- **Root Directory:** `frontend`
- **Build Command:** `next build --no-lint`
- **Environment Variable:** `NEXT_PUBLIC_API_URL` pointing to backend API.

### Backend (Docker / Render / Fly.io)
Deploy the backend using the included production `backend/Dockerfile`:
```bash
docker build -t securefix-backend -f backend/Dockerfile .
docker run -p 8000:8000 -e PORT=8000 securefix-backend
```
See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for complete cloud deployment specifications.

---

## 15. Testing

The backend test suite verifies every agent, model, invariant, mutation, RAG query, and GitHub cloning connector:

```bash
# Run complete test suite from repository root
pytest -q
```

**Verified Test Output:**
```text
======================== 368 passed, 1 warning in 52.86s ========================
```

Frontend production build check:
```bash
cd frontend && npm run build
# Generating static pages (14/14) - 0 errors
```

---

## Guiding Philosophy

> *"A patch is not proof of remediation."*

# VERIFIED WITHIN TESTED SCOPE
