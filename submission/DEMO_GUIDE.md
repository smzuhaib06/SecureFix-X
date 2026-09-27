# SECUREFIX X — Live Hackathon Demonstration Guide

This guide provides exact step-by-step instructions for running the live hackathon demonstration of SECUREFIX X using the verified public GitHub repository: **`https://github.com/vulnerable-apps/nodejs-goof`**.

---

## Prerequisites & Pre-Demo Check

1. **Verify Backend is Running:**
   ```bash
   curl -s http://localhost:8000/health
   # Expected output: {"status":"healthy","service":"securefix-api"}
   ```
2. **Verify Frontend is Running:**
   ```bash
   curl -sI http://localhost:3000
   # Expected output: HTTP/1.1 200 OK
   ```
3. **Open Browser:**
   Navigate to: `http://localhost:3000`

---

## Live Demonstration Flow (5-Minute Walkthrough)

### Step 1: Landing Page & Problem Pitch
- Point out the core philosophy: *"Find it. Understand it. Fix it. Break the fix. Prove it."*
- State clearly: *"Modern AI can hallucinate a patch in seconds. SECUREFIX X focuses on the missing link: proving that the remediation actually prevents exploitation."*

### Step 2: Trigger Live GitHub Ingestion
1. Click **"New Investigation"** in the top navigation bar (`/investigations/new`).
2. In the Repository URL field, enter:
   ```text
   https://github.com/vulnerable-apps/nodejs-goof
   ```
3. Title: `Goof Authentication NoSQL Injection Audit`
4. Click **"Start Investigation"**.
5. *What to highlight:* The backend spawns an isolated sandbox in `/tmp/securefix_sandbox_*`, clones only the required ref with `--depth 1`, and initiates multi-agent scanning.

### Step 3: Inspect the 7 Security Evidence Agents
- Watch the progress bar advance from 0% to 90% via Server-Sent Events (SSE).
- Explain the division of labor across the 7 specialized evidence agents:
  - **RepositoryAgent:** Identified `JavaScript / Express / MongoDB / Mongoose`.
  - **SecurityAgent:** Flagged `CWE-943 (NoSQL Injection)` in `routes/index.js`.
  - **CodeAgent:** Mapped AST dataflow from `req.body.username` -> `Account.find`.
  - **DependencyAgent:** Flagged vulnerable versions of `mongoose@4.2.4` and `express@4.12.4`.
  - **ConfigAgent:** Identified container root execution in `Dockerfile`.
  - **TestAgent:** Discovered Mocha/Jest spec suites.
  - **RuntimeAgent:** Honestly noted that live daemon logs are currently `UNAVAILABLE` (no synthetic logs fabricated).

### Step 4: Explore RAG Knowledge & Grounded AI Reasoning
1. Click on the **"AI Reasoning & RAG"** tab.
2. Show the **RAG Citations**:
   - `CWE-943`: Improper Neutralization of Special Elements used in Data Query Logic.
   - `FWGUIDE-EXPRESS-MONGO`: Hardening Mongoose Query Construction.
3. Show the **Grounding Guarantee**:
   - The reasoning strictly quotes verified symbols (`routes/index.js:39`, `req.body.username`).
   - Mention the `AIGroundingValidator` which programmatically prevents hallucinated routes or non-existent files.

### Step 5: Human-in-the-Loop Approval Gate
1. Scroll down to the **Remediation & Patch** section.
2. Review the unified diff showing the input sanitization / type casting on login inputs.
3. Click the green button: **"Approve Remediation"**.
4. Status transitions to `APPROVED` -> `REPAIRING` -> `VERIFYING`.

### Step 6: Adversarial Verification & Mutation Assurance
1. Click on the **"Verification Engine"** tab.
2. Point out the **Adversarial Variants**:
   - The engine replays real attack vectors (`$gt` injections, nested objects).
   - Shows that the exploit packets are blocked while legitimate authentication passes.
3. Point out the **Controlled Mutation Testing**:
   - Deliberately weakened mutants of the patch were injected.
   - The test suite detected all mutants (100% Mutation Detection Score).

### Step 7: Final Scorecard
- Point to the final banner: **VERIFIED WITHIN TESTED SCOPE**.
- Reiterate: *"We don't claim unprovable universal security. We provide auditable evidence for the exact attack surface and invariants tested."*
