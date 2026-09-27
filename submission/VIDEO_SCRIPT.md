# SECUREFIX X — 2 to 3 Minute Hackathon Demo Video Script

**Target Duration:** 2 minutes 40 seconds  
**Visual Format:** 16:9 Screen Recording + Voiceover Narration  
**Demo Target:** `https://github.com/vulnerable-apps/nodejs-goof`  

---

### [0:00 – 0:15] Introduction & The Problem
- **Visual:** Full-screen browser on the SECUREFIX X landing page (`http://localhost:3000`). Clean, modern dark-mode enterprise UI showing the tagline: *"Find it. Understand it. Fix it. Break the fix. Prove it."*
- **Audio / Voiceover:**  
  > *"Security tools can find vulnerabilities, and AI can generate patches. But a patch is not proof of remediation. Generating code is trivial—what developers need is proof that the fix actually holds under attack."*

---

### [0:15 – 0:35] GitHub Ingestion & Dynamic Sandboxing
- **Visual:** Navigate to `/investigations/new`. Paste the public GitHub URL: `https://github.com/vulnerable-apps/nodejs-goof`. Click **"Start Investigation"**. Show the live status indicating Git clone and technology detection.
- **Audio / Voiceover:**  
  > *"SECUREFIX X starts with a real repository and builds security evidence directly from its codebase. Here, we point it to a live public GitHub repository: Node.js Goof. SECUREFIX securely clones it into an isolated sandbox and immediately identifies the stack as JavaScript, Express, and MongoDB."*

---

### [0:35 – 0:55] The Seven Security Evidence Agents
- **Visual:** Screen transitions to the live investigation dashboard. The 7 agents populate their milestones via real Server-Sent Events (SSE). Expand the finding to reveal line 39 in `routes/index.js`, highlighting:
  - Source: `req.body.username`, `req.body.password`
  - Sink: `Account.find({ username: req.body.username, password: req.body.password })`
  - Finding: `CWE-943 (NoSQL Injection)`
- **Audio / Voiceover:**  
  > *"Seven specialized security evidence agents independently analyze the repository. The Code and Security agents trace untrusted user input from POST /login directly into a Mongoose database query without sanitization, capturing exact code lines and dataflow provenance."*

---

### [0:55 – 1:15] Local RAG Security Knowledge Retrieval
- **Visual:** Click into the **RAG Knowledge & Standards** tab. Show ranked citations:
  - `CWE-943`: Improper Neutralization in Data Query Logic (Score: 1.22)
  - `FWGUIDE-EXPRESS-MONGO`: Hardening Mongoose Query Construction (Score: 0.88)
  - `OWASP-A03-2021`: Injection Flaws & Mitigation
- **Audio / Voiceover:**  
  > *"The evidence is grounded against curated security knowledge from CWE, OWASP, ASVS, and framework guidance. Our local RAG engine matches the Mongoose query pattern against proven standards, providing full provenance for why this knowledge was selected."*

---

### [1:15 – 1:30] Grounded AI Security Reasoning
- **Visual:** Scroll to the **AI Reasoning Panel**. Show the structured root cause analysis, invariant statement, and grounded citations.
- **Audio / Voiceover:**  
  > *"A grounded reasoning layer connects the repository evidence with security knowledge to explain the root cause and remediation. A strict grounding validator ensures the AI references only real repository code and valid standards, eliminating hallucinations."*

---

### [1:30 – 1:45] Human-in-the-Loop Approval Gate
- **Visual:** Show the interactive **Approval Gate**. The patch diff is previewed. The user reviews the unified diff sanitizing `req.body` parameters, clicks **"Approve & Apply Remediation"**.
- **Audio / Voiceover:**  
  > *"A human remains in control before remediation is applied. SECUREFIX presents a precise, minimal patch. Once approved, the patch is applied directly to the sandboxed repository."*

---

### [1:45 – 2:10] Adversarial Verification
- **Visual:** The UI switches to the **Verification Engine** tab. The automated test runner executes bounded adversarial attack variants against the patched code:
  - Variant 1: BSON `$gt` operator payload
  - Variant 2: Nested `$ne` object injection
  - Variant 3: Boundary parameter type confusion
  All adversarial attacks return HTTP 401 Unauthorized / Rejected.
- **Audio / Voiceover:**  
  > *"The key difference is what happens after the patch. SECUREFIX X actively tries to break the remediation using bounded adversarial variants. It replays real attack payloads against the patched route, proving that the bypass vectors are genuinely blocked while legitimate logins still work."*

---

### [2:10 – 2:25] Mutation Assurance
- **Visual:** Show the **Mutation Testing** scorecard. The engine injects controlled faulty mutants into the patch (e.g. weakened boolean check) and proves the test suite catches them. Mutation score: 100%.
- **Audio / Voiceover:**  
  > *"Controlled faulty mutations test whether our verification process can actually detect weakened fixes. If a faulty mutant slips through, assurance is withheld."*

---

### [2:25 – 2:40] Final Verdict & Assurance
- **Visual:** Full-screen scorecard showing the badge:
  **VERIFIED WITHIN TESTED SCOPE**
  - Invariant Verified: YES
  - Adversarial Bypasses: 0 / 3
  - Mutation Score: 100%
  - Test Suite: 368 passing
- **Audio / Voiceover:**  
  > *"SECUREFIX X doesn't claim universal security. It provides evidence for what was actually tested and verified. Find it. Understand it. Fix it. Break the fix. Prove it."*
