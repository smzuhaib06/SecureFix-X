# SECUREFIX X — Screen Recording & Video Production Guide

**Target Duration:** 2 minutes 40 seconds  
**Aspect Ratio:** 16:9 (1920x1080 Full HD recommended)  
**Tools Recommended:** OBS Studio, SimpleScreenRecorder, Loom, or QuickTime  

---

## 1. Setup & Environment Preparation

1. **Resolution:** Set display scaling to 100% and browser viewport to 1920x1080.
2. **Clean Desktop:** Close background windows, notifications, and unnecessary browser tabs.
3. **Services Running:**
   - Backend on `http://localhost:8000`
   - Frontend on `http://localhost:3000`
4. **Browser Setup:** Open Google Chrome or Brave at `http://localhost:3000` in Dark Mode.

---

## 2. Recording Timeline & Actions

| Timestamp | Screen Action | Voiceover / Talking Point |
|---|---|---|
| **0:00 - 0:15** | Start on Home Page (`/`). Slowly scroll hero section showing the tagline and workflow diagram. | *"Security tools can find vulnerabilities, and AI can generate patches. But a patch is not proof of remediation."* |
| **0:15 - 0:35** | Click "New Investigation", paste `https://github.com/vulnerable-apps/nodejs-goof`, click "Start Investigation". | *"SECUREFIX X starts with a real repository and builds security evidence directly from its codebase. Here, we point it to a live public GitHub repository: Node.js Goof."* |
| **0:35 - 0:55** | Watch progress bar move to 90%. Expand the primary finding in `routes/index.js:39`. Highlight source/sink. | *"Seven specialized security evidence agents independently analyze the repository. The Code and Security agents trace untrusted user input from POST /login directly into a Mongoose query without sanitization."* |
| **0:55 - 1:15** | Click "AI Reasoning & RAG" tab. Highlight the CWE-943 and OWASP citations with relevance scores. | *"The evidence is grounded against security knowledge from CWE, OWASP, ASVS, and framework guidance."* |
| **1:15 - 1:30** | Scroll to the Root Cause explanation and Invariant section. Highlight grounding guarantees. | *"A grounded reasoning layer connects the repository evidence with security knowledge to explain the root cause and remediation."* |
| **1:30 - 1:45** | Scroll down to the Approval Gate. Show the clean unified diff. Click "Approve Remediation". | *"A human remains in control before remediation is applied."* |
| **1:45 - 2:10** | Switch to the "Verification Engine" tab. Show adversarial test execution and blocked exploit payloads. | *"The key difference is what happens after the patch. SECUREFIX X actively tries to break the remediation using bounded adversarial variants."* |
| **2:10 - 2:25** | Show Mutation Testing section with 100% mutant detection score. | *"Controlled faulty mutations test whether our verification process can actually detect weakened fixes."* |
| **2:25 - 2:40** | Highlight the final banner: **VERIFIED WITHIN TESTED SCOPE**. | *"SECUREFIX X doesn't claim universal security. It provides evidence for what was actually tested and verified."* |

---

## 3. Post-Recording Checklist
- [ ] Ensure audio is crisp and background noise is minimized.
- [ ] Save output as `submission/SECUREFIX_X_DEMO.mp4` (H.264 / AAC).
- [ ] Upload to YouTube (Unlisted) or Google Drive for hackathon judges.
